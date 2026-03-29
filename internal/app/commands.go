package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

func usageText() string {
	return strings.TrimSpace(`
Usage:
  secretproxy [global flags] start
  secretproxy [global flags] check [text]
  secretproxy [global flags] status
  secretproxy [global flags] patterns update
  secretproxy [global flags] service <install|uninstall|start|stop|status|logs>

Global Flags:
  -port int
        override listen port
  -version
        print version and exit
  -help, -h
        show help
`)
}

// Version is set by the main package at startup (injected via ldflags).
var Version = "dev"

func Run(args []string, stdout, stderr io.Writer) error {
	initLogger(DefaultConfig().SlogLevel(), DefaultConfig().LogFormatValue())

	fs := flag.NewFlagSet("secretproxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	port := fs.Int("port", 0, "override listen port")
	showVersion := fs.Bool("version", false, "print version and exit")
	showHelp := fs.Bool("help", false, "show help")
	fs.BoolVar(showHelp, "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Fprintln(stdout, "secretproxy", Version)
		return nil
	}

	cmd := "start"
	cmdArgs := fs.Args()
	if len(cmdArgs) > 0 {
		cmd = cmdArgs[0]
		cmdArgs = cmdArgs[1:]
	}

	configPath := ConfigPath()
	if !fileExists(configPath) {
		_ = GenerateDefaultConfig(configPath)
	}
	cfg := LoadConfig(configPath)
	if *port != 0 {
		cfg.Port = *port
	}

	initLogger(cfg.SlogLevel(), cfg.LogFormatValue())

	if *showHelp || cmd == "help" {
		fmt.Fprintln(stdout, usageText())
		return nil
	}

	return runCommand(cmd, cmdArgs, cfg, configPath, stdout, stderr)
}

func runCommand(cmd string, args []string, cfg Config, configPath string, stdout, stderr io.Writer) error {
	switch cmd {
	case "", "start":
		if len(args) > 0 {
			return fmt.Errorf("start takes no arguments")
		}
		return runStart(cfg)
	case "check":
		return runCheck(cfg, args, stdout)
	case "status":
		if len(args) > 0 {
			return fmt.Errorf("status takes no arguments")
		}
		return runStatus(cfg, configPath, stdout)
	case "patterns":
		return runPatternsCommand(cfg, args, stdout)
	case "service":
		if len(args) < 1 {
			return fmt.Errorf("usage: secretproxy service [install|uninstall|start|stop|status|logs]")
		}
		return ServiceCommand(args[0])
	default:
		fmt.Fprintln(stderr, usageText())
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runStart(cfg Config) error {
	masker := NewMasker(cfg.PII, cfg.Patterns, cfg.CacheSize, cfg.VaultSize, cfg.UnmaskEnabled(), cfg.PlaceholderModeValue())
	proxy := NewProxy(masker, cfg.Routes, cfg.DefaultTarget, cfg.MaxBodySize)

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	srv := &http.Server{Addr: addr, Handler: proxy}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logShutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	logStartup(Version, addr)
	for _, rt := range sortedRoutes(cfg.Routes) {
		logRoute(rt.slug, rt.target)
	}
	if cfg.DefaultTarget != "" {
		logDefaultRoute(cfg.DefaultTarget)
	}

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runCheck(cfg Config, args []string, stdout io.Writer) error {
	masker := NewMasker(cfg.PII, cfg.Patterns, cfg.CacheSize, cfg.VaultSize, cfg.UnmaskEnabled(), cfg.PlaceholderModeValue())

	input, err := readInlineOrStdin(args)
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "─── Input ───")
	fmt.Fprintln(stdout, input)
	fmt.Fprintln(stdout, "─── Masked ──")
	masked, dur := masker.MaskTextTimed(input)
	fmt.Fprintln(stdout, masked)
	fmt.Fprintln(stdout, "─── Unmask ──")
	unmasked := masker.UnmaskText(masked)
	fmt.Fprintln(stdout, unmasked)
	fmt.Fprintf(stdout, "─── scan: %s | size: %d bytes | roundtrip: %s ──\n",
		dur, len(input), map[bool]string{true: "OK", false: "MISMATCH"}[unmasked == input])
	return nil
}

func runStatus(cfg Config, configPath string, stdout io.Writer) error {
	running, latency, err := probeHealth(cfg.Port)
	servicePath := serviceManifestPath()

	state := "stopped"
	health := "not reachable"
	if running {
		state = "running"
		health = fmt.Sprintf("ok (%s)", latency.Round(time.Millisecond))
	} else if err != nil {
		health = err.Error()
	}

	fmt.Fprintf(stdout, "state: %s\n", state)
	fmt.Fprintf(stdout, "listen: %s\n", localBaseURL(cfg.Port))
	fmt.Fprintf(stdout, "health: %s\n", health)
	fmt.Fprintf(stdout, "config: %s\n", configPath)
	fmt.Fprintf(stdout, "config_file: %s\n", yesNo(fileExists(configPath)))
	fmt.Fprintf(stdout, "service_file: %s\n", servicePath)
	fmt.Fprintf(stdout, "service_installed: %s\n", yesNo(fileExists(servicePath)))
	fmt.Fprintf(stdout, "unmask: %t\n", cfg.UnmaskEnabled())
	fmt.Fprintf(stdout, "placeholder_mode: %s\n", cfg.PlaceholderModeValue())
	fmt.Fprintf(stdout, "log_format: %s\n", cfg.LogFormatValue())
	fmt.Fprintf(stdout, "log_level: %s\n", cfg.LogLevelValue())
	fmt.Fprintf(stdout, "routes: %d\n", len(cfg.Routes))
	if cfg.DefaultTarget != "" {
		fmt.Fprintf(stdout, "default_target: %s\n", cfg.DefaultTarget)
	}
	return nil
}

func runPatternsCommand(cfg Config, args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: secretproxy patterns update")
	}
	switch args[0] {
	case "update":
		if err := UpdateGitleaksRules(); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Restart proxy to apply new patterns.")
		return nil
	default:
		return fmt.Errorf("unknown patterns command %q", args[0])
	}
}

func readInlineOrStdin(args []string) (string, error) {
	if len(args) > 0 {
		return strings.Join(args, " "), nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read stdin: %w", err)
	}
	return string(data), nil
}

type routeEntry struct {
	slug   string
	target string
}

func sortedRoutes(routes map[string]string) []routeEntry {
	out := make([]routeEntry, 0, len(routes))
	for slug, target := range routes {
		out = append(out, routeEntry{slug: slug, target: target})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].slug < out[j].slug })
	return out
}

func localBaseURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func probeHealth(port int) (bool, time.Duration, error) {
	client := &http.Client{Timeout: 750 * time.Millisecond}
	start := time.Now()
	resp, err := client.Get(localBaseURL(port) + "/health")
	latency := time.Since(start)
	if err != nil {
		return false, latency, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return false, latency, fmt.Errorf("unexpected health response: %d %q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return true, latency, nil
}

func checkPortAvailable(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	ln.Close()
	return nil
}

func validateConfigFile(path string) error {
	if !fileExists(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cfg := DefaultConfig()
	_, err = toml.Decode(string(data), &cfg)
	return err
}

func validateRoutes(cfg Config) []string {
	var errs []string
	for _, rt := range sortedRoutes(cfg.Routes) {
		if err := validateHTTPURL(rt.target); err != nil {
			errs = append(errs, fmt.Sprintf("%s=%v", rt.slug, err))
		}
	}
	if cfg.DefaultTarget != "" {
		if err := validateHTTPURL(cfg.DefaultTarget); err != nil {
			errs = append(errs, fmt.Sprintf("default_target=%v", err))
		}
	}
	return errs
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	return nil
}

func serviceManifestPath() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist")
	}
	return filepath.Join(home, ".config", "systemd", "user", "secretproxy.service")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
