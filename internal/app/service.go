package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"text/template"
)

const serviceName = "com.secretproxy"

func ServiceCommand(action string) error {
	switch action {
	case "install":
		return serviceInstall()
	case "uninstall":
		return serviceUninstall()
	case "start":
		return serviceStart()
	case "stop":
		return serviceStop()
	case "status":
		return serviceStatus()
	case "logs":
		return serviceLogs()
	default:
		return fmt.Errorf("unknown action: %s (use: install, uninstall, start, stop, status, logs)", action)
	}
}

// ── macOS (launchd) ──────────────────────────────

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Binary}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>{{.HomeDir}}</string>
</dict>
</plist>
`

// ── Linux (systemd user) ─────────────────────────

const systemdUnit = `[Unit]
Description=secretproxy
After=network.target

[Service]
ExecStart={{.Binary}}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`

func binaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(exe)
}

func serviceInstall() error {
	bin, err := binaryPath()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, ".secretproxy")
	os.MkdirAll(logDir, 0755)

	if runtime.GOOS == "darwin" {
		return installLaunchd(bin, home, logDir)
	}
	return installSystemd(bin)
}

func installLaunchd(bin, home, logDir string) error {
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	os.MkdirAll(plistDir, 0755)
	path := filepath.Join(plistDir, serviceName+".plist")

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tmpl := template.Must(template.New("plist").Parse(launchdPlist))
	err = tmpl.Execute(f, map[string]string{
		"Label":   serviceName,
		"Binary":  bin,
		"LogDir":  logDir,
		"HomeDir": home,
	})
	if err != nil {
		return err
	}

	fmt.Println("Installed:", path)

	// Auto-start
	if err := runCmd("launchctl", "load", path); err != nil {
		fmt.Println("Run manually: secretproxy service start")
	} else {
		fmt.Println("Service started.")
		fmt.Println("Logs: secretproxy service logs")
	}
	return nil
}

func installSystemd(bin string) error {
	home, _ := os.UserHomeDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	os.MkdirAll(unitDir, 0755)
	path := filepath.Join(unitDir, "secretproxy.service")

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tmpl := template.Must(template.New("unit").Parse(systemdUnit))
	err = tmpl.Execute(f, map[string]string{"Binary": bin})
	if err != nil {
		return err
	}

	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", "secretproxy").Run()
	exec.Command("systemctl", "--user", "start", "secretproxy").Run()

	fmt.Println("Installed:", path)
	fmt.Println("Service started.")
	fmt.Println("Logs: secretproxy service logs")
	return nil
}

func serviceUninstall() error {
	_ = serviceStop()

	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		path := filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("Removed:", path)
	} else {
		home, _ := os.UserHomeDir()
		path := filepath.Join(home, ".config", "systemd", "user", "secretproxy.service")
		exec.Command("systemctl", "--user", "disable", "secretproxy").Run()
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		exec.Command("systemctl", "--user", "daemon-reload").Run()
		fmt.Println("Removed:", path)
	}
	return nil
}

func serviceStart() error {
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		path := filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist")
		return runCmd("launchctl", "load", path)
	}
	return runCmd("systemctl", "--user", "start", "secretproxy")
}

func serviceStop() error {
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		path := filepath.Join(home, "Library", "LaunchAgents", serviceName+".plist")
		return runCmd("launchctl", "unload", path)
	}
	return runCmd("systemctl", "--user", "stop", "secretproxy")
}

func serviceStatus() error {
	if runtime.GOOS == "darwin" {
		return runCmd("launchctl", "list", serviceName)
	}
	return runCmd("systemctl", "--user", "status", "secretproxy")
}

func serviceLogs() error {
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		logFile := filepath.Join(home, ".secretproxy", "stderr.log")
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			fmt.Println("No logs yet. Is the service running?")
			fmt.Println("  secretproxy service start")
			return nil
		}
		return runCmd("tail", "-f", logFile)
	}
	return runCmd("journalctl", "--user", "-u", "secretproxy", "-f")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
