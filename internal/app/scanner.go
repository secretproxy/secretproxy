package app

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	lru "github.com/hashicorp/golang-lru/v2"
)

//go:embed gitleaks.toml
var embeddedRules embed.FS

type Rule struct {
	ID       string
	Regex    *regexp.Regexp
	Keywords []string
	Entropy  float64
}

type Scanner struct {
	rules      []Rule
	noKeyword  []int            // rule indices without keywords (always run)
	keywordMap map[string][]int // keyword -> rule indices
	acMatcher  *ahocorasick.Trie
	cache      *lru.Cache[[32]byte, []Finding]
	workers    int
}

type Finding struct {
	RuleID string
	Secret string
}

type gitleaksRule struct {
	ID       string   `toml:"id"`
	Regex    string   `toml:"regex"`
	Keywords []string `toml:"keywords"`
	Entropy  float64  `toml:"entropy"`
}

type gitleaksConfig struct {
	Rules []gitleaksRule `toml:"rules"`
}

type PatternSummary struct {
	Source        string
	Gitleaks      int
	Builtins      int
	Custom        int
	Total         int
	EnabledCustom []string
	InvalidCustom []string
	SourceErr     error
}

type matchSpan struct {
	start int
	end   int
}

func NewScanner(customPatterns []PatternEntry, cacheSize int) *Scanner {
	if cacheSize <= 0 {
		cacheSize = 2048
	}
	cache, _ := lru.New[[32]byte, []Finding](cacheSize)
	s := &Scanner{
		keywordMap: make(map[string][]int),
		workers:    runtime.NumCPU(),
		cache:      cache,
	}

	if data, source, err := loadGitleaksRulesData(); err == nil {
		s.loadGitleaksRules(data)
		slog.Debug("rules_source", "source", source)
	}

	// Built-in patterns not covered by gitleaks
	for _, b := range builtinPatterns() {
		if re, err := regexp.Compile(b.pattern); err == nil {
			s.rules = append(s.rules, Rule{ID: b.id, Regex: re, Entropy: 3})
		}
	}

	// Load custom patterns
	for _, p := range customPatterns {
		if !p.IsEnabled() {
			continue
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			slog.Warn("pattern_skipped", "label", p.Label, "err", err)
			continue
		}
		s.rules = append(s.rules, Rule{
			ID:    p.Label,
			Regex: re,
		})
	}

	s.buildIndex()
	slog.Debug("scanner_ready",
		"rules", len(s.rules),
		"keywords", len(s.keywordMap),
		"always_on", len(s.noKeyword),
		"workers", s.workers,
		"cache", cacheSize,
	)
	return s
}

func builtinPatterns() []struct{ id, pattern string } {
	return []struct{ id, pattern string }{
		{"secret-key-generic", `\bsk-[a-zA-Z0-9_\-.]{20,}\b`},
		{"database-url", `(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s:]+:[^\s@]+@[^\s]+`},
	}
}

func (s *Scanner) loadGitleaksRules(data []byte) {
	var cfg gitleaksConfig
	if _, err := tomlDecode(string(data), &cfg); err != nil {
		slog.Warn("rules_parse_error", "err", err)
		return
	}

	for _, r := range cfg.Rules {
		if r.Regex == "" {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			continue
		}
		kw := make([]string, len(r.Keywords))
		for i, k := range r.Keywords {
			kw[i] = strings.ToLower(k)
		}
		s.rules = append(s.rules, Rule{
			ID:       r.ID,
			Regex:    re,
			Keywords: kw,
			Entropy:  r.Entropy,
		})
	}
}

// buildIndex builds Aho-Corasick automaton from all keywords
// and maps each keyword to the rules that use it.
func (s *Scanner) buildIndex() {
	var allKeywords []string
	for i, r := range s.rules {
		if len(r.Keywords) == 0 {
			s.noKeyword = append(s.noKeyword, i)
		} else {
			for _, kw := range r.Keywords {
				s.keywordMap[kw] = append(s.keywordMap[kw], i)
				allKeywords = append(allKeywords, kw)
			}
		}
	}

	if len(allKeywords) > 0 {
		s.acMatcher = ahocorasick.NewTrieBuilder().AddStrings(allKeywords).Build()
	}
}

func cacheKey(text string) [32]byte {
	return sha256.Sum256([]byte(text))
}

// DetectString scans text and returns all findings.
// Uses cache to skip already-scanned text and parallel regex execution.
func (s *Scanner) DetectString(text string) []Finding {
	// Cache lookup
	key := cacheKey(text)
	if cached, ok := s.cache.Get(key); ok {
		return cached
	}

	placeholderSpans := findPlaceholderSpans(text)

	// Determine active rules via Aho-Corasick
	activeIndices := s.findActiveRules(stripPlaceholders(text))

	// Run regex in parallel
	var findings []Finding
	if len(activeIndices) <= 4 || s.workers <= 1 {
		findings = s.runRules(activeIndices, text, placeholderSpans)
	} else {
		findings = s.runRulesParallel(activeIndices, text, placeholderSpans)
	}

	s.cache.Add(key, findings)
	return findings
}

func loadGitleaksRulesData() ([]byte, string, error) {
	localPath := filepath.Join(configDir(), "gitleaks.toml")
	if data, err := os.ReadFile(localPath); err == nil {
		return data, localPath, nil
	}
	data, err := embeddedRules.ReadFile("gitleaks.toml")
	if err != nil {
		return nil, "", err
	}
	return data, "embedded", nil
}

func GetPatternSummary(customPatterns []PatternEntry) PatternSummary {
	summary := PatternSummary{
		Builtins: len(builtinPatterns()),
	}

	data, source, err := loadGitleaksRulesData()
	if err != nil {
		summary.SourceErr = err
		return summary
	}
	summary.Source = source

	var cfg gitleaksConfig
	if _, err := tomlDecode(string(data), &cfg); err != nil {
		summary.SourceErr = err
		return summary
	}
	for _, r := range cfg.Rules {
		if r.Regex == "" {
			continue
		}
		if _, err := regexp.Compile(r.Regex); err == nil {
			summary.Gitleaks++
		}
	}

	for _, p := range customPatterns {
		if !p.IsEnabled() {
			continue
		}
		if _, err := regexp.Compile(p.Regex); err != nil {
			summary.InvalidCustom = append(summary.InvalidCustom, p.Label)
			continue
		}
		summary.EnabledCustom = append(summary.EnabledCustom, p.Label)
		summary.Custom++
	}

	sort.Strings(summary.EnabledCustom)
	sort.Strings(summary.InvalidCustom)
	summary.Total = summary.Gitleaks + summary.Builtins + summary.Custom
	return summary
}

func (p PatternSummary) SourceDisplay() string {
	if p.Source == "" {
		return "unknown"
	}
	return p.Source
}

func stripPlaceholders(text string) string {
	return placeholderRe.ReplaceAllStringFunc(text, func(m string) string {
		return strings.Repeat(" ", len(m))
	})
}

func findPlaceholderSpans(text string) []matchSpan {
	indices := placeholderRe.FindAllStringIndex(text, -1)
	spans := make([]matchSpan, 0, len(indices))
	for _, idx := range indices {
		spans = append(spans, matchSpan{start: idx[0], end: idx[1]})
	}
	return spans
}

func overlapsPlaceholder(start, end int, spans []matchSpan) bool {
	for _, span := range spans {
		if start < span.end && end > span.start {
			return true
		}
	}
	return false
}

func (s *Scanner) findActiveRules(text string) []int {
	active := make([]int, 0, len(s.noKeyword)+10)
	active = append(active, s.noKeyword...)

	if s.acMatcher != nil {
		textLower := strings.ToLower(text)
		seen := make(map[int]bool)
		for _, m := range s.acMatcher.MatchString(textLower) {
			kw := string(m.Match())
			for _, idx := range s.keywordMap[kw] {
				if !seen[idx] {
					seen[idx] = true
					active = append(active, idx)
				}
			}
		}
	}
	return active
}

func (s *Scanner) runRules(indices []int, text string, placeholderSpans []matchSpan) []Finding {
	var findings []Finding
	for _, idx := range indices {
		findings = append(findings, s.matchRule(&s.rules[idx], text, placeholderSpans)...)
	}
	return findings
}

func (s *Scanner) runRulesParallel(indices []int, text string, placeholderSpans []matchSpan) []Finding {
	ch := make(chan int, len(indices))
	for _, idx := range indices {
		ch <- idx
	}
	close(ch)

	var mu sync.Mutex
	var all []Finding
	var wg sync.WaitGroup

	workers := s.workers
	if workers > len(indices) {
		workers = len(indices)
	}

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			var local []Finding
			for idx := range ch {
				local = append(local, s.matchRule(&s.rules[idx], text, placeholderSpans)...)
			}
			if len(local) > 0 {
				mu.Lock()
				all = append(all, local...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return all
}

func (s *Scanner) matchRule(r *Rule, text string, placeholderSpans []matchSpan) []Finding {
	var findings []Finding
	for _, match := range r.Regex.FindAllStringSubmatchIndex(text, -1) {
		start, end := match[0], match[1]
		if len(match) > 3 && match[2] != -1 {
			start, end = match[2], match[3]
		}
		if overlapsPlaceholder(start, end, placeholderSpans) {
			continue
		}
		secret := text[start:end]
		if secret == "" {
			continue
		}
		if r.Entropy > 0 && shannonEntropy(secret) < r.Entropy {
			continue
		}
		findings = append(findings, Finding{
			RuleID: r.ID,
			Secret: secret,
		})
	}
	return findings
}

const gitleaksURL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secretproxy")
}

func UpdateGitleaksRules() error {
	resp, err := http.Get(gitleaksURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB max
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	dir := configDir()
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "gitleaks.toml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	fmt.Printf("Downloaded %d bytes to %s\n", len(data), path)
	return nil
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range []byte(s) {
		freq[b]++
	}
	n := float64(len(s))
	var ent float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
