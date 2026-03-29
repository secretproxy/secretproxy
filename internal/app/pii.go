package app

import (
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type PiiDetector struct {
	rules []piiRule
}

type PiiMatch struct {
	Value      string
	EntityType string
	Score      float64
}

type piiRule struct {
	name     string
	regex    *regexp.Regexp
	validate func(string) bool
}

// placeholder pattern: [[LABEL:preview_hash]] or [[LABEL:hash]] — skip during PII scanning
var placeholderRe = regexp.MustCompile(`\[\[[A-Z0-9_]+:[^\]]+\]\]`)

func NewPiiDetector(_ PiiConfig) *PiiDetector {
	d := &PiiDetector{}
	d.rules = []piiRule{
		{
			name:     "EMAIL",
			regex:    regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			validate: validateEmail,
		},
		{
			name:     "PHONE",
			regex:    regexp.MustCompile(`\+[0-9][0-9 ()\-]{5,14}[0-9]`),
			validate: validatePhone,
		},
		{
			name:     "CREDIT_CARD",
			regex:    regexp.MustCompile(`\b\d(?:[ \-]?\d){12,15}\b`),
			validate: validateLuhn,
		},
		{
			name:     "IBAN",
			regex:    regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}[A-Z0-9]{7,27}\b`),
			validate: validateIBAN,
		},
		{
			name:     "PRIVATE_IP",
			regex:    regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
			validate: validatePrivateIP,
		},
		{
			name:     "GPS_COORDS",
			regex:    regexp.MustCompile(`\b[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}\b`),
			validate: validateGPS,
		},
		{
			name:     "INTERNAL_URL",
			regex:    regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.(?:internal|local|corp|lan|intranet)\b`),
			validate: func(s string) bool { return !strings.HasPrefix(s, "localhost") },
		},
	}
	return d
}

func (d *PiiDetector) Scan(text string) []PiiMatch {
	// Blank out placeholders so we don't re-mask them
	clean := placeholderRe.ReplaceAllStringFunc(text, func(m string) string {
		return strings.Repeat(" ", len(m))
	})

	var results []PiiMatch
	for _, rule := range d.rules {
		for _, loc := range rule.regex.FindAllStringIndex(clean, -1) {
			value := text[loc[0]:loc[1]] // original text, not blanked
			if rule.validate != nil && !rule.validate(value) {
				continue
			}
			results = append(results, PiiMatch{
				Value:      value,
				EntityType: rule.name,
				Score:      1.0,
			})
		}
	}
	return results
}

// ── Validators ──────────────────────────────────

func validateEmail(s string) bool {
	at := strings.LastIndex(s, "@")
	if at < 1 {
		return false
	}
	domain := s[at+1:]
	// Must have at least one dot, TLD >= 2 chars
	dot := strings.LastIndex(domain, ".")
	if dot < 1 || len(domain)-dot-1 < 2 {
		return false
	}
	// Reject numeric-only TLD (e.g., version strings like lib@1.2.3)
	tld := domain[dot+1:]
	for _, r := range tld {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func validatePhone(s string) bool {
	// Count actual digits
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 7 && digits <= 15
}

func validateLuhn(s string) bool {
	// Extract digits only
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 16 {
		return false
	}

	// Luhn algorithm
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func validateIBAN(s string) bool {
	// Remove spaces
	clean := strings.ReplaceAll(s, " ", "")
	if len(clean) < 15 || len(clean) > 34 {
		return false
	}

	// Country code must be letters, check digits must be digits
	cc := clean[:2]
	for _, r := range cc {
		if !unicode.IsUpper(r) {
			return false
		}
	}

	// Move first 4 chars to end, convert letters to numbers (A=10, B=11, ...)
	rearranged := clean[4:] + clean[:4]
	var numStr strings.Builder
	for _, r := range rearranged {
		if unicode.IsUpper(r) {
			numStr.WriteString(strconv.Itoa(int(r-'A') + 10))
		} else if unicode.IsDigit(r) {
			numStr.WriteRune(r)
		} else {
			return false
		}
	}

	// mod 97 == 1
	n := new(big.Int)
	n.SetString(numStr.String(), 10)
	mod := new(big.Int).Mod(n, big.NewInt(97))
	return mod.Int64() == 1
}

func validatePrivateIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func validateGPS(s string) bool {
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}
