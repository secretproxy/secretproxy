package app

import (
	"testing"
)

func piiDetector() *PiiDetector {
	return NewPiiDetector(PiiConfig{Enabled: true})
}

func TestPiiEmail(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"contact user@example.com please",
		"send to admin@company.co.uk",
		"alice.bob+tag@gmail.com",
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "EMAIL" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected EMAIL match in %q", s)
		}
	}

	negatives := []string{
		"file@2.0 is a version",
		"not-an-email@123",
		"lib@1.2.3",
	}
	for _, s := range negatives {
		matches := d.Scan(s)
		for _, m := range matches {
			if m.EntityType == "EMAIL" {
				t.Errorf("false positive EMAIL in %q: %s", s, m.Value)
			}
		}
	}
}

func TestPiiPhone(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"call +7 999 123-45-67",
		"phone: +1 (555) 123-4567",
		"+44 20 7946 0958",
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "PHONE" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected PHONE match in %q", s)
		}
	}

	negatives := []string{
		"HISTSIZE=10000",
		"2025-03-29 14:47:37",
		"port 9900",
		"+0",
	}
	for _, s := range negatives {
		matches := d.Scan(s)
		for _, m := range matches {
			if m.EntityType == "PHONE" {
				t.Errorf("false positive PHONE in %q: %s", s, m.Value)
			}
		}
	}
}

func TestPiiCreditCard(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"card: 4111111111111111",         // Visa test, Luhn valid
		"card: 5500000000000004",         // Mastercard test, Luhn valid
		"pay with 4111-1111-1111-1111",   // with dashes
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "CREDIT_CARD" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected CREDIT_CARD match in %q", s)
		}
	}

	negatives := []string{
		"id: 1234567890123",        // 13 digits, Luhn invalid
		"max_body_size = 10485760", // config number
		"HISTSIZE=10000",
		"1234567890123456",         // 16 digits, Luhn invalid
	}
	for _, s := range negatives {
		matches := d.Scan(s)
		for _, m := range matches {
			if m.EntityType == "CREDIT_CARD" {
				t.Errorf("false positive CREDIT_CARD in %q: %s", s, m.Value)
			}
		}
	}
}

func TestPiiIBAN(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"transfer to DE89370400440532013000",
		"IBAN: GB29NWBK60161331926819",
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "IBAN" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected IBAN match in %q", s)
		}
	}

	negatives := []string{
		"AB12FAKE000000000000", // invalid checksum
		"HELLO WORLD 12345",
	}
	for _, s := range negatives {
		matches := d.Scan(s)
		for _, m := range matches {
			if m.EntityType == "IBAN" {
				t.Errorf("false positive IBAN in %q: %s", s, m.Value)
			}
		}
	}
}

func TestPiiPrivateIP(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"server at 10.0.1.50",
		"host: 192.168.1.1",
		"ip 172.16.0.100",
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "PRIVATE_IP" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected PRIVATE_IP match in %q", s)
		}
	}

	negatives := []string{
		"8.8.8.8 is Google DNS",
		"172.15.0.1 is not private",
	}
	for _, s := range negatives {
		matches := d.Scan(s)
		for _, m := range matches {
			if m.EntityType == "PRIVATE_IP" {
				t.Errorf("false positive PRIVATE_IP in %q: %s", s, m.Value)
			}
		}
	}
}

func TestPiiGPS(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"location: 55.7558, 37.6173",
		"coords -33.8688, 151.2093",
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "GPS_COORDS" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected GPS_COORDS match in %q", s)
		}
	}

	negatives := []string{
		"value: 100.1234, 200.5678", // lon > 180
		"pi is 3.14159265",          // not a pair
	}
	for _, s := range negatives {
		matches := d.Scan(s)
		for _, m := range matches {
			if m.EntityType == "GPS_COORDS" {
				t.Errorf("false positive GPS_COORDS in %q: %s", s, m.Value)
			}
		}
	}
}

func TestPiiInternalURL(t *testing.T) {
	d := piiDetector()

	positives := []string{
		"go to jira.company.internal",
		"host: grafana.monitoring.corp",
		"db.prod.lan is down",
	}
	for _, s := range positives {
		matches := d.Scan(s)
		found := false
		for _, m := range matches {
			if m.EntityType == "INTERNAL_URL" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected INTERNAL_URL match in %q", s)
		}
	}
}

func TestPiiSkipsPlaceholders(t *testing.T) {
	d := piiDetector()

	inputs := []string{
		"token [[PII_EMAIL_5c394c2e14640cea]]",
		"key [[GENERIC_API_KEY_934d6feb689a5a87]]",
		"[[PII_NATIONAL_ID_ed99f4e13c587b92]]",
	}
	for _, s := range inputs {
		matches := d.Scan(s)
		if len(matches) > 0 {
			t.Errorf("placeholder should not trigger PII: %q matched %v", s, matches[0])
		}
	}
}

func TestPiiNoFalsePositivesOnCommonText(t *testing.T) {
	d := piiDetector()

	clean := []string{
		"HISTSIZE=10000",
		"SAVEHIST=10000",
		"max_body_size = 10485760",
		"2025-03-29 14:47:37",
		"the model is claude-sonnet-4-20250514",
		"port = 9900",
		"cache_size = 2048",
		"http://localhost:9900/anthropic",
		"https://api.anthropic.com/v1/messages",
	}
	for _, s := range clean {
		matches := d.Scan(s)
		if len(matches) > 0 {
			t.Errorf("false positive in %q: %s=%s", s, matches[0].EntityType, matches[0].Value)
		}
	}
}
