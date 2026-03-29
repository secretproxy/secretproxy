package app

import (
	"strings"
	"testing"
)

func TestUsageTextMentionsNewCommands(t *testing.T) {
	usage := usageText()
	for _, needle := range []string{"start", "check [text]", "status", "patterns update"} {
		if !strings.Contains(usage, needle) {
			t.Fatalf("usage missing %q", needle)
		}
	}
}
