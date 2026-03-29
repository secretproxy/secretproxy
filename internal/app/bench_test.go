package app

import (
	"fmt"
	"strings"
	"testing"
)

var benchMasker *Masker

func init() {
	benchMasker = NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, true, "preview")
}

var sampleSmall = "export KEY=sk_live_abcdef1234567890ab and glpat-xYz12345678901234567"
var sampleMedium = strings.Repeat(sampleSmall+" ", 50)                                // ~5KB
var sampleLarge = strings.Repeat(sampleSmall+" ", 500)                                // ~50KB
var sampleClean = strings.Repeat("the quick brown fox jumps over the lazy dog ", 100) // ~4.5KB, no secrets
var sampleJSON = `{"model":"gpt-4o","messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"debug this config: stripe=sk_live_abcdef1234567890ab gitlab=glpat-AbCdEf1234567890 postgres=postgres://alice:secretpass@db.internal:5432/app"},{"role":"assistant","content":"I can help with that."}]}`
var sampleJSONInput = `{"model":"gpt-4.1","input":[{"role":"user","content":"use sk_live_abcdef1234567890ab and redis://alice:secretpass@cache.internal:6379/0 to test the connection"}]}`
var sampleJSONClean = `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"explain how retries work in this service"}]}`
var sampleMaskedResponse = `{"output_text":"Use sk_live_abcdef1234567890ab and glpat-xYz12345678901234567 in the generated curl example."}`

func setBenchBytes(b *testing.B, sample string) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(sample)))
}

func BenchmarkMaskText_Small(b *testing.B) {
	setBenchBytes(b, sampleSmall)
	for i := 0; i < b.N; i++ {
		benchMasker.MaskText(sampleSmall)
	}
}

func BenchmarkMaskText_Medium(b *testing.B) {
	setBenchBytes(b, sampleMedium)
	for i := 0; i < b.N; i++ {
		benchMasker.MaskText(sampleMedium)
	}
}

func BenchmarkMaskText_Large(b *testing.B) {
	setBenchBytes(b, sampleLarge)
	for i := 0; i < b.N; i++ {
		benchMasker.MaskText(sampleLarge)
	}
}

func BenchmarkMaskText_CleanNoSecrets(b *testing.B) {
	setBenchBytes(b, sampleClean)
	for i := 0; i < b.N; i++ {
		benchMasker.MaskText(sampleClean)
	}
}

func BenchmarkDetectOnly_Small(b *testing.B) {
	setBenchBytes(b, sampleSmall)
	for i := 0; i < b.N; i++ {
		benchMasker.scanner.DetectString(sampleSmall)
	}
}

func BenchmarkDetectOnly_Large(b *testing.B) {
	setBenchBytes(b, sampleLarge)
	for i := 0; i < b.N; i++ {
		benchMasker.scanner.DetectString(sampleLarge)
	}
}

func BenchmarkMaskJSON_ClaudeLike(b *testing.B) {
	setBenchBytes(b, sampleJSON)
	for i := 0; i < b.N; i++ {
		if _, err := benchMasker.MaskJSON([]byte(sampleJSON)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaskJSON_InputArray(b *testing.B) {
	setBenchBytes(b, sampleJSONInput)
	for i := 0; i < b.N; i++ {
		if _, err := benchMasker.MaskJSON([]byte(sampleJSONInput)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaskBody_JSONWithSecrets(b *testing.B) {
	setBenchBytes(b, sampleJSON)
	for i := 0; i < b.N; i++ {
		benchMasker.MaskBody([]byte(sampleJSON), "application/json")
	}
}

func BenchmarkMaskBody_JSONClean(b *testing.B) {
	setBenchBytes(b, sampleJSONClean)
	for i := 0; i < b.N; i++ {
		benchMasker.MaskBody([]byte(sampleJSONClean), "application/json")
	}
}

func BenchmarkUnmaskText_ResponseBody(b *testing.B) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, true, "preview")
	_ = m.MaskText("stripe sk_live_abcdef1234567890ab gitlab glpat-AbCdEf1234567890")
	setBenchBytes(b, sampleMaskedResponse)
	for i := 0; i < b.N; i++ {
		m.UnmaskText(sampleMaskedResponse)
	}
}

// Cold path benchmarks — unique text each iteration, no cache hits
func BenchmarkMaskText_Small_Cold(b *testing.B) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, true, "preview")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.MaskText(fmt.Sprintf("%s %d", sampleSmall, i))
	}
}

func BenchmarkMaskText_Large_Cold(b *testing.B) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, true, "preview")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.MaskText(fmt.Sprintf("%s %d", sampleLarge, i))
	}
}

func BenchmarkMaskText_Clean_Cold(b *testing.B) {
	m := NewMasker(PiiConfig{Enabled: false}, nil, 0, 0, true, "preview")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.MaskText(fmt.Sprintf("%s %d", sampleClean, i))
	}
}
