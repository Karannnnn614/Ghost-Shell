// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package analyze

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"ghostshell/internal/cast"
	"ghostshell/internal/span"
)

// startUnix is the session start (unix seconds) used by the correlation tests;
// it matches `base` (the span timestamp origin) so a span starting at
// (base + k*sec) maps to cast-relative second k.
const startUnix = int64(1700000000)

type castEv struct {
	t    float64
	typ  string // "o" or "i"
	data string
}

// buildCast hand-assembles a decrypted asciinema v2 cast: a header line (with
// the given unix-seconds timestamp; 0 omits the field entirely) followed by one
// line per event. This is the exact shape correlateOutput consumes.
func buildCast(timestamp int64, evs []castEv) string {
	var b strings.Builder
	hdr, _ := json.Marshal(cast.Header{Version: 2, Width: 80, Height: 24, Timestamp: timestamp})
	b.Write(hdr)
	b.WriteByte('\n')
	for _, e := range evs {
		data, _ := json.Marshal(e.data)
		fmt.Fprintf(&b, "[%.6f, %q, %s]\n", e.t, e.typ, data)
	}
	return b.String()
}

// TestAnalyze_FailureOutputCorrelation is the core correlation test: each
// failure must capture exactly the output events inside its [StartTS, EndTS]
// window, output events outside every window must be dropped, and input ("i")
// events must be ignored.
func TestAnalyze_FailureOutputCorrelation(t *testing.T) {
	spans := []span.Span{
		sp("failA", "cmd-a", 1, 2, 1), // window rel [1,3]
		sp("ok", "cmd-ok", 3, 1, 0),   // success -> no Failure entry
		sp("failB", "cmd-b", 5, 2, 2), // window rel [5,7]
	}
	castText := buildCast(startUnix, []castEv{
		{0.5, "o", "before\r\n"},      // before any window -> dropped
		{1.5, "o", "A-out\r\n"},       // in A
		{1.6, "i", "typed-input\r\n"}, // input -> ignored even though in A's window
		{2.5, "o", "A-err: boom\r\n"}, // in A
		{4.0, "o", "middle\r\n"},      // between windows -> dropped
		{6.0, "o", "B-fatal\r\n"},     // in B
		{8.0, "o", "after\r\n"},       // past all windows -> dropped
	})

	sum, err := Analyze(spans, strings.NewReader(castText), startUnix, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(sum.Failures) != 2 {
		t.Fatalf("want 2 failures, got %d: %+v", len(sum.Failures), sum.Failures)
	}
	a, b := sum.Failures[0], sum.Failures[1]
	if a.SpanID != "failA" || b.SpanID != "failB" {
		t.Fatalf("failure order = %s,%s; want failA,failB", a.SpanID, b.SpanID)
	}

	if !strings.Contains(a.Output, "A-out") || !strings.Contains(a.Output, "A-err: boom") {
		t.Errorf("failA.Output missing expected content: %q", a.Output)
	}
	for _, bad := range []string{"before", "typed-input", "middle", "after", "B-fatal"} {
		if strings.Contains(a.Output, bad) {
			t.Errorf("failA.Output leaked %q: %q", bad, a.Output)
		}
	}
	if a.OutputTruncated {
		t.Errorf("failA.Output should not be truncated: %q", a.Output)
	}

	if !strings.Contains(b.Output, "B-fatal") {
		t.Errorf("failB.Output missing B-fatal: %q", b.Output)
	}
	for _, bad := range []string{"middle", "after", "A-out"} {
		if strings.Contains(b.Output, bad) {
			t.Errorf("failB.Output leaked %q: %q", bad, b.Output)
		}
	}
}

// When sessionStartUnix <= 0, correlation must fall back to the cast header's
// Timestamp.
func TestAnalyze_FallsBackToHeaderTimestamp(t *testing.T) {
	spans := []span.Span{sp("fail", "cmd", 1, 2, 1)} // window rel [1,3]
	castText := buildCast(startUnix, []castEv{
		{2.0, "o", "header-timestamp-path\r\n"},
	})
	sum, err := Analyze(spans, strings.NewReader(castText), 0, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(sum.Failures) != 1 || !strings.Contains(sum.Failures[0].Output, "header-timestamp-path") {
		t.Fatalf("fallback to header timestamp failed: %+v", sum.Failures)
	}
}

// Output beyond MaxOutputBytes must keep the tail and set OutputTruncated.
func TestAnalyze_OutputTruncationKeepsTail(t *testing.T) {
	spans := []span.Span{sp("fail", "cmd", 1, 2, 1)} // window rel [1,3]
	castText := buildCast(startUnix, []castEv{
		{1.5, "o", "0123456789ABCDE"}, // 15 bytes; cap 10 keeps last 10
	})
	sum, err := Analyze(spans, strings.NewReader(castText), startUnix, Options{MaxOutputBytes: 10})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	f := sum.Failures[0]
	if !f.OutputTruncated {
		t.Errorf("OutputTruncated = false, want true")
	}
	if f.Output != "56789ABCDE" {
		t.Errorf("Output = %q, want %q (last 10 bytes)", f.Output, "56789ABCDE")
	}
}

// Truncation must accumulate across multiple events, not just within one event.
func TestAnalyze_OutputTruncationAcrossEvents(t *testing.T) {
	spans := []span.Span{sp("fail", "cmd", 1, 5, 1)} // window rel [1,6]
	castText := buildCast(startUnix, []castEv{
		{1.5, "o", "AAAAA"},
		{2.5, "o", "BBBBB"},
		{3.5, "o", "CCCCC"}, // 15 bytes total; cap 8 -> last 8 "BBBCCCCC"
	})
	sum, err := Analyze(spans, strings.NewReader(castText), startUnix, Options{MaxOutputBytes: 8})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	f := sum.Failures[0]
	if !f.OutputTruncated || f.Output != "BBBCCCCC" {
		t.Errorf("cumulative truncation wrong: Output=%q trunc=%v", f.Output, f.OutputTruncated)
	}
}

// With no usable session start (sessionStartUnix<=0 AND no header timestamp),
// Analyze must return an error but STILL deliver a fully-populated deterministic
// Summary with empty failure outputs.
func TestAnalyze_NoSessionStartErrorsButSummaryValid(t *testing.T) {
	spans := []span.Span{
		sp("fail", "cmd", 1, 2, 1),
		sp("ok", "ok", 0, 1, 0),
	}
	castText := buildCast(0, []castEv{{1.5, "o", "unreachable\r\n"}}) // header omits timestamp
	sum, err := Analyze(spans, strings.NewReader(castText), 0, Options{})
	if err == nil {
		t.Fatalf("want an error when no session start is available")
	}
	if sum.CommandCount != 2 || sum.FailureCount != 1 {
		t.Errorf("deterministic summary should still be populated: %+v", sum)
	}
	if len(sum.Failures) != 1 || sum.Failures[0].Output != "" {
		t.Errorf("failure output should be empty when correlation could not run: %+v", sum.Failures)
	}
}

// A nil cast reader is valid: failures are still reported, just without output,
// and Analyze returns no error.
func TestAnalyze_NilCast(t *testing.T) {
	spans := []span.Span{sp("fail", "cmd", 1, 2, 1)}
	sum, err := Analyze(spans, nil, startUnix, Options{})
	if err != nil {
		t.Fatalf("nil cast must not error: %v", err)
	}
	if len(sum.Failures) != 1 || sum.Failures[0].Output != "" {
		t.Errorf("nil cast: want 1 failure with empty output, got %+v", sum.Failures)
	}
}

// A malformed event line mid-stream must be tolerated fail-open: output
// collected before it survives, and Analyze does not error.
func TestAnalyze_MalformedEventIsFailOpen(t *testing.T) {
	spans := []span.Span{sp("fail", "cmd", 1, 5, 1)} // window rel [1,6]
	// Hand-build: header, one good event in-window, then a garbage line.
	var b strings.Builder
	hdr, _ := json.Marshal(cast.Header{Version: 2, Timestamp: startUnix})
	b.Write(hdr)
	b.WriteByte('\n')
	b.WriteString(`[1.5, "o", "good-output\r\n"]` + "\n")
	b.WriteString("this is not a valid event line\n")
	sum, err := Analyze(spans, strings.NewReader(b.String()), startUnix, Options{})
	if err != nil {
		t.Fatalf("malformed event should be fail-open, got error: %v", err)
	}
	if len(sum.Failures) != 1 || !strings.Contains(sum.Failures[0].Output, "good-output") {
		t.Errorf("output before the malformed line should survive: %+v", sum.Failures)
	}
}
