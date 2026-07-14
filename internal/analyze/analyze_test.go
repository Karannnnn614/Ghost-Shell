// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package analyze

import (
	"encoding/json"
	"testing"
	"time"

	"ghostshell/internal/span"
)

func TestOptionsWithDefaults(t *testing.T) {
	got := Options{}.withDefaults()
	want := Options{
		RetryThreshold: DefaultRetryThreshold,
		RetryWindow:    DefaultRetryWindow,
		TopLatency:     DefaultTopLatency,
		MaxOutputBytes: DefaultMaxOutputBytes,
	}
	if got != want {
		t.Fatalf("withDefaults on zero Options = %+v, want %+v", got, want)
	}
	// Explicit values must be preserved; negatives fall back to defaults.
	custom := Options{RetryThreshold: 7, RetryWindow: time.Minute, TopLatency: 2, MaxOutputBytes: 99}.withDefaults()
	if custom.RetryThreshold != 7 || custom.RetryWindow != time.Minute || custom.TopLatency != 2 || custom.MaxOutputBytes != 99 {
		t.Fatalf("withDefaults clobbered explicit values: %+v", custom)
	}
	neg := Options{RetryThreshold: -1, TopLatency: -5, MaxOutputBytes: -1, RetryWindow: -time.Second}.withDefaults()
	if neg != want {
		t.Fatalf("negative fields should fall back to defaults: %+v", neg)
	}
}

func TestValidSorted_FiltersAndOrders(t *testing.T) {
	spans := []span.Span{
		sp("c", "c", 30, 1, 0),
		sp("a", "a", 10, 1, 0),
		{SpanID: "", Cmd: "no-id", StartTS: base, EndTS: base + sec},         // invalid: empty id
		{SpanID: "bad", Cmd: "reversed", StartTS: base + 5*sec, EndTS: base}, // invalid: end<start
		{SpanID: "zerostart", Cmd: "x", StartTS: 0, EndTS: sec},              // invalid: start<=0
		sp("b", "b", 20, 1, 0),
	}
	got := validSorted(spans)
	if len(got) != 3 {
		t.Fatalf("want 3 valid spans, got %d: %+v", len(got), got)
	}
	ids := []string{got[0].SpanID, got[1].SpanID, got[2].SpanID}
	if ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Fatalf("validSorted order = %v, want [a b c] by StartTS", ids)
	}
}

func TestValidSorted_DoesNotMutateInput(t *testing.T) {
	spans := []span.Span{sp("c", "c", 30, 1, 0), sp("a", "a", 10, 1, 0)}
	_ = validSorted(spans)
	if spans[0].SpanID != "c" || spans[1].SpanID != "a" {
		t.Fatalf("input slice was reordered: %+v", spans)
	}
}

func TestWallDuration(t *testing.T) {
	spans := []span.Span{
		sp("a", "a", 0, 5, 0),  // [0,5]
		sp("b", "b", 2, 20, 0), // [2,22] -> latest end
		sp("c", "c", 10, 1, 0), // [10,11]
	}
	if got := wallDuration(validSorted(spans)); got != 22*sec {
		t.Errorf("wallDuration = %d, want %d (0..22s wall clock)", got, 22*sec)
	}
	if got := wallDuration(nil); got != 0 {
		t.Errorf("wallDuration(nil) = %d, want 0", got)
	}
}

// TestAnalyze_RunStats checks the top-level counters and that every detector's
// output is wired into the Summary.
func TestAnalyze_RunStats(t *testing.T) {
	spans := []span.Span{
		sp("d1", "deploy", 0, 1, 1),
		sp("d2", "deploy", 5, 1, 1),
		sp("d3", "deploy", 10, 1, 1), // retry loop of 3, all failing
		sp("slow", "build all", 20, 60, 0),
		sp("ok", "ls", 100, 1, 0),
	}
	sum, err := Analyze(spans, nil, 0, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if sum.CommandCount != 5 {
		t.Errorf("CommandCount = %d, want 5", sum.CommandCount)
	}
	if sum.FailureCount != 3 || len(sum.Failures) != 3 {
		t.Errorf("FailureCount = %d / len(Failures) = %d, want 3/3", sum.FailureCount, len(sum.Failures))
	}
	// Wall clock: earliest start 0, latest end 101s (ls at 100 for 1s).
	if sum.TotalDurationNanos != 101*sec {
		t.Errorf("TotalDurationNanos = %d, want %d", sum.TotalDurationNanos, 101*sec)
	}
	if sum.TotalDurationHuman != time.Duration(101*sec).String() {
		t.Errorf("TotalDurationHuman = %q", sum.TotalDurationHuman)
	}
	if len(sum.RetryLoops) != 1 || sum.RetryLoops[0].Count != 3 {
		t.Errorf("expected one retry loop of 3, got %+v", sum.RetryLoops)
	}
	if len(sum.RedundantCommands) != 1 || sum.RedundantCommands[0].NormalizedCmd != "deploy" {
		t.Errorf("expected 'deploy' redundant, got %+v", sum.RedundantCommands)
	}
	if len(sum.SlowestCommands) == 0 || sum.SlowestCommands[0].SpanID != "slow" {
		t.Errorf("expected 'slow' as slowest, got %+v", sum.SlowestCommands)
	}
}

// The Summary must be JSON-serializable with the documented field names, since
// Part D marshals it and hands it to the local model.
func TestSummary_JSONShape(t *testing.T) {
	spans := []span.Span{
		sp("d1", "deploy", 0, 1, 1),
		sp("d2", "deploy", 5, 1, 1),
		sp("d3", "deploy", 10, 1, 1),
		sp("slow", "build", 20, 30, 0),
	}
	sum, err := Analyze(spans, nil, 0, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	b, err := json.Marshal(sum)
	if err != nil {
		t.Fatalf("Summary is not JSON-serializable: %v", err)
	}

	// Round-trip into a generic map and assert the documented top-level keys.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"command_count", "failure_count", "total_duration_nanos", "total_duration_human",
		"retry_loops", "redundant_commands", "slowest_commands", "failures",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("Summary JSON missing documented key %q", key)
		}
	}

	// A full round-trip must reproduce the struct exactly.
	var back Summary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	rb, _ := json.Marshal(back)
	if string(rb) != string(b) {
		t.Errorf("Summary JSON round-trip mismatch:\n first: %s\nsecond: %s", b, rb)
	}
}

// Determinism: identical input must yield byte-identical Summary JSON.
func TestAnalyze_Deterministic(t *testing.T) {
	spans := []span.Span{
		sp("d3", "deploy", 10, 1, 1),
		sp("d1", "deploy", 0, 1, 1),
		sp("t2", "go test", 8, 4, 1),
		sp("d2", "deploy", 5, 1, 1),
		sp("t1", "go test", 2, 2, 0),
		sp("slow", "build", 40, 30, 0),
	}
	var first string
	for i := 0; i < 5; i++ {
		sum, err := Analyze(spans, nil, 0, Options{})
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		b, _ := json.Marshal(sum)
		if i == 0 {
			first = string(b)
			continue
		}
		if string(b) != first {
			t.Fatalf("non-deterministic Summary on run %d:\n want %s\n  got %s", i, first, b)
		}
	}
}

func TestAnalyze_EmptyInput(t *testing.T) {
	sum, err := Analyze(nil, nil, 0, Options{})
	if err != nil {
		t.Fatalf("Analyze(nil): %v", err)
	}
	if sum.CommandCount != 0 || sum.FailureCount != 0 || sum.TotalDurationNanos != 0 {
		t.Errorf("empty input should yield zero stats: %+v", sum)
	}
	if len(sum.RetryLoops) != 0 || len(sum.RedundantCommands) != 0 || len(sum.SlowestCommands) != 0 || len(sum.Failures) != 0 {
		t.Errorf("empty input should yield empty detector lists: %+v", sum)
	}
}
