// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package analyze

import (
	"reflect"
	"testing"
	"time"

	"ghostshell/internal/span"
)

// sec is the number of nanoseconds in one second, for building span timestamps
// at second granularity in the tests.
const sec = int64(time.Second)

// sp is a terse span constructor: an invocation of cmd that starts at
// (base + startSec) seconds, runs for durSec seconds, and exits code.
func sp(id, cmd string, startSec, durSec, code int64) span.Span {
	return span.Span{
		SpanID:   id,
		Cmd:      cmd,
		StartTS:  base + startSec*sec,
		EndTS:    base + (startSec+durSec)*sec,
		ExitCode: int(code),
	}
}

// base is an arbitrary session start in unix nanoseconds (2023-11-14 22:13:20
// UTC = 1700000000s), so tests exercise realistic large timestamps.
const base = 1700000000 * int64(time.Second)

func TestNormalizeCmd(t *testing.T) {
	cases := map[string]string{
		"ls -la":       "ls -la",
		"  ls   -la  ": "ls -la",
		"ls\t-la":      "ls -la",
		"ls\n-la":      "ls -la",
		"":             "",
		"   ":          "",
		"echo  a  b":   "echo a b",
	}
	for in, want := range cases {
		if got := normalizeCmd(in); got != want {
			t.Errorf("normalizeCmd(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectRetryLoops_RunAndThreshold(t *testing.T) {
	window := (60 * time.Second).Nanoseconds()
	spans := []span.Span{
		sp("a1", "make deploy", 0, 1, 1),
		sp("a2", "make deploy", 10, 1, 1),
		sp("a3", "make deploy", 20, 1, 0),  // 3rd within 60s of each -> a retry loop
		sp("a4", "make deploy", 300, 1, 1), // 280s gap -> starts a new, single-item run (not a loop)
		sp("b1", "ls", 5, 1, 0),
		sp("b2", "ls", 6, 1, 0), // only 2 -> below threshold, not a loop
	}
	loops := detectRetryLoops(validSorted(spans), 3, window)
	if len(loops) != 1 {
		t.Fatalf("want exactly 1 retry loop, got %d: %+v", len(loops), loops)
	}
	l := loops[0]
	if l.NormalizedCmd != "make deploy" || l.Count != 3 {
		t.Fatalf("loop = %+v, want make deploy x3", l)
	}
	if l.FailureCount != 2 {
		t.Errorf("FailureCount = %d, want 2", l.FailureCount)
	}
	if !reflect.DeepEqual(l.SpanIDs, []string{"a1", "a2", "a3"}) {
		t.Errorf("SpanIDs = %v, want [a1 a2 a3]", l.SpanIDs)
	}
	if !reflect.DeepEqual(l.ExitCodes, []int{1, 1, 0}) {
		t.Errorf("ExitCodes = %v, want [1 1 0]", l.ExitCodes)
	}
	if l.SampleCmd != "make deploy" {
		t.Errorf("SampleCmd = %q", l.SampleCmd)
	}
}

func TestDetectRetryLoops_NearIdenticalWhitespace(t *testing.T) {
	spans := []span.Span{
		sp("a1", "git  push", 0, 1, 1),
		sp("a2", " git push ", 1, 1, 1),
		sp("a3", "git\tpush", 2, 1, 1),
	}
	loops := detectRetryLoops(validSorted(spans), 3, (60 * time.Second).Nanoseconds())
	if len(loops) != 1 || loops[0].Count != 3 {
		t.Fatalf("near-identical (whitespace-only) invocations should group into one loop of 3, got %+v", loops)
	}
	if loops[0].NormalizedCmd != "git push" {
		t.Errorf("NormalizedCmd = %q, want %q", loops[0].NormalizedCmd, "git push")
	}
}

func TestDetectRetryLoops_WindowSplitsRuns(t *testing.T) {
	// Six identical invocations: three tight, a big gap, three tight. With a 60s
	// window that is two separate loops of 3.
	spans := []span.Span{
		sp("a1", "curl x", 0, 1, 1),
		sp("a2", "curl x", 5, 1, 1),
		sp("a3", "curl x", 10, 1, 1),
		sp("a4", "curl x", 1000, 1, 1),
		sp("a5", "curl x", 1005, 1, 1),
		sp("a6", "curl x", 1010, 1, 1),
	}
	loops := detectRetryLoops(validSorted(spans), 3, (60 * time.Second).Nanoseconds())
	if len(loops) != 2 {
		t.Fatalf("want 2 loops split by the gap, got %d: %+v", len(loops), loops)
	}
	if loops[0].FirstStartTS >= loops[1].FirstStartTS {
		t.Errorf("loops not ordered by FirstStartTS: %+v", loops)
	}
	if loops[0].SpanIDs[0] != "a1" || loops[1].SpanIDs[0] != "a4" {
		t.Errorf("unexpected run boundaries: %+v", loops)
	}
}

func TestDetectRedundant(t *testing.T) {
	spans := []span.Span{
		sp("a1", "go build", 0, 2, 0),
		sp("a2", "go build", 100, 3, 0), // duplicate -> redundant, total 5s
		sp("b1", "go test", 10, 4, 1),
		sp("b2", "go test", 20, 6, 0),
		sp("b3", "go test", 30, 1, 0),     // 3 occurrences
		sp("c1", "vim main.go", 40, 1, 0), // unique -> not redundant
	}
	red := detectRedundant(validSorted(spans))
	if len(red) != 2 {
		t.Fatalf("want 2 redundant commands, got %d: %+v", len(red), red)
	}
	// Ordered by Count desc: "go test" (3) before "go build" (2).
	if red[0].NormalizedCmd != "go test" || red[0].Count != 3 {
		t.Errorf("red[0] = %+v, want go test x3 first", red[0])
	}
	if red[1].NormalizedCmd != "go build" || red[1].Count != 2 {
		t.Errorf("red[1] = %+v, want go build x2", red[1])
	}
	if want := int64(11) * sec; red[0].TotalDurationNanos != want {
		t.Errorf("go test total = %d, want %d", red[0].TotalDurationNanos, want)
	}
	if want := int64(5) * sec; red[1].TotalDurationNanos != want {
		t.Errorf("go build total = %d, want %d", red[1].TotalDurationNanos, want)
	}
	if !reflect.DeepEqual(red[1].SpanIDs, []string{"a1", "a2"}) {
		t.Errorf("go build SpanIDs = %v, want [a1 a2]", red[1].SpanIDs)
	}
}

func TestDetectLatency_RankAndTopN(t *testing.T) {
	spans := []span.Span{
		sp("fast", "echo hi", 0, 1, 0),
		sp("slow", "sleep 30", 5, 30, 0),
		sp("mid", "make", 40, 10, 2),
		sp("slowest", "dd big", 60, 100, 0),
	}
	lat := detectLatency(validSorted(spans), 2)
	if len(lat) != 2 {
		t.Fatalf("want top 2, got %d: %+v", len(lat), lat)
	}
	if lat[0].SpanID != "slowest" || lat[1].SpanID != "slow" {
		t.Errorf("ranking = %s,%s; want slowest,slow", lat[0].SpanID, lat[1].SpanID)
	}
	if lat[0].DurationNanos != 100*sec {
		t.Errorf("slowest duration = %d, want %d", lat[0].DurationNanos, 100*sec)
	}
	if lat[1].ExitCode != 0 {
		t.Errorf("slow ExitCode = %d, want 0", lat[1].ExitCode)
	}
}

func TestDetectLatency_TieBreakStable(t *testing.T) {
	// Equal durations must break the tie deterministically by StartTS then
	// SpanID, so the ranking is reproducible.
	spans := []span.Span{
		sp("z", "cmd", 10, 5, 0),
		sp("a", "cmd", 10, 5, 0), // same start, same dur -> SpanID tiebreak: a before z
		sp("m", "cmd", 5, 5, 0),  // earlier start -> ranks first among equal durs
	}
	lat := detectLatency(validSorted(spans), 3)
	got := []string{lat[0].SpanID, lat[1].SpanID, lat[2].SpanID}
	if !reflect.DeepEqual(got, []string{"m", "a", "z"}) {
		t.Errorf("tie-break order = %v, want [m a z]", got)
	}
}

func TestDetectLatency_ZeroN(t *testing.T) {
	spans := []span.Span{sp("a", "x", 0, 1, 0)}
	if got := detectLatency(validSorted(spans), 0); got != nil {
		t.Errorf("n=0 should yield nil, got %+v", got)
	}
}

func TestCollectFailures(t *testing.T) {
	spans := []span.Span{
		sp("ok", "true", 0, 1, 0),
		sp("bad1", "false", 5, 1, 1),
		sp("bad2", "exit 2", 2, 1, 2),
	}
	f := collectFailures(validSorted(spans))
	if len(f) != 2 {
		t.Fatalf("want 2 failures, got %d: %+v", len(f), f)
	}
	// Start-time order: bad2 (t=2) before bad1 (t=5).
	if f[0].SpanID != "bad2" || f[1].SpanID != "bad1" {
		t.Errorf("failure order = %s,%s; want bad2,bad1", f[0].SpanID, f[1].SpanID)
	}
	if f[0].ExitCode != 2 || f[1].ExitCode != 1 {
		t.Errorf("exit codes = %d,%d", f[0].ExitCode, f[1].ExitCode)
	}
	if f[0].Output != "" || f[0].OutputTruncated {
		t.Errorf("collectFailures must leave Output empty; got %q trunc=%v", f[0].Output, f[0].OutputTruncated)
	}
}
