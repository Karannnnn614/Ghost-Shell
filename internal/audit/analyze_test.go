// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ghostshell/internal/span"
)

// TestAnalyzeNoAIRendersReport: `analyze --no-ai <id>` prints the deterministic
// report (command/failure counts, the failing commands, the slowest section) and
// makes NO model call. Reuses the encrypted-store helpers from tree_test.go.
func TestAnalyzeNoAIRendersReport(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "asess"
	const traceID = "0123456789abcdef0123456789abcdef"

	writeTracedCast(t, central, "alice", id, "bash", traceID)
	writeSpanChunk(t, "alice", traceID, "c1", key, sampleSpans(traceID)...)

	out := captureStdout(t, func() {
		if err := Analyze([]string{"--no-ai", id}); err != nil {
			t.Fatalf("Analyze --no-ai: %v", err)
		}
	})
	// sampleSpans: 4 commands, 2 failures (make build exit 2, gcc main.c exit 1).
	for _, want := range []string{
		"4 commands", "2 failed",
		"Failures (2)",
		"make build", "gcc main.c",
		"Slowest commands",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("analyze report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "AI analysis") {
		t.Errorf("--no-ai must not print an AI section:\n%s", out)
	}
}

// TestAnalyzeNoTraceData: a session with no trace header reports it and exits 0.
func TestAnalyzeNoTraceData(t *testing.T) {
	central := setupCentral(t)
	writeCast(t, central, "dave", "plain", "bash", "hello\n")

	out := captureStdout(t, func() {
		if err := Analyze([]string{"--no-ai", "plain"}); err != nil {
			t.Fatalf("Analyze(plain) should not error: %v", err)
		}
	})
	if !strings.Contains(out, "no process-trace data recorded") {
		t.Errorf("expected no-trace-data message, got:\n%s", out)
	}
}

// TestAnalyzeDetectsRetryAndRepeat: the same command run three times in a row is
// surfaced as both a retry loop and a repeated command.
func TestAnalyzeDetectsRetryAndRepeat(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "retry"
	const traceID = "aaaabbbbccccddddaaaabbbbccccdddd"

	writeTracedCast(t, central, "bob", id, "bash", traceID)
	spans := []span.Span{
		{SpanID: traceID + ".1", Cmd: "pytest", StartTS: 1 * nsSec, EndTS: 2 * nsSec, ExitCode: 1, Depth: 0},
		{SpanID: traceID + ".2", Cmd: "pytest", StartTS: 3 * nsSec, EndTS: 4 * nsSec, ExitCode: 1, Depth: 0},
		{SpanID: traceID + ".3", Cmd: "pytest", StartTS: 5 * nsSec, EndTS: 6 * nsSec, ExitCode: 0, Depth: 0},
	}
	writeSpanChunk(t, "bob", traceID, "c1", key, spans...)

	out := captureStdout(t, func() {
		if err := Analyze([]string{"--no-ai", id}); err != nil {
			t.Fatalf("Analyze: %v", err)
		}
	})
	for _, want := range []string{"Retry loops", "Repeated commands", "pytest"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in report:\n%s", want, out)
		}
	}
}

// TestAnalyzeModelUnavailableStillPrintsReport: without --no-ai, when Ollama is
// unreachable, the deterministic report still prints and a clear install hint is
// shown. OLLAMA_HOST is pointed at a closed loopback port so the outcome is
// deterministic even on a machine that has a real Ollama running.
func TestAnalyzeModelUnavailableStillPrintsReport(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "aisess"
	const traceID = "1111111111111111aaaaaaaaaaaaaaaa"

	writeTracedCast(t, central, "carol", id, "bash", traceID)
	writeSpanChunk(t, "carol", traceID, "c1", key, sampleSpans(traceID)...)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed := srv.URL
	srv.Close() // free the port → connections refused → ErrUnavailable
	t.Setenv("OLLAMA_HOST", closed)

	out := captureStdout(t, func() {
		if err := Analyze([]string{id}); err != nil { // no --no-ai: attempt the model pass
			t.Fatalf("Analyze: %v", err)
		}
	})
	if !strings.Contains(out, "make build") {
		t.Errorf("deterministic report should still print when the model is down:\n%s", out)
	}
	if !strings.Contains(out, "AI analysis unavailable") {
		t.Errorf("expected an Ollama-unavailable hint:\n%s", out)
	}
}

// TestAnalyzeRefusesNonLoopbackModel: a non-loopback OLLAMA_HOST without
// --allow-remote is refused (no data sent), while the deterministic report still
// prints — the safety rail can never be tripped by an env var alone.
func TestAnalyzeRefusesNonLoopbackModel(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "remote"
	const traceID = "2222222222222222bbbbbbbbbbbbbbbb"

	writeTracedCast(t, central, "erin", id, "bash", traceID)
	writeSpanChunk(t, "erin", traceID, "c1", key, sampleSpans(traceID)...)

	t.Setenv("OLLAMA_HOST", "http://10.11.12.13:11434")

	out := captureStdout(t, func() {
		if err := Analyze([]string{id}); err != nil {
			t.Fatalf("Analyze: %v", err)
		}
	})
	if !strings.Contains(out, "make build") {
		t.Errorf("deterministic report should still print:\n%s", out)
	}
	if !strings.Contains(out, "AI analysis skipped") || !strings.Contains(out, "non-loopback") {
		t.Errorf("expected a non-loopback refusal note:\n%s", out)
	}
}
