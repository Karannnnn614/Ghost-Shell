// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package record

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ghostshell/internal/config"
	"ghostshell/internal/span"
)

// buildHeader stamps the trace id into the cast header under span.HeaderTraceKey
// (so tree/analyze can correlate), and adds nothing when there is no trace id.
func TestBuildHeaderTraceKey(t *testing.T) {
	h := buildHeader([]string{"/bin/bash"}, "/bin/bash", "deadbeefcafef00d")
	if got := h.Env[span.HeaderTraceKey]; got != "deadbeefcafef00d" {
		t.Fatalf("header %s = %q, want the trace id", span.HeaderTraceKey, got)
	}
	// The pre-existing SHELL/TERM keys must survive.
	if h.Env["SHELL"] != "/bin/bash" {
		t.Errorf("SHELL key clobbered: %v", h.Env)
	}

	h2 := buildHeader([]string{"/bin/bash"}, "/bin/bash", "")
	if _, ok := h2.Env[span.HeaderTraceKey]; ok {
		t.Fatalf("empty trace id must not add the %s header key: %v", span.HeaderTraceKey, h2.Env)
	}
}

// mintTraceID returns a 32-char (16-byte) lowercase hex string, which is
// path-safe and passes the daemon's trace-id allowlist.
func TestMintTraceID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := mintTraceID()
		if !re.MatchString(id) {
			t.Fatalf("mintTraceID() = %q, want 32 hex chars", id)
		}
		if seen[id] {
			t.Fatalf("mintTraceID() returned a duplicate %q", id)
		}
		seen[id] = true
	}
}

func TestTraceShimPathOverride(t *testing.T) {
	if traceShimPath() != defaultTraceShim {
		t.Fatalf("default traceShimPath() = %q, want %q", traceShimPath(), defaultTraceShim)
	}
	t.Setenv("GHOSTSHELL_TRACE_SHIM", "/tmp/custom-shim.sh")
	if got := traceShimPath(); got != "/tmp/custom-shim.sh" {
		t.Fatalf("overridden traceShimPath() = %q, want /tmp/custom-shim.sh", got)
	}
}

func TestRegularFileExists(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "shim.sh")
	if regularFileExists(f) {
		t.Fatal("regularFileExists on a missing file = true")
	}
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !regularFileExists(f) {
		t.Fatal("regularFileExists on a present regular file = false")
	}
	if regularFileExists(dir) {
		t.Fatal("regularFileExists on a directory = true")
	}
	if regularFileExists("") {
		t.Fatal("regularFileExists on empty path = true")
	}
}

// Fail-open: with tracing fully wired (shim present) but the daemon unreachable
// AND no `ghostshell` on PATH, the recording must still complete, capture the
// child's output, and never hang — a span failure can't break the shell.
func TestRunTracingFailOpenDaemonDown(t *testing.T) {
	shim, err := filepath.Abs(filepath.Join("..", "..", "scripts", "trace-shim.sh"))
	if err != nil {
		t.Fatalf("resolve shim path: %v", err)
	}
	if !regularFileExists(shim) {
		t.Skipf("trace shim not found at %s", shim)
	}
	t.Setenv("GHOSTSHELL_TRACE_SHIM", shim)
	// Point the daemon socket at a path with nothing listening (daemon down).
	t.Setenv("GHOSTSHELL_DAEMON_SOCK", filepath.Join(t.TempDir(), "nope.sock"))
	t.Setenv("GHOSTSHELL_DIAL_TIMEOUT_SEC", "1")
	config.Reset()
	t.Cleanup(config.Reset)

	out := filepath.Join(t.TempDir(), "t.cast")
	null := openDevNull(t)
	defer null.Close()

	origIn, origOut := os.Stdin, os.Stdout
	os.Stdin = null
	os.Stdout = null

	done := make(chan error, 1)
	go func() {
		done <- Run([]string{"-q", "-o", out, "/bin/bash", "-c", "echo traced-alive"})
	}()

	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(20 * time.Second):
		os.Stdin, os.Stdout = origIn, origOut
		t.Fatal("Run hung with tracing wired and the daemon down")
	}
	os.Stdin, os.Stdout = origIn, origOut

	if runErr != nil {
		t.Fatalf("Run returned error with tracing wired: %v", runErr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	if !strings.Contains(string(data), "traced-alive") {
		t.Fatalf("recording missing the child's output (tracing disturbed recording): %q", data)
	}
}
