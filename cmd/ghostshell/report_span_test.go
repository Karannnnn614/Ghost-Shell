// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// feedStdin swaps os.Stdin for a pipe carrying payload (then EOF) and returns a
// restore func. reportSpan reads span lines from os.Stdin.
func feedStdin(t *testing.T, payload string) func() {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = pr
	go func() {
		_, _ = io.WriteString(pw, payload)
		_ = pw.Close()
	}()
	return func() { os.Stdin = orig; _ = pr.Close() }
}

// reportSpan must write "SPAN <traceID>\n" then the span lines from stdin.
func TestReportSpanSendsToDaemon(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "trace.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type got struct {
		line, body string
	}
	recv := make(chan got, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		body, _ := io.ReadAll(br)
		recv <- got{line, string(body)}
	}()

	payload := `{"span_id":"t.1.1","parent_span_id":"","cmd":"ls","start_ts":1,"end_ts":2,"exit_code":0,"depth":0}` + "\n"
	restore := feedStdin(t, payload)
	defer restore()

	t.Setenv("GHOSTSHELL_TRACE_SOCK", sock)
	t.Setenv("GHOSTSHELL_TRACE_ID", "abc123def456")
	reportSpan()

	select {
	case r := <-recv:
		if strings.TrimSpace(r.line) != "SPAN abc123def456" {
			t.Fatalf("handshake line = %q, want %q", r.line, "SPAN abc123def456\\n")
		}
		if r.body != payload {
			t.Fatalf("forwarded body = %q, want %q", r.body, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never received the span report")
	}
}

// With no daemon listening, reportSpan must fail open fast (bounded by its
// deadline) and never hang the shell.
func TestReportSpanNoDaemonFailsOpenFast(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHOSTSHELL_TRACE_SOCK", filepath.Join(dir, "nope.sock"))
	t.Setenv("GHOSTSHELL_TRACE_ID", "abc123")
	restore := feedStdin(t, `{"span_id":"t.1.1"}`+"\n")
	defer restore()

	done := make(chan struct{})
	start := time.Now()
	go func() { reportSpan(); close(done) }()
	select {
	case <-done:
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("reportSpan took %v with no daemon; must fail open fast", el)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reportSpan hung with no daemon")
	}
}

// Missing env (no socket / trace id) must be an immediate no-op that never even
// blocks on reading stdin.
func TestReportSpanMissingEnvIsNoop(t *testing.T) {
	t.Setenv("GHOSTSHELL_TRACE_SOCK", "")
	t.Setenv("GHOSTSHELL_TRACE_ID", "")
	// Deliberately do NOT feed stdin: a correct no-op returns before reading it.
	done := make(chan struct{})
	go func() { reportSpan(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reportSpan blocked despite missing env — it should return immediately")
	}
}

// A trace id carrying a newline/space (protocol injection) must be refused
// before any dial, so no second command can be smuggled into the socket line.
func TestReportSpanRejectsUnsafeTraceID(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "trace.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	connected := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			connected <- struct{}{}
			c.Close()
		}
	}()

	t.Setenv("GHOSTSHELL_TRACE_SOCK", sock)
	t.Setenv("GHOSTSHELL_TRACE_ID", "abc\ninjected SPAN evil")
	restore := feedStdin(t, "x\n")
	defer restore()

	reportSpan()

	select {
	case <-connected:
		t.Fatal("reportSpan dialed the daemon with an unsafe (newline-injected) trace id")
	case <-time.After(300 * time.Millisecond):
		// good: no connection was made
	}
}
