// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package record

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostshell/internal/config"
)

// openDevNull opens /dev/null for reading and writing.
func openDevNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	return f
}

// TestRunNonInteractivePipe runs the equivalent of:
//
//	ghostshell rec -q -o <tmpfile> /bin/bash -c 'echo hello-rec-test'
//
// Verifies: no error, output file exists and is non-empty, first line is a
// valid cast v2 JSON header.
func TestRunNonInteractivePipe(t *testing.T) {
	outPath := t.TempDir() + "/out.cast"

	null := openDevNull(t)
	defer null.Close()

	// Swap os.Stdin and os.Stdout before Run; restore immediately after so the
	// restore happens before any deferred t.Cleanup funcs run. This avoids a
	// race between the cleanup write and goroutines inside Run that read
	// os.Stdin (watchResize).
	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin = null
	os.Stdout = null

	err := Run([]string{"-q", "-o", outPath, "/bin/bash", "-c", "echo hello-rec-test"})

	os.Stdin = origStdin
	os.Stdout = origStdout

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("output file not found: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("output file is empty")
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("output file has no lines")
	}
	firstLine := sc.Text()

	var hdr struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal([]byte(firstLine), &hdr); err != nil {
		t.Fatalf("first line not valid JSON: %v — line: %q", err, firstLine)
	}
	if hdr.Version != 2 {
		t.Errorf("header version = %d, want 2", hdr.Version)
	}
}

// TestRunPipeStdinExitsCleanly verifies that piping commands through stdin
// exits within a deadline and does not hang. This exercises the sync.Once /
// force-close PTY fix: closing stdin EOF → Ctrl-D write → 500ms grace →
// ptmx.Close() → SIGHUP → child exits.
func TestRunPipeStdinExitsCleanly(t *testing.T) {
	outPath := t.TempDir() + "/pipe.cast"

	// Build a stdin pipe. Write a short command then close the write end so
	// bash sees EOF; the io.Copy goroutine in Run will then trigger the PTY
	// close path.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	// Use a short, single-token command (no spaces) so bash line-editing in
	// the PTY cannot wrap it across multiple output chunks.
	if _, err := pw.WriteString("echo ok\n"); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	pw.Close()

	null := openDevNull(t)
	defer null.Close()

	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin = pr
	os.Stdout = null

	done := make(chan error, 1)
	go func() { done <- Run([]string{"-q", "-o", outPath, "/bin/bash", "-s"}) }()

	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(15 * time.Second):
		os.Stdin = origStdin
		os.Stdout = origStdout
		pr.Close()
		t.Fatal("Run did not complete within 15s — likely hung on stdin EOF")
	}

	// Restore before any assertions so the deferred null.Close is safe.
	os.Stdin = origStdin
	os.Stdout = origStdout
	pr.Close()

	if runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	// The output file is a cast (JSON-lines). The "ok" from "echo ok" should
	// appear somewhere in the event data.
	if !strings.Contains(string(data), "ok") {
		t.Errorf("output file does not contain expected echo output; content: %q", string(data))
	}
}

// TestRunPropagatesChildExitCode records a command that exits non-zero and
// asserts Run returns an *ExitError carrying that exact code, so callers can
// map it to os.Exit (e.g. `ghostshell rec -- false` must not exit 0).
func TestRunPropagatesChildExitCode(t *testing.T) {
	outPath := t.TempDir() + "/exit.cast"

	null := openDevNull(t)
	defer null.Close()

	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin = null
	os.Stdout = null

	err := Run([]string{"-q", "-o", outPath, "/bin/sh", "-c", "exit 7"})

	os.Stdin = origStdin
	os.Stdout = origStdout

	if err == nil {
		t.Fatal("Run returned nil for a child that exited non-zero; want *ExitError")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("Run error = %v (%T); want *ExitError", err, err)
	}
	if ee.Code != 7 {
		t.Errorf("ExitError.Code = %d, want 7", ee.Code)
	}
	if got, want := ee.Error(), "command exited with status 7"; got != want {
		t.Errorf("ExitError.Error() = %q, want %q", got, want)
	}
}

// TestRunCapturesTrailingOutputOnChildExit records a command that prints a
// distinctive marker and then exits on its own (child-initiated exit, the
// common interactive `exit` case). It guards the drain fix: after cmd.Wait()
// returns, Run must let the output reader drain the PTY's remaining buffered
// bytes before force-closing the master, otherwise the last command's trailing
// output is truncated. The marker must appear in the recorded cast.
func TestRunCapturesTrailingOutputOnChildExit(t *testing.T) {
	outPath := t.TempDir() + "/trailing.cast"

	null := openDevNull(t)
	defer null.Close()

	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin = null
	os.Stdout = null

	const marker = "TRAILING_MARKER_9f3c"
	done := make(chan error, 1)
	go func() {
		// echo the marker, then exit; the child terminates itself, exercising the
		// post-Wait drain path rather than the stdin-EOF force-close path.
		done <- Run([]string{"-q", "-o", outPath, "/bin/sh", "-c", "echo " + marker})
	}()

	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(15 * time.Second):
		os.Stdin = origStdin
		os.Stdout = origStdout
		t.Fatal("Run did not complete within 15s")
	}

	os.Stdin = origStdin
	os.Stdout = origStdout

	if runErr != nil {
		t.Fatalf("Run returned error: %v", runErr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), marker) {
		t.Errorf("recorded cast is missing the trailing marker %q (output truncated on child exit); content: %q",
			marker, string(data))
	}
}

// TestOpenSinkFallbackFileMode verifies the fallback recording file is created
// with mode 0600 (not world-/group-readable), since captured terminal output
// may contain secrets. An explicit path skips the daemon-dial branch.
func TestOpenSinkFallbackFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode.cast")

	sink, dest, err := openSink(path)
	if err != nil {
		t.Fatalf("openSink: %v", err)
	}
	defer sink.Close()

	if dest != path {
		t.Errorf("openSink dest = %q, want %q", dest, path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat sink file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("sink file mode = %#o, want 0600", perm)
	}
}

// TestMakeRawRestoreIsIdempotent verifies the restore func is safe to call
// more than once (the nil-guard makes a double-restore a no-op). Run relies on
// this so a single deferred restore() always leaves the terminal restored on
// every exit path, including error paths. On a non-terminal fd MakeRaw is
// skipped, so restore must also be a harmless no-op.
func TestMakeRawRestoreIsIdempotent(t *testing.T) {
	null := openDevNull(t)
	defer null.Close()

	restore := makeRawRestore(int(null.Fd()))
	if restore == nil {
		t.Fatal("makeRawRestore returned nil func")
	}
	// Must not panic and must remain safe across repeated calls.
	restore()
	restore()
}

// pointDaemonAt makes openSink's config.Load() dial sock and fall back into
// dir, with a short dial timeout. It resets the config singleton so the env
// takes effect, and restores it after the test.
func pointDaemonAt(t *testing.T, sock, dir string) {
	t.Helper()
	t.Setenv("GHOSTSHELL_DAEMON_SOCK", sock)
	t.Setenv("GHOSTSHELL_DIR", dir)
	t.Setenv("GHOSTSHELL_DIAL_TIMEOUT_SEC", "1")
	config.Reset()
	t.Cleanup(config.Reset)
}

func assertLocalFallback(t *testing.T, sink io.WriteCloser, dest, dir string) {
	t.Helper()
	if strings.Contains(dest, "central") {
		t.Fatalf("expected local fallback, got central dest %q", dest)
	}
	if !strings.HasPrefix(dest, dir) {
		t.Errorf("fallback dest %q is not under local dir %q", dest, dir)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat fallback file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("fallback file mode = %#o, want 0600 (captured output may hold secrets)", perm)
	}
	if fi.Size() != 0 {
		t.Errorf("fresh fallback file should be empty (no partial/truncated cast), size = %d", fi.Size())
	}
}

// TestOpenSinkFallbackDaemonUnreachable: when the daemon socket does not exist,
// the dial fails fast (ECONNREFUSED/ENOENT within DialTimeout) and openSink
// falls back cleanly to a fresh 0600 user-local file — no partial cast.
func TestOpenSinkFallbackDaemonUnreachable(t *testing.T) {
	tmp := t.TempDir()
	pointDaemonAt(t, filepath.Join(tmp, "nope.sock"), tmp)

	sink, dest, err := openSink("")
	if err != nil {
		t.Fatalf("openSink: %v", err)
	}
	defer sink.Close()
	assertLocalFallback(t, sink, dest, tmp)
}

// TestOpenSinkFallbackSocketRefused: a socket FILE exists but nothing is
// accepting (a stale socket left after a daemon crash). A unix connect to it
// fails fast with ECONNREFUSED, so openSink must fall back to local rather than
// hang or error out.
func TestOpenSinkFallbackSocketRefused(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "stale.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Keep the socket file on Close so a connect finds a path with nothing
	// accepting behind it — exactly the post-crash stale-socket case.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = ln.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("expected stale socket file to remain: %v", err)
	}

	pointDaemonAt(t, sock, tmp)

	sink, dest, err := openSink("")
	if err != nil {
		t.Fatalf("openSink: %v", err)
	}
	defer sink.Close()
	assertLocalFallback(t, sink, dest, tmp)
}

// TestOpenSinkErrAckFallsBackLocal: the daemon ACCEPTS and replies "ERR ...\n"
// (session rejected — cap reached, disk full, or id collision). Before the ack
// handshake the recorder ignored the reply and streamed the whole cast into the
// doomed connection, silently losing the recording. Now it must fall back to a
// local 0600 file.
func TestOpenSinkErrAckFallsBackLocal(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "rej.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var rec [4]byte
		_, _ = io.ReadFull(c, rec[:]) // consume "REC\n"
		_, _ = c.Write([]byte("ERR too many sessions\n"))
	}()
	pointDaemonAt(t, sock, tmp)

	sink, dest, err := openSink("")
	if err != nil {
		t.Fatalf("openSink: %v", err)
	}
	defer sink.Close()
	assertLocalFallback(t, sink, dest, tmp)
}

// TestOpenSinkOkAckUsesCentral: the daemon replies "OK\n" (session registered),
// so the recorder commits to the central sink (the returned conn), not local.
func TestOpenSinkOkAckUsesCentral(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "ok.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		var rec [4]byte
		_, _ = io.ReadFull(c, rec[:]) // consume "REC\n"
		_, _ = c.Write([]byte("OK\n"))
		_, _ = io.Copy(io.Discard, c) // drain until the recorder closes
		_ = c.Close()
	}()
	pointDaemonAt(t, sock, tmp)

	sink, dest, err := openSink("")
	if err != nil {
		t.Fatalf("openSink: %v", err)
	}
	defer sink.Close()
	if !strings.Contains(dest, "central") {
		t.Fatalf("expected central sink on OK ack, got dest %q", dest)
	}
}

// TestOpenSinkNoHangSilentDaemon: a daemon that ACCEPTS the connection but never
// reads and never sends the "OK" ack (wedged/hung). The recorder's bounded ack
// read trips its deadline, so it RETURNS PROMPTLY (no hung login via the
// profile.d hook) AND falls back to a local file instead of streaming into a
// doomed connection.
func TestOpenSinkNoHangSilentDaemon(t *testing.T) {
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "silent.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c // hold open, never read
	}()

	pointDaemonAt(t, sock, tmp)

	type result struct {
		sink io.WriteCloser
		dest string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		s, d, e := openSink("")
		done <- result{s, d, e}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("openSink returned error against an accepting daemon: %v", r.err)
		}
		// The ack read times out, so the recorder falls back to a local 0600 file
		// rather than committing to the wedged central connection.
		assertLocalFallback(t, r.sink, r.dest, tmp)
		if r.sink != nil {
			_ = r.sink.Close()
		}
	case <-time.After(10 * time.Second):
		t.Fatal("openSink HUNG on an accepting-but-silent daemon — would block a login")
	}

	select {
	case c := <-accepted:
		_ = c.Close()
	default:
	}
}

func TestSSHWrapperDoesNotNestGhostshellRec(t *testing.T) {
	tmp := t.TempDir()
	fakeGhostshell := filepath.Join(tmp, "ghostshell")
	if err := os.WriteFile(fakeGhostshell, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\"\n"), 0o755); err != nil {
		t.Fatalf("write fake ghostshell: %v", err)
	}

	wrapper := filepath.Join("..", "..", "scripts", "ghostshell-ssh-wrap.sh")
	cmd := exec.Command("sh", wrapper)
	cmd.Env = append(os.Environ(),
		"PATH="+tmp+":"+os.Getenv("PATH"),
		"SHELL=/bin/sh",
		"SSH_ORIGINAL_COMMAND=ghostshell rec -q /bin/bash -s",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapper returned error: %v; output: %s", err, out)
	}
	got := strings.TrimSpace(string(out))
	want := "rec -q /bin/bash -s"
	if got != want {
		t.Fatalf("wrapper ghostshell args = %q, want %q", got, want)
	}
}
