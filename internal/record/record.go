// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package record spawns a shell under a PTY and records its output.
package record

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"ghostshell/internal/cast"
	"ghostshell/internal/config"
	"ghostshell/internal/span"
	"ghostshell/internal/store"
)

// defaultTraceShim is where the package installs the bash trace shim; the
// recorder points the traced shell's BASH_ENV (and, for an interactive bash,
// --rcfile) at it. Overridable via GHOSTSHELL_TRACE_SHIM for tests. If the file
// does not exist, process-trace tracing silently no-ops and recording is
// unaffected.
const defaultTraceShim = "/usr/share/ghostshell/trace-shim.sh"

// traceShimPath returns the trace shim path, overridable via the
// GHOSTSHELL_TRACE_SHIM environment variable (used by tests and operators who
// relocate the shim).
func traceShimPath() string {
	if v := os.Getenv("GHOSTSHELL_TRACE_SHIM"); v != "" {
		return v
	}
	return defaultTraceShim
}

// mintTraceID returns a hex-encoded 16-byte random trace id (path-safe). An
// empty string is returned if the system RNG fails, in which case the caller
// disables tracing for the session (recording is unaffected).
func mintTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// regularFileExists reports whether p names an existing regular file.
func regularFileExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// drainGrace bounds how long Run waits, after the child is reaped, for the
// output reader to drain the PTY's remaining buffered bytes and finish on its
// own before the master is force-closed. Once all slave holders exit the master
// read returns on its own, so this window is normally not hit; it is only a
// backstop against a lingering grandchild that keeps the slave open, ensuring
// Run cannot hang. Kept short so a stuck reader doesn't delay shutdown visibly.
const drainGrace = 2 * time.Second

// ExitError reports that the recorded child process exited with a non-zero
// status. Run returns it (wrapped) so callers can propagate the child's exit
// code, e.g. main.go: var ee *ExitError; if errors.As(err, &ee) { os.Exit(ee.Code) }.
type ExitError struct{ Code int }

func (e *ExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", e.Code)
}

// openSink picks where the recording goes: stream to the root daemon when
// reachable (central, root-only), else a user-local file (fail-open). An
// explicit -o always uses a local file at that path.
//
// Fail-open + hang-safety: the connect is bounded by cfg.DialTimeout, and the
// "REC" handshake (see recHandshake) is bounded by write+read deadlines. The
// daemon replies "OK\n" only once the session is registered; a rejection
// (session cap, disk full, id collision) replies "ERR ...\n", and a wedged
// daemon that accepted but never answers trips the read deadline. In ALL of
// those cases — and on any dial failure (e.g. a stale socket → ECONNREFUSED) —
// we fall back to the user-local file, so the recording is never silently lost
// and a shell/login is never blocked by daemon trouble. Deadlines are cleared
// once OK is received so the long-lived streaming phase (and a legitimately idle
// live shell) is not bounded.
func openSink(out string) (io.WriteCloser, string, error) {
	if out == "" {
		cfg := config.Load()
		if conn, derr := net.DialTimeout("unix", cfg.SocketPath, cfg.DialTimeout); derr == nil {
			if central, ok := recHandshake(conn, cfg.DialTimeout); ok {
				return central, "ghostshell-daemon (central)", nil
			}
			_ = conn.Close()
		}
	}
	path := out
	if path == "" {
		p, err := store.NewPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	// 0o600: captured terminal output can contain secrets, so never create it
	// world-/group-readable (os.Create would use 0o666 & umask).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, "", err
	}
	return f, path, nil
}

// recHandshake performs the "REC" handshake with the daemon and reports whether
// the central sink is usable. It writes "REC\n" (bounded by a write deadline),
// then waits (bounded by a read deadline) for the daemon's "OK\n" ack. Any other
// outcome returns ok=false so the caller falls back to a user-local file:
//   - "ERR ...\n": the daemon rejected the session (cap reached, disk full, id
//     collision) — without this ack the recorder would stream into a doomed
//     connection and silently lose the recording.
//   - read timeout: the daemon accepted the connection but is wedged / not
//     reading — without the bounded read the shell would hang mid-login.
//   - EOF / any I/O error.
//
// On success both deadlines are cleared: the long-lived streaming phase must not
// be bounded, and a legitimately idle live shell must not be killed by a
// deadline. The ack is exactly "OK\n" (3 bytes) on success or a longer
// "ERR ...\n" on rejection, so reading a fixed 3 bytes distinguishes them (an
// ERR line begins "ERR"); io.ReadFull reports a short read (timeout/EOF) as an
// error, which also routes to the local fallback.
func recHandshake(conn net.Conn, timeout time.Duration) (net.Conn, bool) {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, false
	}
	if _, err := conn.Write([]byte("REC\n")); err != nil {
		return nil, false
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, false
	}
	var ack [3]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || string(ack[:2]) != "OK" {
		return nil, false
	}
	_ = conn.SetWriteDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Time{})
	return conn, true
}

// Run records a session. args is the rec subcommand's argv (after "rec").
func Run(args []string) error {
	fs := flag.NewFlagSet("rec", flag.ContinueOnError)
	out := fs.String("o", "", "output file (default: auto-named in store dir)")
	quietFlag := fs.Bool("q", false, "suppress the recording banner and saved-path message")
	if err := fs.Parse(args); err != nil {
		return err
	}
	quiet := *quietFlag || os.Getenv("GHOSTSHELL_QUIET") != ""

	cmdArgs := fs.Args()
	// explicitCmd records whether the user passed a command vector as rec
	// positionals (vs. defaulting to $SHELL). Only the default-shell case is
	// eligible for the interactive `bash --rcfile` trace path.
	explicitCmd := len(cmdArgs) > 0
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	if len(cmdArgs) == 0 {
		cmdArgs = []string{shell}
	}

	// Mint the session's process-trace id up front so it can be stamped into the
	// cast header (for later correlation) and exported to the traced shell. A
	// failure to mint simply disables tracing (traceID == ""); recording proceeds.
	traceID := mintTraceID()

	sink, dest, serr := openSink(*out)
	if serr != nil {
		return serr
	}
	defer sink.Close()

	cw, err := cast.NewWriter(sink, buildHeader(cmdArgs, shell, traceID))
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr,
			"ghostshell: recording to %s — type 'exit' or Ctrl-D to stop\r\n", dest)
	}

	// Process-trace wiring (ADDITIVE, fail-open). Tracing activates only when a
	// trace id was minted AND the shim exists on disk; otherwise the exec and
	// environment are byte-for-byte unchanged and recording is unaffected.
	shimPath := traceShimPath()
	traceOn := traceID != "" && regularFileExists(shimPath)

	execArgs := cmdArgs
	if traceOn && !explicitCmd && filepath.Base(cmdArgs[0]) == "bash" {
		// Interactive bash launched with no explicit command vector: an
		// interactive shell ignores BASH_ENV, so install the trap via --rcfile.
		// The shim sources the user's real rc first, preserving their environment.
		execArgs = []string{cmdArgs[0], "--rcfile", shimPath}
	}

	cmd := exec.Command(execArgs[0], execArgs[1:]...)
	if traceOn {
		// GHOSTSHELL_TRACE_SOCK reuses the same socket path the recorder dials for
		// the daemon (openSink -> config.Load().SocketPath). BASH_ENV covers nested
		// non-interactive bash children; the shim no-ops for non-bash shells.
		cmd.Env = append(os.Environ(),
			"GHOSTSHELL_TRACE_ID="+traceID,
			"GHOSTSHELL_TRACE_SOCK="+config.Load().SocketPath,
			"GHOSTSHELL_TRACE_DEPTH=0",
			"BASH_ENV="+shimPath,
		)
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	var closePTY sync.Once
	closePTYFn := func() { closePTY.Do(func() { _ = ptmx.Close() }) }
	defer closePTYFn()

	// Snapshot the child's PID/pgid once, up front, while it is guaranteed live.
	// After cmd.Wait() reaps the child the kernel may recycle the PID, so any
	// later signal must be gated on childExited to avoid hitting a reused PID.
	pid := cmd.Process.Pid
	var childExited atomic.Bool

	start := time.Now()
	var wg sync.WaitGroup

	winch := watchResize(ptmx, &wg)
	// The terminal is restored solely via this defer: the nil-guard inside
	// makeRawRestore makes a second call a no-op, so restoration happens on
	// every exit path even if cleanup below is skipped (e.g. wg.Wait blocks).
	restore := makeRawRestore(int(os.Stdin.Fd()))
	defer restore()

	// Forward SIGHUP (SSH disconnect) to the child process group so it exits
	// cleanly instead of leaving ghostshell rec blocked in cmd.Wait() forever.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		if _, ok := <-hup; ok && !childExited.Load() {
			_ = syscall.Kill(-pid, syscall.SIGHUP)
		}
	}()

	// stdin → PTY. On EOF: try Ctrl-D (graceful), then force-close PTY master.
	// Some kernels/distros do not send SIGHUP to the child on PTY master close
	// (depends on whether the slave is the child's controlling terminal), so we
	// also send SIGHUP explicitly to the child process group — but only if the
	// child has not already been reaped, to avoid signalling a recycled PID.
	//
	// io.Copy blocks on os.Stdin, which cannot be unblocked portably once the
	// child exits on its own; this goroutine may therefore outlive Run while
	// parked on that read. That is benign: closePTYFn/childExited make its
	// wake-up path a no-op, so it neither writes to a reused fd nor signals a
	// reused PID. It is intentionally not joined via wg for that reason.
	go func() {
		_, _ = io.Copy(ptmx, os.Stdin)
		_, _ = ptmx.Write([]byte{4}) // Ctrl-D: graceful EOF signal
		time.Sleep(config.Load().EOFGrace)
		closePTYFn() // close master fd
		if !childExited.Load() {
			_ = syscall.Kill(-pid, syscall.SIGHUP) // explicit SIGHUP to process group
		}
	}()

	// PTY -> local stdout + recording.
	wg.Add(1)
	go pumpOutput(ptmx, cw, start, &wg)

	waitErr := cmd.Wait()
	childExited.Store(true) // gate post-reap signals against PID reuse
	signal.Stop(winch)
	close(winch)
	signal.Stop(hup)
	close(hup)

	// Drain trailing output before force-closing the PTY master. Once the child
	// and all slave holders have exited, the master read returns naturally
	// (EOF/EIO) after the kernel buffer is drained, so pumpOutput finishes on
	// its own and records the last command's final bytes. Force-closing the
	// master here unconditionally would race that final read and truncate the
	// tail (e.g. the output of the last command before `exit`). We therefore
	// wait for the reader to finish on its own, and only force-close as a
	// backstop if it is still blocked after a short grace (e.g. a lingering
	// grandchild keeping the slave open), so Run can never hang.
	pumpDone := make(chan struct{})
	go func() { wg.Wait(); close(pumpDone) }()
	select {
	case <-pumpDone:
		closePTYFn()
	case <-time.After(drainGrace):
		closePTYFn() // backstop: unblock a reader still parked on Read
		<-pumpDone
	}
	_ = cw.Close()

	if !quiet {
		fmt.Fprintf(os.Stderr, "\r\nghostshell: session saved to %s\n", dest)
	}

	// Surface the child's exit code via ExitError (callers map it to os.Exit);
	// any other Wait error is a real failure and is returned wrapped.
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			// Propagate only a genuine non-zero EXIT status. A child terminated
			// by a signal reports ExitCode() == -1 — that includes the SIGHUP we
			// send to end the recording on stdin EOF / SSH disconnect, which is a
			// normal end, not a failure — so don't surface it as an error.
			if code := ee.ExitCode(); code > 0 {
				return &ExitError{Code: code}
			}
			return nil
		}
		return fmt.Errorf("waiting for command: %w", waitErr)
	}
	return nil
}

// buildHeader builds the cast header, using the current terminal size if
// available. When traceID is non-empty it is stamped under span.HeaderTraceKey
// so `tree`/`analyze` can later correlate the recording to its span store;
// asciinema tolerates the extra header key and playback is unaffected.
func buildHeader(cmdArgs []string, shell, traceID string) cast.Header {
	width, height := 80, 24
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		if w, h, err := term.GetSize(fd); err == nil {
			width, height = w, h
		}
	}
	env := map[string]string{"SHELL": shell, "TERM": os.Getenv("TERM")}
	if traceID != "" {
		env[span.HeaderTraceKey] = traceID
	}
	return cast.Header{
		Width:     width,
		Height:    height,
		Timestamp: time.Now().Unix(),
		Command:   strings.Join(cmdArgs, " "),
		Env:       env,
	}
}

// watchResize forwards SIGWINCH to the PTY and syncs the initial size.
// It increments wg by 1 and decrements it when the goroutine exits, so the
// caller's wg.Wait() is guaranteed to see the goroutine fully stopped before
// returning (prevents data races on os.Stdin in tests).
func watchResize(ptmx *os.File, wg *sync.WaitGroup) chan os.Signal {
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range winch {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	winch <- syscall.SIGWINCH
	return winch
}

// makeRawRestore puts the terminal in raw mode and returns a restore func.
func makeRawRestore(fd int) func() {
	var oldState *term.State
	if term.IsTerminal(fd) {
		if st, err := term.MakeRaw(fd); err == nil {
			oldState = st
		}
	}
	return func() {
		if oldState != nil {
			_ = term.Restore(fd, oldState)
			oldState = nil
		}
	}
}

// pumpOutput copies PTY output to the local terminal and the recording.
// It flushes to the recording sink at most every flushInterval (and once at
// end) rather than on every chunk, so interactive typing stays snappy while
// live tail still sees output within ~flushInterval.
func pumpOutput(ptmx *os.File, cw *cast.Writer, start time.Time, wg *sync.WaitGroup) {
	defer wg.Done()
	const flushInterval = 100 * time.Millisecond
	buf := make([]byte, config.Load().ScrollBuffer)
	lastFlush := time.Now()
	for {
		n, rerr := ptmx.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
			_ = cw.WriteOutput(time.Since(start).Seconds(), buf[:n])
			if time.Since(lastFlush) >= flushInterval {
				_ = cw.Flush()
				lastFlush = time.Now()
			}
		}
		if rerr != nil {
			_ = cw.Flush()
			return
		}
	}
}
