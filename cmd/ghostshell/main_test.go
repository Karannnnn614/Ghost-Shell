// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostshell/internal/config"
)

func TestParseLsScope(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantAll  bool
		wantUser string
	}{
		{"none", nil, false, ""},
		{"all long", []string{"--all"}, true, ""},
		{"all short", []string{"-a"}, true, ""},
		{"user space form", []string{"--user", "alice"}, false, "alice"},
		{"user equals form", []string{"--user=bob"}, false, "bob"},
		{"user flag without value", []string{"--user"}, false, ""},
		{"all and user both", []string{"--all", "--user", "carol"}, true, "carol"},
		{"user space last wins", []string{"--user", "x", "--user", "y"}, false, "y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAll, gotUser := parseLsScope(tt.args)
			if gotAll != tt.wantAll || gotUser != tt.wantUser {
				t.Errorf("parseLsScope(%v) = (%v, %q), want (%v, %q)",
					tt.args, gotAll, gotUser, tt.wantAll, tt.wantUser)
			}
		})
	}
}

// resolvePlayTarget must resolve the single positional target correctly even
// when flags (and their values) are present — a naive "last non-flag arg"
// heuristic would mis-pick a flag value like `--speed 2` → "2". A missing
// positional is a usage error.
func TestResolvePlayTarget(t *testing.T) {
	ok := []struct {
		name string
		args []string
		want string
	}{
		{"bare target", []string{"abc123"}, "abc123"},
		{"flag space value then target", []string{"--speed", "2", "abc123"}, "abc123"},
		{"flag equals value then target", []string{"--speed=2", "abc123"}, "abc123"},
		{"target then flag", []string{"abc123", "--idle", "5"}, "abc123"},
		{"both flags then target", []string{"--speed", "2", "--idle", "1", "abc123"}, "abc123"},
		{"file path target with flag", []string{"--speed", "1.5", "/tmp/rec.cast"}, "/tmp/rec.cast"},
	}
	for _, tt := range ok {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePlayTarget(tt.args)
			if err != nil {
				t.Fatalf("resolvePlayTarget(%v) error: %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("resolvePlayTarget(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}

	// Missing positional -> usage error (the caller maps this to exit 2).
	bad := [][]string{
		nil,
		{"--speed", "2"},
		{"--idle", "5"},
		{"--speed=2"},
	}
	for _, args := range bad {
		if _, err := resolvePlayTarget(args); err == nil {
			t.Errorf("resolvePlayTarget(%v) = nil error, want usage error", args)
		}
	}
}

func TestCommandHelpBackup(t *testing.T) {
	h, ok := commandHelp("backup")
	if !ok {
		t.Fatal(`commandHelp("backup") returned ok=false; case is missing from switch`)
	}
	if h == "" {
		t.Error(`commandHelp("backup") returned empty help text`)
	}
	for _, term := range []string{"backup", "backup_type", "backup_target"} {
		if !strings.Contains(h, term) {
			t.Errorf("help text missing %q", term)
		}
	}
}

// Every user-facing subcommand listed in usage must have detailed help so that
// `ghostshell help <cmd>` / `ghostshell <cmd> --help` always prints something complete
// (no "no help for" fallback). The hidden aliases (ls-user, play-user,
// ansible-ingest, __complete) are intentionally excluded.
func TestCommandHelpCoversEverySubcommand(t *testing.T) {
	cmds := []string{
		"init", "rec", "record", "play", "ls", "list", "tail", "tree",
		"status", "search", "export", "prune", "ansible", "completion", "backup",
	}
	for _, c := range cmds {
		t.Run(c, func(t *testing.T) {
			h, ok := commandHelp(c)
			if !ok {
				t.Fatalf("commandHelp(%q) ok=false; missing from switch", c)
			}
			if strings.TrimSpace(h) == "" {
				t.Fatalf("commandHelp(%q) returned empty help text", c)
			}
			// A complete help block names the command and shows a usage line.
			if !strings.Contains(h, "ghostshell "+c) && !strings.Contains(h, "usage:") {
				t.Errorf("commandHelp(%q) looks incomplete (no usage line):\n%s", c, h)
			}
		})
	}
}

// The new `status` help must enumerate the fields the command reports so the
// docs stay aligned with the output contract.
func TestCommandHelpStatusFields(t *testing.T) {
	h, ok := commandHelp("status")
	if !ok {
		t.Fatal(`commandHelp("status") ok=false`)
	}
	for _, term := range []string{"daemon_reachable", "sessions_active", "store_size"} {
		if !strings.Contains(h, term) {
			t.Errorf("status help missing %q", term)
		}
	}
}

// daemonReachable must report false for a socket path with no listener and true
// once a listener is bound, so --check / status reflect live state. It must also
// not hang: a non-positive timeout falls back to a bounded dial.
func TestDaemonReachable(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "ghostshell-daemon.sock")

	// No listener yet -> not reachable.
	if daemonReachable(sock, 200*time.Millisecond) {
		t.Errorf("daemonReachable on unbound socket = true, want false")
	}

	// Bind a listener -> reachable.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if !daemonReachable(sock, 200*time.Millisecond) {
		t.Errorf("daemonReachable on bound socket = false, want true")
	}
	// Non-positive timeout must still complete (falls back internally).
	if !daemonReachable(sock, 0) {
		t.Errorf("daemonReachable with zero timeout = false, want true")
	}
}

// runConfigCheck must emit the resolved key-file path, the socket path, and the
// new daemon_reachable line — extending (not breaking) the key=value output
// contract. Existing lines (socket_path, central_dir, key_file) must remain.
func TestRunConfigCheckShowsResolvedAndReachability(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "ghostshell-daemon.sock")
	central := filepath.Join(dir, "central")
	t.Setenv("GHOSTSHELL_DAEMON_SOCK", sock)
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", central)
	t.Setenv("GHOSTSHELL_CONFIG", filepath.Join(dir, "does-not-exist.conf"))
	config.Reset()
	t.Cleanup(config.Reset)

	out := captureStdout(t, func() {
		if code := runConfigCheck(); code != 0 {
			t.Fatalf("runConfigCheck exit code = %d, want 0", code)
		}
	})

	// Resolved values (existing contract) still present.
	for _, want := range []string{"socket_path", "central_dir", "key_file"} {
		if !strings.Contains(out, want) {
			t.Errorf("--check output missing %q line; got:\n%s", want, out)
		}
	}
	// Resolved key file path is the central-relative default.
	if !strings.Contains(out, filepath.Join(central, ".ghostshell.key")) {
		t.Errorf("--check should print resolved key path %s; got:\n%s", filepath.Join(central, ".ghostshell.key"), out)
	}
	// New: daemon reachability line, "no" because nothing is listening.
	reachableNo := false
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "daemon_reachable") && strings.HasSuffix(l, "= no") {
			reachableNo = true
		}
	}
	if !reachableNo {
		t.Errorf("--check should report daemon_reachable = no with no listener; got:\n%s", out)
	}
}

// captureStdout redirects os.Stdout while fn runs and returns what was written.
// runConfigCheck prints resolved values to stdout (warnings go to stderr).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, e := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if e != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}
