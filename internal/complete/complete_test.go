// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package complete

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"ghostshell/internal/config"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns whatever
// fn wrote. Used because Complete/Script print candidates directly to stdout.
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	runErr := fn()

	if cerr := w.Close(); cerr != nil {
		t.Fatalf("close pipe writer: %v", cerr)
	}
	out, rerr := io.ReadAll(r)
	if rerr != nil {
		t.Fatalf("read pipe: %v", rerr)
	}
	if runErr != nil {
		t.Fatalf("function returned error: %v", runErr)
	}
	return string(out)
}

func TestScriptBashSucceeds(t *testing.T) {
	out := captureStdout(t, func() error { return Script([]string{"bash"}) })
	if !strings.Contains(out, "_ghostshell()") {
		t.Errorf("bash script does not contain expected completion function; got %d bytes", len(out))
	}
}

func TestScriptDefaultsToBash(t *testing.T) {
	out := captureStdout(t, func() error { return Script(nil) })
	if !strings.Contains(out, "_ghostshell()") {
		t.Errorf("default (no-arg) Script did not emit the bash script")
	}
}

func TestScriptUnsupportedShellErrors(t *testing.T) {
	for _, shell := range []string{"zsh", "fish", "powershell", "nonsense"} {
		err := Script([]string{shell})
		if err == nil {
			t.Errorf("Script(%q) = nil, want unsupported-shell error", shell)
			continue
		}
		if !strings.Contains(err.Error(), "unsupported shell") {
			t.Errorf("Script(%q) error = %q, want it to mention unsupported shell", shell, err.Error())
		}
	}
}

func TestCompleteSubcommands(t *testing.T) {
	out := captureStdout(t, func() error { return Complete([]string{"subcommands"}) })
	for _, want := range []string{"rec", "play", "ls", "tail", "completion"} {
		if !strings.Contains(out, want) {
			t.Errorf("subcommands output missing %q; got %q", want, out)
		}
	}
}

// The embedded bash script must offer session-id completion for `tree` (reusing
// the central-sessions candidate kind) and the new --json flag. This keeps the
// completion script in sync with the `tree <session-id>` / `--json` forms the
// CLI now accepts.
func TestBashScriptCompletesTree(t *testing.T) {
	out := captureStdout(t, func() error { return Script([]string{"bash"}) })
	for _, want := range []string{"tree)", "__complete central-sessions", "--json"} {
		if !strings.Contains(out, want) {
			t.Errorf("bash completion script missing %q for tree; got:\n%s", want, out)
		}
	}
}

// central-sessions is the candidate kind reused for tree/tail/export session-id
// completion; it must run without error and emit nothing extraneous on an empty
// store (completion stays silent rather than failing).
func TestCompleteCentralSessionsIsSilentOnEmptyStore(t *testing.T) {
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", t.TempDir())
	config.Reset()
	t.Cleanup(config.Reset)
	out := captureStdout(t, func() error { return Complete([]string{"central-sessions"}) })
	if strings.TrimSpace(out) != "" {
		t.Errorf("central-sessions on an empty store printed %q, want nothing", out)
	}
}

func TestCompleteNoArgsIsNoop(t *testing.T) {
	out := captureStdout(t, func() error { return Complete(nil) })
	if out != "" {
		t.Errorf("Complete(nil) printed %q, want nothing", out)
	}
}

func TestCompleteUnknownKindIsNoop(t *testing.T) {
	out := captureStdout(t, func() error { return Complete([]string{"does-not-exist"}) })
	if out != "" {
		t.Errorf("Complete(unknown) printed %q, want nothing", out)
	}
}

// TestCompleteLocalSessionsSanitizes confirms that candidate filenames carrying
// whitespace or shell metacharacters are filtered out of the emitted list,
// while a clean name survives. The list is derived from filenames and embedded
// unquoted into compgen -W, so unsafe names must never be printed.
func TestCompleteLocalSessionsSanitizes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHOSTSHELL_DIR", dir)

	files := []string{
		"clean-session.cast",   // kept
		"with space.cast",      // dropped: whitespace
		"semi;rm -rf.cast",     // dropped: shell metachar
		"dollar$(whoami).cast", // dropped: command substitution
		"pipe|evil.cast",       // dropped: pipe
		"good_2026-06-17.cast", // kept
		"ignored.txt",          // not a .cast, never a candidate
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}

	out := captureStdout(t, func() error { return Complete([]string{"local-sessions"}) })
	got := splitNonEmpty(out)
	sort.Strings(got)
	want := []string{"clean-session.cast", "good_2026-06-17.cast"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	in := []string{
		"ok",
		"also-ok_1.cast",
		"",               // empty dropped
		"has space",      // dropped
		"tab\there",      // dropped
		"new\nline",      // dropped
		"back`tick",      // dropped
		"sub$(x)",        // dropped
		"and&background", // dropped
		"semi;colon",     // dropped
		"glob*star",      // dropped
		"quote'single",   // dropped
		"quote\"double",  // dropped
		"back\\slash",    // dropped
		"null\x00byte",   // dropped
	}
	got := sanitize(in)
	want := []string{"ok", "also-ok_1.cast"}
	if len(got) != len(want) {
		t.Fatalf("sanitize(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sanitize result = %v, want %v", got, want)
		}
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
