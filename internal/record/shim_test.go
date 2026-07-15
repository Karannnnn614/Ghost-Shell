// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package record

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostshell/internal/span"
)

// setEnvKV replaces (or appends) key=val in env. Replacing in place is required
// for PATH: a duplicate PATH entry would leave getenv resolving the ORIGINAL
// value (glibc returns the first match), so the fake `ghostshell` on our dir
// would never be found.
func setEnvKV(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}

// runShim runs `bash main.sh` in a temp dir with the trace shim wired via
// BASH_ENV and a fake `ghostshell` that appends every reported span line to a
// capture file synchronously (GHOSTSHELL_TRACE_SYNC=1), then returns the parsed
// spans. aux maps additional script filenames to their contents. The run is
// bounded by a context so a shim bug can never hang the suite.
func runShim(t *testing.T, traceID, mainScript string, aux map[string]string) []span.Span {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	shim, err := filepath.Abs(filepath.Join("..", "..", "scripts", "trace-shim.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !regularFileExists(shim) {
		t.Skipf("trace shim not found at %s", shim)
	}

	dir := t.TempDir()
	capture := filepath.Join(dir, "spans.jsonl")

	// Fake `ghostshell`: read the reported span line from stdin and append it to
	// the capture file. #!/bin/sh (dash) + `unset BASH_ENV` so it never re-sources
	// the bash shim and traces itself.
	fake := filepath.Join(dir, "ghostshell")
	fakeBody := "#!/bin/sh\nunset BASH_ENV\ncat >> " + shellQuote(capture) + "\n"
	if err := os.WriteFile(fake, []byte(fakeBody), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range aux {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write aux %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "main.sh"), []byte(mainScript), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "main.sh")
	cmd.Dir = dir
	env := os.Environ()
	env = setEnvKV(env, "PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	env = setEnvKV(env, "BASH_ENV", shim)
	env = setEnvKV(env, "GHOSTSHELL_TRACE_ID", traceID)
	env = setEnvKV(env, "GHOSTSHELL_TRACE_SYNC", "1")
	env = setEnvKV(env, "GHOSTSHELL_PARENT_SPAN", "") // clean top-level context
	env = setEnvKV(env, "GHOSTSHELL_TRACE_DEPTH", "0")
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("shim run hung (killed by timeout); output:\n%s", out)
	}
	if err != nil {
		// A non-zero script exit (e.g. from `false`) is expected; only a failure
		// to start is fatal.
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("bash run failed to start: %v; output:\n%s", err, out)
		}
	}

	data, rerr := os.ReadFile(capture)
	if rerr != nil {
		return nil // no spans captured
	}
	spans, perr := span.ReadAll(bytes.NewReader(data))
	if perr != nil {
		t.Fatalf("parse captured spans: %v\ncapture:\n%s", perr, data)
	}
	return spans
}

// shellQuote single-quotes s for safe embedding in the fake shell script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// indexByCmd maps each command text to the first span that recorded it.
func indexByCmd(spans []span.Span) map[string]span.Span {
	m := map[string]span.Span{}
	for _, s := range spans {
		if _, ok := m[s.Cmd]; !ok {
			m[s.Cmd] = s
		}
	}
	return m
}

// The DEBUG trap must fire for each simple command and finalize it with the
// PREVIOUS command's exit code read at the top of the next firing.
func TestShimCapturesExitCodes(t *testing.T) {
	spans := runShim(t, "traceexit", "true\nfalse\necho hello\n", nil)
	if len(spans) == 0 {
		t.Fatal("no spans captured — the DEBUG trap did not fire")
	}
	byCmd := indexByCmd(spans)

	want := map[string]int{"true": 0, "false": 1, "echo hello": 0}
	for cmd, code := range want {
		s, ok := byCmd[cmd]
		if !ok {
			t.Fatalf("no span captured for %q; got %+v", cmd, spans)
		}
		if s.ExitCode != code {
			t.Errorf("span %q exit_code = %d, want %d", cmd, s.ExitCode, code)
		}
		if !s.Valid() {
			t.Errorf("span %q is not Valid: %+v", cmd, s)
		}
		if s.Depth != 0 || s.ParentSpanID != "" {
			t.Errorf("top-level span %q: depth=%d parent=%q, want depth 0 / empty parent", cmd, s.Depth, s.ParentSpanID)
		}
	}
}

// A nested `bash inner.sh` must attribute its commands UNDER the invoking
// command's span at depth+1, while the outer shell's commands stay siblings at
// depth 0.
func TestShimNestedParentChain(t *testing.T) {
	aux := map[string]string{"inner.sh": "echo inner1\necho inner2\n"}
	main := "echo outer1\nbash inner.sh\necho outer2\n"
	spans := runShim(t, "tracenest", main, aux)
	if len(spans) == 0 {
		t.Fatal("no spans captured")
	}
	byCmd := indexByCmd(spans)

	invoke, ok := byCmd["bash inner.sh"]
	if !ok {
		t.Fatalf("no span for the 'bash inner.sh' invocation; got %+v", spans)
	}
	if invoke.Depth != 0 || invoke.ParentSpanID != "" {
		t.Errorf("invoke span: depth=%d parent=%q, want depth 0 / empty parent", invoke.Depth, invoke.ParentSpanID)
	}

	for _, c := range []string{"echo inner1", "echo inner2"} {
		s, ok := byCmd[c]
		if !ok {
			t.Fatalf("no span for nested command %q; got %+v", c, spans)
		}
		if s.ParentSpanID != invoke.SpanID {
			t.Errorf("nested %q parent = %q, want the 'bash inner.sh' span id %q", c, s.ParentSpanID, invoke.SpanID)
		}
		if s.Depth != 1 {
			t.Errorf("nested %q depth = %d, want 1", c, s.Depth)
		}
	}
	for _, c := range []string{"echo outer1", "echo outer2"} {
		s := byCmd[c]
		if s.Depth != 0 || s.ParentSpanID != "" {
			t.Errorf("outer %q: depth=%d parent=%q, want depth 0 / empty parent", c, s.Depth, s.ParentSpanID)
		}
	}
}

// A `#!/bin/sh` (dash) child gets NO structured tracing (it reads no BASH_ENV
// and sets no BASH_VERSION). The invocation is still captured at the parent
// level, but the sh subtree must NOT be falsely reported as traced.
func TestShimShScriptDegradedNoop(t *testing.T) {
	aux := map[string]string{"shscript.sh": "#!/bin/sh\necho from-sh-1\necho from-sh-2\n"}
	main := "echo outer1\n./shscript.sh\necho outer2\n"
	spans := runShim(t, "tracesh", main, aux)

	byCmd := indexByCmd(spans)
	if _, ok := byCmd["./shscript.sh"]; !ok {
		t.Errorf("no span for the ./shscript.sh invocation (parent-level capture); got %+v", spans)
	}
	for _, s := range spans {
		if strings.Contains(s.Cmd, "from-sh") {
			t.Errorf("sh (dash) subtree was falsely traced: %+v", s)
		}
	}
}

// countByCmd tallies how many spans recorded each command text.
func countByCmd(spans []span.Span) map[string]int {
	m := map[string]int{}
	for _, s := range spans {
		m[s.Cmd]++
	}
	return m
}

// Regression (phantom last-span): bash fires the DEBUG trap once more just before
// the EXIT trap, re-presenting the LAST command of every scope. A naive EXIT flush
// therefore double-reported the final command of the top shell AND of every nested
// script. Each real command must be reported EXACTLY once. `indexByCmd` (used by
// the other tests) hides this by keeping only the first occurrence, so assert on
// per-command counts here.
func TestShimNoDuplicateSpans(t *testing.T) {
	aux := map[string]string{"inner.sh": "echo inner-first\necho inner-last\n"}
	main := "echo top-first\nbash inner.sh\necho last\n"
	spans := runShim(t, "tracedup", main, aux)
	if len(spans) == 0 {
		t.Fatal("no spans captured")
	}
	counts := countByCmd(spans)

	// No command — most importantly the last one of each scope — may be doubled.
	for cmd, n := range counts {
		if n != 1 {
			t.Errorf("command %q reported %d times, want exactly 1 (phantom last-span regression); all counts: %+v", cmd, n, counts)
		}
	}
	// Every real command must be present exactly once (5 total: 3 top + 2 nested).
	for _, cmd := range []string{"echo top-first", "bash inner.sh", "echo last", "echo inner-first", "echo inner-last"} {
		if counts[cmd] != 1 {
			t.Errorf("command %q count = %d, want 1; spans: %+v", cmd, counts[cmd], spans)
		}
	}
}

// Regression (worked example for the snapshot-parent design): a sibling command
// that runs AFTER a nested `bash` call returns must attach to the ROOT, not dangle
// under the nested subtree. `echo after` runs after `bash inner.sh` completes.
func TestShimTrailingSiblingAttachesToRoot(t *testing.T) {
	aux := map[string]string{"inner.sh": "echo inner-cmd\n"}
	main := "echo before\nbash inner.sh\necho after\n"
	spans := runShim(t, "traceafter", main, aux)
	byCmd := indexByCmd(spans)

	after, ok := byCmd["echo after"]
	if !ok {
		t.Fatalf("no span for the post-nesting sibling 'echo after'; got %+v", spans)
	}
	if after.Depth != 0 || after.ParentSpanID != "" {
		t.Errorf("post-nesting sibling 'echo after': depth=%d parent=%q, want depth 0 / empty parent (attached to root)",
			after.Depth, after.ParentSpanID)
	}
	// And it must not have been swallowed into the nested subtree.
	inner := byCmd["echo inner-cmd"]
	if after.ParentSpanID == inner.ParentSpanID && inner.ParentSpanID != "" {
		t.Errorf("'echo after' wrongly shares the nested parent %q", inner.ParentSpanID)
	}
}
