// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ghostshell/internal/cast"
	"ghostshell/internal/crypto"
	"ghostshell/internal/span"
	"ghostshell/internal/store"
)

// centralKey writes a valid at-rest encryption key into the temp central store
// (mode 0600, owned by the test user) and returns it, so span chunks written by
// the tests below can later be decrypted through store.OpenCast — exactly the
// path the real `tree` view takes. Call after setupCentral.
func centralKey(t *testing.T) []byte {
	t.Helper()
	key := bytes.Repeat([]byte("k"), crypto.KeySize)
	if err := os.WriteFile(store.KeyPath(), key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return key
}

// writeTracedCast writes a plaintext cast whose header carries the trace id
// under span.HeaderTraceKey, mirroring what the recorder stamps in production
// (buildHeader stores it in the header Env map). store.Header reads it back.
func writeTracedCast(t *testing.T, central, user, id, command, traceID string) {
	t.Helper()
	udir := filepath.Join(central, user)
	if err := os.MkdirAll(udir, 0o700); err != nil {
		t.Fatal(err)
	}
	h := cast.Header{
		Version:   2,
		Width:     80,
		Height:    24,
		Timestamp: 1700000000,
		Command:   command,
		Env:       map[string]string{span.HeaderTraceKey: traceID},
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(udir, id+".cast"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeSpanChunk encrypts the given spans as one JSON-lines chunk under the
// trace's span dir, mirroring how the daemon's SPAN handler writes a chunk (one
// crypto.NewWriter stream per report). Each span is one frame.
func writeSpanChunk(t *testing.T, user, traceID, chunkID string, key []byte, spans ...span.Span) {
	t.Helper()
	dir := store.SpanDir(user, traceID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(store.SpanChunkPath(user, traceID, chunkID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open chunk: %v", err)
	}
	w, err := crypto.NewWriter(f, key)
	if err != nil {
		f.Close()
		t.Fatalf("crypto.NewWriter: %v", err)
	}
	for _, s := range spans {
		line, merr := span.Marshal(s)
		if merr != nil {
			f.Close()
			t.Fatalf("span.Marshal: %v", merr)
		}
		if _, werr := w.Write(line); werr != nil {
			f.Close()
			t.Fatalf("write span frame: %v", werr)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close chunk: %v", err)
	}
}

const (
	nsSec = int64(1_000_000_000)
)

// jNode mirrors the exported jsonNode shape emitted by `tree --json`. It is the
// contract Part D (analyze) parses, so decoding into it here doubles as a guard
// that the field names/shape do not drift.
type jNode struct {
	SpanID     string  `json:"span_id"`
	Cmd        string  `json:"cmd"`
	ExitCode   int     `json:"exit_code"`
	StartTS    int64   `json:"start_ts"`
	EndTS      int64   `json:"end_ts"`
	DurationNS int64   `json:"duration_ns"`
	Depth      int     `json:"depth"`
	Children   []jNode `json:"children"`
}

// sampleSpans returns a small trace: three top-level commands and one nested
// child (gcc under make), deliberately out of chronological order so the sort is
// exercised.
func sampleSpans(traceID string) []span.Span {
	return []span.Span{
		{SpanID: traceID + ".100.1", ParentSpanID: "", Cmd: "echo hi", StartTS: 1 * nsSec, EndTS: 1*nsSec + nsSec/10, ExitCode: 0, Depth: 0},
		{SpanID: traceID + ".100.2", ParentSpanID: "", Cmd: "make build", StartTS: 2 * nsSec, EndTS: 14*nsSec + 3*nsSec/10, ExitCode: 2, Depth: 0},
		{SpanID: traceID + ".200.1", ParentSpanID: traceID + ".100.2", Cmd: "gcc main.c", StartTS: 2*nsSec + nsSec/2, EndTS: 3 * nsSec, ExitCode: 1, Depth: 1},
		{SpanID: traceID + ".100.3", ParentSpanID: "", Cmd: "ls -la", StartTS: 3 * nsSec, EndTS: 3*nsSec + nsSec/10, ExitCode: 0, Depth: 0},
	}
}

// TestTreeSessionRendersNesting: the session process-tree view merges spans from
// multiple encrypted chunks, orders top-level commands by start time, nests a
// child under its parent, and renders exit codes and durations.
func TestTreeSessionRendersNesting(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "sess1"
	const traceID = "0123456789abcdef0123456789abcdef"

	writeTracedCast(t, central, "alice", id, "bash", traceID)
	sp := sampleSpans(traceID)
	// Split across two chunks (interleaved) so the merge + global sort is real.
	writeSpanChunk(t, "alice", traceID, "chunkA", key, sp[0], sp[3]) // echo hi, ls -la
	writeSpanChunk(t, "alice", traceID, "chunkB", key, sp[1], sp[2]) // make build, gcc

	out := captureStdout(t, func() {
		if err := Tree([]string{id}); err != nil {
			t.Fatalf("Tree(%q): %v", id, err)
		}
	})

	if !strings.Contains(out, rootLabel) {
		t.Errorf("output missing synthetic root %q:\n%s", rootLabel, out)
	}
	for _, want := range []string{
		"echo hi  [exit 0, 0.1s]",
		"make build  [exit 2, 12.3s]",
		"ls -la  [exit 0, 0.1s]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// gcc is a child of make build (not last top-level), so it renders indented
	// under a continuation bar and as its parent's last (only) child.
	if !strings.Contains(out, "│  └─ gcc main.c  [exit 1, 0.5s]") {
		t.Errorf("nested child not rendered under its parent:\n%s", out)
	}
	// Top-level chronological order: echo hi (1s) < make build (2s) < ls -la (3s).
	ie := strings.Index(out, "echo hi")
	im := strings.Index(out, "make build")
	il := strings.Index(out, "ls -la")
	if !(ie >= 0 && im >= 0 && il >= 0 && ie < im && im < il) {
		t.Errorf("top-level ordering wrong (echo=%d make=%d ls=%d):\n%s", ie, im, il, out)
	}
	// ls -la is the final top-level node, so it uses the closing connector.
	if !strings.Contains(out, "└─ ls -la  [exit 0, 0.1s]") {
		t.Errorf("last top-level node should use the closing connector:\n%s", out)
	}
}

// TestTreeSessionJSON: --json emits the documented nested shape with a synthetic
// root (span_id "", depth -1), correct durations, exit codes, and nesting.
func TestTreeSessionJSON(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "sessJSON"
	const traceID = "abcdef0123456789abcdef0123456789"

	writeTracedCast(t, central, "bob", id, "bash", traceID)
	sp := sampleSpans(traceID)
	writeSpanChunk(t, "bob", traceID, "only", key, sp...)

	out := captureStdout(t, func() {
		if err := Tree([]string{"--json", id}); err != nil {
			t.Fatalf("Tree --json: %v", err)
		}
	})

	var root jNode
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if root.SpanID != "" || root.Cmd != rootLabel || root.Depth != -1 {
		t.Errorf("synthetic root shape wrong: span_id=%q cmd=%q depth=%d", root.SpanID, root.Cmd, root.Depth)
	}
	if len(root.Children) != 3 {
		t.Fatalf("root should have 3 top-level children, got %d: %+v", len(root.Children), root.Children)
	}
	// Children sorted by start_ts: echo hi, make build, ls -la.
	if root.Children[0].Cmd != "echo hi" || root.Children[1].Cmd != "make build" || root.Children[2].Cmd != "ls -la" {
		t.Errorf("children order wrong: %q, %q, %q",
			root.Children[0].Cmd, root.Children[1].Cmd, root.Children[2].Cmd)
	}
	mk := root.Children[1]
	if mk.ExitCode != 2 {
		t.Errorf("make build exit_code = %d, want 2", mk.ExitCode)
	}
	if mk.DurationNS != 14*nsSec+3*nsSec/10-2*nsSec {
		t.Errorf("make build duration_ns = %d, want %d", mk.DurationNS, 14*nsSec+3*nsSec/10-2*nsSec)
	}
	if len(mk.Children) != 1 || mk.Children[0].Cmd != "gcc main.c" {
		t.Fatalf("make build should nest gcc main.c; got %+v", mk.Children)
	}
	gcc := mk.Children[0]
	if gcc.ExitCode != 1 || gcc.Depth != 1 || gcc.DurationNS != nsSec/2 {
		t.Errorf("gcc node wrong: exit=%d depth=%d dur=%d", gcc.ExitCode, gcc.Depth, gcc.DurationNS)
	}
	// Leaf children arrays must be present (empty), never null.
	if gcc.Children == nil {
		t.Errorf("leaf node children should be an empty array, not null")
	}
}

// TestTreeSessionDeepParentChain: a linear parent chain nests one level per
// span, and a span whose parent id is unknown is reattached to the root (still
// visible, never dropped).
func TestTreeSessionDeepParentChain(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "chain"
	const traceID = "11112222333344445555666677778888"

	writeTracedCast(t, central, "carol", id, "bash", traceID)
	spans := []span.Span{
		{SpanID: traceID + ".1", ParentSpanID: "", Cmd: "A", StartTS: 1 * nsSec, EndTS: 2 * nsSec, Depth: 0},
		{SpanID: traceID + ".2", ParentSpanID: traceID + ".1", Cmd: "B", StartTS: 2 * nsSec, EndTS: 3 * nsSec, Depth: 1},
		{SpanID: traceID + ".3", ParentSpanID: traceID + ".2", Cmd: "C", StartTS: 3 * nsSec, EndTS: 4 * nsSec, Depth: 2},
		// Orphan: parent id never appears -> reattach to root.
		{SpanID: traceID + ".9", ParentSpanID: traceID + ".does-not-exist", Cmd: "orphan", StartTS: 5 * nsSec, EndTS: 6 * nsSec, Depth: 3},
	}
	writeSpanChunk(t, "carol", traceID, "c1", key, spans...)

	out := captureStdout(t, func() {
		if err := Tree([]string{"--json", id}); err != nil {
			t.Fatalf("Tree --json: %v", err)
		}
	})
	var root jNode
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	// Two top-level nodes: A (real chain root) and orphan (reattached).
	if len(root.Children) != 2 {
		t.Fatalf("want 2 top-level nodes (A + reattached orphan), got %d: %+v", len(root.Children), root.Children)
	}
	// Sorted by start_ts: A (1s) before orphan (5s).
	a := root.Children[0]
	orphan := root.Children[1]
	if a.Cmd != "A" || orphan.Cmd != "orphan" {
		t.Fatalf("top-level nodes wrong: %q, %q", a.Cmd, orphan.Cmd)
	}
	// Verify the A -> B -> C chain nests one level per hop.
	if len(a.Children) != 1 || a.Children[0].Cmd != "B" {
		t.Fatalf("A should nest B; got %+v", a.Children)
	}
	b := a.Children[0]
	if len(b.Children) != 1 || b.Children[0].Cmd != "C" {
		t.Fatalf("B should nest C; got %+v", b.Children)
	}
	if len(b.Children[0].Children) != 0 {
		t.Errorf("C should be a leaf; got %+v", b.Children[0].Children)
	}
}

// TestTreeSessionNoTraceData: a session recorded without a trace header prints
// the clear "no process-trace data" message and returns nil (not an error).
func TestTreeSessionNoTraceData(t *testing.T) {
	central := setupCentral(t)
	// Plain cast, no trace header (uses the sibling test helper writeCast).
	writeCast(t, central, "dave", "plain", "bash", "hello\n")

	out := captureStdout(t, func() {
		if err := Tree([]string{"plain"}); err != nil {
			t.Fatalf("Tree(plain) should not error: %v", err)
		}
	})
	if !strings.Contains(out, "no process-trace data recorded") {
		t.Errorf("expected no-trace-data message, got:\n%s", out)
	}
}

// TestTreeSessionEmptyAndCorruptSpans: a traced session with no chunks reports
// an empty tree gracefully, and a corrupt (undecodable) chunk must not crash the
// view — spans are recovered fail-open.
func TestTreeSessionEmptyAndCorruptSpans(t *testing.T) {
	central := setupCentral(t)
	_ = centralKey(t)
	const traceID = "cafebabecafebabecafebabecafebabe"

	// (1) Traced cast, but the span dir has no chunks at all.
	writeTracedCast(t, central, "erin", "empty", "bash", traceID)
	out := captureStdout(t, func() {
		if err := Tree([]string{"empty"}); err != nil {
			t.Fatalf("Tree(empty): %v", err)
		}
	})
	if !strings.Contains(out, rootLabel) || !strings.Contains(out, "no commands captured") {
		t.Errorf("empty trace should render root + no-commands note, got:\n%s", out)
	}

	// (2) Traced cast whose only chunk is garbage bytes: must not crash, and the
	// render degrades to an empty tree (fail-open, mirroring span.ReadAll).
	const traceID2 = "deadc0dedeadc0dedeadc0dedeadc0de"
	writeTracedCast(t, central, "erin", "garbage", "bash", traceID2)
	gdir := store.SpanDir("erin", traceID2)
	if err := os.MkdirAll(gdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.SpanChunkPath("erin", traceID2, "junk"), []byte("this is not an encrypted span stream\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out2 := captureStdout(t, func() {
		if err := Tree([]string{"garbage"}); err != nil {
			t.Fatalf("Tree(garbage) should be fail-open, got error: %v", err)
		}
	})
	if !strings.Contains(out2, rootLabel) {
		t.Errorf("garbage-chunk trace should still render the root, got:\n%s", out2)
	}
}

// TestTreeSessionSanitizesCommand: a recorded command carrying a terminal escape
// sequence must be neutralized in the rendered line (no raw ESC reaches the
// operator's terminal), while the visible text is preserved.
func TestTreeSessionSanitizesCommand(t *testing.T) {
	central := setupCentral(t)
	key := centralKey(t)
	const id = "evil"
	const traceID = "feedfacefeedfacefeedfacefeedface"

	writeTracedCast(t, central, "mallory", id, "bash", traceID)
	// ESC[2J is a screen-clear; a naive renderer would let it execute.
	evil := "echo \x1b[2Jpwned"
	writeSpanChunk(t, "mallory", traceID, "c1", key,
		span.Span{SpanID: traceID + ".1", Cmd: evil, StartTS: 1 * nsSec, EndTS: 2 * nsSec, Depth: 0})

	out := captureStdout(t, func() {
		if err := Tree([]string{id}); err != nil {
			t.Fatalf("Tree: %v", err)
		}
	})
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("raw ESC leaked into rendered tree output: %q", out)
	}
	if !strings.Contains(out, "echo [2Jpwned") {
		t.Errorf("sanitized command text not preserved as expected, got:\n%s", out)
	}
}

// TestTreeNoArgPreservesWholeStoreView: the no-positional-arg `tree` must keep
// its original whole-store behavior — print the central dir header and each
// user's session subtree.
func TestTreeNoArgPreservesWholeStoreView(t *testing.T) {
	central := setupCentral(t)
	writeCast(t, central, "alice", "s1", "bash", "hi\n")

	out := captureStdout(t, func() {
		if err := Tree(nil); err != nil {
			t.Fatalf("Tree(nil): %v", err)
		}
	})
	if !strings.Contains(out, central) {
		t.Errorf("whole-store tree should print the central dir %q, got:\n%s", central, out)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, "s1") {
		t.Errorf("whole-store tree should list user alice and session s1, got:\n%s", out)
	}
}

// TestTreeJSONWithoutSessionIDErrors: --json is meaningful only with a session
// id; used with no positional it must be a usage error, not the whole-store dump.
func TestTreeJSONWithoutSessionIDErrors(t *testing.T) {
	setupCentral(t)
	if err := Tree([]string{"--json"}); err == nil {
		t.Error("Tree(--json) with no session id should be a usage error")
	}
}
