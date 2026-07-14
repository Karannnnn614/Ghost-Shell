// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// The span path builders must never be steerable outside the central store by a
// crafted user / traceID / chunkID, mirroring the guarantee proved for the
// cast/ansible builders. (traversalVariants, setupTempEnv and underCentral are
// defined in the sibling store test files.)
func TestSpanPathBuildersNeverEscapeCentral(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	for _, v := range traversalVariants {
		paths := map[string]string{
			"SpanDir.user":    SpanDir(v, "trace"),
			"SpanDir.trace":   SpanDir("alice", v),
			"SpanChunk.user":  SpanChunkPath(v, "trace", "chunk"),
			"SpanChunk.trace": SpanChunkPath("alice", v, "chunk"),
			"SpanChunk.chunk": SpanChunkPath("alice", "trace", v),
		}
		for name, p := range paths {
			if !underCentral(central, p) {
				t.Errorf("%s(%q) = %q escapes central store %q", name, v, p, central)
			}
		}
	}
}

// Legitimate components build the exact expected path (the fail-closed guard is
// a no-op for already-validated callers).
func TestSpanPathBuildersValidComponents(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	if got, want := SpanDir("alice", "abc123"), filepath.Join(central, "alice", "spans", "abc123"); got != want {
		t.Errorf("SpanDir = %q, want %q", got, want)
	}
	want := filepath.Join(central, "alice", "spans", "abc123", "chunk1"+SpanExt)
	if got := SpanChunkPath("alice", "abc123", "chunk1"); got != want {
		t.Errorf("SpanChunkPath = %q, want %q", got, want)
	}
	if SpanExt != ".gsspan" {
		t.Errorf("SpanExt = %q, want %q (other agents depend on this)", SpanExt, ".gsspan")
	}
}

func TestValidTraceIDAccepts(t *testing.T) {
	good := []string{
		"abc",
		"0123456789abcdef0123456789abcdef", // a real 16-byte hex trace id
		"a.b-c_d",                          // full allowlist charset
		"20200101T000000.000000000-4242-ab12cd34ef56", // a real minted chunk id
	}
	for _, g := range good {
		if !ValidTraceID(g) {
			t.Errorf("ValidTraceID(%q) = false, want true", g)
		}
	}
}

func TestValidTraceIDRejects(t *testing.T) {
	bad := []string{
		"", ".", "..", "a/b", `a\b`, "a b", "a\tb", "a\nb", "a;b", "../x",
		"a%2fb", strings.Repeat("a", 129),
	}
	for _, b := range bad {
		if ValidTraceID(b) {
			t.Errorf("ValidTraceID(%q) = true, want false", b)
		}
	}
}

// Every entry of the shared traversal corpus must be rejected outright — the
// daemon gates the client-supplied traceID on this before it touches disk.
func TestValidTraceIDRejectsTraversalCorpus(t *testing.T) {
	for _, v := range traversalVariants {
		if ValidTraceID(v) {
			t.Errorf("ValidTraceID(%q) = true, want false (traversal corpus)", v)
		}
	}
}
