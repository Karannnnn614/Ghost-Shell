// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package store

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SpanExt is the on-disk extension for an encrypted span chunk file. Each chunk
// is one self-contained crypto stream (magic + stream id + frames) holding one
// or more JSON-lines spans; a per-trace directory collects all of a session's
// chunks.
const SpanExt = ".gsspan"

// spanSubdir is the per-user sub-directory under the central store that holds
// every trace directory: <central>/<user>/spans/<traceID>/.
const spanSubdir = "spans"

// spanIDMaxLen bounds a traceID / chunkID length. A traceID is 32 hex chars
// (16 random bytes); a server-minted chunkID is <nanos>-<pid>-<rand> (~45
// chars). The cap keeps a client-supplied traceID from driving an unbounded
// path component.
const spanIDMaxLen = 128

// ValidTraceID reports whether s is safe to use as a span path component and as
// a token in the daemon's line-oriented socket protocol. It mirrors
// ansible.ValidRunID: a length-bounded allowlist of [A-Za-z0-9._-], further
// gated through safeComponent so "." / ".." / a separator can never slip
// through. The daemon calls this on the client-supplied traceID before it
// touches the filesystem; SpanDir/SpanChunkPath additionally fail closed via
// componentOrInvalid, so a bug that skipped this check still cannot traverse.
func ValidTraceID(s string) bool {
	if len(s) < 1 || len(s) > spanIDMaxLen {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return safeComponent(s)
}

// SpanDir returns a session's per-trace span directory:
// <central>/<user>/spans/<traceID>. Both the user and traceID components are
// validated (fail-closed via componentOrInvalid) so a crafted value such as
// ".." or "../../etc" cannot escape the central store.
func SpanDir(user, traceID string) string {
	return filepath.Join(CentralDir(), componentOrInvalid(user), spanSubdir, componentOrInvalid(traceID))
}

// SpanChunkPath returns the path of one encrypted span chunk within a trace
// directory: <SpanDir>/<chunkID>.gsspan. All three components are validated
// (fail-closed) so neither a crafted traceID nor a crafted chunkID can escape
// the store.
func SpanChunkPath(user, traceID, chunkID string) string {
	return filepath.Join(SpanDir(user, traceID), componentOrInvalid(chunkID)+SpanExt)
}

// SpanChunks lists the chunk filenames (with the SpanExt extension) in a
// session's trace directory, sorted lexically — which, because chunkIDs are
// nanosecond-timestamp prefixed, is roughly chronological. A missing directory
// yields an empty list and no error (a session with no captured spans is not an
// error). Mirrors AnsibleRuns for the span store; `tree`/`analyze` decrypt each
// returned chunk via OpenCast and merge the spans.
func SpanChunks(user, traceID string) ([]string, error) {
	dir := SpanDir(user, traceID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var chunks []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), SpanExt) {
			chunks = append(chunks, e.Name())
		}
	}
	sort.Strings(chunks)
	return chunks, nil
}
