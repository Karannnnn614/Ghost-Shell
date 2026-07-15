// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package span defines the on-the-wire and at-rest shape of a process-trace
// span: one recorded shell command with its parent link, timing, and exit code.
//
// Spans are serialized as JSON-lines (one JSON object per line). The trace shim
// (scripts/trace-shim.sh) emits them from a bash DEBUG/EXIT trap, the recorder
// stamps the owning traceID into the asciinema cast header under HeaderTraceKey,
// and the daemon stores them encrypted in a per-trace directory in the central
// store. `tree`/`analyze` read the header's traceID, decrypt the chunks, and
// merge them back into a tree via ReadAll.
package span

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// HeaderTraceKey is the asciinema cast-header key under which the recorder
// writes the session's traceID. `tree`/`analyze` read it back to locate the
// span store for a recording. asciinema tolerates extra header keys, so adding
// it does not affect playback.
const HeaderTraceKey = "ghostshell_trace"

// Span is a single recorded shell command in a process trace.
//
// SpanID is "<traceID>.<BASHPID>.<counter>", globally unique across every bash
// process participating in one traceID. ParentSpanID is the SpanID of the
// command that spawned this command's shell (empty for a top-level command,
// i.e. a direct child of the synthetic trace root). Depth is 0 at the top
// interactive shell and increments by one per nested bash.
type Span struct {
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
	Cmd          string `json:"cmd"`
	StartTS      int64  `json:"start_ts"` // unix nanoseconds
	EndTS        int64  `json:"end_ts"`   // unix nanoseconds
	ExitCode     int    `json:"exit_code"`
	Depth        int    `json:"depth"`
}

// Marshal encodes s as one JSON-lines record: a single-line JSON object
// terminated by a newline. encoding/json escapes every control character
// (including any newline in Cmd) within the string, so the object can never
// contain an embedded newline that would split the record. Callers append the
// returned bytes directly to a JSON-lines stream.
func Marshal(s Span) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ReadAll parses a JSON-lines span stream, returning every span it can decode.
// It is deliberately fail-open: blank lines are skipped, and a line that does
// not parse as a Span (a corrupt line, or a truncated trailing line left by a
// recording whose daemon died mid-write) is skipped rather than aborting the
// parse. Only an underlying read error (other than EOF) is returned, alongside
// whatever spans were decoded before it. The returned spans are not filtered by
// Valid; callers decide whether to drop malformed-but-parseable records.
func ReadAll(r io.Reader) ([]Span, error) {
	br := bufio.NewReader(r)
	var spans []Span
	for {
		line, err := br.ReadString('\n')
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			var s Span
			if json.Unmarshal([]byte(trimmed), &s) == nil {
				spans = append(spans, s)
			}
			// A malformed line (including a truncated trailing line) is skipped:
			// a dropped span must never wedge the parse of the rest.
		}
		if err != nil {
			if err == io.EOF {
				return spans, nil
			}
			return spans, err
		}
	}
}

// Valid reports whether s is a well-formed, usable span: it has a SpanID (the
// tree node key), a positive start timestamp, an end at or after the start
// (non-negative duration), and a non-negative depth. A span reported by the
// shim is always finalized (its EndTS/ExitCode set) before it is sent, so a
// record failing Valid is treated as corrupt.
func (s Span) Valid() bool {
	return s.SpanID != "" && s.StartTS > 0 && s.EndTS >= s.StartTS && s.Depth >= 0
}
