// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package span

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// Marshal must produce a single-line JSON record terminated by exactly one
// newline, and ReadAll must decode a concatenated stream back to the originals.
func TestMarshalReadAllRoundTrip(t *testing.T) {
	in := []Span{
		{SpanID: "t.100.1", ParentSpanID: "", Cmd: "ls -la", StartTS: 1000, EndTS: 2000, ExitCode: 0, Depth: 0},
		{SpanID: "t.100.2", ParentSpanID: "t.100.1", Cmd: `echo "hi" && grep x`, StartTS: 2000, EndTS: 2500, ExitCode: 1, Depth: 0},
		{SpanID: "t.200.1", ParentSpanID: "t.100.2", Cmd: "make build", StartTS: 3000, EndTS: 9000, ExitCode: 2, Depth: 1},
	}
	var buf bytes.Buffer
	for _, s := range in {
		b, err := Marshal(s)
		if err != nil {
			t.Fatalf("Marshal(%+v): %v", s, err)
		}
		if n := bytes.Count(b, []byte{'\n'}); n != 1 || b[len(b)-1] != '\n' {
			t.Fatalf("Marshal produced %d newlines / bad terminator: %q", n, b)
		}
		buf.Write(b)
	}
	got, err := ReadAll(&buf)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

// A newline (or other control char) embedded in Cmd must be escaped by Marshal
// so the record stays one line, and must be recovered verbatim by ReadAll.
func TestMarshalEscapesControlCharsInCmd(t *testing.T) {
	s := Span{SpanID: "t.1.1", Cmd: "echo a\nrm -rf /\t# tab", StartTS: 1, EndTS: 2}
	b, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(b, []byte{'\n'}); n != 1 {
		t.Fatalf("embedded newline not escaped: %d newlines in %q", n, b)
	}
	got, err := ReadAll(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Cmd != s.Cmd {
		t.Fatalf("cmd not preserved through round-trip: %+v", got)
	}
}

// ReadAll must be fail-open: skip blank and malformed lines and tolerate a
// truncated trailing line (a chunk cut off mid-write), returning the spans it
// could decode with no error.
func TestReadAllToleratesMalformedAndTruncated(t *testing.T) {
	input := strings.Join([]string{
		`{"span_id":"a","start_ts":1,"end_ts":2}`, // valid
		``,         // blank -> skipped
		`   `,      // whitespace -> skipped
		`not json`, // malformed -> skipped
		`{"span_id":"b","start_ts":3,"end_ts":4}`, // valid
		`{"span_id":"c","start_ts":5,`,            // truncated trailing (no newline)
	}, "\n")

	got, err := ReadAll(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadAll returned an error on tolerable input: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 decodable spans, got %d: %+v", len(got), got)
	}
	if got[0].SpanID != "a" || got[1].SpanID != "b" {
		t.Fatalf("decoded the wrong spans: %+v", got)
	}
}

func TestValid(t *testing.T) {
	cases := []struct {
		name string
		s    Span
		want bool
	}{
		{"instantaneous", Span{SpanID: "x", StartTS: 1, EndTS: 1}, true},
		{"normal", Span{SpanID: "x", StartTS: 1, EndTS: 2, Depth: 3}, true},
		{"no id", Span{SpanID: "", StartTS: 1, EndTS: 2}, false},
		{"no start", Span{SpanID: "x", StartTS: 0, EndTS: 2}, false},
		{"end before start", Span{SpanID: "x", StartTS: 5, EndTS: 2}, false},
		{"negative depth", Span{SpanID: "x", StartTS: 1, EndTS: 2, Depth: -1}, false},
	}
	for _, c := range cases {
		if got := c.s.Valid(); got != c.want {
			t.Errorf("%s: Valid() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHeaderTraceKeyStable(t *testing.T) {
	if HeaderTraceKey != "ghostshell_trace" {
		t.Fatalf("HeaderTraceKey = %q, want %q (other agents depend on this exact value)", HeaderTraceKey, "ghostshell_trace")
	}
}
