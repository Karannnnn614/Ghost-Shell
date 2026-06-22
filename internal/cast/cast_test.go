package cast

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// BenchmarkWriterWriteOutput measures the per-chunk cost of the record hot
// path's encode step (one PTY read -> one cast event). The ns/op and B/op show
// this step is trivial relative to the I/O around it (ptmx.Read + stdout write),
// confirming the record pipeline is I/O-bound, not encode-bound. See OPTIMIZATIONS.md.
func BenchmarkWriterWriteOutput(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 4096) // a typical PTY read chunk
	cw, err := NewWriter(io.Discard, Header{Width: 80, Height: 24})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := cw.WriteOutput(float64(i)*0.01, payload); err != nil {
			b.Fatal(err)
		}
	}
	_ = cw.Flush()
}

// TestRoundTrip writes a header + several events and reads them back,
// verifying that all fields and special characters survive the round-trip.
func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	h := Header{
		Width:     80,
		Height:    24,
		Timestamp: 1700000000,
		Command:   "bash",
		Title:     "my session",
		Env:       map[string]string{"TERM": "xterm"},
	}

	w, err := NewWriter(&buf, h)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	type eventIn struct {
		t    float64
		data []byte
	}
	events := []eventIn{
		{0.0, []byte("hello\r\n")},
		{1.5, []byte("tab\tend")},
		{2.25, []byte(`say "hi"`)},
		{3.0, []byte("line1\nline2\n")},
		{100.123456, []byte("end")},
	}

	for _, e := range events {
		if err := w.WriteOutput(e.t, e.data); err != nil {
			t.Fatalf("WriteOutput(%v): %v", e.t, err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))

	got, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if got.Version != 2 {
		t.Errorf("Version: got %d, want 2", got.Version)
	}
	if got.Width != 80 {
		t.Errorf("Width: got %d, want 80", got.Width)
	}
	if got.Height != 24 {
		t.Errorf("Height: got %d, want 24", got.Height)
	}
	if got.Timestamp != 1700000000 {
		t.Errorf("Timestamp: got %d, want 1700000000", got.Timestamp)
	}
	if got.Command != "bash" {
		t.Errorf("Command: got %q, want %q", got.Command, "bash")
	}
	if got.Title != "my session" {
		t.Errorf("Title: got %q, want %q", got.Title, "my session")
	}
	if got.Env["TERM"] != "xterm" {
		t.Errorf("Env[TERM]: got %q, want %q", got.Env["TERM"], "xterm")
	}

	for i, e := range events {
		ev, err := ReadEvent(r)
		if err != nil {
			t.Fatalf("ReadEvent[%d]: %v", i, err)
		}
		if ev.Time != e.t {
			t.Errorf("event[%d].Time: got %v, want %v", i, ev.Time, e.t)
		}
		if ev.Type != "o" {
			t.Errorf("event[%d].Type: got %q, want %q", i, ev.Type, "o")
		}
		if ev.Data != string(e.data) {
			t.Errorf("event[%d].Data: got %q, want %q", i, ev.Data, string(e.data))
		}
	}
}

// TestSplitMultibyteRune verifies that a UTF-8 rune split across two writes
// (as PTY reads can do) survives the round-trip intact rather than being
// corrupted to U+FFFD. Reproduces the "gibberish in editor replay" bug.
func TestSplitMultibyteRune(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// "│" (U+2502, box-drawing) is 3 bytes: 0xE2 0x94 0x82. Split after byte 1.
	full := []byte("ab│cd")
	idx := bytes.IndexByte(full, 0xE2) + 1 // split mid-rune
	if err := w.WriteOutput(0.0, full[:idx]); err != nil {
		t.Fatalf("WriteOutput(part1): %v", err)
	}
	if err := w.WriteOutput(0.5, full[idx:]); err != nil {
		t.Fatalf("WriteOutput(part2): %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	var got string
	for {
		ev, err := ReadEvent(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent: %v", err)
		}
		got += ev.Data
	}
	if got != string(full) {
		t.Errorf("reassembled: got %q, want %q", got, string(full))
	}
	if strings.ContainsRune(got, '�') {
		t.Errorf("output contains U+FFFD replacement char: %q", got)
	}
}

// TestReadEventEOF asserts that reading past the last event returns io.EOF.
func TestReadEventEOF(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteOutput(0.0, []byte("x")); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))

	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if _, err := ReadEvent(r); err != nil {
		t.Fatalf("ReadEvent (first): %v", err)
	}
	_, err = ReadEvent(r)
	if err != io.EOF {
		t.Errorf("ReadEvent past end: got %v, want io.EOF", err)
	}
}

// TestBlankLinesSkipped verifies that blank lines between events are ignored.
func TestBlankLinesSkipped(t *testing.T) {
	// Build a cast body manually: header + event + blank + event.
	body := `{"version":2,"width":80,"height":24}
[0.100000, "o", "first"]

[1.200000, "o", "second"]
`
	r := bufio.NewReader(strings.NewReader(body))

	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	e1, err := ReadEvent(r)
	if err != nil {
		t.Fatalf("ReadEvent[0]: %v", err)
	}
	if e1.Data != "first" {
		t.Errorf("event[0].Data: got %q, want %q", e1.Data, "first")
	}

	e2, err := ReadEvent(r)
	if err != nil {
		t.Fatalf("ReadEvent[1]: %v", err)
	}
	if e2.Data != "second" {
		t.Errorf("event[1].Data: got %q, want %q", e2.Data, "second")
	}

	_, err = ReadEvent(r)
	if err != io.EOF {
		t.Errorf("ReadEvent past end: got %v, want io.EOF", err)
	}
}

// TestReadHeaderInvalid asserts that a non-JSON first line produces an error.
func TestReadHeaderInvalid(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"plain text", "not json\n"},
		{"empty object fragment", "{\n"},
		{"bare number", "42\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.input))
			_, err := ReadHeader(r)
			if err == nil {
				t.Errorf("ReadHeader(%q): expected error, got nil", tc.input)
			}
		})
	}
}

// TestPartialRuneAtClose verifies that a multibyte rune left incomplete when
// Close is called is still flushed (not dropped) and surfaces as U+FFFD on
// read, per the documented unavoidable-EOF behavior.
func TestPartialRuneAtClose(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Write a complete prefix plus the first byte of "│" (0xE2), then close
	// without ever supplying the remaining two continuation bytes.
	if err := w.WriteOutput(0.0, []byte("ok")); err != nil {
		t.Fatalf("WriteOutput(prefix): %v", err)
	}
	if err := w.WriteOutput(0.5, []byte{0xE2}); err != nil {
		t.Fatalf("WriteOutput(partial): %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	var got string
	for {
		ev, err := ReadEvent(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent: %v", err)
		}
		got += ev.Data
	}
	// The dangling 0xE2 must not be silently dropped: it is flushed and the
	// JSON decoder yields U+FFFD for it.
	if !strings.ContainsRune(got, '�') {
		t.Errorf("partial rune at Close: got %q, want a U+FFFD replacement", got)
	}
	if !strings.HasPrefix(got, "ok") {
		t.Errorf("prefix lost: got %q, want it to start with %q", got, "ok")
	}
}

// TestSplitFourByteRuneEachBoundary splits a 4-byte rune (U+1F600, "😀":
// 0xF0 0x9F 0x98 0x80) at every interior boundary across two writes and
// verifies lossless reassembly with no U+FFFD.
func TestSplitFourByteRuneEachBoundary(t *testing.T) {
	full := []byte("x😀y") // 1 + 4 + 1 bytes
	runeStart := bytes.IndexByte(full, 0xF0)
	for cut := 1; cut <= 3; cut++ {
		split := runeStart + cut
		t.Run("cut"+string(rune('0'+cut)), func(t *testing.T) {
			var buf bytes.Buffer
			w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
			if err != nil {
				t.Fatalf("NewWriter: %v", err)
			}
			if err := w.WriteOutput(0.0, full[:split]); err != nil {
				t.Fatalf("WriteOutput(part1): %v", err)
			}
			if err := w.WriteOutput(0.5, full[split:]); err != nil {
				t.Fatalf("WriteOutput(part2): %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
			if _, err := ReadHeader(r); err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			var got string
			for {
				ev, err := ReadEvent(r)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("ReadEvent: %v", err)
				}
				got += ev.Data
			}
			if got != string(full) {
				t.Errorf("split at %d: reassembled %q, want %q", split, got, string(full))
			}
			if strings.ContainsRune(got, '�') {
				t.Errorf("split at %d: output contains U+FFFD: %q", split, got)
			}
		})
	}
}

// TestInvalidByteNotHeldBack verifies that a genuinely invalid trailing byte
// (a lone 0xFF, which can never start a valid UTF-8 sequence) is emitted
// immediately rather than being held back as if it were a partial rune.
func TestInvalidByteNotHeldBack(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// A single write ending in 0xFF: the byte is not a valid rune start, so
	// it must be emitted in this event, leaving nothing pending.
	if err := w.WriteOutput(0.0, []byte{'a', 0xFF}); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if w.pending != nil {
		t.Errorf("lone 0xFF was held back as pending: %v", w.pending)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	r := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	ev, err := ReadEvent(r)
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	// 0xFF decodes to U+FFFD via JSON, but the 'a' must be present and the
	// event must have been written (not deferred).
	if !strings.HasPrefix(ev.Data, "a") {
		t.Errorf("event data: got %q, want it to start with %q", ev.Data, "a")
	}
	if _, err := ReadEvent(r); err != io.EOF {
		t.Errorf("expected single event then EOF, got err %v", err)
	}
}

// TestReadHeaderNoTrailingNewline verifies a header line with no trailing
// newline at EOF is still parsed (ReadBytes returns the data with io.EOF).
func TestReadHeaderNoTrailingNewline(t *testing.T) {
	body := `{"version":2,"width":80,"height":24}` // no '\n'
	r := bufio.NewReader(strings.NewReader(body))
	h, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if h.Version != 2 || h.Width != 80 || h.Height != 24 {
		t.Errorf("header: got %+v, want version=2 width=80 height=24", h)
	}
	if _, err := ReadEvent(r); err != io.EOF {
		t.Errorf("ReadEvent after headerless EOF: got %v, want io.EOF", err)
	}
}

// TestParseEventLineMalformed covers malformed event arrays: too few
// elements, a wrong-typed time, a wrong-typed type field, and an unknown
// event type. Each must produce an error rather than silent empty output.
func TestParseEventLineMalformed(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"too few elements", `[0.5, "o"]`},
		{"empty array", `[]`},
		{"wrong-typed time", `["nope", "o", "data"]`},
		{"wrong-typed type", `[0.5, 7, "data"]`},
		{"unknown type", `[0.5, "x", "data"]`},
		{"wrong-typed data", `[0.5, "o", 123]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.line + "\n"))
			_, err := ReadEvent(r)
			if err == nil {
				t.Errorf("ReadEvent(%q): expected error, got nil", tc.line)
			}
			if err == io.EOF {
				t.Errorf("ReadEvent(%q): got io.EOF, want a parse error", tc.line)
			}
		})
	}
}

// TestParseEventInputType verifies that the valid "i" (input) event type is
// accepted alongside "o".
func TestParseEventInputType(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("[0.5, \"i\", \"ls\\r\"]\n"))
	ev, err := ReadEvent(r)
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.Type != "i" {
		t.Errorf("Type: got %q, want %q", ev.Type, "i")
	}
	if ev.Data != "ls\r" {
		t.Errorf("Data: got %q, want %q", ev.Data, "ls\r")
	}
}

// TestReadHeaderEmptyFile verifies a 0-byte cast yields io.EOF (not a panic or
// a confusing parse error), which the play layer translates to a clear message.
func TestReadHeaderEmptyFile(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader(nil))
	if _, err := ReadHeader(r); err != io.EOF {
		t.Errorf("ReadHeader(empty) = %v, want io.EOF", err)
	}
}

// TestReadEventHeaderOnlyFile verifies a header-only cast (no events) reads its
// header cleanly and the first ReadEvent returns io.EOF rather than erroring.
func TestReadEventHeaderOnlyFile(t *testing.T) {
	body := "{\"version\":2,\"width\":80,\"height\":24}\n"
	r := bufio.NewReader(strings.NewReader(body))
	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if _, err := ReadEvent(r); err != io.EOF {
		t.Errorf("ReadEvent on header-only cast = %v, want io.EOF", err)
	}
}

// TestReadEventRecoversAfterMalformedLine verifies that a malformed event line
// in the middle of a file is consumed (the reader advances past it) so the
// caller can skip it and still read the following well-formed event. This is the
// contract the play layer relies on to degrade gracefully on a garbled line.
func TestReadEventRecoversAfterMalformedLine(t *testing.T) {
	body := `{"version":2,"width":80,"height":24}
[0.100000, "o", "first"]
[this is not valid json
[0.300000, "o", "third"]
`
	r := bufio.NewReader(strings.NewReader(body))
	if _, err := ReadHeader(r); err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	e1, err := ReadEvent(r)
	if err != nil || e1.Data != "first" {
		t.Fatalf("ReadEvent[0] = %q, %v; want \"first\", nil", e1.Data, err)
	}

	// The malformed line must surface as a (non-EOF) parse error, and must have
	// been fully consumed so the next read sees the line after it.
	if _, err := ReadEvent(r); err == nil || err == io.EOF {
		t.Fatalf("ReadEvent on malformed line = %v; want a non-EOF parse error", err)
	}

	e3, err := ReadEvent(r)
	if err != nil || e3.Data != "third" {
		t.Fatalf("ReadEvent after bad line = %q, %v; want \"third\", nil", e3.Data, err)
	}

	if _, err := ReadEvent(r); err != io.EOF {
		t.Errorf("ReadEvent past end = %v, want io.EOF", err)
	}
}
