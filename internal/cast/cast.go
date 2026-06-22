// Package cast reads and writes the asciinema v2 cast format.
//
// A cast file is JSON-lines: the first line is a header object, and each
// subsequent line is an event array [time, type, data], e.g.
//
//	{"version":2,"width":80,"height":24,"timestamp":1700000000}
//	[0.123456, "o", "hello\r\n"]
package cast

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// Header is the first line of a cast file.
type Header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp,omitempty"`
	Command   string            `json:"command,omitempty"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// Event is one recorded I/O event. Type is "o" (output) or "i" (input).
type Event struct {
	Time float64
	Type string
	Data string
}

// Writer streams cast events to an underlying writer.
type Writer struct {
	w *bufio.Writer
	// pending holds an incomplete trailing UTF-8 sequence carried over from
	// the previous write. PTY reads can split a multibyte rune across chunks;
	// json.Marshal would replace the split halves with U+FFFD, corrupting the
	// recording. We hold the partial bytes and prepend them to the next write.
	pending []byte
	lastT   float64
	// scratch is a reused buffer for assembling each event line, avoiding a
	// per-event allocation in the write hot path.
	scratch []byte
}

// NewWriter writes the header and returns a Writer for the events.
func NewWriter(w io.Writer, h Header) (*Writer, error) {
	h.Version = 2
	bw := bufio.NewWriter(w)
	if err := json.NewEncoder(bw).Encode(h); err != nil {
		return nil, err
	}
	// Flush the header to disk immediately so an in-progress recording is
	// readable by `ghostshell ls` before the session ends.
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return &Writer{w: bw}, nil
}

// WriteOutput appends an output event at t seconds since session start.
func (c *Writer) WriteOutput(t float64, data []byte) error {
	c.lastT = t
	if len(c.pending) > 0 {
		data = append(c.pending, data...)
		c.pending = nil
	}
	if n := completeUTF8Len(data); n < len(data) {
		c.pending = append([]byte(nil), data[n:]...)
		data = data[:n]
	}
	if len(data) == 0 {
		return nil
	}
	return c.emit(t, data)
}

func (c *Writer) emit(t float64, data []byte) error {
	// json.Marshal correctly escapes the data string for JSON; it returns a
	// freshly allocated slice. We assemble the rest of the line into a reused
	// scratch buffer to avoid the fmt.Fprintf reflection/allocation overhead.
	enc, err := json.Marshal(string(data))
	if err != nil {
		return err
	}
	b := c.scratch[:0]
	b = append(b, '[')
	b = strconv.AppendFloat(b, t, 'f', 6, 64)
	b = append(b, `, "o", `...)
	b = append(b, enc...)
	b = append(b, ']', '\n')
	c.scratch = b
	_, err = c.w.Write(b)
	return err
}

// Flush flushes buffered data to the underlying writer. Any incomplete
// trailing multibyte sequence is held back until the next write.
func (c *Writer) Flush() error { return c.w.Flush() }

// Close emits any held trailing bytes and flushes. Call once at session end.
//
// A trailing partial rune that is still incomplete at Close (a multibyte
// sequence whose remaining bytes never arrived) is unavoidably emitted as-is;
// json.Marshal replaces its bytes with U+FFFD. Flushing the partial bytes is
// preferable to silently dropping them. Both the final emit error and the
// flush error are surfaced (joined) so a final-write failure is not lost.
func (c *Writer) Close() error {
	var emitErr error
	if len(c.pending) > 0 {
		emitErr = c.emit(c.lastT, c.pending)
		c.pending = nil
	}
	return errors.Join(emitErr, c.w.Flush())
}

// completeUTF8Len returns the length of b up to the last complete UTF-8
// sequence, holding back an incomplete trailing multibyte sequence (a rune
// split across read boundaries). Genuinely invalid bytes are not held back.
func completeUTF8Len(b []byte) int {
	max := utf8.UTFMax
	if max > len(b) {
		max = len(b)
	}
	for i := 1; i <= max; i++ {
		start := len(b) - i
		if !utf8.RuneStart(b[start]) {
			continue // continuation byte; keep scanning back
		}
		if size := runeLen(b[start]); size > 1 && start+size > len(b) {
			return start // trailing sequence incomplete; hold it
		}
		return len(b)
	}
	return len(b)
}

func runeLen(c byte) int {
	switch {
	case c&0x80 == 0x00:
		return 1
	case c&0xE0 == 0xC0:
		return 2
	case c&0xF0 == 0xE0:
		return 3
	case c&0xF8 == 0xF0:
		return 4
	default:
		return 1
	}
}

// ReadHeader reads and parses the header line.
func ReadHeader(r *bufio.Reader) (Header, error) {
	line, err := r.ReadBytes('\n')
	if len(line) == 0 {
		if err == nil {
			err = io.EOF
		}
		return Header{}, err
	}
	var h Header
	if e := json.Unmarshal(bytes.TrimSpace(line), &h); e != nil {
		return Header{}, fmt.Errorf("invalid cast header: %w", e)
	}
	return h, nil
}

// ReadEvent reads the next event line, skipping blanks. Returns io.EOF at end.
func ReadEvent(r *bufio.Reader) (Event, error) {
	for {
		line, err := r.ReadBytes('\n')
		if len(line) == 0 {
			if err == nil {
				err = io.EOF
			}
			return Event{}, err
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			if err != nil {
				return Event{}, io.EOF
			}
			continue
		}
		return parseEventLine(trimmed)
	}
}

func parseEventLine(b []byte) (Event, error) {
	var raw []json.RawMessage
	if e := json.Unmarshal(b, &raw); e != nil {
		return Event{}, fmt.Errorf("bad event line: %w", e)
	}
	if len(raw) < 3 {
		return Event{}, fmt.Errorf("short event line: %s", b)
	}
	var ev Event
	if e := json.Unmarshal(raw[0], &ev.Time); e != nil {
		return Event{}, fmt.Errorf("bad event time: %w", e)
	}
	if e := json.Unmarshal(raw[1], &ev.Type); e != nil {
		return Event{}, fmt.Errorf("bad event type: %w", e)
	}
	if ev.Type != "o" && ev.Type != "i" {
		return Event{}, fmt.Errorf("unknown event type %q", ev.Type)
	}
	if e := json.Unmarshal(raw[2], &ev.Data); e != nil {
		return Event{}, fmt.Errorf("bad event data: %w", e)
	}
	return ev, nil
}
