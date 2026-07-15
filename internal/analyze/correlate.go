// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package analyze

import (
	"bufio"
	"fmt"
	"time"

	"ghostshell/internal/cast"
)

// correlateOutput fills in each failure's pty-output slice by streaming the
// decrypted cast and collecting the "o" (output) events that fall inside that
// failure's time window.
//
// Spans time-stamp with unix nanoseconds; asciinema events time-stamp with
// seconds relative to the session start (the cast header Timestamp, unix
// seconds). We convert each failure window [StartTS, EndTS] into session-
// relative seconds and gather every output event whose event time lands in
// [startRel, endRel]. Each failure's capture is bounded to maxBytes, keeping the
// tail (the error text almost always comes last); OutputTruncated records
// whether leading bytes were dropped.
//
// br must be positioned at the start of the cast (header line first); this
// function reads and consumes the header. failures is mutated in place — its
// Output/OutputTruncated fields are set — so the caller's slice observes the
// results. A non-nil error means correlation could not be done at all (bad
// header, or no usable session start); the failures slice is then left with
// empty Output fields. A malformed event line mid-stream is NOT an error: the
// pass is fail-open and simply stops early with whatever it has gathered.
func correlateOutput(br *bufio.Reader, sessionStartUnix int64, failures []Failure, maxBytes int) error {
	h, err := cast.ReadHeader(br)
	if err != nil {
		return fmt.Errorf("analyze: read cast header: %w", err)
	}
	start := sessionStartUnix
	if start <= 0 {
		start = h.Timestamp
	}
	if start <= 0 {
		return fmt.Errorf("analyze: no session start (sessionStartUnix <= 0 and cast header has no timestamp); cannot correlate failure output")
	}
	startNanos := start * int64(time.Second)

	// window is a failure's capture buffer in cast-relative seconds.
	type window struct {
		idx        int // index into failures
		start, end float64
		buf        []byte
		truncated  bool
	}
	windows := make([]window, len(failures))
	var maxEnd float64
	for i := range failures {
		s := float64(failures[i].StartTS-startNanos) / float64(time.Second)
		e := float64(failures[i].EndTS-startNanos) / float64(time.Second)
		windows[i] = window{idx: i, start: s, end: e}
		if e > maxEnd {
			maxEnd = e
		}
	}

	for {
		ev, err := cast.ReadEvent(br)
		if err != nil {
			// io.EOF is the normal end; any other (malformed line) is tolerated
			// fail-open — keep whatever was collected so far.
			break
		}
		if ev.Type != "o" {
			continue
		}
		// Events are emitted in non-decreasing time order, so once we pass the
		// latest failure window there is nothing left to match.
		if ev.Time > maxEnd {
			break
		}
		for k := range windows {
			w := &windows[k]
			if ev.Time < w.start || ev.Time > w.end {
				continue
			}
			var trimmed bool
			w.buf, trimmed = appendCapped(w.buf, ev.Data, maxBytes)
			if trimmed {
				w.truncated = true
			}
		}
	}

	for k := range windows {
		w := &windows[k]
		failures[w.idx].Output = string(w.buf)
		failures[w.idx].OutputTruncated = w.truncated
	}
	return nil
}

// appendCapped appends data to buf and keeps at most maxBytes bytes, retaining
// the tail. It reports whether any leading bytes were dropped on this call (so
// the caller can latch a cumulative "truncated" flag). maxBytes is guaranteed
// positive by Options.withDefaults.
func appendCapped(buf []byte, data string, maxBytes int) ([]byte, bool) {
	buf = append(buf, data...)
	if len(buf) <= maxBytes {
		return buf, false
	}
	trimmed := make([]byte, maxBytes)
	copy(trimmed, buf[len(buf)-maxBytes:])
	return trimmed, true
}
