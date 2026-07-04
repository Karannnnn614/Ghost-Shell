// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package play — scrollback.go: line buffer for the scrollback viewer.
package play

import (
	"strings"
	"unicode/utf8"
)

// scrollStep is lines scrolled per key/wheel action.
const scrollStep = 3

const (
	// maxScrollLines caps retained scrollback so a crafted cast with millions of
	// newlines can't exhaust memory; oldest lines are dropped (ring behaviour).
	maxScrollLines = 10000
	// maxLineBytes caps a single line's byte length (escape sequences included)
	// so a cast with no newlines can't grow one line without bound.
	maxLineBytes = 64 * 1024
)

// lineBuf accumulates terminal-output lines for the scrollback viewer.
// Watches \n and \r to delimit lines, strips cursor-movement escape
// sequences, preserves SGR colour/style sequences. Retention is bounded:
// at most maxScrollLines lines (oldest dropped) and maxLineBytes per line.
type lineBuf struct {
	lines []string
	cur   strings.Builder
	// pending holds an escape sequence prefix split across a feed() boundary
	// (e.g. data ended mid-CSI). It is prepended to the next feed() so the
	// sequence is parsed whole instead of being corrupted/dropped.
	pending []byte
}

// commit appends cur as a finished line (honouring the line cap) and resets it.
// Old lines are dropped once the slice grows past a high-water mark, compacting
// down to the most recent maxScrollLines. Compacting in batches (rather than on
// every line once full) keeps dropping amortised O(1) instead of O(n) per line.
func (b *lineBuf) commit() {
	b.lines = append(b.lines, b.cur.String())
	if len(b.lines) > 2*maxScrollLines {
		keep := b.lines[len(b.lines)-maxScrollLines:]
		// Copy onto a fresh array so the dropped strings aren't pinned by the
		// old (larger) backing array's capacity.
		b.lines = append(make([]string, 0, maxScrollLines), keep...)
	}
	b.cur.Reset()
}

// writeCur appends s to the current line unless it would exceed maxLineBytes.
func (b *lineBuf) writeCur(s string) {
	if b.cur.Len()+len(s) > maxLineBytes {
		return
	}
	b.cur.WriteString(s)
}

// feed processes raw terminal output data and appends completed lines.
func (b *lineBuf) feed(data string) {
	if len(b.pending) > 0 {
		data = string(b.pending) + data
		b.pending = b.pending[:0]
	}
	i := 0
	for i < len(data) {
		c := data[i]
		switch {
		case c == '\n':
			b.commit()
			i++
		case c == '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				i++ // CR before LF: skip CR
				continue
			}
			b.cur.Reset() // standalone CR: overwrite line
			i++
		case c == '\x1b':
			// If the escape sequence is incomplete at the end of this chunk,
			// stash the remainder and resume on the next feed() — otherwise a
			// split CSI/OSC would be misparsed and leak bytes into the line.
			if !escComplete(data, i) {
				b.pending = append(b.pending[:0], data[i:]...)
				return
			}
			seq, n, isSGR := parseESC(data, i)
			if isSGR {
				b.writeCur(seq)
			} else if isVerticalMove(seq) {
				// Cursor-up / cursor-position sequences imply a new visual
				// row. Commit the current partial line so scrollback lines
				// map to actual screen rows instead of concatenating.
				if b.cur.Len() > 0 {
					b.commit()
				}
			}
			if n == 0 {
				n = 1
			}
			i += n
		case c >= 0x20 || c == '\t':
			if b.cur.Len() < maxLineBytes {
				b.cur.WriteByte(c)
			}
			i++
		default:
			i++
		}
	}
}

// escComplete reports whether the escape sequence starting at data[i] is fully
// contained in data. Used to detect a sequence split across feed() chunks so
// the remainder can be carried over instead of misparsed.
func escComplete(data string, i int) bool {
	if i >= len(data) || data[i] != '\x1b' {
		return true
	}
	j := i + 1
	if j >= len(data) {
		return false // lone ESC at end
	}
	switch data[j] {
	case '[': // CSI: ESC [ params/intermediates final(0x40..0x7e)
		j++
		for j < len(data) {
			if data[j] >= 0x40 && data[j] <= 0x7e {
				return true
			}
			j++
		}
		return false
	case ']': // OSC: terminated by BEL or ESC \
		j++
		for j < len(data) {
			if data[j] == 0x07 {
				return true
			}
			if data[j] == '\x1b' {
				if j+1 < len(data) {
					return data[j+1] == '\\' // complete only if ST's backslash present
				}
				return false // ESC at end: need the next byte to know
			}
			j++
		}
		return false
	default: // 2-byte sequence: ESC + one byte (already present at data[j])
		return true
	}
}

// parseESC parses an ANSI/VT escape sequence at data[i].
// Returns the sequence text, its byte length, and whether it is an SGR
// (colour/style: ESC [ ... m) sequence. Non-SGR sequences are stripped
// from the scrollback buffer; SGR sequences are kept.
func parseESC(data string, i int) (seq string, n int, isSGR bool) {
	start := i
	if i >= len(data) || data[i] != '\x1b' {
		return "", 0, false
	}
	i++
	if i >= len(data) {
		return data[start:i], 1, false
	}
	switch data[i] {
	case '[': // CSI
		i++
		for i < len(data) {
			b := data[i]
			if b >= 0x40 && b <= 0x7e { // final byte
				i++
				isSGR = b == 'm'
				return data[start:i], i - start, isSGR
			}
			i++
		}
		return data[start:i], i - start, false
	case ']': // OSC — skip until BEL or ESC \
		i++
		for i < len(data) {
			if data[i] == 0x07 {
				i++
				break
			}
			if data[i] == '\x1b' && i+1 < len(data) && data[i+1] == '\\' {
				i += 2
				break
			}
			i++
		}
		return data[start:i], i - start, false
	default: // 2-byte: ESC 7, ESC 8, ESC c, etc.
		i++
		return data[start:i], 2, false
	}
}

// stripAnsi removes all escape sequences for visible-width measurement.
func stripAnsi(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' {
			_, n, _ := parseESC(s, i)
			if n == 0 {
				n = 1
			}
			i += n
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// isVerticalMove returns true for escape sequences that move the cursor to a
// different row: cursor-up (A), cursor-home/position (H), cursor-prev-line (F),
// and ESC M (reverse index). These act as implicit line separators in feed().
func isVerticalMove(seq string) bool {
	if len(seq) == 2 && seq[0] == '\x1b' {
		return seq[1] == 'M' // reverse index
	}
	if len(seq) < 3 || seq[0] != '\x1b' || seq[1] != '[' {
		return false
	}
	final := seq[len(seq)-1]
	return final == 'H' || final == 'A' || final == 'F'
}

// runeWidth returns the number of terminal columns occupied by r.
// Most runes are 1 column; CJK ideographs, fullwidth forms, and most
// emoji are 2 columns (East Asian Width W or F).
func runeWidth(r rune) int {
	if r < 0x1100 {
		return 1
	}
	switch {
	case r >= 0x1100 && r <= 0x115F:
		return 2 // Hangul Jamo
	case r == 0x2329 || r == 0x232A:
		return 2 // Angle brackets
	case r >= 0x2E80 && r <= 0x303E:
		return 2 // CJK Radicals .. CJK Symbols
	case r >= 0x3041 && r <= 0x33FF:
		return 2 // Hiragana..CJK Compatibility
	case r >= 0x3400 && r <= 0x4DBF:
		return 2 // CJK Extension A
	case r >= 0x4E00 && r <= 0xA4CF:
		return 2 // CJK Unified + Yi
	case r >= 0xA960 && r <= 0xA97F:
		return 2 // Hangul Jamo Extended-A
	case r >= 0xAC00 && r <= 0xD7AF:
		return 2 // Hangul Syllables
	case r >= 0xF900 && r <= 0xFAFF:
		return 2 // CJK Compatibility Ideographs
	case r >= 0xFE10 && r <= 0xFE19:
		return 2 // Vertical Forms
	case r >= 0xFE30 && r <= 0xFE4F:
		return 2 // CJK Compatibility Forms
	case r >= 0xFF01 && r <= 0xFF60:
		return 2 // Fullwidth Forms
	case r >= 0xFFE0 && r <= 0xFFE6:
		return 2 // Fullwidth Signs
	case r >= 0x1B000 && r <= 0x1B0FF:
		return 2 // Kana Supplement
	case r >= 0x1F004 && r <= 0x1FFFD:
		return 2 // Emoji and supplemental symbols
	case r >= 0x20000 && r <= 0x2FFFD:
		return 2 // CJK Extension B-F
	case r >= 0x30000 && r <= 0x3FFFD:
		return 2 // CJK Extension G+
	}
	return 1
}

// visWidth returns the visible terminal column width of s, excluding ANSI sequences.
func visWidth(s string) int {
	plain := stripAnsi(s)
	w := 0
	for _, r := range plain {
		w += runeWidth(r)
	}
	return w
}

// truncLine truncates a line (containing ANSI colour sequences) to at most
// maxCols visible terminal columns, appending a reset so colours do not bleed.
func truncLine(s string, maxCols int) string {
	var b strings.Builder
	cols := 0
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' {
			seq, n, _ := parseESC(s, i)
			b.WriteString(seq)
			if n == 0 {
				n = 1
			}
			i += n
			continue
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		rw := runeWidth(r)
		if cols+rw > maxCols {
			break // would overflow — stop here
		}
		b.WriteRune(r)
		cols += rw
		i += sz
	}
	if i < len(s) { // stopped before end of string — line was truncated
		b.WriteString(clrReset)
	}
	return b.String()
}
