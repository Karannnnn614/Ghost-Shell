// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package play

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFormatClock(t *testing.T) {
	cases := map[float64]string{0: "00:00", 5: "00:05", 65: "01:05", 3599: "59:59", 3600: "60:00"}
	for in, want := range cases {
		if got := formatClock(in); got != want {
			t.Errorf("formatClock(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestParseClock(t *testing.T) {
	ok := map[string]float64{"0": 0, "42": 42, "1:05": 65, "10:00": 600, "00:30": 30}
	for in, want := range ok {
		if got, valid := parseClock(in); !valid || got != want {
			t.Errorf("parseClock(%q) = %v,%v want %v,true", in, got, valid, want)
		}
	}
	for _, bad := range []string{"", "1:99", "abc", ":", "-5", "1:2:3"} {
		if got, valid := parseClock(bad); valid {
			t.Errorf("parseClock(%q) = %v,true want invalid", bad, got)
		}
	}
}

func TestFormatSpeed(t *testing.T) {
	cases := map[float64]string{1: "1x", 2: "2x", 0.5: "0.5x", 0.25: "0.25x"}
	for in, want := range cases {
		if got := formatSpeed(in); got != want {
			t.Errorf("formatSpeed(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestFasterSlowerClamp(t *testing.T) {
	if got := faster(maxSpeed); got != maxSpeed {
		t.Errorf("faster at max = %v, want %v", got, maxSpeed)
	}
	if got := slower(minSpeed); got != minSpeed {
		t.Errorf("slower at min = %v, want %v", got, minSpeed)
	}
	if got := faster(1); got != 2 {
		t.Errorf("faster(1) = %v, want 2", got)
	}
}

// TestSpeedClampResultBounds verifies the speed steppers clamp the *result*
// into [minSpeed, maxSpeed], not just gate the step. A value that overshoots a
// boundary (33→66) or starts out of range (from `--speed`) must snap to the
// boundary instead of sticking outside it. Repeated stepping must converge to
// exactly the boundary and stay there.
func TestSpeedClampResultBounds(t *testing.T) {
	// Overshoot above the ceiling snaps to maxSpeed.
	if got := faster(33); got != maxSpeed {
		t.Errorf("faster(33) = %v, want %v (clamped to ceiling)", got, maxSpeed)
	}
	// A start value already above the ceiling is pulled to maxSpeed.
	if got := faster(1000); got != maxSpeed {
		t.Errorf("faster(1000) = %v, want %v", got, maxSpeed)
	}
	// Undershoot below the floor snaps to minSpeed (never to 0).
	if got := slower(minSpeed * 1.5); got != minSpeed {
		t.Errorf("slower(%v) = %v, want %v (clamped to floor)", minSpeed*1.5, got, minSpeed)
	}
	// A start value already below the floor is pulled to minSpeed.
	if got := slower(0.0001); got != minSpeed {
		t.Errorf("slower(0.0001) = %v, want %v", got, minSpeed)
	}
	// Repeated faster() converges to and stays at maxSpeed (no runaway).
	s := 1.0
	for i := 0; i < 100; i++ {
		s = faster(s)
	}
	if s != maxSpeed {
		t.Errorf("faster x100 = %v, want %v", s, maxSpeed)
	}
	// Repeated slower() converges to and stays at minSpeed (never reaches 0,
	// which would stall replay via a zero divisor).
	s = 1.0
	for i := 0; i < 100; i++ {
		s = slower(s)
	}
	if s != minSpeed {
		t.Errorf("slower x100 = %v, want %v", s, minSpeed)
	}
	if s <= 0 {
		t.Fatalf("slower bottomed out at %v (<= 0): would divide timing by zero", s)
	}
}

// visibleLen counts runes outside ANSI escape sequences. A CSI sequence is
// ESC '[' params/intermediates then a final byte in 0x40..0x7e.
func visibleLen(s string) int {
	rs := []rune(s)
	n := 0
	for i := 0; i < len(rs); i++ {
		if rs[i] == 0x1b {
			i++
			if i < len(rs) && rs[i] == '[' {
				i++
				for i < len(rs) && !(rs[i] >= '@' && rs[i] <= '~') {
					i++
				}
				// rs[i] is the final byte; the loop's i++ skips it
			}
			continue
		}
		n++
	}
	return n
}

func TestRenderBarGeometry(t *testing.T) {
	width := 100
	line, barCol, barW := renderBar(width, 30, 120, 1, false, false, "")
	if barW < 10 {
		t.Errorf("barW = %d, want >= 10", barW)
	}
	// The first bar cell sits just after the left text.
	if barCol < 2 {
		t.Errorf("barCol = %d, want >= 2", barCol)
	}
	// Played portion (#) should be about a quarter (30/120) of the bar.
	filled := strings.Count(line, "#")
	wantFilled := int(float64(barW)*0.25 + 0.5)
	if filled != wantFilled {
		t.Errorf("filled=%d want %d (barW=%d)", filled, wantFilled, barW)
	}
	if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
		t.Errorf("bar missing brackets: %q", line)
	}
	// Visible width should not exceed the terminal width.
	if vl := visibleLen(line); vl > width {
		t.Errorf("visible line width %d exceeds %d", vl, width)
	}
	_ = utf8.RuneCountInString(line)
}

func TestRenderBarGotoField(t *testing.T) {
	line, _, _ := renderBar(100, 0, 60, 1, true, true, "1:23")
	if !strings.Contains(line, "goto:") || !strings.Contains(line, "1:23") {
		t.Errorf("goto bar missing input field: %q", line)
	}
}

// TestSafeDrawBarOnlyOnTicker documents the invariant that safeDrawBar
// must not be called after each emitted event (only from the ticker path).
func TestSafeDrawBarOnlyOnTicker(t *testing.T) {
	t.Skip("invariant guard: see play.go main loop — safeDrawBar must NOT appear in the timer.C case")
}

func TestFormatClockHours(t *testing.T) {
	// At and beyond 100 minutes formatClock switches to H:MM:SS so a long cast
	// doesn't render a misleading "120:00".
	cases := map[float64]string{
		5999:  "99:59",   // just under the switch
		6000:  "1:40:00", // 100 minutes
		7200:  "2:00:00", // two hours (the audit's example)
		36000: "10:00:00",
	}
	for in, want := range cases {
		if got := formatClock(in); got != want {
			t.Errorf("formatClock(%v) = %q, want %q", in, got, want)
		}
	}
}

// --- scrollback (scrollback.go) tests ---

func TestLineBufSplitEscape(t *testing.T) {
	// An SGR sequence split across two feed() calls must be preserved whole.
	var b lineBuf
	b.feed("hi\x1b[3")  // CSI cut mid-parameters
	b.feed("1mred\r\n") // remainder + text + newline
	if len(b.lines) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(b.lines), b.lines)
	}
	if got, want := b.lines[0], "hi\x1b[31mred"; got != want {
		t.Errorf("split SGR = %q, want %q", got, want)
	}

	// A non-SGR (cursor-move) sequence split across feed() must be stripped, not
	// leak its tail bytes into the line.
	var c lineBuf
	c.feed("ab\x1b[")
	c.feed("2Kcd\n")
	if len(c.lines) != 1 || c.lines[0] != "abcd" {
		t.Errorf("split non-SGR = %q, want one line \"abcd\"", c.lines)
	}

	// OSC terminated by a split ST (ESC then \ in the next chunk) is stripped.
	var d lineBuf
	d.feed("x\x1b]0;title\x1b")
	d.feed("\\y\n")
	if len(d.lines) != 1 || d.lines[0] != "xy" {
		t.Errorf("split OSC = %q, want one line \"xy\"", d.lines)
	}
}

func TestLineBufCROverwrite(t *testing.T) {
	// A standalone CR resets the current line (progress-bar style redraw).
	var b lineBuf
	b.feed("loading 10%\rloading 90%\r\n")
	if len(b.lines) != 1 || b.lines[0] != "loading 90%" {
		t.Errorf("CR overwrite = %q, want one line \"loading 90%%\"", b.lines)
	}
	// CRLF must not be treated as a standalone CR: it produces exactly one line.
	var c lineBuf
	c.feed("one\r\ntwo\r\n")
	if len(c.lines) != 2 || c.lines[0] != "one" || c.lines[1] != "two" {
		t.Errorf("CRLF handling = %q, want [\"one\" \"two\"]", c.lines)
	}
}

func TestLineBufWideRune(t *testing.T) {
	// Wide runes are stored verbatim; visWidth counts them as 2 columns each.
	var b lineBuf
	b.feed("a世b\n") // 'a'(1) + '世'(2) + 'b'(1) = 4 columns
	if len(b.lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(b.lines))
	}
	if w := visWidth(b.lines[0]); w != 4 {
		t.Errorf("visWidth(%q) = %d, want 4", b.lines[0], w)
	}
}

func TestLineBufLineCap(t *testing.T) {
	// Feeding far more than the cap must keep retained lines bounded (memory
	// safety): the buffer compacts to maxScrollLines once it passes the
	// high-water mark, so length never exceeds 2*maxScrollLines.
	var b lineBuf
	for i := 0; i < 5*maxScrollLines; i++ {
		b.feed("x\n")
		if len(b.lines) > 2*maxScrollLines {
			t.Fatalf("lines grew to %d, exceeds bound %d", len(b.lines), 2*maxScrollLines)
		}
	}
	if len(b.lines) < maxScrollLines {
		t.Errorf("retained %d lines, want at least %d after compaction", len(b.lines), maxScrollLines)
	}
}

func TestRuneWidthBoundaries(t *testing.T) {
	cases := []struct {
		r    rune
		want int
	}{
		{'a', 1},     // ASCII
		{0x10FF, 1},  // just below the first wide block
		{0x1100, 2},  // first Hangul Jamo (wide)
		{0x115F, 2},  // last Hangul Jamo
		{0x1160, 1},  // just past Hangul Jamo → narrow
		{'世', 2},     // CJK ideograph
		{0xFF60, 2},  // last Fullwidth Form
		{0xFF61, 1},  // just past Fullwidth Forms → narrow
		{0x1F600, 2}, // emoji
		{0x20000, 2}, // CJK Extension B
	}
	for _, c := range cases {
		if got := runeWidth(c.r); got != c.want {
			t.Errorf("runeWidth(%#x) = %d, want %d", c.r, got, c.want)
		}
	}
}
