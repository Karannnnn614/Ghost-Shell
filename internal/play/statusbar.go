// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package play

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	// SGR mouse reporting: enable button events with extended (SGR) coordinates.
	mouseEnable  = "\x1b[?1000h\x1b[?1006h"
	mouseDisable = "\x1b[?1006l\x1b[?1000l"

	// clrReset is used by scrollback.go truncLine to close dangling SGR sequences.
	clrReset = "\x1b[0m"
	// clrBold/clrCyan used by chapters.go chapter-list UI.
	clrBold = "\x1b[1m"
	clrCyan = "\x1b[36m"
)

// termSize returns the terminal width and height, with 80x24 fallback.
func termSize() (int, int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// formatClock renders seconds as MM:SS, switching to H:MM:SS once the minutes
// field would reach 100 (i.e. >= 100 minutes) so long casts don't show a
// misleading "120:00" for two hours.
func formatClock(secs float64) string {
	if secs < 0 {
		secs = 0
	}
	t := int(secs + 0.5)
	mins := t / 60
	if mins >= 100 {
		return fmt.Sprintf("%d:%02d:%02d", t/3600, (t%3600)/60, t%60)
	}
	return fmt.Sprintf("%02d:%02d", mins, t%60)
}

// parseClock parses a goto target: "SS", "MM:SS", or "M:SS".
func parseClock(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		m, e1 := strconv.Atoi(s[:i])
		sec, e2 := strconv.Atoi(s[i+1:])
		if e1 != nil || e2 != nil || m < 0 || sec < 0 || sec >= 60 {
			return 0, false
		}
		return float64(m*60 + sec), true
	}
	sec, e := strconv.Atoi(s)
	if e != nil || sec < 0 {
		return 0, false
	}
	return float64(sec), true
}

func formatSpeed(s float64) string {
	return strconv.FormatFloat(s, 'g', -1, 64) + "x"
}

// faster doubles the speed, clamped to maxSpeed. The result is clamped (not
// just the step gated) so a speed that starts above the ceiling — e.g. from
// `--speed 100` — or one that doubles past it (33→66) snaps cleanly to maxSpeed
// instead of sticking out of range and never returning.
func faster(s float64) float64 {
	return clampSpeed(s * 2)
}

// slower halves the speed, clamped to minSpeed (the 1/64× floor). As with
// faster, the result is clamped so a sub-floor start value snaps to minSpeed
// and repeated halving can never reach 0 (which would stall the player).
func slower(s float64) float64 {
	return clampSpeed(s / 2)
}

// clampSpeed bounds a speed multiplier to [minSpeed, maxSpeed]. A non-positive
// or NaN input (which fails both comparisons) is coerced to minSpeed so the
// player never divides timing by zero or a negative factor.
func clampSpeed(s float64) float64 {
	if !(s >= minSpeed) { // false for NaN, <=0, and below the floor
		return minSpeed
	}
	if s > maxSpeed {
		return maxSpeed
	}
	return s
}

// renderBar builds the plain-text status bar and returns it with the 1-based
// column of the first progress-bar fill cell and the inner bar width,
// for mouse-click seeking.
//
// Format (no ANSI color):
//
//	> 01:23 / 05:00 [####      ]  27%  1x   <-/-> seek  pgup scroll  g goto  spc play  q quit
func renderBar(width int, vt, lastT, speed float64, paused, inGoto bool, gotoBuf string) (line string, barCol, barW int) {
	icon := ">"
	if paused {
		icon = "||"
	}
	left := fmt.Sprintf(" %s %s / %s ", icon, formatClock(vt), formatClock(lastT))

	var right string
	if inGoto {
		right = fmt.Sprintf(" goto: %s_  (enter: jump  esc: cancel)", gotoBuf)
	} else {
		pct := 0.0
		if lastT > 0 {
			pct = vt / lastT * 100
		}
		right = fmt.Sprintf("  %3.0f%%  %s   <-/-> seek  pgup scroll  g goto  spc play  q quit", pct, formatSpeed(speed))
	}

	// Available columns for the [####   ] bar including the two bracket chars.
	avail := width - utf8.RuneCountInString(left) - utf8.RuneCountInString(right)
	if avail < 7 {
		avail = 7 // minimum: "[#    ]" = 7
	}
	innerW := avail - 2 // subtract [ and ]
	if innerW < 5 {
		innerW = 5
	}

	filled := 0
	if lastT > 0 {
		filled = int(float64(innerW)*vt/lastT + 0.5)
	}
	if filled > innerW {
		filled = innerW
	}
	if filled < 0 {
		filled = 0
	}

	bar := "[" + strings.Repeat("#", filled) + strings.Repeat(" ", innerW-filled) + "]"

	line = left + bar + right
	// barCol: 1-based column of the first fill char (after the opening "[")
	barCol = utf8.RuneCountInString(left) + 2
	barW = innerW
	return line, barCol, barW
}

// drawStatus paints the status bar on the bottom row without moving the cursor,
// returning the bar's column, width, and row for mouse hit-testing.
func drawStatus(vt, lastT, speed float64, paused, inGoto bool, gotoBuf string) (barCol, barW, row int) {
	w, h := termSize()
	// Guard a minimum usable height: at h==1 there is no content row to reserve
	// and a 1;0 region is degenerate, so treat the screen as if it had 2 rows
	// (content row 1, bar row 2). Better a slightly-off layout than a broken one.
	if h < 2 {
		h = 2
	}
	line, bc, bw := renderBar(w, vt, lastT, speed, paused, inGoto, gotoBuf)
	// Save cursor; re-assert the scroll region (a recording — e.g. dpkg's
	// progress bar — may have set its own, which would scroll our reserved row
	// into the content); go to the bottom row, clear it, disable autowrap (so a
	// full-width line can't scroll), draw, re-enable autowrap, restore cursor.
	region := fmt.Sprintf("\x1b[1;%dr", h-1)
	fmt.Fprintf(os.Stdout, "\x1b7%s\x1b[%d;1H\x1b[2K\x1b[?7l%s\x1b[?7h\x1b8", region, h, line)
	return bc, bw, h
}

// drawScrollBar paints the scroll-mode indicator on the given row.
// Plain text, no color. Uses DECSC/DECRC so caller's cursor is unaffected.
func drawScrollBar(total, offset, row int) {
	w, _ := termSize()
	var msg string
	if offset == 0 {
		msg = fmt.Sprintf(" [SCROLL] %d lines   pgup/up/wheel: scroll up   any other key: exit", total)
	} else {
		msg = fmt.Sprintf(" [SCROLL] -%d/%d   pgdn/down/wheel: scroll down   any other key: exit", offset, total)
	}
	// Truncate to terminal width using display columns (visWidth handles wide chars).
	if visWidth(msg) > w {
		// clip rune by rune until it fits
		runes := []rune(msg)
		for len(runes) > 0 && visWidth(string(runes)) > w {
			runes = runes[:len(runes)-1]
		}
		msg = string(runes)
	}
	fmt.Fprintf(os.Stdout, "\x1b7\x1b[%d;1H\x1b[2K\x1b[?7l%s\x1b[?7h\x1b8", row, msg)
}
