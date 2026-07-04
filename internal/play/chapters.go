// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package play

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"ghostshell/internal/cast"
)

// chapter is a jump point: a command found in the recording and the time at
// which its prompt line completed.
type chapter struct {
	t     float64
	label string
}

// ansiRe strips terminal escape sequences (CSI, OSC, charset, ESC 7/8/=/>),
// so prompt detection runs against plain text.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[78=>]`)

// promptRe matches a stripped shell-prompt line of the common form
// user@host:cwd$ command (or ending in #). Capture group 1 is the command.
var promptRe = regexp.MustCompile(`[\w.\-]+@[\w.\-]+:[^#$\n]*[#$]\s+(\S.*)`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// buildChapters scans recorded output for shell-prompt lines and returns each
// command with the timestamp at which its line completed. Heuristic: relies on
// a user@host:cwd$ style prompt; custom or colorful prompts may yield nothing,
// in which case the caller falls back to manual time entry.
func buildChapters(events []cast.Event) []chapter {
	var chs []chapter
	var line strings.Builder
	var lineT float64

	flush := func() {
		raw := strings.TrimRight(line.String(), "\r") // drop the CR of a CRLF
		line.Reset()
		if i := strings.LastIndexByte(raw, '\r'); i >= 0 {
			raw = raw[i+1:] // prompts redraw after a CR; keep the final paint
		}
		clean := strings.TrimRight(stripANSI(raw), " \t")
		m := promptRe.FindStringSubmatch(clean)
		if m == nil {
			return
		}
		cmd := strings.TrimSpace(m[1])
		if cmd == "" {
			return
		}
		if len(cmd) > 80 {
			cmd = cmd[:79] + "…"
		}
		chs = append(chs, chapter{t: lineT, label: cmd})
	}

	for _, ev := range events {
		if ev.Type != "o" {
			continue
		}
		for i := 0; i < len(ev.Data); i++ {
			if ev.Data[i] == '\n' {
				lineT = ev.Time
				flush()
			} else {
				line.WriteByte(ev.Data[i])
			}
		}
	}
	return chs
}

// chapterAt returns the index of the latest chapter at or before t.
func chapterAt(chs []chapter, t float64) int {
	sel := 0
	for i, c := range chs {
		if c.t <= t {
			sel = i
		} else {
			break
		}
	}
	return sel
}

// chapterWindow returns the number of visible chapter rows for a terminal of
// height h (reserving a title and footer row) and the index of the first
// chapter shown so that sel stays visible. Shared by the renderer
// (drawChapterList) and the mouse hit-test in the player so both agree on which
// chapter a given screen row maps to.
func chapterWindow(sel, h int) (rows, top int) {
	rows = h - 2 // title + footer
	if rows < 1 {
		rows = 1
	}
	if sel >= rows {
		top = sel - rows + 1
	}
	return rows, top
}

// drawChapterList renders the full-screen jump menu with the selected row
// highlighted, scrolling to keep the selection visible.
func drawChapterList(chs []chapter, sel, w, h int) {
	rows, top := chapterWindow(sel, h)
	end := top + rows
	if end > len(chs) {
		end = len(chs)
	}

	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H")
	fmt.Fprintf(&b, "%s ghostshell — jump to command  (%d found)%s\r\n", clrBold, len(chs), clrReset)
	for i := top; i < end; i++ {
		label := chs[i].label
		if max := w - 14; max > 1 && len(label) > max {
			label = label[:max-1] + "…"
		}
		row := fmt.Sprintf(" %3d  %s  %s", i+1, formatClock(chs[i].t), label)
		if i == sel {
			fmt.Fprintf(&b, "\x1b[7m%-*s\x1b[0m\r\n", w-1, row)
		} else {
			fmt.Fprintf(&b, "%s\r\n", row)
		}
	}
	_, _ = io.WriteString(os.Stdout, b.String())
	fmt.Fprintf(os.Stdout, "\x1b[%d;1H\x1b[2K%s ↑/↓ or j/k select · enter jump · t type time · q back%s",
		h, clrCyan, clrReset)
}
