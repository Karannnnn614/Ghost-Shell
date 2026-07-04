// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package play

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// evKind tags a decoded terminal-input event.
type evKind int

const (
	evByte   evKind = iota // a ground byte (printable or control) in ev.b
	evArrow                // an arrow key; ev.b is 'A','B','C', or 'D'
	evMouse                // a mouse button event at ev.mx,ev.my (1-based)
	evScroll               // scroll action; ev.up true=up false=down
)

// event is one decoded input from the terminal.
type event struct {
	kind  evKind
	b     byte // evByte: the byte; evArrow: the arrow final byte
	mx    int  // evMouse: column (1-based)
	my    int  // evMouse: row (1-based)
	press bool // evMouse: left-button press (vs release/other)
	up    bool // evScroll: true=scroll up, false=scroll down
}

type inputState int

const (
	stGround inputState = iota
	stEsc
	stCSI
	stSS3
	stOSC
	stOSCEsc
)

// inputParser turns a raw terminal byte stream into events. It recognises the
// keys the player needs (printable/control bytes, arrows, SGR mouse) and
// swallows every other escape sequence — notably the terminal's own replies to
// query sequences echoed during replay (Device Attributes, cursor reports, OSC
// color answers), which are all ESC-prefixed and must not be seen as input.
type inputParser struct {
	state  inputState
	csiBuf []byte // CSI parameter/intermediate bytes, for arrow and mouse decode
}

func (p *inputParser) feed(b byte, out chan<- event) {
	switch p.state {
	case stGround:
		if b == 0x1b {
			p.state = stEsc
			return
		}
		out <- event{kind: evByte, b: b}
	case stEsc:
		switch b {
		case '[':
			p.state = stCSI
			p.csiBuf = p.csiBuf[:0]
		case 'O': // SS3 — application-keypad arrows (ESC O A..D)
			p.state = stSS3
		case ']':
			p.state = stOSC
		default:
			p.state = stGround
		}
	case stCSI:
		if b >= 0x40 && b <= 0x7e { // final byte
			p.dispatchCSI(b, out)
			p.state = stGround
		} else {
			p.csiBuf = append(p.csiBuf, b)
		}
	case stSS3:
		if b == 'A' || b == 'B' || b == 'C' || b == 'D' {
			out <- event{kind: evArrow, b: b}
		}
		p.state = stGround
	case stOSC:
		switch b {
		case 0x07: // BEL terminates OSC
			p.state = stGround
		case 0x1b: // possible ST (ESC \)
			p.state = stOSCEsc
		}
	case stOSCEsc:
		if b == '\\' {
			p.state = stGround
		} else {
			// Back-to-back sequence: this ESC began a new one. Re-dispatch.
			p.state = stEsc
			p.feed(b, out)
		}
	}
}

func (p *inputParser) dispatchCSI(final byte, out chan<- event) {
	params := string(p.csiBuf)

	// Bare arrows (no parameters).
	if params == "" {
		switch final {
		case 'A', 'B', 'C', 'D':
			out <- event{kind: evArrow, b: final}
		}
		return
	}

	// Arrows with modifiers: Shift+Up (1;2A) / Shift+Down (1;2B) → scroll.
	if final == 'A' || final == 'B' || final == 'C' || final == 'D' {
		if params == "1;2" && (final == 'A' || final == 'B') {
			out <- event{kind: evScroll, up: final == 'A'}
			return
		}
		// Other modifier combos: pass through as bare arrow.
		out <- event{kind: evArrow, b: final}
		return
	}

	// Tilde sequences: PageUp (5~) / PageDown (6~).
	if final == '~' {
		switch params {
		case "5":
			out <- event{kind: evScroll, up: true}
		case "6":
			out <- event{kind: evScroll, up: false}
		}
		return
	}

	// SGR mouse: ESC [ < btn ; col ; row (M=press | m=release).
	if (final == 'M' || final == 'm') && len(p.csiBuf) > 0 && p.csiBuf[0] == '<' {
		parts := strings.Split(params[1:], ";")
		if len(parts) != 3 {
			return
		}
		btn, e1 := strconv.Atoi(parts[0])
		col, e2 := strconv.Atoi(parts[1])
		row, e3 := strconv.Atoi(parts[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return
		}
		// Mouse wheel: btn=64 (up) / btn=65 (down). Bit 0x40 marks wheel/extra
		// buttons; decode the two we care about and stop.
		if btn == 64 || btn == 65 {
			out <- event{kind: evScroll, up: btn == 64}
			return
		}
		// SGR button byte layout: low 2 bits select the button (0=left, 1=middle,
		// 2=right, 3=release); 0x04/0x08/0x10 are Shift/Meta/Ctrl modifiers; 0x20
		// is the motion (drag) flag; 0x40 marks wheel/extra (handled above).
		// A left press is: final 'M' (down, not 'm' release), low 2 bits == 0
		// (left button), and the motion bit clear (a real click, not a drag).
		// Modifier bits are ignored so Shift/Ctrl/Alt+click still register.
		leftPress := final == 'M' && (btn&0x03) == 0 && (btn&0x20) == 0
		out <- event{kind: evMouse, mx: col, my: row, press: leftPress}
	}
}

// readInput reads stdin and emits decoded events until stdin closes or done is
// signalled. Parser state persists across reads so an escape sequence split
// across reads still decodes correctly.
//
// The read is interruptible: stdin is put in non-blocking mode and polled with
// a short timeout so that on quit/SIGTERM the caller can close done and this
// goroutine returns instead of staying blocked in a read forever (which would
// leak the goroutine and could steal a byte destined for the shell). On exit it
// restores stdin to blocking mode and closes out.
func readInput(out chan<- event, done <-chan struct{}) {
	defer close(out)

	fd := int(os.Stdin.Fd())
	// Non-blocking + poll lets us wake up periodically to observe done. If we
	// can't switch modes (e.g. stdin isn't a normal fd), fall back to a plain
	// blocking read; the goroutine may then outlive a quit, but that path only
	// occurs when stdin isn't an interruptible tty.
	if err := unix.SetNonblock(fd, true); err != nil {
		readInputBlocking(out, done)
		return
	}
	defer func() { _ = unix.SetNonblock(fd, false) }()

	var p inputParser
	buf := make([]byte, 64)
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		select {
		case <-done:
			return
		default:
		}
		// Poll with a 100ms timeout so done is checked even when idle.
		if _, err := unix.Poll(pfd, 100); err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		// POLLHUP/POLLERR mean the far end is gone; fall through to read so we
		// observe EOF/error and return instead of spinning.
		if pfd[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			continue // timeout; re-check done
		}
		n, err := unix.Read(fd, buf)
		for i := 0; i < n; i++ {
			p.feed(buf[i], out)
		}
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return
		}
		if n == 0 { // EOF
			return
		}
	}
}

// readInputBlocking is the fallback used when stdin can't be put in
// non-blocking mode. It is not interruptible by done.
func readInputBlocking(out chan<- event, done <-chan struct{}) {
	var p inputParser
	buf := make([]byte, 64)
	for {
		n, err := os.Stdin.Read(buf)
		for i := 0; i < n; i++ {
			p.feed(buf[i], out)
		}
		if err != nil {
			return
		}
		select {
		case <-done:
			return
		default:
		}
	}
}
