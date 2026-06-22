package play

import "testing"

// collect feeds bytes through the parser and returns the emitted events.
func collect(b []byte) []event {
	out := make(chan event, 64)
	var p inputParser
	for _, c := range b {
		p.feed(c, out)
	}
	close(out)
	var evs []event
	for e := range out {
		evs = append(evs, e)
	}
	return evs
}

func TestParserPlainBytes(t *testing.T) {
	evs := collect([]byte("q g"))
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3", len(evs))
	}
	if evs[0].kind != evByte || evs[0].b != 'q' {
		t.Errorf("evs[0] = %+v, want byte 'q'", evs[0])
	}
	if evs[2].b != 'g' {
		t.Errorf("evs[2].b = %q, want 'g'", evs[2].b)
	}
}

func TestParserArrows(t *testing.T) {
	cases := map[string]byte{
		"\x1b[A": 'A', "\x1b[B": 'B', "\x1b[C": 'C', "\x1b[D": 'D',
		"\x1bOA": 'A', "\x1bOD": 'D', // SS3 application-keypad arrows
	}
	for seq, want := range cases {
		evs := collect([]byte(seq))
		if len(evs) != 1 || evs[0].kind != evArrow || evs[0].b != want {
			t.Errorf("%q -> %+v, want arrow %q", seq, evs, want)
		}
	}
}

// A Device Attributes reply and a cursor-position report must produce no
// events — they are the terminal answering replayed queries, not user input.
func TestParserSwallowsQueryReplies(t *testing.T) {
	for _, seq := range []string{
		"\x1b[?62;c",                       // DA1 reply
		"\x1b[>0;276;0c",                   // DA2 reply
		"\x1b[24;80R",                      // cursor position report
		"\x1b]11;rgb:1e1e/1e1e/1e1e\x07",   // OSC color reply (BEL)
		"\x1b]10;rgb:ffff/ffff/ffff\x1b\\", // OSC color reply (ST)
	} {
		if evs := collect([]byte(seq)); len(evs) != 0 {
			t.Errorf("%q produced %d events, want 0: %+v", seq, len(evs), evs)
		}
	}
}

// After an OSC reply terminated by ST, a following real key must still decode.
func TestParserOSCThenKey(t *testing.T) {
	evs := collect([]byte("\x1b]11;rgb:0/0/0\x1b\\q"))
	if len(evs) != 1 || evs[0].b != 'q' {
		t.Fatalf("got %+v, want single byte 'q'", evs)
	}
}

func TestParserMouseLeftPress(t *testing.T) {
	// SGR mouse left-button press at column 40, row 24.
	evs := collect([]byte("\x1b[<0;40;24M"))
	if len(evs) != 1 || evs[0].kind != evMouse {
		t.Fatalf("got %+v, want one mouse event", evs)
	}
	m := evs[0]
	if !m.press || m.mx != 40 || m.my != 24 {
		t.Errorf("mouse = %+v, want press at 40,24", m)
	}
	// Release ('m') is not a left press.
	rel := collect([]byte("\x1b[<0;40;24m"))
	if len(rel) != 1 || rel[0].press {
		t.Errorf("release = %+v, want press=false", rel)
	}
	// Wheel (bit 64) is not a left press.
	wheel := collect([]byte("\x1b[<64;40;24M"))
	if len(wheel) != 1 || wheel[0].press {
		t.Errorf("wheel = %+v, want press=false", wheel)
	}
}

func TestParserMouseModifiedClick(t *testing.T) {
	// A modified left click (Shift=4 / Meta=8 / Ctrl=16 added to button 0) must
	// still register as a left press — modifier bits are ignored.
	for _, btn := range []int{4, 8, 16, 4 + 16} {
		seq := []byte("\x1b[<" + itoa(btn) + ";10;5M")
		evs := collect(seq)
		if len(evs) != 1 || evs[0].kind != evMouse || !evs[0].press {
			t.Errorf("modified click btn=%d -> %+v, want left press", btn, evs)
		}
	}
	// A drag (motion bit 0x20 set, e.g. btn 32) is NOT a click.
	drag := collect([]byte("\x1b[<32;10;5M"))
	if len(drag) != 1 || drag[0].press {
		t.Errorf("drag = %+v, want press=false", drag)
	}
	// Middle (1) and right (2) buttons are not left presses.
	for _, btn := range []int{1, 2} {
		evs := collect([]byte("\x1b[<" + itoa(btn) + ";10;5M"))
		if len(evs) != 1 || evs[0].press {
			t.Errorf("button %d -> %+v, want press=false", btn, evs)
		}
	}
}

// itoa is a tiny helper so the test doesn't pull in strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestParserSplitEscape(t *testing.T) {
	// Feed an arrow one byte at a time across "reads": state must persist.
	out := make(chan event, 4)
	var p inputParser
	for _, c := range []byte("\x1b[C") {
		p.feed(c, out)
	}
	close(out)
	var evs []event
	for e := range out {
		evs = append(evs, e)
	}
	if len(evs) != 1 || evs[0].kind != evArrow || evs[0].b != 'C' {
		t.Fatalf("split arrow -> %+v, want one right arrow", evs)
	}
}
