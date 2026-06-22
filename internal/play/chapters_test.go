package play

import (
	"testing"

	"ghostshell/internal/cast"
)

func TestBuildChapters(t *testing.T) {
	events := []cast.Event{
		{Time: 0.0, Type: "o", Data: "root@host:~# apt update\r\n"},
		{Time: 0.5, Type: "o", Data: "Hit:1 http://archive...\r\n"},
		{Time: 5.0, Type: "o", Data: "root@host:~# \x1b[32mvim\x1b[0m /etc/hosts\r\n"}, // colored
		{Time: 9.0, Type: "o", Data: "some plain output line\r\n"},
		{Time: 12.0, Type: "o", Data: "root@host:/tmp# ls -la\r\n"},
	}
	chs := buildChapters(events)
	if len(chs) != 3 {
		t.Fatalf("got %d chapters, want 3: %+v", len(chs), chs)
	}
	want := []struct {
		t     float64
		label string
	}{
		{0.0, "apt update"},
		{5.0, "vim /etc/hosts"},
		{12.0, "ls -la"},
	}
	for i, w := range want {
		if chs[i].t != w.t || chs[i].label != w.label {
			t.Errorf("chapter[%d] = {%v %q}, want {%v %q}", i, chs[i].t, chs[i].label, w.t, w.label)
		}
	}
}

func TestBuildChaptersNoPrompt(t *testing.T) {
	// A non-interactive recording (no prompts) yields no chapters.
	events := []cast.Event{
		{Time: 0, Type: "o", Data: "starting deploy\r\n"},
		{Time: 1, Type: "o", Data: "done\r\n"},
	}
	if chs := buildChapters(events); len(chs) != 0 {
		t.Errorf("got %d chapters, want 0: %+v", len(chs), chs)
	}
}

func TestChapterAt(t *testing.T) {
	chs := []chapter{{t: 0}, {t: 5}, {t: 12}}
	cases := map[float64]int{0: 0, 3: 0, 5: 1, 11: 1, 12: 2, 99: 2}
	for at, want := range cases {
		if got := chapterAt(chs, at); got != want {
			t.Errorf("chapterAt(%v) = %d, want %d", at, got, want)
		}
	}
}

func TestSaveDelta(t *testing.T) {
	cases := []struct {
		in    string
		delta int
		reset bool
	}{
		{"", 0, false},
		{"\x1b7", 1, false},
		{"\x1b8", -1, false},
		{"\x1b7abc\x1b8", 0, false},
		{"\x1b7\x1b[38;0f", 1, false}, // open save, no restore (split across events)
		{"plain text", 0, false},
		{"\x1bc", 0, true}, // RIS resets
	}
	for _, c := range cases {
		d, r := saveDelta(c.in)
		if d != c.delta || r != c.reset {
			t.Errorf("saveDelta(%q) = %d,%v want %d,%v", c.in, d, r, c.delta, c.reset)
		}
	}
}
