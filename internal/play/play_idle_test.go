// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package play

import (
	"math"
	"testing"
	"time"

	"ghostshell/internal/cast"
)

func TestClampIdleGaps(t *testing.T) {
	events := []cast.Event{
		{Time: 0.5, Type: "o", Data: "a"},
		{Time: 5.5, Type: "o", Data: "b"},  // 5.0s gap → should clamp to 2.0
		{Time: 5.6, Type: "o", Data: "c"},  // 0.1s gap → unchanged
		{Time: 10.6, Type: "o", Data: "d"}, // 5.0s gap → should clamp to 2.0
	}
	got := clampIdleGaps(events, 2.0)

	want := []float64{0.5, 2.5, 2.6, 4.6}
	for i, ev := range got {
		if math.Abs(ev.Time-want[i]) > 1e-9 {
			t.Errorf("event[%d]: got %.2f want %.2f", i, ev.Time, want[i])
		}
	}
	// originals must be untouched (clamp returns a copy)
	if events[1].Time != 5.5 {
		t.Error("clampIdleGaps mutated input slice")
	}
}

func TestClampIdleGapsNoop(t *testing.T) {
	events := []cast.Event{{Time: 1.0}, {Time: 2.0}}
	got := clampIdleGaps(events, 0) // maxIdle==0 → no-op
	if len(got) != 2 || got[0].Time != 1.0 || got[1].Time != 2.0 {
		t.Error("expected no-op when maxIdle==0")
	}
}

func TestSanitizeEvents(t *testing.T) {
	inf := math.Inf(1)
	ninf := math.Inf(-1)
	nan := math.NaN()
	events := []cast.Event{
		{Time: -3, Type: "o", Data: "a"},   // negative → 0
		{Time: 1, Type: "o", Data: "b"},    // ok
		{Time: 0.5, Type: "o", Data: "c"},  // decreasing → pinned to 1
		{Time: nan, Type: "o", Data: "d"},  // NaN → previous (1)
		{Time: inf, Type: "o", Data: "e"},  // +Inf → previous + maxWaitSeconds
		{Time: 2, Type: "o", Data: "f"},    // < previous (huge) → pinned to previous
		{Time: ninf, Type: "o", Data: "g"}, // -Inf → 0, then pinned to previous
	}
	got := sanitizeEvents(events)
	// Every timestamp must be finite, non-negative, and non-decreasing.
	var prev float64
	for i, ev := range got {
		if math.IsNaN(ev.Time) || math.IsInf(ev.Time, 0) {
			t.Errorf("event[%d] still non-finite: %v", i, ev.Time)
		}
		if ev.Time < 0 {
			t.Errorf("event[%d] negative: %v", i, ev.Time)
		}
		if ev.Time < prev {
			t.Errorf("event[%d] decreased: %v < %v", i, ev.Time, prev)
		}
		prev = ev.Time
	}
	if got[0].Time != 0 {
		t.Errorf("negative not clamped to 0: %v", got[0].Time)
	}
	if got[1].Time != 1 {
		t.Errorf("valid time mutated: %v", got[1].Time)
	}
	if got[2].Time != 1 {
		t.Errorf("decreasing not pinned: %v", got[2].Time)
	}
	if got[3].Time != 1 {
		t.Errorf("NaN not pinned to previous: %v", got[3].Time)
	}
	if got[4].Time != 1+maxWaitSeconds {
		t.Errorf("+Inf not converted to capped gap: %v", got[4].Time)
	}
}

func TestClampWait(t *testing.T) {
	cases := []struct {
		in   float64
		want time.Duration
	}{
		{-1, 0},
		{0, 0},
		{math.NaN(), 0},
		{math.Inf(1), maxWaitSeconds * time.Second},
		{maxWaitSeconds + 100, maxWaitSeconds * time.Second},
		{1.5, 1500 * time.Millisecond},
	}
	for _, c := range cases {
		if got := clampWait(c.in); got != c.want {
			t.Errorf("clampWait(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestClampSeek(t *testing.T) {
	const lastT = 100.0
	cases := []struct {
		in, want float64
	}{
		{-5, 0},
		{0, 0},
		{50, 50},
		{100, 100},
		{150, 100}, // beyond end clamps to lastT
		{math.NaN(), 0},
	}
	for _, c := range cases {
		if got := clampSeek(c.in, lastT); got != c.want {
			t.Errorf("clampSeek(%v, %v) = %v, want %v", c.in, lastT, got, c.want)
		}
	}
}
