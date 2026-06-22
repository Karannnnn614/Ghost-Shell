package play

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlayFileEmptyCastClearError verifies that replaying a 0-byte cast returns
// a clear, path-bearing message instead of a bare "EOF", and does not panic.
func TestPlayFileEmptyCastClearError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.cast")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty cast: %v", err)
	}
	err := PlayFile(path, 1.0, 0)
	if err == nil {
		t.Fatal("PlayFile(empty) returned nil; want a clear error")
	}
	if !strings.Contains(err.Error(), "empty or invalid cast") {
		t.Errorf("PlayFile(empty) error = %q, want it to mention 'empty or invalid cast'", err)
	}
}

// TestPlayFileHeaderOnlyCast verifies that a header-only cast (valid header, no
// events) replays without error and without panicking. With no stdout tty in
// tests it takes the linear path and simply produces no output.
func TestPlayFileHeaderOnlyCast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "header.cast")
	body := "{\"version\":2,\"width\":80,\"height\":24}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write header-only cast: %v", err)
	}
	if err := PlayFile(path, 1.0, 0); err != nil {
		t.Errorf("PlayFile(header-only) = %v, want nil", err)
	}
}

// TestReadCastEventsSkipsMalformedLine verifies that a malformed event line in
// the middle of an otherwise-valid body is skipped (not fatal): the surrounding
// good events are returned and replay can proceed.
func TestReadCastEventsSkipsMalformedLine(t *testing.T) {
	body := `[0.100000, "o", "first"]
[GARBAGE not json
[0.300000, "o", "third"]
`
	r := bufio.NewReader(strings.NewReader(body))
	events, err := readCastEvents(r)
	if err != nil {
		t.Fatalf("readCastEvents: %v (a single bad line must not abort)", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (bad line skipped): %+v", len(events), events)
	}
	if events[0].Data != "first" || events[1].Data != "third" {
		t.Errorf("events = %q,%q; want first,third", events[0].Data, events[1].Data)
	}
}

// TestReadCastEventsCorruptBodyErrors verifies that a body consisting almost
// entirely of malformed lines exceeds the skip budget and surfaces an error
// rather than silently replaying as an empty/near-empty session.
func TestReadCastEventsCorruptBodyErrors(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxSkippableEvents+5; i++ {
		b.WriteString("[not valid json line\n")
	}
	r := bufio.NewReader(strings.NewReader(b.String()))
	if _, err := readCastEvents(r); err == nil {
		t.Fatal("readCastEvents on wholly-corrupt body returned nil; want an error")
	}
}

// TestReadCastEventsAllValid is a regression guard that the skip path does not
// disturb the normal all-good case.
func TestReadCastEventsAllValid(t *testing.T) {
	body := `[0.000000, "o", "a"]
[1.000000, "o", "b"]
[2.000000, "i", "c"]
`
	r := bufio.NewReader(strings.NewReader(body))
	events, err := readCastEvents(r)
	if err != nil {
		t.Fatalf("readCastEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
}
