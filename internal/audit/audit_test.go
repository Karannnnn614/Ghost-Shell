// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"ghostshell/internal/config"
)

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// setupCentral points the central store at a fresh temp dir and returns it.
// It also simulates running as root (euid 0) so the requireRoot gate that
// guards every central-store command lets the test through; the test binary
// itself runs unprivileged. asRoot(t) restores the real euid source on cleanup.
func setupCentral(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", dir)
	t.Setenv("GHOSTSHELL_DIR", t.TempDir())
	config.Reset()
	t.Cleanup(config.Reset)
	asRoot(t)
	return dir
}

// asRoot makes requireRoot believe the process is root for the duration of the
// test, restoring the real os.Geteuid source afterwards.
func asRoot(t *testing.T) {
	t.Helper()
	prev := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = prev })
}

// asUser makes requireRoot believe the process is an unprivileged user (uid
// 1000), restoring the real source afterwards. Used to exercise the rejection
// path of the root-enforcement gate.
func asUser(t *testing.T) {
	t.Helper()
	prev := geteuid
	geteuid = func() int { return 1000 }
	t.Cleanup(func() { geteuid = prev })
}

// writeCast writes a plaintext cast file for user/id with the given header
// command and output event data. No key needed (plaintext, not TTEC1).
func writeCast(t *testing.T, central, user, id, command string, outputs ...string) {
	t.Helper()
	udir := filepath.Join(central, user)
	if err := os.MkdirAll(udir, 0o700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(`{"version":2,"width":80,"height":24,"timestamp":1700000000,"command":`)
	b.WriteString(jsonStr(command))
	b.WriteString("}\n")
	for i, o := range outputs {
		b.WriteString("[")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`, "o", `)
		b.WriteString(jsonStr(o))
		b.WriteString("]\n")
	}
	if err := os.WriteFile(filepath.Join(udir, id+".cast"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, e := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if e != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestLastNLines(t *testing.T) {
	tests := []struct {
		name   string
		n      int
		events []string
		want   string
	}{
		{
			name:   "fewer than N lines",
			n:      20,
			events: []string{"line1\nline2\nline3\n"},
			want:   "line1\nline2\nline3\n",
		},
		{
			name:   "exactly trims to last N lines",
			n:      2,
			events: []string{"a\nb\nc\nd\n"},
			want:   "c\nd\n",
		},
		{
			name:   "line split across two events",
			n:      2,
			events: []string{"a\nb\npart", "ial\nc\n"},
			want:   "partial\nc\n",
		},
		{
			name:   "no trailing newline keeps partial",
			n:      2,
			events: []string{"a\nb\nc"},
			want:   "b\nc",
		},
		{
			name:   "single event single line",
			n:      5,
			events: []string{"hello world"},
			want:   "hello world",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newLineRing(tc.n)
			for _, e := range tc.events {
				r.add(e)
			}
			if got := r.String(); got != tc.want {
				t.Errorf("lastNLines = %q, want %q", got, tc.want)
			}
		})
	}
}

// Issue #10: a corrupt header must surface as an "(unreadable)" marker rather
// than rendering a blank row.
func TestLsUserUnreadableMarker(t *testing.T) {
	central := setupCentral(t)
	udir := filepath.Join(central, "alice")
	if err := os.MkdirAll(udir, 0o700); err != nil {
		t.Fatal(err)
	}
	// First line is not valid JSON -> header read fails.
	if err := os.WriteFile(filepath.Join(udir, "bad.cast"), []byte("not json at all\n[0, \"o\", \"hi\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := LsUser([]string{"alice"}); err != nil {
			t.Fatalf("LsUser: %v", err)
		}
	})
	if !strings.Contains(out, "(unreadable)") {
		t.Errorf("expected (unreadable) marker in ls-user output, got:\n%s", out)
	}
}

func TestTreeUnreadableMarker(t *testing.T) {
	central := setupCentral(t)
	udir := filepath.Join(central, "alice")
	if err := os.MkdirAll(udir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(udir, "bad.cast"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := Tree(nil); err != nil {
			t.Fatalf("Tree: %v", err)
		}
	})
	if !strings.Contains(out, "(unreadable)") {
		t.Errorf("expected (unreadable) marker in tree output, got:\n%s", out)
	}
}

func TestSearchUnreadableMarker(t *testing.T) {
	central := setupCentral(t)
	writeCast(t, central, "alice", "good", "echo hi", "nginx config ok\n")
	udir := filepath.Join(central, "alice")
	if err := os.WriteFile(filepath.Join(udir, "bad.cast"), []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := Search([]string{"--all"}); err != nil {
			t.Fatalf("Search: %v", err)
		}
	})
	if !strings.Contains(out, "(unreadable)") {
		t.Errorf("expected (unreadable) marker in search --all output, got:\n%s", out)
	}
}

// Issue #8: search must find matches and produce deterministic, user-grouped
// output that is identical across repeated runs.
func TestSearchFindsAndIsDeterministic(t *testing.T) {
	central := setupCentral(t)
	// Multiple users and sessions so the worker pool has work to reorder.
	// alice has two matching sessions to exercise intra-user ordering.
	writeCast(t, central, "alice", "a1", "echo one", "hello nginx world\n")
	writeCast(t, central, "alice", "a2", "echo two", "another nginx line\n")
	writeCast(t, central, "bob", "b1", "run nginx", "starting up\n")
	writeCast(t, central, "carol", "c1", "echo three", "nginx restart done\n")

	run := func() string {
		return captureStdout(t, func() {
			if err := Search([]string{"nginx"}); err != nil {
				t.Fatalf("Search: %v", err)
			}
		})
	}
	first := run()
	if !strings.Contains(first, "user=alice") || !strings.Contains(first, "user=bob") || !strings.Contains(first, "user=carol") {
		t.Errorf("expected matches for alice, bob, carol; got:\n%s", first)
	}
	// alice must appear before bob before carol (sorted user order preserved).
	ia := strings.Index(first, "user=alice")
	ib := strings.Index(first, "user=bob")
	ic := strings.Index(first, "user=carol")
	if !(ia < ib && ib < ic) {
		t.Errorf("user ordering not preserved: alice=%d bob=%d carol=%d\n%s", ia, ib, ic, first)
	}
	// Intra-user store order: session a1 must precede a2.
	if i1, i2 := strings.Index(first, "session=a1"), strings.Index(first, "session=a2"); i1 < 0 || i2 < 0 || i1 > i2 {
		t.Errorf("intra-user ordering not preserved: a1=%d a2=%d\n%s", i1, i2, first)
	}
	// Determinism: identical output across repeated runs.
	for i := 0; i < 5; i++ {
		if got := run(); got != first {
			t.Errorf("search output not deterministic on run %d:\nfirst:\n%s\ngot:\n%s", i, first, got)
		}
	}
}

// parseTime must reject any value starting with "-" before shelling out to
// date(1): GNU date would otherwise treat it as an option (e.g. "-f FILE"),
// allowing argument injection from a --from/--to/range value.
func TestParseTimeRejectsLeadingDash(t *testing.T) {
	for _, s := range []string{"-f", "-f /etc/passwd", "-d", "--date=now", "-"} {
		if _, err := parseTime(s); err == nil {
			t.Errorf("parseTime(%q) = nil error, want rejection of leading-'-' value", s)
		}
	}
	// A normal absolute date must still parse via the built-in layouts (no
	// dependence on date(1), so this is portable across CI runners).
	if _, err := parseTime("2026-05-01 12:00"); err != nil {
		t.Errorf("parseTime(valid) unexpectedly failed: %v", err)
	}
}

// pruneFilter: "all" matches everything; "days N" requires N>0 and only matches
// known timestamps older than the cutoff; "days 0" and negative are rejected;
// "range" excludes unknown timestamps.
func TestPruneFilter(t *testing.T) {
	now := time.Now()
	old := now.AddDate(0, 0, -10).Unix()
	recent := now.AddDate(0, 0, -1).Unix()

	t.Run("all matches everything including unknown ts", func(t *testing.T) {
		f, err := pruneFilter("all")
		if err != nil {
			t.Fatal(err)
		}
		for _, ts := range []int64{0, recent, old} {
			if !f(ts) {
				t.Errorf("all: f(%d) = false, want true", ts)
			}
		}
	})

	t.Run("days 0 rejected", func(t *testing.T) {
		if _, err := pruneFilter("days 0"); err == nil {
			t.Error(`pruneFilter("days 0") = nil error, want rejection`)
		}
	})

	t.Run("days negative rejected", func(t *testing.T) {
		if _, err := pruneFilter("days -3"); err == nil {
			t.Error(`pruneFilter("days -3") = nil error, want rejection`)
		}
	})

	t.Run("days N matches old, excludes recent and unknown", func(t *testing.T) {
		f, err := pruneFilter("days 5")
		if err != nil {
			t.Fatal(err)
		}
		if !f(old) {
			t.Errorf("days 5: old session should match")
		}
		if f(recent) {
			t.Errorf("days 5: recent session should not match")
		}
		if f(0) {
			t.Errorf("days 5: unknown timestamp must never match a time selection")
		}
	})

	t.Run("range excludes unknown timestamp", func(t *testing.T) {
		f, err := pruneFilter("range 2000-01-01 2100-01-01")
		if err != nil {
			t.Fatal(err)
		}
		if f(0) {
			t.Errorf("range: unknown timestamp must never match")
		}
		if !f(recent) {
			t.Errorf("range: in-window timestamp should match")
		}
	})

	t.Run("range bad times rejected", func(t *testing.T) {
		if _, err := pruneFilter("range -f 2100-01-01"); err == nil {
			t.Error("range with leading-'-' FROM should be rejected")
		}
	})

	t.Run("unrecognized selection rejected", func(t *testing.T) {
		if _, err := pruneFilter("bogus"); err == nil {
			t.Error("unrecognized selection should be rejected")
		}
	})
}

// confirm must accept only the exact word "yes" for an irreversible bulk delete;
// "y", "YES", and anything else (including the empty default) must abort.
func TestConfirmAcceptsOnlyYes(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"yes\n", true},
		{"y\n", false},
		{"YES\n", false},
		{"\n", false}, // empty -> default "no"
		{"no\n", false},
		{"yes please\n", false},
	}
	for _, tt := range tests {
		r := bufio.NewReader(strings.NewReader(tt.in))
		if got := confirm(r, 3); got != tt.want {
			t.Errorf("confirm(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// Export must refuse to clobber an existing output file unless --force is given,
// and any file it creates must be mode 0600 (decrypted plaintext can hold
// secrets). Mode bits are only meaningful on POSIX.
func TestExportRefusesClobberAndCreates0600(t *testing.T) {
	central := setupCentral(t)
	writeCast(t, central, "alice", "s1", "echo hi", "hello\n")

	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "out.cast")

	// Fresh export creates the file.
	if err := Export([]string{"-o", outFile, "s1"}); err != nil {
		t.Fatalf("first Export: %v", err)
	}
	fi, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat exported file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("exported file mode = %#o, want 0600", perm)
		}
	}

	// Second export to the same path must fail (no --force).
	if err := Export([]string{"-o", outFile, "s1"}); err == nil {
		t.Errorf("Export over existing file = nil error, want clobber refusal")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("clobber error = %v, want 'already exists'", err)
	}

	// With --force it overwrites and still creates 0600.
	if err := Export([]string{"-o", outFile, "--force", "s1"}); err != nil {
		t.Fatalf("Export --force: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err = os.Stat(outFile)
		if err != nil {
			t.Fatalf("stat after --force: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("force-exported file mode = %#o, want 0600", perm)
		}
	}
}

// Root enforcement (defense-in-depth): every command that reads the central
// store must reject a non-root caller with a clear permission error BEFORE
// touching the store, even when GHOSTSHELL_CENTRAL_DIR happens to be readable (as a
// temp dir is in tests). A non-root user must not be able to enumerate or
// decrypt another user's session by guessing its id.
func TestRequireRootRejectsNonRoot(t *testing.T) {
	central := setupCentral(t) // sets euid 0 via asRoot
	// Plant a recording so a missing-file error can't masquerade as the gate.
	writeCast(t, central, "alice", "secret", "echo hi", "topsecret\n")

	// Now drop to an unprivileged uid for the rest of the test.
	asUser(t)

	checks := []struct {
		name string
		call func() error
	}{
		{"ls --all", func() error { return LsUser(nil) }},
		{"ls --user", func() error { return LsUser([]string{"alice"}) }},
		{"play-user", func() error { return PlayUser([]string{"secret"}) }},
		{"export", func() error { return Export([]string{"secret"}) }},
		{"export -o guessed id", func() error { return Export([]string{"-o", filepath.Join(t.TempDir(), "x"), "secret"}) }},
		{"tail static", func() error { return TailStatic([]string{"secret"}) }},
		{"tail -f", func() error { return TailLive([]string{"secret"}) }},
		{"tree", func() error { return Tree(nil) }},
		{"search", func() error { return Search([]string{"topsecret"}) }},
		{"search --all", func() error { return Search([]string{"--all"}) }},
		{"prune", func() error { return Prune([]string{"--yes"}) }},
		{"status", func() error { return Status(nil) }},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			if err == nil {
				t.Fatalf("%s as non-root = nil error, want permission denial", c.name)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("%s error = %q, want a 'permission denied' message", c.name, err.Error())
			}
			// The secret content must never leak into the error string.
			if strings.Contains(err.Error(), "topsecret") {
				t.Errorf("%s error leaked recorded content: %q", c.name, err.Error())
			}
		})
	}
}

// As root, the same commands must succeed (the gate lets root through). This
// guards against the gate being too aggressive and blocking the legitimate
// operator path.
func TestRequireRootAllowsRoot(t *testing.T) {
	central := setupCentral(t) // euid 0
	writeCast(t, central, "alice", "s1", "echo hi", "hello world\n")

	if err := LsUser(nil); err != nil {
		t.Errorf("LsUser as root: %v", err)
	}
	if err := Tree(nil); err != nil {
		t.Errorf("Tree as root: %v", err)
	}
	out := captureStdout(t, func() {
		if err := Search([]string{"hello"}); err != nil {
			t.Errorf("Search as root: %v", err)
		}
	})
	if !strings.Contains(out, "session=s1") {
		t.Errorf("Search as root should find s1; got:\n%s", out)
	}
}

// Status as root must report the live snapshot: it counts every session, flags
// the active ones, and sums the on-disk file sizes of the central store.
func TestStatusReportsCountsAndSize(t *testing.T) {
	central := setupCentral(t) // euid 0
	writeCast(t, central, "alice", "a1", "echo one", "x\n")
	writeCast(t, central, "alice", "a2", "echo two", "yy\n")
	writeCast(t, central, "bob", "b1", "echo three", "zzz\n")

	// Independently compute the expected on-disk size.
	var want int64
	for _, p := range []string{
		filepath.Join(central, "alice", "a1.cast"),
		filepath.Join(central, "alice", "a2.cast"),
		filepath.Join(central, "bob", "b1.cast"),
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want += fi.Size()
	}

	out := captureStdout(t, func() {
		if err := Status(nil); err != nil {
			t.Fatalf("Status: %v", err)
		}
	})
	// hasField matches a "<key> ... = <val>" line tolerant of column padding.
	hasField := func(key, val string) bool {
		for _, line := range strings.Split(out, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, key) && strings.HasSuffix(l, "= "+val) {
				return true
			}
		}
		return false
	}
	if !hasField("sessions_total", "3") {
		t.Errorf("status should report 3 sessions; got:\n%s", out)
	}
	if !hasField("users", "2") {
		t.Errorf("status should report 2 users; got:\n%s", out)
	}
	// None of the planted sessions are active (their pids/timestamps are fake).
	if !hasField("sessions_active", "0") {
		t.Errorf("status should report 0 active; got:\n%s", out)
	}
	if !hasField("store_size", humanSize(want)) {
		t.Errorf("status store_size should match on-disk total %s; got:\n%s", humanSize(want), out)
	}
}

// Prune size accounting must reflect the ON-DISK encrypted file size (os.Stat),
// not the raw/decrypted byte count, so the "freed" figure matches what the disk
// reclaims. collectPruneTargets sums os.Stat sizes; assert each target's size
// equals its file's stat size and the total matches their sum.
func TestPruneTargetsUseOnDiskSize(t *testing.T) {
	central := setupCentral(t) // euid 0
	writeCast(t, central, "alice", "p1", "echo a", "some output here\n")
	writeCast(t, central, "alice", "p2", "echo b", "more and longer output line\n")

	matchAll := func(int64) bool { return true }
	hits, total := collectPruneTargets([]string{"alice"}, matchAll)
	if len(hits) != 2 {
		t.Fatalf("collectPruneTargets returned %d hits, want 2", len(hits))
	}
	var sum int64
	for _, h := range hits {
		fi, err := os.Stat(h.path)
		if err != nil {
			t.Fatalf("stat %s: %v", h.path, err)
		}
		if h.size != fi.Size() {
			t.Errorf("target %s size = %d, want on-disk %d", h.name, h.size, fi.Size())
		}
		sum += fi.Size()
	}
	if total != sum {
		t.Errorf("collectPruneTargets total = %d, want sum of on-disk sizes %d", total, sum)
	}
}

// inWindow unifies the zero-timestamp policy with prune: an unknown timestamp is
// included only when there is no window at all, and excluded the moment any
// bound is set.
func TestInWindowZeroTimestampPolicy(t *testing.T) {
	from := time.Date(2026, 5, 1, 0, 0, 0, 0, time.Local)
	to := time.Date(2026, 5, 31, 0, 0, 0, 0, time.Local)

	if !inWindow(0, time.Time{}, time.Time{}) {
		t.Error("unknown ts with no bounds should be included")
	}
	if inWindow(0, from, time.Time{}) {
		t.Error("unknown ts with a --from bound should be excluded")
	}
	if inWindow(0, time.Time{}, to) {
		t.Error("unknown ts with a --to bound should be excluded")
	}
	inRange := time.Date(2026, 5, 15, 0, 0, 0, 0, time.Local).Unix()
	if !inWindow(inRange, from, to) {
		t.Error("known ts inside window should be included")
	}
	before := time.Date(2026, 4, 1, 0, 0, 0, 0, time.Local).Unix()
	if inWindow(before, from, to) {
		t.Error("known ts before window should be excluded")
	}
}
