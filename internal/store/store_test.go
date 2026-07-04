// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package store

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"ghostshell/internal/cast"
	"ghostshell/internal/config"
	"ghostshell/internal/crypto"
)

// setupTempEnv points GHOSTSHELL_DIR, GHOSTSHELL_CENTRAL_DIR and GHOSTSHELL_KEY_FILE at
// temp paths and resets the config singleton so store picks them up.
func setupTempEnv(t *testing.T) (dir, central, keyFile string) {
	t.Helper()
	dir = t.TempDir()
	central = t.TempDir()
	keyFile = filepath.Join(t.TempDir(), "ghostshell.key")
	t.Setenv("GHOSTSHELL_DIR", dir)
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", central)
	t.Setenv("GHOSTSHELL_KEY_FILE", keyFile)
	config.Reset()
	t.Cleanup(config.Reset)
	return dir, central, keyFile
}

func TestNewNameFormat(t *testing.T) {
	name := NewName()
	re := regexp.MustCompile(`^\d{8}T\d{6}\.\d{9}-\d+\.cast$`)
	if !re.MatchString(name) {
		t.Fatalf("NewName() = %q, does not match <timestamp>-<pid>.cast", name)
	}
}

func TestParseNameTimeRoundTrip(t *testing.T) {
	now := time.Now()
	stamp := now.Format("20060102T150405.000000000")
	got, err := parseNameTime(stamp)
	if err != nil {
		t.Fatalf("parseNameTime(%q) error: %v", stamp, err)
	}
	// Round-trip the formatted stamp; compare re-formatted strings to avoid
	// sub-nanosecond / monotonic-clock differences.
	if got.Format("20060102T150405.000000000") != stamp {
		t.Fatalf("round-trip mismatch: got %q want %q",
			got.Format("20060102T150405.000000000"), stamp)
	}
}

func TestIsActiveFalseCases(t *testing.T) {
	// Malformed name: no "-pid" suffix.
	if isActive("not-a-valid-name") {
		t.Errorf("isActive on malformed name = true, want false")
	}
	if IsActive("garbage") {
		t.Errorf("IsActive on malformed name = true, want false")
	}
	// Well-formed name but an implausible / dead pid that is not a running
	// ghostshell process.
	stamp := time.Now().Format("20060102T150405.000000000")
	deadPid := 2147483646 // near max int32, not a live ghostshell process
	name := stamp + "-" + strconv.Itoa(deadPid) + ".cast"
	if isActive(name) {
		t.Errorf("isActive on dead-pid name = true, want false")
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		secs float64
		want string
	}{
		{0, "0s"},
		{-5, "0s"},
		{5, "5s"},
		{65, "1m05s"},
		{3661, "1h01m01s"},
	}
	for _, c := range cases {
		if got := humanDuration(c.secs); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.secs, got, c.want)
		}
	}
}

func TestTrunc(t *testing.T) {
	if got := trunc("short", 20); got != "short" {
		t.Errorf("trunc no-op = %q, want %q", got, "short")
	}
	if got := trunc("hello world", 5); got != "hell…" {
		t.Errorf("trunc long = %q, want %q", got, "hell…")
	}
	// n<=3 edge: byte-slice without ellipsis.
	if got := trunc("hello", 3); got != "hel" {
		t.Errorf("trunc n<=3 = %q, want %q", got, "hel")
	}
	if got := trunc("hello", 0); got != "" {
		t.Errorf("trunc n=0 = %q, want %q", got, "")
	}
}

// buildCast renders a small plaintext cast payload via the cast package.
func buildCast(t *testing.T, cmd, out string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := cast.NewWriter(&buf, cast.Header{Width: 80, Height: 24, Timestamp: 1700000000, Command: cmd})
	if err != nil {
		t.Fatalf("cast.NewWriter: %v", err)
	}
	if err := w.WriteOutput(0.1, []byte(out)); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("cast Close: %v", err)
	}
	return buf.Bytes()
}

func TestOpenCastPlaintext(t *testing.T) {
	dir, _, _ := setupTempEnv(t)
	plain := buildCast(t, "echo hi", "hi\r\n")
	p := filepath.Join(dir, "plain.cast")
	if err := os.WriteFile(p, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := OpenCast(p)
	if err != nil {
		t.Fatalf("OpenCast plaintext: %v", err)
	}
	defer rc.Close()
	got, err := readAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("OpenCast plaintext = %q, want %q", got, plain)
	}
}

func TestOpenCastEncrypted(t *testing.T) {
	dir, _, keyFile := setupTempEnv(t)
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	plain := buildCast(t, "secret-cmd", "top secret\r\n")

	p := filepath.Join(dir, "enc.cast")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := crypto.NewWriter(f, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	rc, err := OpenCast(p)
	if err != nil {
		t.Fatalf("OpenCast encrypted: %v", err)
	}
	defer rc.Close()
	got, err := readAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("OpenCast decrypted = %q, want %q", got, plain)
	}
}

func TestFindCentral(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	user := "alice"
	id := "20240101T120000.000000000-123"
	userDir := filepath.Join(central, user)
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(userDir, id+".cast")
	if err := os.WriteFile(want, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, lookup := range []string{id, id + ".cast"} {
		path, gotUser, err := FindCentral(lookup)
		if err != nil {
			t.Fatalf("FindCentral(%q) error: %v", lookup, err)
		}
		if path != want {
			t.Errorf("FindCentral(%q) path = %q, want %q", lookup, path, want)
		}
		if gotUser != user {
			t.Errorf("FindCentral(%q) user = %q, want %q", lookup, gotUser, user)
		}
	}

	if _, _, err := FindCentral("does-not-exist"); err == nil {
		t.Errorf("FindCentral(missing) error = nil, want non-nil")
	}
}

func TestSafeComponent(t *testing.T) {
	good := []string{"alice", "20240101T120000.000000000-123", "run1", "a.b"}
	for _, s := range good {
		if !safeComponent(s) {
			t.Errorf("safeComponent(%q) = false, want true", s)
		}
	}
	bad := []string{"", ".", "..", "../etc", "a/b", `a\b`, "/abs", "sub/", "..\\x"}
	for _, s := range bad {
		if safeComponent(s) {
			t.Errorf("safeComponent(%q) = true, want false", s)
		}
	}
}

func TestFindCentralRejectsTraversal(t *testing.T) {
	setupTempEnv(t)
	// A traversal / separator id must be rejected before it is ever used as a
	// path component or in an os.Stat probe.
	for _, id := range []string{"../../etc/passwd", "..", `..\..\x`, "a/b"} {
		if _, _, err := FindCentral(id); err == nil {
			t.Errorf("FindCentral(%q) error = nil, want rejection", id)
		}
	}
}

func TestUserSessionsRejectsBadUser(t *testing.T) {
	setupTempEnv(t)
	for _, u := range []string{"..", "../other", "a/b", ""} {
		if _, err := UserSessions(u); err == nil {
			t.Errorf("UserSessions(%q) error = nil, want rejection", u)
		}
	}
}

func TestUsersSkipsUnsafeNames(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	// A normal user dir is listed; a dotfile-style "." component can't be a
	// real dir name, so assert the valid one is returned and traversal-y names
	// (which os.ReadDir would never yield as a single entry anyway) are not.
	if err := os.MkdirAll(filepath.Join(central, "alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	users, err := Users()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0] != "alice" {
		t.Fatalf("Users() = %v, want [alice]", users)
	}
}

func TestIsAnsibleRunRejectsTraversal(t *testing.T) {
	setupTempEnv(t)
	if IsAnsibleRun("../../etc/passwd") {
		t.Errorf("IsAnsibleRun(traversal) = true, want false")
	}
}

func TestOpenCastRejectsInsecureKeyMode(t *testing.T) {
	dir, _, keyFile := setupTempEnv(t)
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	// Group/other readable key must be refused when decrypting.
	if err := os.WriteFile(keyFile, key, 0o644); err != nil {
		t.Fatal(err)
	}
	plain := buildCast(t, "secret-cmd", "top secret\r\n")
	p := filepath.Join(dir, "enc.cast")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := crypto.NewWriter(f, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCast(p); err == nil {
		t.Fatalf("OpenCast with 0644 key = nil error, want refusal")
	}
}

func TestOpenCastEmptyFileIsPlaintext(t *testing.T) {
	dir, _, _ := setupTempEnv(t)
	// A file shorter than the magic prefix is a short read (EOF/ErrUnexpectedEOF)
	// and must be treated as (empty) plaintext, not as an I/O error.
	p := filepath.Join(dir, "empty.cast")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := OpenCast(p)
	if err != nil {
		t.Fatalf("OpenCast empty file: %v", err)
	}
	defer rc.Close()
	got, err := readAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("OpenCast empty file = %q, want empty", got)
	}
}

func TestIsAnsibleRun(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	user := "bob"
	runid := "20240101T120000-run1"
	ansibleDir := filepath.Join(central, user, "ansible")
	if err := os.MkdirAll(ansibleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ansibleDir, runid+".ajsonl"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsAnsibleRun(runid) {
		t.Errorf("IsAnsibleRun(%q) = false, want true", runid)
	}
	if IsAnsibleRun("no-such-run") {
		t.Errorf("IsAnsibleRun(missing) = true, want false")
	}
}

func TestListUnreadableHeader(t *testing.T) {
	dir, _, _ := setupTempEnv(t)
	// A .cast file with garbage (no valid header) should not crash List and
	// should be surfaced rather than rendered with blank fields.
	bad := filepath.Join(dir, "20240101T120000.000000000-999999999.cast")
	if err := os.WriteFile(bad, []byte("not json at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := List(nil); err != nil {
			t.Fatalf("List error: %v", err)
		}
	})
	if !bytes.Contains([]byte(out), []byte("(unreadable)")) {
		t.Fatalf("List did not surface unreadable recording; output:\n%s", out)
	}
}

// TestWriteFileAtomicSuccess verifies the final file appears under its real name
// with the requested mode and exact contents, and that no temp/partial file is
// left behind in the directory.
func TestWriteFileAtomicSuccess(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("complete and durable\n")
	if err := WriteFileAtomic(dir, "session.cast", 0o600, func(w io.Writer) error {
		_, err := w.Write(payload)
		return err
	}); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("contents = %q, want %q", got, payload)
	}
	fi, err := os.Stat(filepath.Join(dir, "session.cast"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("final mode = %o, want 600", perm)
	}
	assertNoStrayFiles(t, dir, "session.cast")
}

// TestWriteFileAtomicWriteFailureLeavesNoPartial simulates the writer callback
// failing partway through (a stand-in for a crash/aborted ingest): the real
// destination must never exist, and the temp file must be cleaned up so a
// half-written recording is never visible or ingestable.
func TestWriteFileAtomicWriteFailureLeavesNoPartial(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("simulated mid-write failure")
	err := WriteFileAtomic(dir, "session.cast", 0o600, func(w io.Writer) error {
		_, _ = w.Write([]byte("partial bytes that must never be visible"))
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WriteFileAtomic error = %v, want %v", err, wantErr)
	}
	if _, serr := os.Stat(filepath.Join(dir, "session.cast")); !os.IsNotExist(serr) {
		t.Fatalf("destination must not exist after a failed write, stat err = %v", serr)
	}
	assertNoStrayFiles(t, dir, "")
}

// TestWriteFileAtomicReplacesExisting verifies an existing file is replaced
// atomically: on success the new contents win, and (the point of the temp+rename
// dance) the old file is never observed truncated.
func TestWriteFileAtomicReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "session.cast")
	if err := os.WriteFile(dst, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(dir, "session.cast", 0o600, func(w io.Writer) error {
		_, err := w.Write([]byte("NEW CONTENTS"))
		return err
	}); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "NEW CONTENTS" {
		t.Fatalf("contents = %q, want replaced", got)
	}
	assertNoStrayFiles(t, dir, "session.cast")
}

// TestWriteFileAtomicRejectsUnsafeName verifies a name that is not a bare
// basename (traversal/separator) is rejected before any file is created, so the
// primitive itself cannot be coerced into writing outside dir.
func TestWriteFileAtomicRejectsUnsafeName(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape.cast", "a/b.cast", "..", ""} {
		err := WriteFileAtomic(dir, name, 0o600, func(w io.Writer) error { return nil })
		if err == nil {
			t.Errorf("WriteFileAtomic(name=%q) = nil error, want rejection", name)
		}
	}
	assertNoStrayFiles(t, dir, "")
}

// assertNoStrayFiles fails if dir contains any entry other than keep. It catches
// leaked ".<name>.tmp-*" temp files from a failed or successful atomic write.
func assertNoStrayFiles(t *testing.T, dir, keep string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != keep {
			t.Fatalf("stray file left in dir: %q", e.Name())
		}
	}
}

// --- helpers ---

func readAll(rc interface{ Read([]byte) (int, error) }) ([]byte, error) {
	br := bufio.NewReader(rc)
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(br); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		done <- b.Bytes()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return string(<-done)
}
