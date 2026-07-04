// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// redirectPasswdFile points PasswdFile at a temp location for the duration of
// the test and ensures the parent directory exists. The original value is
// restored on cleanup.
func redirectPasswdFile(t *testing.T) {
	t.Helper()
	orig := PasswdFile
	t.Cleanup(func() { PasswdFile = orig })
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir temp dir: %v", err)
	}
	PasswdFile = filepath.Join(dir, ".playback_passwd")
}

func TestSetPasswordAndIsSet(t *testing.T) {
	redirectPasswdFile(t)

	if IsSet() {
		t.Fatal("IsSet() = true before any password set, want false")
	}
	if err := SetPassword("hunter2pass"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !IsSet() {
		t.Fatal("IsSet() = false after SetPassword, want true")
	}
}

func TestVerify(t *testing.T) {
	redirectPasswdFile(t)

	if err := SetPassword("correct-horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := Verify("correct-horse"); err != nil {
		t.Errorf("Verify(correct) = %v, want nil", err)
	}
	if err := Verify("wrong-horse"); !errors.Is(err, ErrIncorrectPassword) {
		t.Errorf("Verify(wrong) = %v, want ErrIncorrectPassword", err)
	}
}

func TestSetPasswordTightensExistingFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits are not enforced on Windows")
	}
	redirectPasswdFile(t)

	// Pre-create the hash file with loose, world-readable permissions.
	if err := os.WriteFile(PasswdFile, []byte("stale"), 0644); err != nil {
		t.Fatalf("pre-create passwd: %v", err)
	}
	if err := SetPassword("tighten-me"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	info, err := os.Stat(PasswdFile)
	if err != nil {
		t.Fatalf("stat passwd: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("passwd mode = %o after SetPassword, want 600", got)
	}
}

func TestRemove(t *testing.T) {
	redirectPasswdFile(t)

	if err := SetPassword("to-be-removed"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !IsSet() {
		t.Fatal("IsSet() = false after SetPassword, want true")
	}
	if err := Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if IsSet() {
		t.Fatal("IsSet() = true after Remove, want false")
	}
}

func TestRemoveAbsentIsNil(t *testing.T) {
	redirectPasswdFile(t)

	if IsSet() {
		t.Fatal("IsSet() = true with no password file, want false")
	}
	if err := Remove(); err != nil {
		t.Errorf("Remove() when absent = %v, want nil", err)
	}
}

// Verify must distinguish a wrong password (ErrIncorrectPassword) from an I/O
// failure reading the hash file: a missing/unreadable hash file must NOT be
// reported as a wrong password (which a caller might treat as "try again"),
// and must NEVER be reported as a success (fail-closed).
func TestVerifyIOErrorIsNotIncorrectPassword(t *testing.T) {
	redirectPasswdFile(t) // points at a temp path that does not exist yet

	err := Verify("anything")
	if err == nil {
		t.Fatal("Verify with no hash file returned nil — must fail closed")
	}
	if errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("Verify I/O error reported as ErrIncorrectPassword: %v", err)
	}
}

// Verify must reject a tampered/corrupt hash file (not valid bcrypt) without
// panicking and without treating it as a match.
func TestVerifyCorruptHashRejected(t *testing.T) {
	redirectPasswdFile(t)
	if err := os.WriteFile(PasswdFile, []byte("not-a-bcrypt-hash"), 0600); err != nil {
		t.Fatalf("write corrupt hash: %v", err)
	}
	if err := Verify("anything"); err == nil {
		t.Fatal("Verify against a corrupt hash returned nil — must fail closed")
	}
}

// PromptAndVerify is a no-op (returns nil) when no password is configured, so
// playback is unguarded only when the operator has not set a password.
func TestPromptAndVerifyNoPasswordSet(t *testing.T) {
	redirectPasswdFile(t) // no password file created
	if err := PromptAndVerify(); err != nil {
		t.Fatalf("PromptAndVerify with no password set = %v, want nil", err)
	}
}
