// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

//go:build linux

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ghostshell/internal/crypto"
)

// TestOpenCastRefusesSymlink is the ingest/open symlink attack: a user plants
// ~/.local/share/ghostshell/foo.cast as a symlink and the root daemon sweeps it.
// The open must be refused (O_NOFOLLOW -> ELOOP) before any bytes are read, so a
// symlink can never redirect a root read at an arbitrary target. The symlink
// here points at a *valid regular cast* to prove the refusal is about the final
// component being a symlink, not about the target.
func TestOpenCastRefusesSymlink(t *testing.T) {
	dir, _, _ := setupTempEnv(t)
	target := filepath.Join(dir, "target.cast")
	if err := os.WriteFile(target, buildCast(t, "echo hi", "hi\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "evil.cast")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	rc, err := OpenCast(link)
	if err == nil {
		rc.Close()
		t.Fatalf("OpenCast(symlink) = nil error, want refusal (ELOOP)")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("OpenCast(symlink) error = %v, want ELOOP", err)
	}
}

// TestOpenCastRefusesSymlinkToSensitiveTarget is the concrete /etc/shadow shape:
// even when the planted symlink points at a root-readable file *outside* the
// store, the open is refused, so nothing outside the store is ever read.
func TestOpenCastRefusesSymlinkToSensitiveTarget(t *testing.T) {
	dir, _, _ := setupTempEnv(t)
	link := filepath.Join(dir, "shadow.cast")
	// /etc/passwd is world-readable and always present; standing in for /etc/shadow
	// without needing the test to run as root. The point is that the target is
	// outside the store and must never be reachable via the symlink.
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	rc, err := OpenCast(link)
	if err == nil {
		rc.Close()
		t.Fatalf("OpenCast(symlink -> /etc/passwd) = nil error, want refusal")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("OpenCast(symlink) error = %v, want ELOOP", err)
	}
}

// TestOpenCastRefusesNonRegular proves a non-regular file that slips past
// O_NOFOLLOW (it is not itself a symlink) is still refused by the explicit
// IsRegular() check before any decryption — covering a directory and a fifo.
func TestOpenCastRefusesNonRegular(t *testing.T) {
	dir, _, _ := setupTempEnv(t)

	t.Run("directory", func(t *testing.T) {
		d := filepath.Join(dir, "adir.cast")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		rc, err := OpenCast(d)
		if err == nil {
			rc.Close()
			t.Fatalf("OpenCast(dir) = nil error, want 'not a regular file'")
		}
	})

	t.Run("fifo", func(t *testing.T) {
		fifo := filepath.Join(dir, "afifo.cast")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatalf("mkfifo: %v", err)
		}
		// OpenCast opens O_RDONLY (no O_NONBLOCK), which blocks on a fifo until a
		// writer appears. Rendezvous with a writer goroutine so the open returns
		// and the IsRegular() guard can reject it, instead of blocking forever.
		werr := make(chan error, 1)
		go func() {
			wf, e := os.OpenFile(fifo, os.O_WRONLY, 0)
			if e == nil {
				_ = wf.Close()
			}
			werr <- e
		}()
		rc, err := OpenCast(fifo)
		if err == nil {
			rc.Close()
			t.Fatalf("OpenCast(fifo) = nil error, want 'not a regular file'")
		}
		<-werr
	})
}

// TestReadDecryptKeyRejectsNonRootOwner proves the at-rest key must be owned by
// root (or the process euid): a 0600 key owned by some *other* unprivileged user
// — which an attacker could plant to coerce decryption with an attacker-chosen
// key — is refused. Requires root to chown the key to a foreign uid, so it skips
// when not run as root.
func TestReadDecryptKeyRejectsNonRootOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown the key file to a foreign uid")
	}
	dir, _, keyFile := setupTempEnv(t)
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	const foreignUID = 12345
	if err := os.Chown(keyFile, foreignUID, foreignUID); err != nil {
		t.Skipf("chown key file: %v", err)
	}
	// Build a real encrypted cast so OpenCast must read (and validate) the key.
	p := filepath.Join(dir, "enc.cast")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := crypto.NewWriter(f, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(buildCast(t, "secret", "top secret\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rc, err := OpenCast(p)
	if err == nil {
		rc.Close()
		t.Fatalf("OpenCast with foreign-owned key = nil error, want refusal")
	}
}

// TestReadDecryptKeyRefusesSymlinkedKey proves the key path itself is opened
// O_NOFOLLOW: a symlink planted at the key path (pointing at attacker-chosen
// bytes) is refused rather than followed, closing a key-swap TOCTOU.
func TestReadDecryptKeyRefusesSymlinkedKey(t *testing.T) {
	dir, _, keyFile := setupTempEnv(t)
	realKey := filepath.Join(dir, "real.key")
	key := make([]byte, crypto.KeySize)
	if err := os.WriteFile(realKey, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realKey, keyFile); err != nil {
		t.Fatal(err)
	}
	// Build an encrypted cast whose decryption forces a key read.
	p := filepath.Join(dir, "enc.cast")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := crypto.NewWriter(f, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(buildCast(t, "x", "y\r\n")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	rc, err := OpenCast(p)
	if err == nil {
		rc.Close()
		t.Fatalf("OpenCast with symlinked key path = nil error, want refusal (ELOOP)")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("symlinked key open error = %v, want ELOOP", err)
	}
}
