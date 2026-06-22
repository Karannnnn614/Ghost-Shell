package daemon

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ghostshell/internal/config"
	"ghostshell/internal/crypto"
	"ghostshell/internal/store"
)

// newTestSession builds a session whose disk writes go to an in-memory buffer
// (enc) so tests can exercise fan-out without the store/crypto stack.
func newTestSession() (*session, *bytes.Buffer) {
	var disk bytes.Buffer
	s := &session{enc: &disk, subs: map[net.Conn]*subscriber{}}
	return s, &disk
}

// --- #1: tailer fan-out decoupling ----------------------------------------

// A stalled subscriber (its conn is never read) must not block disk writes nor
// a fast subscriber. The slow sub eventually gets dropped; writes keep flowing.
func TestSlowSubscriberDoesNotBlockWrites(t *testing.T) {
	s, disk := newTestSession()

	// Fast subscriber: drained continuously.
	fastSrv, fastCli := net.Pipe()
	defer fastSrv.Close()
	defer fastCli.Close()
	s.subscribe(fastSrv)

	gotFast := make(chan int, 1)
	go func() {
		n := 0
		b := make([]byte, 4096)
		for {
			r, err := fastCli.Read(b)
			n += r
			if err != nil {
				gotFast <- n
				return
			}
		}
	}()

	// Slow/stalled subscriber: server side registered, client side NEVER read.
	slowSrv, slowCli := net.Pipe()
	defer slowSrv.Close()
	defer slowCli.Close()
	s.subscribe(slowSrv)

	// Write far more chunks than the subscriber channel can buffer. If writes
	// blocked on the stalled subscriber this would deadlock; with a deadline we
	// assert it returns promptly.
	payload := bytes.Repeat([]byte("x"), 1024)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 5000; i++ {
			if err := s.write(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writes blocked on a stalled subscriber (head-of-line blocking)")
	}

	// All bytes must have reached disk synchronously and in order.
	if disk.Len() != 5000*len(payload) {
		t.Fatalf("disk got %d bytes, want %d", disk.Len(), 5000*len(payload))
	}

	// Closing the session releases everything (fast reader sees EOF).
	if err := s.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-gotFast:
	case <-time.After(5 * time.Second):
		t.Fatal("fast subscriber did not unblock after session close")
	}
}

// A subscriber receives the bytes written after it subscribed, even when the
// caller reuses its buffer between writes (the session must copy).
func TestSubscriberGetsCopiedBytes(t *testing.T) {
	s, _ := newTestSession()

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	s.subscribe(srv)

	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 4)
		_, _ = io.ReadFull(cli, b)
		got <- append([]byte(nil), b...)
	}()

	// Reused buffer: write "AAAA", then immediately overwrite it.
	buf := []byte("AAAA")
	if err := s.write(buf); err != nil {
		t.Fatalf("write: %v", err)
	}
	copy(buf, "BBBB") // mutate the caller buffer after handing it off

	select {
	case b := <-got:
		if string(b) != "AAAA" {
			t.Fatalf("subscriber got %q, want %q — bytes not copied", b, "AAAA")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber received nothing")
	}
	_ = s.close()
}

// Closing the session must release a live (never-dropped) subscriber: its conn
// is closed so a blocked Read unblocks with an error. This exercises close()'s
// release path specifically (the subscriber stays well under the channel cap so
// write() never drops it).
func TestCloseReleasesLiveSubscriber(t *testing.T) {
	s, _ := newTestSession()

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	s.subscribe(srv)

	// A reader that consumes everything, then reports the error it eventually
	// sees (EOF/closed pipe once the session releases the conn).
	readErr := make(chan error, 1)
	go func() {
		b := make([]byte, 64)
		for {
			if _, err := cli.Read(b); err != nil {
				readErr <- err
				return
			}
		}
	}()

	// A few small writes, far below subChanCap, so the subscriber is never the
	// lagging one and remains registered until close().
	for i := 0; i < 4; i++ {
		if err := s.write([]byte("hello")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	if err := s.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-readErr:
	case <-time.After(5 * time.Second):
		t.Fatal("close() did not release the live subscriber's conn")
	}
}

// --- #2: homeDirsFromPasswd parser ----------------------------------------

func TestHomeDirsFromPasswd(t *testing.T) {
	content := []byte(strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"bob:x:1001:1001:Bob:/var/home/bob:/bin/zsh",
		"# a comment line",
		"malformed-line-without-fields",
		"dup:x:1002:1002::/home/alice:/bin/bash", // duplicate home -> deduped
		"",
	}, "\n"))

	got := homeDirsFromPasswd(content)
	sort.Strings(got)

	want := []string{"/home/alice", "/root", "/usr/sbin", "/var/home/bob"}
	if len(got) != len(want) {
		t.Fatalf("homeDirsFromPasswd = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("homeDirsFromPasswd = %v, want %v", got, want)
		}
	}
}

// --- #4: per-UID session cap is configurable -------------------------------

// reserve must honor the registry's cap, and setCap must change it under the
// lock so SIGHUP reloads take effect without a restart.
func TestRegistryCap(t *testing.T) {
	reg := &registry{live: map[string]sessionRef{}, connCount: map[uint32]int{}, cap: 2}

	const uid = uint32(1000)
	for i := 0; i < 2; i++ {
		if !reg.reserve(uid) {
			t.Fatalf("reservation %d under cap=2 should succeed", i+1)
		}
	}
	if reg.reserve(uid) {
		t.Fatal("third reservation should be rejected at cap=2")
	}

	// Releasing one slot lets a new reservation through.
	reg.release(uid)
	if !reg.reserve(uid) {
		t.Fatal("reservation after release should succeed")
	}

	// Raising the cap (as SIGHUP would) admits more sessions immediately.
	reg.setCap(5)
	for i := 0; i < 3; i++ {
		if !reg.reserve(uid) {
			t.Fatalf("reservation %d up to the raised cap=5 should succeed", i+1)
		}
	}
	if reg.reserve(uid) {
		t.Fatal("reservation beyond raised cap=5 should be rejected")
	}
}

// setCap, reserve and release must be race-free (run under -race).
func TestRegistryCapRace(t *testing.T) {
	reg := &registry{live: map[string]sessionRef{}, connCount: map[uint32]int{}, cap: 10}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(uid uint32) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if reg.reserve(uid) {
					reg.release(uid)
				}
			}
		}(uint32(i))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			reg.setCap(j%20 + 1)
		}
	}()
	wg.Wait()
}

// --- #5: backupConfigChanged pure helper -----------------------------------

func TestBackupConfigChanged_NoDiff(t *testing.T) {
	a := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 60}
	b := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 60}
	if backupConfigChanged(a, b) {
		t.Error("expected no change")
	}
}

func TestBackupConfigChanged_TypeChanged(t *testing.T) {
	a := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 60}
	b := &config.Config{BackupType: "bucket_aws", BackupTarget: "host:/b", BackupIntervalSec: 60}
	if !backupConfigChanged(a, b) {
		t.Error("expected change when BackupType differs")
	}
}

func TestBackupConfigChanged_TargetChanged(t *testing.T) {
	a := &config.Config{BackupType: "rsync", BackupTarget: "host:/a", BackupIntervalSec: 60}
	b := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 60}
	if !backupConfigChanged(a, b) {
		t.Error("expected change when BackupTarget differs")
	}
}

func TestBackupConfigChanged_IntervalChanged(t *testing.T) {
	a := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 60}
	b := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 120}
	if !backupConfigChanged(a, b) {
		t.Error("expected change when BackupIntervalSec differs")
	}
}

// --- #6: backupLoop goroutine -----------------------------------------------

func TestBackupLoopDisabledDoesNotFire(t *testing.T) {
	cfg := &config.Config{BackupType: "", BackupTarget: "", BackupIntervalSec: 0}
	updates := make(chan *config.Config)
	fired := make(chan struct{}, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go backupLoop(ctx, cfg, updates, func(_ context.Context, c *config.Config) error {
		fired <- struct{}{}
		return nil
	})

	select {
	case <-ctx.Done():
		// correct: timeout expired without runFn firing
	case <-fired:
		t.Fatal("backupLoop fired runFn when backup was disabled")
	}
}

func TestBackupLoopFiresOnTick(t *testing.T) {
	orig := backupTickUnit
	backupTickUnit = time.Millisecond
	defer func() { backupTickUnit = orig }()

	cfg := &config.Config{
		BackupType:        "rsync",
		BackupTarget:      "host:/b",
		BackupIntervalSec: 10,
	}
	updates := make(chan *config.Config)
	fired := make(chan struct{}, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go backupLoop(ctx, cfg, updates, func(_ context.Context, c *config.Config) error {
		select {
		case fired <- struct{}{}:
		default:
		}
		return nil
	})

	select {
	case <-fired:
		// correct: fired within timeout
	case <-ctx.Done():
		t.Fatal("backupLoop did not fire runFn within timeout")
	}
}

func TestBackupLoopReloadResetsTimer(t *testing.T) {
	orig := backupTickUnit
	backupTickUnit = time.Millisecond
	defer func() { backupTickUnit = orig }()

	initial := &config.Config{BackupType: "", BackupIntervalSec: 0}
	updates := make(chan *config.Config, 1)
	fired := make(chan struct{}, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go backupLoop(ctx, initial, updates, func(_ context.Context, c *config.Config) error {
		select {
		case fired <- struct{}{}:
		default:
		}
		return nil
	})

	updates <- &config.Config{
		BackupType:        "rsync",
		BackupTarget:      "host:/b",
		BackupIntervalSec: 10,
	}

	select {
	case <-fired:
		// correct: fired after reload enabled it
	case <-ctx.Done():
		t.Fatal("backupLoop did not fire after reload enabled backup")
	}
}

func TestBackupLoopStopsOnContextCancel(t *testing.T) {
	orig := backupTickUnit
	backupTickUnit = time.Millisecond
	defer func() { backupTickUnit = orig }()

	cfg := &config.Config{BackupType: "rsync", BackupTarget: "host:/b", BackupIntervalSec: 10}
	updates := make(chan *config.Config)
	exited := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		backupLoop(ctx, cfg, updates, func(_ context.Context, c *config.Config) error { return nil })
		close(exited)
	}()

	cancel()
	select {
	case <-exited:
		// correct: goroutine exited after cancel
	case <-time.After(time.Second):
		t.Fatal("backupLoop did not exit after context cancel")
	}
}

// --- #3: in-progress local recordings are not ingested truncated -----------

// copyFile succeeds for a stable source: the destination is a valid encrypted
// copy and the source is left intact (removal is the caller's job).
func TestCopyFileStable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "20200101T000000.000000000-1.cast")
	if err := os.WriteFile(src, bytes.Repeat([]byte("data"), 100), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.cast")
	key := bytes.Repeat([]byte("k"), 32)

	if err := copyFile(src, dst, key); err != nil {
		t.Fatalf("copyFile on stable source: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("destination missing after successful copy: %v", err)
	}
}

// If the source grows during the copy, copyFile must detect the size change,
// remove the partial destination, and return an error so the caller leaves the
// source in place for a later run.
func TestCopyFileSizeChangedRemovesPartial(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "20200101T000000.000000000-1.cast")
	if err := os.WriteFile(src, bytes.Repeat([]byte("data"), 100), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.cast")
	key := bytes.Repeat([]byte("k"), 32)

	// Hook fires after the snapshot+copy, before the re-check: append to the
	// source so its size differs from the snapshot.
	copyFileAfterCopy = func() {
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		_, _ = f.Write([]byte("more"))
		_ = f.Close()
	}
	defer func() { copyFileAfterCopy = nil }()

	if err := copyFile(src, dst, key); err == nil {
		t.Fatal("copyFile should fail when the source changes during copy")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("partial destination should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("source should be left in place, stat err=%v", err)
	}
}

// --- shared helpers for the live-tail / ANSIBLE tests ----------------------

// unixConnPair returns a connected pair of *net.UnixConn (server, client) over a
// transient listening socket in a temp dir. Both are closed by t.Cleanup.
func unixConnPair(t *testing.T) (srv, cli *net.UnixConn) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	cc, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-accepted
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	srv = a.c.(*net.UnixConn)
	cli = cc.(*net.UnixConn)
	t.Cleanup(func() { srv.Close(); cli.Close() })
	return srv, cli
}

// newDiskSession builds a session backed by a real encrypted cast file at path,
// using key, so OpenCastSnapshot can decrypt the on-disk prefix exactly as in
// production. Returns the session and its file path.
func newDiskSession(t *testing.T, key []byte) (*session, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.cast")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open cast: %v", err)
	}
	enc, err := crypto.NewWriter(f, key)
	if err != nil {
		f.Close()
		t.Fatalf("crypto writer: %v", err)
	}
	return &session{f: f, enc: enc, subs: map[net.Conn]*subscriber{}}, path
}

// waitSubs blocks until the session has exactly n subscribers (or fails).
func waitSubs(t *testing.T, s *session, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := len(s.subs)
		s.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d subscriber(s)", n)
}

// withTempStore points the config singleton at a fresh temp central dir and
// writes a valid key there, so store.CentralDir()/store.KeyPath() resolve into
// it for the duration of the test. Returns the key bytes.
func withTempStore(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", dir)
	config.Reset()
	t.Cleanup(config.Reset)
	key := bytes.Repeat([]byte("k"), crypto.KeySize)
	if err := os.WriteFile(store.KeyPath(), key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return key
}

// --- live-tail: non-root TAIL rejected -------------------------------------

// A non-root peer asking to TAIL must be refused before any session lookup.
func TestHandleTailRejectsNonRoot(t *testing.T) {
	srv, cli := unixConnPair(t)
	reg := &registry{live: map[string]sessionRef{}, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	done := make(chan struct{})
	go func() {
		handleTail(srv, "whatever", &unix.Ucred{Uid: 1000}, reg)
		close(done)
	}()

	buf := make([]byte, 64)
	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := cli.Read(buf)
	if got := string(buf[:n]); !strings.Contains(got, "requires root") {
		t.Fatalf("non-root tail: got %q, want a 'requires root' error", got)
	}
	srv.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleTail did not return after rejecting non-root")
	}
}

// --- live-tail: multi-tailer fan-out ---------------------------------------

// Two tailers subscribed to the same live session both receive every byte
// written after they subscribed.
func TestMultiTailerFanout(t *testing.T) {
	s, _ := newTestSession()

	const nTailers = 3
	clis := make([]net.Conn, nTailers)
	for i := 0; i < nTailers; i++ {
		srv, cli := net.Pipe()
		t.Cleanup(func() { srv.Close(); cli.Close() })
		clis[i] = cli
		s.subscribe(srv)
	}
	waitSubs(t, s, nTailers)

	want := bytes.Repeat([]byte("payload-"), 32) // < subChanCap chunks, never dropped
	got := make([]chan []byte, nTailers)
	for i := 0; i < nTailers; i++ {
		got[i] = make(chan []byte, 1)
		go func(c net.Conn, out chan []byte) {
			b := make([]byte, len(want))
			if _, err := io.ReadFull(c, b); err != nil {
				out <- nil
				return
			}
			out <- b
		}(clis[i], got[i])
	}

	if err := s.write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	for i := 0; i < nTailers; i++ {
		select {
		case b := <-got[i]:
			if !bytes.Equal(b, want) {
				t.Fatalf("tailer %d got %q, want %q", i, b, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("tailer %d received nothing — fan-out missed a subscriber", i)
		}
	}
	_ = s.close()
}

// --- live-tail: disconnect mid-stream, no goroutine leak -------------------

// A tailer that disconnects mid-stream must be deregistered and its drain
// goroutine must exit, leaving no leak and not blocking the recorder.
func TestTailerDisconnectNoGoroutineLeak(t *testing.T) {
	s, _ := newTestSession()

	srv, cli := net.Pipe()
	t.Cleanup(func() { srv.Close() })
	s.subscribe(srv)
	waitSubs(t, s, 1)

	before := runtime.NumGoroutine()

	// Disconnect the client; the next fan-out write to a dead pipe makes drain's
	// conn.Write fail, so it deregisters and exits.
	cli.Close()

	// Keep writing; the dead subscriber must be removed (not block writes).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := s.write([]byte("tick")); err != nil {
			t.Fatalf("write after disconnect: %v", err)
		}
		s.mu.Lock()
		n := len(s.subs)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnected tailer was never deregistered")
		}
		time.Sleep(time.Millisecond)
	}

	// The drain goroutine should be gone. Allow scheduler slack.
	leakDeadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(leakDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutine leak after tailer disconnect: before=%d after=%d", before, after)
	}
	_ = s.close()
}

// --- live-tail: replay -> live byte continuity -----------------------------

// addTailer must replay the recorded prefix and then stream live bytes with no
// gap and no overlap at the handoff. Backed by a real encrypted file so the
// snapshot decrypt path matches production.
func TestReplayLiveContinuity(t *testing.T) {
	// store.OpenCastSnapshot reads the key via store.KeyPath(); point it at a
	// temp store and use that same key to write the cast.
	key := withTempStore(t)
	s, path := newDiskSession(t, key)

	// Historical prefix: several frames written before anyone tails.
	prefix := []byte("HISTORY-0123456789-")
	for i := 0; i < 4; i++ {
		if err := s.write(prefix); err != nil {
			t.Fatalf("prefix write: %v", err)
		}
	}
	wantPrefix := bytes.Repeat(prefix, 4)

	srv, cli := unixConnPair(t)

	wantSuffix := bytes.Repeat([]byte("LIVE-abcdefghij-"), 4)
	want := append(append([]byte{}, wantPrefix...), wantSuffix...)

	// Reader pulls exactly the expected number of bytes (replay + live). Reading
	// the full payload *before* close() keeps the assertion independent of close
	// ordering: every byte must arrive over the live stream, contiguous and
	// non-overlapping with the replayed prefix.
	readDone := make(chan []byte, 1)
	go func() {
		b := make([]byte, len(want))
		_, err := io.ReadFull(cli, b)
		if err != nil {
			readDone <- nil
			return
		}
		readDone <- b
	}()

	tailDone := make(chan struct{})
	go func() {
		s.addTailer(srv, path)
		close(tailDone)
	}()

	// Wait until the tailer has registered (boundary snapshotted) before writing
	// live bytes, so the suffix is delivered via the live channel — exactly the
	// handoff we are testing.
	waitSubs(t, s, 1)

	suffix := []byte("LIVE-abcdefghij-")
	for i := 0; i < 4; i++ {
		if err := s.write(suffix); err != nil {
			t.Fatalf("suffix write: %v", err)
		}
	}

	var got []byte
	select {
	case got = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("tail reader did not receive the full replay+live stream")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("replay->live not contiguous:\n got %q\nwant %q", got, want)
	}

	// Tidy up: closing the session releases the tailer's drain goroutine.
	if err := s.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-tailDone:
	case <-time.After(5 * time.Second):
		t.Fatal("addTailer did not return after session close")
	}
}

// --- ANSIBLE ingest path ----------------------------------------------------

// handleAnsible must reserve/release a per-UID slot, write a decryptable file,
// and refuse a duplicate runID (O_EXCL) rather than clobbering it.
func TestHandleAnsibleIngest(t *testing.T) {
	key := withTempStore(t)
	reg := &registry{live: map[string]sessionRef{}, key: key, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 2}

	const runID = "run-20200101T000000-abc"
	payload := []byte(`{"event":"start"}` + "\n" + `{"event":"end"}` + "\n")

	run := func() {
		srv, cli := unixConnPair(t)
		done := make(chan struct{})
		go func() {
			handleAnsible(srv, newBufReader(srv), runID, &unix.Ucred{Uid: 1000}, reg)
			close(done)
		}()
		if _, err := cli.Write(payload); err != nil {
			t.Fatalf("client write: %v", err)
		}
		_ = cli.CloseWrite() // signal EOF so the handler's read loop ends
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handleAnsible did not return")
		}
	}

	run()

	// Slot must be released (entry deleted at zero).
	reg.mu.Lock()
	cc := reg.connCount[1000]
	reg.mu.Unlock()
	if cc != 0 {
		t.Fatalf("connCount[1000] = %d after ANSIBLE, want 0 (reserve/release unbalanced)", cc)
	}

	// File must exist and decrypt back to the payload.
	uname := lookupUser(1000)
	path := filepath.Join(store.CentralDir(), uname, "ansible", runID+".ajsonl")
	rc, err := store.OpenCast(path)
	if err != nil {
		t.Fatalf("open stored ansible file: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("stored ansible bytes = %q, want %q", got, payload)
	}

	// A second ingest with the same runID must NOT clobber the first (O_EXCL):
	// the original file content is preserved.
	run()
	rc2, err := store.OpenCast(path)
	if err != nil {
		t.Fatalf("reopen after duplicate ingest: %v", err)
	}
	got2, _ := io.ReadAll(rc2)
	rc2.Close()
	if !bytes.Equal(got2, payload) {
		t.Fatalf("duplicate runID clobbered the file: got %q, want %q", got2, payload)
	}
}

// newBufReader adapts a conn into the *bufio.Reader handleAnsible expects.
func newBufReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// --- ingest filter: partial/temp/dotfiles are never swept ------------------

// ingestible must admit only completed regular .cast recordings and reject
// dotfiles, temp/partial suffixes (.tmp/.part) and non-.cast entries, so an
// atomic temp+rename in-progress write (or a hidden partial) is never ingested
// mid-write nor deleted out from under the writer.
func TestIngestibleFilter(t *testing.T) {
	dir := t.TempDir()
	// name -> want ingestible
	cases := map[string]bool{
		"20200101T000000.000000000-1.cast": true,  // normal completed recording
		"session.cast":                     true,  // explicit -o name
		".rec.cast.tmp":                    false, // hidden atomic temp
		"rec.cast.tmp":                     false, // atomic temp (ext .tmp)
		"rec.cast.part":                    false, // partial marker
		".hidden.cast":                     false, // dotfile (temp/partial convention)
		"notes.txt":                        false, // not a recording
		"rec.castx":                        false, // not .cast
	}
	for name := range cases {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// A directory named like a cast must also be rejected.
	if err := os.Mkdir(filepath.Join(dir, "weird.cast"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cases["weird.cast"] = false

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		want, known := cases[e.Name()]
		if !known {
			t.Fatalf("unexpected entry %q", e.Name())
		}
		if got := ingestible(e); got != want {
			t.Errorf("ingestible(%q) = %v, want %v", e.Name(), got, want)
		}
	}
}

// ingestHome must not delete a source whose name marks it as a temp/partial
// (atomic temp+rename in flight): it is skipped, copied nowhere, and left in
// place for the writer to finish/rename.
func TestIngestHomeSkipsTempFiles(t *testing.T) {
	central := t.TempDir()
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", central)
	config.Reset()
	t.Cleanup(config.Reset)

	home := t.TempDir()
	srcDir := filepath.Join(home, ".local", "share", "ghostshell")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	temp := filepath.Join(srcDir, "rec.cast.tmp")
	if err := os.WriteFile(temp, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	dot := filepath.Join(srcDir, ".inprogress.cast")
	if err := os.WriteFile(dot, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write dot: %v", err)
	}

	key := bytes.Repeat([]byte("k"), crypto.KeySize)
	ingestHome(home, key)

	// Both temp/partial sources must still exist (not swept, not removed).
	if _, err := os.Stat(temp); err != nil {
		t.Errorf("temp file was removed/ingested: %v", err)
	}
	if _, err := os.Stat(dot); err != nil {
		t.Errorf("dotfile partial was removed/ingested: %v", err)
	}
	// And nothing should have been written into the central store for this user.
	uname := filepath.Base(home)
	if _, err := os.Stat(filepath.Join(central, uname, "rec.cast.tmp")); !os.IsNotExist(err) {
		t.Errorf("temp file leaked into central store, stat err=%v", err)
	}
}

// --- session id uniqueness under concurrency -------------------------------

// add must never overwrite a live id: a second add with the same id is rejected,
// leaving the first session's ref intact. This guards a tailer from resolving an
// id to the wrong (clobbering) recording.
func TestRegistryAddRejectsDuplicateID(t *testing.T) {
	reg := &registry{live: map[string]sessionRef{}, connCount: map[uint32]int{}}
	s1, _ := newTestSession()
	s2, _ := newTestSession()

	if !reg.add("id-1", s1, "/p/1") {
		t.Fatal("first add should succeed")
	}
	if reg.add("id-1", s2, "/p/2") {
		t.Fatal("duplicate add should be rejected, not overwrite")
	}
	ref, ok := reg.get("id-1")
	if !ok || ref.sess != s1 || ref.path != "/p/1" {
		t.Fatalf("duplicate add clobbered the live session: ref=%+v ok=%v", ref, ok)
	}
}

// Concurrent adds of distinct ids all register, and concurrent adds racing on a
// single shared id admit exactly one winner (run under -race).
func TestRegistryConcurrentAddDistinctAndRaced(t *testing.T) {
	reg := &registry{live: map[string]sessionRef{}, connCount: map[uint32]int{}}

	// 1) Distinct ids: every one must register (no lost updates).
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, _ := newTestSession()
			id := "sess-" + strconv.Itoa(i)
			if !reg.add(id, s, "/p/"+id) {
				t.Errorf("distinct id %s failed to register", id)
			}
		}(i)
	}
	wg.Wait()
	reg.mu.RLock()
	got := len(reg.live)
	reg.mu.RUnlock()
	if got != n {
		t.Fatalf("registered %d distinct sessions, want %d", got, n)
	}

	// 2) Many goroutines race to claim ONE shared id: exactly one wins.
	var winners int64
	var wg2 sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			s, _ := newTestSession()
			if reg.add("shared", s, "/p/shared") {
				atomic.AddInt64(&winners, 1)
			}
		}()
	}
	wg2.Wait()
	if winners != 1 {
		t.Fatalf("shared-id claim winners = %d, want exactly 1", winners)
	}
}

// --- SO_PEERCRED authorization: storage keyed off the VERIFIED uid ----------

// handleAnsible must store under the directory derived from the VERIFIED peer
// uid (cred.Uid), never any client-supplied identity. Two different creds write
// to two different user dirs even with the same payload, so a user cannot
// ingest "as" another user.
func TestHandleAnsibleStoresUnderVerifiedUID(t *testing.T) {
	key := withTempStore(t)
	reg := &registry{live: map[string]sessionRef{}, key: key, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	ingest := func(uid uint32, runID string) {
		srv, cli := unixConnPair(t)
		done := make(chan struct{})
		go func() {
			handleAnsible(srv, newBufReader(srv), runID, &unix.Ucred{Uid: uid}, reg)
			close(done)
		}()
		_, _ = cli.Write([]byte(`{"type":"run"}` + "\n"))
		_ = cli.CloseWrite()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handleAnsible did not return")
		}
	}

	ingest(0, "run-root-0001")
	ingest(1000, "run-user-1000")

	// Each run must land under its OWN verified-uid user dir, and NOT under the
	// other's — proving the dir is chosen from cred.Uid, not the request.
	rootDir := filepath.Join(store.CentralDir(), lookupUser(0), "ansible")
	userDir := filepath.Join(store.CentralDir(), lookupUser(1000), "ansible")
	if _, err := os.Stat(filepath.Join(rootDir, "run-root-0001.ajsonl")); err != nil {
		t.Errorf("root run not stored under root dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(userDir, "run-user-1000.ajsonl")); err != nil {
		t.Errorf("user run not stored under user dir: %v", err)
	}
	// Cross-check: the user's run must not appear in root's dir.
	if _, err := os.Stat(filepath.Join(rootDir, "run-user-1000.ajsonl")); !os.IsNotExist(err) {
		t.Errorf("user run leaked into root dir, stat err=%v", err)
	}
}

// A non-root peer must be refused tail of another user's session before any
// session lookup, regardless of the requested id — authorization is on the
// verified peer uid, not a client field. (Companion to TestHandleTailRejectsNonRoot,
// asserting the reservation/registry is untouched by the rejected request.)
func TestHandleTailNonRootDoesNotTouchRegistry(t *testing.T) {
	srv, cli := unixConnPair(t)
	reg := &registry{live: map[string]sessionRef{}, connCount: map[uint32]int{}, conns: map[net.Conn]struct{}{}, cap: 4}

	done := make(chan struct{})
	go func() {
		handleTail(srv, "someones-private-session", &unix.Ucred{Uid: 1000}, reg)
		close(done)
	}()
	_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _ := cli.Read(buf)
	if !strings.Contains(string(buf[:n]), "requires root") {
		t.Fatalf("non-root tail not rejected: got %q", buf[:n])
	}
	srv.Close()
	<-done

	// No connCount reservation should have been taken for a rejected tail.
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if len(reg.connCount) != 0 {
		t.Fatalf("rejected tail mutated connCount: %v", reg.connCount)
	}
}
