// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package daemon implements ghostshell-daemon: the root collector that receives session
// recordings from per-user `ghostshell rec` clients, stores them in the central
// root-only store, and fans out live sessions to root tailers.
//
// Protocol (line-based handshake, then raw bytes):
//
//	client -> "REC\n"              then streams asciinema v2 cast bytes (recorder)
//	client -> "TAIL <id>\n"        then reads live cast bytes (root only)
//	client -> "ANSIBLE <runid>\n"  then streams JSON-lines ansible run bytes
package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"ghostshell/internal/ansible"
	"ghostshell/internal/backup"
	"ghostshell/internal/config"
	"ghostshell/internal/crypto"
	"ghostshell/internal/logger"
	"ghostshell/internal/store"
)

// isTemporary returns true for transient network errors that are safe to retry.
// net.Error.Temporary() was deprecated in Go 1.18; we check syscall-level EAGAIN/EINTR.
func isTemporary(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	// EINTR or EAGAIN from accept — safe to retry.
	var errno interface{ Temporary() bool }
	if errors.As(err, &errno) {
		return errno.Temporary()
	}
	return false
}

// subChanCap is the number of chunks buffered per tailer before it is
// considered lagging and dropped. A chunk is one recorder Read (<=32KiB), so
// this absorbs a brief stall without unbounded memory growth.
const subChanCap = 256

// handshakeTimeout bounds how long a freshly accepted connection has to send
// its command line. The socket is world-connectable (0666), so without this a
// local user could open a connection, send no newline, and pin a goroutine+fd
// forever (slowloris) — before the per-UID SessionCap is even consulted. The
// deadline is cleared once a valid handshake is read.
const handshakeTimeout = 10 * time.Second

// acceptBackoff is how long the accept loop pauses after a transient
// fd-exhaustion error (EMFILE/ENFILE) before retrying, so a momentary fd
// shortage doesn't kill the daemon or spin the CPU.
const acceptBackoff = 50 * time.Millisecond

// shutdownGrace bounds how long Run waits for in-flight handler goroutines to
// finish after the context is cancelled before returning anyway.
const shutdownGrace = 5 * time.Second

// isFDExhaustion reports whether err is an accept failure caused by running out
// of file descriptors (per-process EMFILE or system-wide ENFILE). These are
// transient: the daemon should back off and keep serving rather than exit.
func isFDExhaustion(err error) bool {
	return errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE)
}

// subscriber is a single live tailer. Its conn is written to by a dedicated
// drain goroutine reading from ch, so a slow/stuck conn never blocks the
// recorder or other tailers (the fan-out is decoupled from the disk write).
type subscriber struct {
	sess *session // owning session, so drain can deregister itself on write error
	conn net.Conn
	ch   chan []byte
	done chan struct{} // closed by the drain goroutine when it exits
}

type session struct {
	mu        sync.Mutex
	f         *os.File  // underlying file, for sync/close
	enc       io.Writer // encrypting writer over f; recorded bytes land as ciphertext
	subs      map[net.Conn]*subscriber
	diskBytes int64 // plaintext bytes durably written so far (under mu)
	done      bool
}

// write persists b to disk synchronously and in order, then fans b out to every
// live tailer via a NON-BLOCKING send of a private copy. The caller may reuse b
// after write returns, so the copy is mandatory. A tailer whose channel is full
// (lagging) is dropped rather than blocking the recorder or peer tailers.
func (s *session) write(b []byte) error {
	s.mu.Lock()
	if s.enc != nil {
		if _, err := s.enc.Write(b); err != nil { // encrypted to disk
			s.mu.Unlock()
			return err
		}
	}
	// Account for durably-written plaintext under the lock so a tailer
	// registering concurrently snapshots an exact replay boundary (see register):
	// every byte counted here is in a complete, flushed on-disk frame.
	s.diskBytes += int64(len(b))
	if len(s.subs) == 0 {
		s.mu.Unlock()
		return nil
	}
	// Copy once; the same immutable slice is safe to share across subscribers.
	cp := make([]byte, len(b))
	copy(cp, b)
	var dropped []*subscriber
	for c, sub := range s.subs {
		select {
		case sub.ch <- cp:
		default:
			// Lagging tailer: drop it instead of blocking the disk write path.
			delete(s.subs, c)
			close(sub.ch)
			dropped = append(dropped, sub)
		}
	}
	s.mu.Unlock()
	for _, sub := range dropped {
		logger.Warnf("ghostshell-daemon: dropping lagging tailer %v (buffer of %d chunks full)",
			sub.conn.RemoteAddr(), subChanCap)
	}
	// Close dropped conns outside the lock so we never hold s.mu across a conn
	// op. Closing the conn also unblocks a drain goroutine stuck in conn.Write
	// (a stalled tailer) so its fd/goroutine don't leak until session close.
	for _, sub := range dropped {
		_ = sub.conn.Close()
	}
	return nil
}

// subscribe registers c as a live tailer and starts its drain goroutine. The
// caller must hold no lock. If the session is already done, c is closed. Used
// by tests and any caller that needs no historical replay.
func (s *session) subscribe(c net.Conn) {
	sub, _, ok := s.register(c)
	if !ok {
		_ = c.Close()
		return
	}
	go sub.drain()
}

// register atomically adds c as a live tailer and returns the count of
// plaintext bytes already written to disk at that instant. Because the disk
// write (and its diskBytes bump in write()) and this registration are both
// serialized on s.mu, the returned boundary partitions the stream exactly:
// every byte at or before it is on disk (replay it), every byte after it is
// queued to this subscriber's channel (stream it live). No gap, no overlap. The
// drain goroutine is NOT started here — the caller starts it after any replay so
// historical bytes and live bytes can't interleave on the same conn. ok is
// false if the session already ended (nothing registered).
func (s *session) register(c net.Conn) (sub *subscriber, replayBytes int64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil, 0, false
	}
	sub = &subscriber{sess: s, conn: c, ch: make(chan []byte, subChanCap), done: make(chan struct{})}
	s.subs[c] = sub
	return sub, s.diskBytes, true
}

// remove deregisters sub if still present and closes its channel so the drain
// goroutine exits. Called when a tailer's conn write fails so a dead subscriber
// stops receiving (and buffering) copies. Returns true if it removed sub (and
// thus closed the channel); false if write()/close() had already removed it.
func (s *session) remove(sub *subscriber) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.subs[sub.conn]; ok && cur == sub {
		delete(s.subs, sub.conn)
		close(sub.ch)
		return true
	}
	return false
}

// drain writes queued chunks to the subscriber's conn until the channel is
// closed (lagging drop or session close) or a conn write fails.
func (sub *subscriber) drain() {
	defer close(sub.done)
	for b := range sub.ch {
		if _, err := sub.conn.Write(b); err != nil {
			// Conn is dead. Deregister so write()/close() stop fanning out to us;
			// then keep draining whatever is already queued so a concurrent
			// write() (which may still hold a reference) never blocks on the
			// channel.
			sub.sess.remove(sub)
			for range sub.ch {
			}
			return
		}
	}
}

func (s *session) addTailer(c net.Conn, path string) {
	// Register and snapshot the on-disk replay boundary atomically so historical
	// replay and live fan-out are contiguous and non-overlapping. Live bytes
	// written from now on buffer in sub.ch while we replay; we start the drain
	// goroutine only after replay so historical and live bytes never interleave
	// on c.
	sub, replayBytes, ok := s.register(c)
	if !ok {
		_ = c.Close()
		return
	}
	if replayBytes > 0 {
		rc, err := store.OpenCastSnapshot(path)
		if err != nil {
			s.dropAndClose(sub)
			return
		}
		// Replay exactly replayBytes of plaintext. The snapshot (opened decrypted,
		// matching the plaintext live stream) may have grown past the boundary,
		// but those later bytes are already queued for live delivery — replaying
		// them would duplicate. io.CopyN stops precisely at the boundary.
		_, copyErr := io.CopyN(c, rc, replayBytes)
		closeErr := rc.Close()
		if copyErr != nil || closeErr != nil {
			s.dropAndClose(sub)
			return
		}
	}
	// Replay is complete (or there was nothing to replay). Hand off to the drain
	// goroutine, which flushes anything that buffered during replay and then
	// streams live bytes. If the tailer lagged so badly during replay that
	// write() already dropped it, sub.ch is closed and drain exits at once.
	sub.drain()
}

// dropAndClose deregisters sub (if write()/close() hasn't already) and closes
// its conn, draining any buffered chunks so a concurrent write() never blocks.
func (s *session) dropAndClose(sub *subscriber) {
	if s.remove(sub) {
		for range sub.ch { // we closed the channel; drain residual sends
		}
	}
	close(sub.done)
	_ = sub.conn.Close()
}

func (s *session) close() error {
	s.mu.Lock()
	s.done = true
	var err error
	if s.f != nil {
		if syncErr := s.f.Sync(); syncErr != nil {
			err = syncErr
		}
		if closeErr := s.f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		s.f = nil
	}
	subs := make([]*subscriber, 0, len(s.subs))
	for c, sub := range s.subs {
		subs = append(subs, sub)
		delete(s.subs, c)
		close(sub.ch) // stop the drain goroutine
	}
	s.mu.Unlock()
	// Close conns and wait for drain goroutines outside the lock so a slow conn
	// can't hold s.mu (which the recorder needs).
	for _, sub := range subs {
		_ = sub.conn.Close()
		<-sub.done
	}
	return err
}

type registry struct {
	mu        sync.RWMutex // RWMutex: concurrent reads (tail) don't block each other
	live      map[string]sessionRef
	key       []byte         // at-rest encryption key
	connCount map[uint32]int // per-UID connection count
	cap       int            // per-UID concurrent session cap; updatable on SIGHUP

	connMu sync.Mutex            // guards conns; separate from mu (held during blocking shutdown close)
	conns  map[net.Conn]struct{} // currently-handled conns, for shutdown force-close
	wg     sync.WaitGroup        // tracks handler + ingest goroutines for bounded shutdown
}

// trackConn registers c as an in-flight handler connection so shutdown can force
// it closed (unblocking a recorder's Read or a tailer's io.Copy).
func (r *registry) trackConn(c net.Conn) {
	r.connMu.Lock()
	if r.conns == nil {
		r.conns = map[net.Conn]struct{}{}
	}
	r.conns[c] = struct{}{}
	r.connMu.Unlock()
}

// untrackConn removes c once its handler returns.
func (r *registry) untrackConn(c net.Conn) {
	r.connMu.Lock()
	delete(r.conns, c)
	r.connMu.Unlock()
}

// closeConns force-closes every in-flight handler connection. Called on ctx
// cancel so recorders blocked in Read and tailers blocked in io.Copy unblock and
// their handlers return, letting Run wait on the WaitGroup and exit promptly.
func (r *registry) closeConns() {
	r.connMu.Lock()
	for c := range r.conns {
		_ = c.Close()
	}
	r.connMu.Unlock()
}

type sessionRef struct {
	sess *session
	path string
}

// add registers a live session under id, returning false WITHOUT overwriting if
// id is already live. The id is <timestamp.ns>-<pid> derived from the verified
// peer pid, so a collision is not normally reachable (a pid hosts one process at
// a time); the guard ensures that even under an unforeseen collision we reject
// the newcomer rather than silently clobber the map entry of an in-progress
// session — which would orphan its file handle and subscribers and make its id
// resolve to the wrong recording for tailers.
func (r *registry) add(id string, s *session, path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.live[id]; exists {
		return false
	}
	r.live[id] = sessionRef{s, path}
	return true
}

func (r *registry) remove(id string) {
	r.mu.Lock()
	delete(r.live, id)
	r.mu.Unlock()
}

func (r *registry) get(id string) (sessionRef, bool) {
	r.mu.RLock()
	ref, ok := r.live[id]
	r.mu.RUnlock()
	return ref, ok
}

// reserve atomically claims a session slot for uid if it is under the cap,
// returning false (and reserving nothing) when the cap is reached.
func (r *registry) reserve(uid uint32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connCount[uid] >= r.cap {
		return false
	}
	r.connCount[uid]++
	return true
}

// release returns a previously reserved slot for uid. The map entry is deleted
// when the count reaches zero so connCount doesn't grow unbounded with the set
// of UIDs ever seen; a defensive guard prevents underflow on an unbalanced
// release.
func (r *registry) release(uid uint32) {
	r.mu.Lock()
	if n := r.connCount[uid]; n > 1 {
		r.connCount[uid] = n - 1
	} else {
		delete(r.connCount, uid)
	}
	r.mu.Unlock()
}

// setCap updates the per-UID session cap under the lock. It is called from the
// SIGHUP handler so an edited config takes effect without a daemon restart.
func (r *registry) setCap(c int) {
	r.mu.Lock()
	r.cap = c
	r.mu.Unlock()
}

// backupConfigChanged reports whether any backup-relevant field differs.
// Pure helper — no I/O — so it can be unit-tested without goroutines.
func backupConfigChanged(prev, nc *config.Config) bool {
	return prev.BackupType != nc.BackupType ||
		prev.BackupTarget != nc.BackupTarget ||
		prev.BackupIntervalSec != nc.BackupIntervalSec
}

// Run starts the daemon: ingests stray user-local recordings, then serves the
// unix socket until ctx is cancelled or the process is terminated. cfg supplies
// the initial socket path and per-UID session cap. reload, if non-nil, delivers
// freshly-parsed configs (e.g. from a SIGHUP handler); each one re-applies the
// safely-reloadable fields (log level, session cap) without a restart.
func Run(ctx context.Context, cfg *config.Config, reload <-chan *config.Config) error {
	socketPath := cfg.SocketPath
	if err := os.MkdirAll(store.CentralDir(), 0o700); err != nil {
		return fmt.Errorf("create central dir: %w", err)
	}
	// Enforce root-only perms even if the dir pre-existed with looser modes.
	if err := os.Chmod(store.CentralDir(), 0o700); err != nil {
		return fmt.Errorf("chmod central dir: %w", err)
	}

	key, err := ensureKey()
	if err != nil {
		return err
	}

	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", socketPath, err)
	}
	// Any user may connect to be recorded; access control on the *files* is
	// what enforces root-only reads.
	if err := os.Chmod(socketPath, 0o666); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	reg := &registry{
		live:      map[string]sessionRef{},
		key:       key,
		connCount: map[uint32]int{},
		conns:     map[net.Conn]struct{}{},
		cap:       cfg.SessionCap,
	}

	// Start ingest after the socket is ready so connections aren't dropped
	// while a large spool is being processed. Tracked in the WaitGroup so a
	// mid-copy ingest can't race process exit.
	reg.wg.Add(1)
	go func() {
		defer reg.wg.Done()
		ingestLocalRecordings(key)
	}()
	backupCfgCh := make(chan *config.Config, 1)
	go backupLoop(ctx, cfg, backupCfgCh, backup.Run)

	// On context cancel, close the listener so Accept() unblocks, then force every
	// in-flight handler connection closed so recorders mid-write and tailers
	// unblock and their goroutines return.
	go func() {
		<-ctx.Done()
		ln.Close()
		reg.closeConns()
	}()

	logger.Infof("ghostshell-daemon: listening on %s, storing in %s (encrypted)", socketPath, store.CentralDir())

	// Apply hot-reloadable config on SIGHUP-delivered configs. socket_path and
	// central_dir cannot change at runtime — they require a restart.
	if reload != nil {
		go func() {
			prevBackupType := cfg.BackupType
			prevBackupTarget := cfg.BackupTarget
			prevBackupIntervalSec := cfg.BackupIntervalSec
			for {
				select {
				case <-ctx.Done():
					return
				case nc, ok := <-reload:
					if !ok {
						return
					}
					logger.Set(logger.Level(nc.LogLevel))
					reg.setCap(nc.SessionCap)
					logger.Infof("ghostshell-daemon: config reloaded (SIGHUP): log_level=%d session_cap=%d", nc.LogLevel, nc.SessionCap)
					if nc.SocketPath != socketPath || nc.CentralDir != store.CentralDir() {
						logger.Infof("ghostshell-daemon: socket_path / central_dir changes require a restart to take effect")
					}
					if backupConfigChanged(
						&config.Config{BackupType: prevBackupType, BackupTarget: prevBackupTarget, BackupIntervalSec: prevBackupIntervalSec},
						nc,
					) {
						select {
						case backupCfgCh <- nc:
						default:
							// A reload is already queued; the latest config will be received on next tick.
						}
						prevBackupType = nc.BackupType
						prevBackupTarget = nc.BackupTarget
						prevBackupIntervalSec = nc.BackupIntervalSec
						logger.Infof("ghostshell-daemon: backup config reloaded (type=%s target=%s interval=%ds)",
							nc.BackupType, nc.BackupTarget, nc.BackupIntervalSec)
					}
				}
			}
		}()
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.Infof("ghostshell-daemon: shutting down")
				break
			}
			// Out of file descriptors (EMFILE/ENFILE): transient. Back off briefly
			// instead of exiting, so a momentary fd shortage neither kills the
			// daemon nor busy-spins the accept loop.
			if isFDExhaustion(err) {
				logger.Warnf("ghostshell-daemon: accept: fd exhaustion (%v) — backing off %s", err, acceptBackoff)
				time.Sleep(acceptBackoff)
				continue
			}
			// Other transient errors (e.g. EINTR/EAGAIN): log and retry.
			if isTemporary(err) {
				logger.Warnf("ghostshell-daemon: accept (retrying): %v", err)
				continue
			}
			return fmt.Errorf("ghostshell-daemon: accept fatal: %w", err)
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			// Should never happen with a unix listener, but guard the cast.
			logger.Errorf("ghostshell-daemon: unexpected conn type %T", conn)
			_ = conn.Close()
			continue
		}
		reg.wg.Add(1)
		go func() {
			defer reg.wg.Done()
			handle(uc, reg)
		}()
	}

	// Graceful shutdown: conns were force-closed by the ctx.Done goroutine, so
	// handlers (and ingest) should return promptly. Wait, bounded, so a wedged
	// handler can't hang process exit indefinitely.
	done := make(chan struct{})
	go func() {
		reg.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownGrace):
		logger.Warnf("ghostshell-daemon: shutdown grace (%s) elapsed with handlers still running", shutdownGrace)
	}
	return nil
}

func handle(conn *net.UnixConn, reg *registry) {
	// Track the conn so shutdown can force it closed (and untrack on return).
	reg.trackConn(conn)
	defer reg.untrackConn(conn)
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("ghostshell-daemon: panic in handle: %v", r)
		}
	}()

	cred, err := peerCred(conn)
	if err != nil || cred == nil {
		return
	}

	// Bound the handshake: the socket is world-connectable (0666), so without a
	// read deadline a local user could connect, send no newline, and pin this
	// goroutine+fd forever (slowloris) before the per-UID cap is consulted.
	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	// Valid handshake read; clear the deadline so the (potentially long-lived)
	// recording / tail stream isn't subject to it.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	line = strings.TrimSpace(line)

	switch {
	case line == "REC":
		handleRec(conn, br, cred, reg)
	case strings.HasPrefix(line, "TAIL "):
		handleTail(conn, strings.TrimSpace(line[5:]), cred, reg)
	case strings.HasPrefix(line, "ANSIBLE "):
		handleAnsible(conn, br, strings.TrimSpace(line[8:]), cred, reg)
	default:
		_, _ = conn.Write([]byte("ERR unknown command\n"))
	}
}

func handleRec(conn *net.UnixConn, br *bufio.Reader, cred *unix.Ucred, reg *registry) {
	if !reg.reserve(cred.Uid) {
		_, _ = conn.Write([]byte("ERR too many sessions\n"))
		return
	}
	defer reg.release(cred.Uid)

	uname := lookupUser(cred.Uid)
	dir := store.UserDir(uname)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.Chmod(dir, 0o700)

	id := fmt.Sprintf("%s-%d", time.Now().Format("20060102T150405.000000000"), cred.Pid)
	path := store.CastPath(uname, id)
	// O_EXCL|O_NOFOLLOW: never follow a symlink planted at the target, and never
	// truncate/clobber an existing file. The id is <timestamp.ns>-<pid> from the
	// verified peer pid so a collision is not normally reachable, but O_EXCL makes
	// the guarantee structural: if two handlers ever raced to the same path, the
	// loser fails to open (EEXIST) instead of O_TRUNC-ing the winner's in-progress
	// recording out from under it. (Replaces the old O_TRUNC, which could corrupt a
	// live session's file on an unforeseen id collision.)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		logger.Errorf("ghostshell-daemon: open session file %s: %v", path, err)
		_, _ = conn.Write([]byte("ERR session file unavailable\n"))
		return
	}
	enc, err := crypto.NewWriter(f, reg.key)
	if err != nil {
		f.Close()
		return
	}

	sess := &session{f: f, enc: enc, subs: map[net.Conn]*subscriber{}}
	// Reject (don't clobber) if the id is somehow already live: the file is closed
	// and removed so a rejected handler leaves nothing behind.
	if !reg.add(id, sess, path) {
		logger.Warnf("ghostshell-daemon: session id collision %s — rejecting", id)
		_ = f.Close()
		_ = os.Remove(path)
		_, _ = conn.Write([]byte("ERR session id collision\n"))
		return
	}
	logger.Infof("ghostshell-daemon: session started  user=%-20s id=%s", uname, id)
	var totalBytes int64
	defer func() {
		if err := sess.close(); err != nil {
			logger.Warnf("ghostshell-daemon: close %s: %v", path, err)
		}
		reg.remove(id)
		logger.Infof("ghostshell-daemon: session closed   user=%-20s id=%s bytes=%d", uname, id, totalBytes)
	}()

	buf := make([]byte, 32*1024)
	for {
		n, rerr := br.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
			if err := sess.write(buf[:n]); err != nil {
				logger.Warnf("ghostshell-daemon: write %s (uid=%d): %v — session truncated", path, cred.Uid, err)
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func handleTail(conn *net.UnixConn, id string, cred *unix.Ucred, reg *registry) {
	if cred.Uid != 0 {
		_, _ = conn.Write([]byte("ERR tail requires root\n"))
		return
	}
	id = strings.TrimSuffix(id, ".cast")
	ref, ok := reg.get(id)
	if !ok {
		_, _ = conn.Write([]byte("ERR no active session " + id + "\n"))
		return
	}
	// addTailer replays the recorded prefix, then drains live bytes inline; it
	// returns when the recorder ends (session.close() closes our channel) or the
	// tailer's conn write fails (disconnect). A final drain of any client-sent
	// bytes lets the conn close cleanly.
	ref.sess.addTailer(conn, ref.path)
	_, _ = io.Copy(io.Discard, conn)
}

// handleAnsible stores an Ansible playbook run from `ghostshell ansible-ingest`.
// The run id is already validated by the ingest process but we re-validate
// here before using it as a path component.
func handleAnsible(conn *net.UnixConn, br *bufio.Reader, runID string, cred *unix.Ucred, reg *registry) {
	if !ansible.ValidRunID(runID) {
		_, _ = conn.Write([]byte("ERR invalid ansible run id\n"))
		return
	}

	// Apply the same per-UID reservation as handleRec so a user can't open
	// unbounded concurrent ANSIBLE streams (an ingest counts against the cap).
	if !reg.reserve(cred.Uid) {
		_, _ = conn.Write([]byte("ERR too many sessions\n"))
		return
	}
	defer reg.release(cred.Uid)

	uname := lookupUser(cred.Uid)
	dir := store.AnsibleDir(uname)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.Chmod(dir, 0o700)

	path := store.AnsiblePath(uname, runID)
	// O_EXCL: a duplicate (client-controlled) runID must not truncate/clobber an
	// already-stored run. O_NOFOLLOW: don't follow a symlink planted at the
	// target. EEXIST therefore means "already stored" — reject rather than
	// overwrite.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			logger.Warnf("ghostshell-daemon: ansible run %s already stored — refusing to overwrite", runID)
			_, _ = conn.Write([]byte("ERR ansible run already stored\n"))
			return
		}
		logger.Errorf("ghostshell-daemon: open ansible file %s: %v", path, err)
		_, _ = conn.Write([]byte("ERR ansible file unavailable\n"))
		return
	}
	enc, err := crypto.NewWriter(f, reg.key)
	if err != nil {
		f.Close()
		return
	}
	logger.Infof("ghostshell-daemon: ansible run started user=%-20s run=%s", uname, runID)

	var ansibleBytes int64
	var writeErr error
	buf := make([]byte, 32*1024)
	for {
		n, rerr := br.Read(buf)
		if n > 0 {
			ansibleBytes += int64(n)
			if _, werr := enc.Write(buf[:n]); werr != nil {
				writeErr = werr
				break
			}
		}
		if rerr != nil {
			break
		}
	}

	// Surface a Sync/Close failure: a discarded fsync error can mean the run was
	// not durably persisted, so downgrade the "stored" line to a warning.
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		logger.Warnf("ghostshell-daemon: ansible run NOT fully stored user=%-20s run=%s bytes=%d (write=%v sync=%v close=%v)",
			uname, runID, ansibleBytes, writeErr, syncErr, closeErr)
		return
	}
	logger.Infof("ghostshell-daemon: ansible run stored  user=%-20s run=%s bytes=%d", uname, runID, ansibleBytes)
}

func peerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

func lookupUser(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil || u.Username == "" {
		return strconv.FormatUint(uint64(uid), 10)
	}
	// Validate username is safe to use as a path component.
	uname := u.Username
	for _, c := range uname {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return strconv.FormatUint(uint64(uid), 10)
		}
	}
	if uname == "." || uname == ".." || strings.HasPrefix(uname, ".") || strings.Contains(uname, "/") {
		return strconv.FormatUint(uint64(uid), 10)
	}
	return uname
}

// ensureKey loads the at-rest key, creating it on first run. It refuses to
// create a new key when recordings already exist (a new key would make them
// permanently unreadable) — the operator must restore the original key.
func ensureKey() ([]byte, error) {
	kp := store.KeyPath()
	data, err := os.ReadFile(kp)
	if err == nil {
		if len(data) != crypto.KeySize {
			return nil, fmt.Errorf("key %s has wrong size %d", kp, len(data))
		}
		setImmutable(kp) // best-effort; idempotent
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key %s: %w", kp, err)
	}
	if encryptedRecordingsExist() {
		return nil, fmt.Errorf("encryption key %s is missing but ENCRYPTED recordings exist in %s; "+
			"restore the original key — refusing to start (a new key would make them permanently unreadable)",
			kp, store.CentralDir())
	}
	key, gerr := crypto.GenerateKey()
	if gerr != nil {
		return nil, gerr
	}
	if werr := os.WriteFile(kp, key, 0o600); werr != nil {
		return nil, fmt.Errorf("write key %s: %w", kp, werr)
	}
	_ = os.Chmod(kp, 0o600)
	setImmutable(kp) // protect from rm/vi/sed/>/tee even by root (until chattr -i)
	logger.Infof("ghostshell-daemon: created NEW encryption key at %s — BACK IT UP NOW. "+
		"Losing it makes every recording permanently unreadable.", kp)
	return key, nil
}

// setImmutable sets the FS immutable flag (chattr +i) on path so it cannot be
// modified, deleted, or renamed — even by root — until `chattr -i`. Best-effort:
// silently skips on filesystems that do not support it.
func setImmutable(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return // e.g. EOPNOTSUPP / ENOTTY on unsupported fs
	}
	const fsImmutableFL = 0x00000010 // FS_IMMUTABLE_FL (stable kernel ABI)
	if flags&fsImmutableFL != 0 {
		return // already immutable
	}
	_ = unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, flags|fsImmutableFL)
}

// encryptedRecordingsExist reports whether any central cast is already
// encrypted (magic-prefixed). Plaintext recordings from before encryption was
// enabled do not need a key and are not a reason to refuse startup.
func encryptedRecordingsExist() bool {
	users, err := store.Users()
	if err != nil {
		return false
	}
	for _, u := range users {
		names, _ := store.UserSessions(u)
		for _, n := range names {
			f, err := os.Open(filepath.Join(store.UserDir(u), n))
			if err != nil {
				continue
			}
			magic := make([]byte, len(crypto.Magic))
			if _, err := io.ReadFull(f, magic); err != nil {
				f.Close()
				continue // unreadable file — skip
			}
			f.Close()
			if crypto.MagicVersion(magic) != 0 {
				return true
			}
		}
	}
	return false
}

// ingestLocalRecordings sweeps per-user local recordings into the central
// store on startup, encrypting them so sessions recorded while the daemon was
// down become root-only. Source files are removed after a successful copy.
func ingestLocalRecordings(key []byte) {
	for _, home := range homeDirs() {
		ingestHome(home, key)
	}
}

// homeDirs returns the set of home directories to sweep for stray local
// recordings. It enumerates real accounts from /etc/passwd (covering LDAP/SSSD
// homes under /var/home, service accounts, etc.) and always includes /root.
// If /etc/passwd can't be read it falls back to the old /root + /home/* scan.
func homeDirs() []string {
	if content, err := os.ReadFile("/etc/passwd"); err == nil {
		return homeDirsFromPasswd(content)
	}
	homes := []string{"/root"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				homes = append(homes, filepath.Join("/home", e.Name()))
			}
		}
	}
	return homes
}

// homeDirsFromPasswd extracts the absolute home directories (field 6) from
// /etc/passwd content. /root is always included; results are deduped and
// malformed/relative entries are skipped. It is pure so it can be unit-tested.
func homeDirsFromPasswd(content []byte) []string {
	seen := map[string]struct{}{"/root": {}}
	homes := []string{"/root"}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		home := fields[5]
		if !strings.HasPrefix(home, "/") {
			continue
		}
		if _, ok := seen[home]; ok {
			continue
		}
		seen[home] = struct{}{}
		homes = append(homes, home)
	}
	return homes
}

func ingestHome(home string, key []byte) {
	uname := filepath.Base(home)
	src := filepath.Join(home, ".local", "share", "ghostshell")
	entries, err := os.ReadDir(src)
	if err != nil {
		return
	}
	dstDir := store.UserDir(uname)
	for _, e := range entries {
		if !ingestible(e) || store.IsActive(e.Name()) {
			continue
		}
		if err := os.MkdirAll(dstDir, 0o700); err != nil {
			continue
		}
		sp := filepath.Join(src, e.Name())
		if copyFile(sp, filepath.Join(dstDir, e.Name()), key) == nil {
			_ = os.Remove(sp)
		}
	}
}

// ingestible reports whether a local directory entry is a completed recording
// safe to sweep into the central store. It admits only regular .cast files and
// rejects:
//   - directories and non-regular entries (symlinks, fifos, devices), so a user
//     can't redirect the root ingest at an arbitrary target via the dir listing
//     (copyFile re-checks with O_NOFOLLOW, but skipping here avoids the attempt);
//   - dotfiles and any name carrying a partial/temp marker (".tmp"/".part"),
//     which is the convention for an atomic temp+rename in-progress write — such
//     a file may be incomplete (or about to be renamed away) and must never be
//     ingested mid-write nor deleted out from under the writer.
func ingestible(e os.DirEntry) bool {
	name := e.Name()
	if !e.Type().IsRegular() {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return false // hidden/temp dotfile (e.g. ".rec.cast.tmp" or a partial)
	}
	if filepath.Ext(name) != ".cast" {
		return false // not a recording (covers ".cast.tmp" / ".part" temp suffixes)
	}
	return true
}

// copyFileAfterCopy is a test hook fired after the bytes are copied but before
// the post-copy re-check, used to simulate the source changing mid-copy. nil in
// production.
var copyFileAfterCopy func()

// backupTickUnit is multiplied by BackupIntervalSec to produce the ticker
// interval. Tests override this to time.Millisecond for fast ticks.
var backupTickUnit = time.Second

// backupLoop runs the periodic backup goroutine. A nil tickC (when backup is
// disabled) is never selected, so the loop parks cheaply on ctx.Done() and
// updates only. Reload via the updates channel resets the ticker.
func backupLoop(
	ctx context.Context,
	initial *config.Config,
	updates <-chan *config.Config,
	runFn func(context.Context, *config.Config) error,
) {
	cur := initial
	var ticker *time.Ticker
	var tickC <-chan time.Time

	resetTicker := func(cfg *config.Config) {
		if ticker != nil {
			ticker.Stop()
			ticker = nil
			tickC = nil
		}
		if cfg.BackupIntervalSec > 0 && cfg.BackupType != "" {
			ticker = time.NewTicker(time.Duration(cfg.BackupIntervalSec) * backupTickUnit)
			tickC = ticker.C
		}
	}
	resetTicker(cur)
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case nc, ok := <-updates:
			if !ok {
				return
			}
			cur = nc
			resetTicker(cur)
		case <-tickC:
			if err := runFn(ctx, cur); err != nil {
				logger.Errorf("ghostshell-daemon: backup failed: %v", err)
			} else {
				logger.Infof("ghostshell-daemon: backup completed (type=%s target=%s)", cur.BackupType, cur.BackupTarget)
			}
		}
	}
}

// copyFile copies a user-owned plaintext source into the root-only central
// store, encrypting it. The source is opened O_NOFOLLOW and verified to be a
// regular file, so a user cannot symlink a recording at a root-readable target
// (e.g. /etc/shadow) and have the root daemon copy it into the central store.
//
// To avoid capturing a truncated in-progress recording, copyFile snapshots the
// source size up front and re-checks after copying: if the recording became
// active again or its size changed, the partial destination is removed and an
// error is returned so the caller leaves the source for a later run.
func copyFile(src, dst string, key []byte) (retErr error) {
	in, err := os.OpenFile(src, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err // ELOOP if src is a symlink
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("ingest: %s is not a regular file", src)
	}
	startSize := fi.Size()
	// Write atomically: encrypt into a temp file in the destination directory,
	// fsync it, then rename into place. A crash mid-ingest can therefore never
	// leave a partial, readable <id>.cast visible in the central store, and a
	// concurrent reader (e.g. root running `ghostshell play <id>`) never observes a
	// half-written file. store.WriteFileAtomic removes the temp on any error.
	dir, name := filepath.Split(dst)
	return store.WriteFileAtomic(dir, name, 0o600, func(w io.Writer) error {
		enc, err := crypto.NewWriter(w, key)
		if err != nil {
			return err
		}
		if _, err := io.Copy(enc, in); err != nil {
			return err
		}
		if copyFileAfterCopy != nil {
			copyFileAfterCopy()
		}
		// Re-check: a recording that became active again, or whose size changed
		// during the copy, may have been captured truncated — skip it this run.
		if store.IsActive(filepath.Base(src)) {
			return fmt.Errorf("ingest: %s became active during copy — skipping", src)
		}
		cur, err := in.Stat()
		if err != nil {
			return err
		}
		if cur.Size() != startSize {
			return fmt.Errorf("ingest: %s size changed during copy (%d -> %d) — skipping",
				src, startSize, cur.Size())
		}
		return nil
	})
}
