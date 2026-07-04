// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package store manages where recordings live and how they are listed.
//
// Two locations exist:
//   - user-local: $GHOSTSHELL_DIR or ~/.local/share/ghostshell (fallback when the
//     daemon is down; later swept into the central store).
//   - central:    $GHOSTSHELL_CENTRAL_DIR or /var/lib/ghostshell, root:root 0700,
//     per-user subdirs, files 0600 — only root can read these.
package store

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ghostshell/internal/cast"
	"ghostshell/internal/config"
	"ghostshell/internal/crypto"
	"golang.org/x/term"
)

// safeComponent reports whether s is safe to use as a single path component
// (a username or session id) when joined onto the central store root. It
// rejects empty, ".", "..", and anything containing a path separator so a
// value taken from CLI args or an attacker-controlled directory name cannot
// escape the central store via traversal. A local copy lives here to avoid an
// import cycle with internal/ansible.
func safeComponent(s string) bool {
	return s != "" && s != "." && s != ".." &&
		!strings.ContainsAny(s, "/\\") && filepath.Base(s) == s
}

// Dir returns the user-local recordings directory.
func Dir() string {
	if d := os.Getenv("GHOSTSHELL_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ghostshell"
	}
	return filepath.Join(home, ".local", "share", "ghostshell")
}

// CentralDir returns the central root-only recordings directory.
func CentralDir() string {
	return config.Load().CentralDir
}

// KeyPath returns the at-rest encryption key path (root-only).
func KeyPath() string {
	return config.Load().ResolvedKeyFile()
}

type castReadCloser struct {
	io.Reader
	f *os.File
}

func (c *castReadCloser) Close() error { return c.f.Close() }

// OpenCast opens a cast file for reading, transparently decrypting it if it is
// an encrypted (magic-prefixed) file. Reads follow the file to its end,
// including data appended after opening (used by live tail).
func OpenCast(path string) (io.ReadCloser, error) {
	return openCast(path, false)
}

// OpenCastSnapshot is like OpenCast but bounded to the file's size at open
// time, so replaying an in-progress recording stops at the point playback
// began instead of following (and never finishing) a still-growing session.
func OpenCastSnapshot(path string) (io.ReadCloser, error) {
	return openCast(path, true)
}

func openCast(path string, snapshot bool) (io.ReadCloser, error) {
	// O_NOFOLLOW: a recording in a central user dir that is actually a symlink
	// (planted by the user) must not redirect a root read at an arbitrary
	// target. The open fails with ELOOP if the final component is a symlink.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, serr := f.Stat()
	if serr != nil {
		f.Close()
		return nil, serr
	}
	// Refuse anything that is not a regular file (e.g. a fifo or device that
	// slipped past O_NOFOLLOW because it is not a symlink itself).
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	var size int64 = -1
	if snapshot {
		size = fi.Size()
	}
	magic := make([]byte, len(crypto.Magic))
	n, merr := io.ReadFull(f, magic)
	if merr != nil && !errors.Is(merr, io.EOF) && !errors.Is(merr, io.ErrUnexpectedEOF) {
		// A short read (EOF/ErrUnexpectedEOF) just means a file smaller than
		// the magic prefix — treat it as plaintext below. Any other error is a
		// real I/O failure and must be surfaced rather than silently masked.
		f.Close()
		return nil, merr
	}
	if ver := crypto.MagicVersion(magic[:n]); ver != 0 {
		key, kerr := readDecryptKey()
		if kerr != nil {
			f.Close()
			return nil, kerr
		}
		var src io.Reader = f
		if size >= 0 {
			// Both magics are the same length; the V2 stream id sits within the
			// limited region and is consumed by the reader.
			src = io.LimitReader(f, size-int64(len(crypto.Magic)))
		}
		// V2 carries a 16-byte stream id and binds each frame with AAD; a legacy
		// V1 file has neither.
		var dr io.Reader
		var derr error
		if ver == 2 {
			dr, derr = crypto.NewReaderV2(src, key)
		} else {
			dr, derr = crypto.NewReader(src, key)
		}
		// The cipher has copied/expanded the key into its own internal round-key
		// state, so the original key bytes read from disk are no longer needed.
		// Wipe this locally-owned buffer so the raw at-rest key does not linger in
		// the process heap for the lifetime of the (possibly long-lived) reader.
		zero(key)
		if derr != nil {
			f.Close()
			return nil, derr
		}
		return &castReadCloser{Reader: dr, f: f}, nil
	}
	// Plaintext: rewind and hand back the raw file (bounded if snapshot).
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if size >= 0 {
		return &castReadCloser{Reader: io.LimitReader(f, size), f: f}, nil
	}
	return f, nil
}

// zero overwrites b with zeros. Used to wipe a locally-owned copy of the
// at-rest encryption key once the cipher has consumed it, so the raw key does
// not remain readable in the process heap.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// WriteFileAtomic writes the bytes produced by write into a file at
// filepath.Join(dir, name) atomically: it writes to a temp file in the SAME
// directory (so the final os.Rename is a same-filesystem, atomic operation),
// fsyncs the file's contents and then the directory entry, and only then
// renames it into place. A crash at any point leaves either the old file or no
// file under name — never a half-written, ingestable partial. The temp file is
// removed on any error. perm is applied to the final file.
//
// This is the atomic-write primitive for the fail-open ingest path: a recording
// copied into the central store (or written user-locally) must never become
// visible under its real name until it is complete and durable.
func WriteFileAtomic(dir, name string, perm os.FileMode, write func(io.Writer) error) (retErr error) {
	if !safeComponent(name) {
		return fmt.Errorf("invalid file name %q", name)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// On any error path, close (best-effort) and remove the temp file so a failed
	// write never leaves a stray partial behind.
	defer func() {
		if retErr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := write(tmp); err != nil {
		return err
	}
	// fsync the data before the rename: a rename can otherwise be persisted while
	// the file's contents are still only in the page cache, yielding a visible
	// but empty/partial file after a crash.
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmpName, final); err != nil {
		return err
	}
	// fsync the directory so the rename itself is durable.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// readDecryptKey reads the at-rest encryption key after verifying it is a
// regular file owned by root with no group/other permission bits. The key
// decrypts every recording in the central store, so a key that is world- or
// group-readable, or owned by a non-root user, may have been tampered with or
// swapped and must not be trusted to decrypt root-readable data.
func readDecryptKey() ([]byte, error) {
	kp := KeyPath()
	fi, err := os.Lstat(kp)
	if err != nil {
		return nil, fmt.Errorf("cannot stat decryption key %s: %w", kp, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("decryption key %s is not a regular file", kp)
	}
	// Reject any group/other bits: the key must be 0600 (or stricter).
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("decryption key %s has insecure mode %#o (want 0600)", kp, perm)
	}
	// The key must be owned by root (the production owner) or by the process's
	// own effective user. A key owned by some other unprivileged user could
	// have been planted to coerce a decryption with an attacker-chosen key.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && uint64(st.Uid) != uint64(os.Geteuid()) {
			return nil, fmt.Errorf("decryption key %s must be owned by root (uid 0), got uid %d", kp, st.Uid)
		}
	}
	return os.ReadFile(kp)
}

// NewPath returns an auto-named cast path in the user-local dir, creating it.
func NewPath() (string, error) {
	d := Dir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(d, NewName()), nil
}

// NewName returns an auto-generated cast filename: <timestamp>-<pid>.cast.
func NewName() string {
	return fmt.Sprintf("%s-%d.cast", time.Now().Format("20060102T150405.000000000"), os.Getpid())
}

// List prints user-local recordings (the personal view).
func List(args []string) error {
	d := Dir()
	files, err := castsIn(d)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("no recordings yet (dir: %s)\n", d)
			return nil
		}
		return err
	}
	if len(files) == 0 {
		fmt.Printf("no recordings in %s\n", d)
		return nil
	}
	// Fixed cols: STATUS(7) + FILE(26) + STARTED(19) + DURATION(9) + separators(" │ " × 4 = 12) + leading " " = 64
	const fixedW = 64
	cmdW := termWidth() - fixedW
	if cmdW < 20 {
		cmdW = 20
	}
	cols := []TableCol{{Width: 7}, {Width: 26}, {Width: 19}, {Width: 9}, {Width: cmdW}}
	PrintTableHeader(cols, []string{"STATUS", "FILE", "STARTED", "DURATION", "COMMAND"})
	for _, name := range files {
		p := filepath.Join(d, name)
		h, herr := readHeader(p)
		status := "SAVED"
		dur := Duration(p)
		if isActive(name) {
			status = "ACTIVE"
			dur += "+"
		}
		command := trunc(h.Command, cmdW)
		if herr != nil {
			// Surface unreadable/corrupt recordings instead of silently
			// rendering blank columns (which looks like an empty session).
			status = "ERROR"
			command = trunc("(unreadable)", cmdW)
		}
		PrintTableRow(cols, []string{status, name, started(h), dur, command})
	}
	return nil
}

// Users lists usernames that have a directory in the central store.
func Users() ([]string, error) {
	entries, err := os.ReadDir(CentralDir())
	if err != nil {
		return nil, err
	}
	var users []string
	for _, e := range entries {
		// Skip directory names that are not safe single path components so a
		// crafted entry can never be used as a traversal segment downstream.
		if e.IsDir() && safeComponent(e.Name()) {
			users = append(users, e.Name())
		}
	}
	sort.Strings(users)
	return users, nil
}

// UserSessions lists the cast filenames for a user in the central store.
func UserSessions(user string) ([]string, error) {
	if !safeComponent(user) {
		return nil, fmt.Errorf("invalid user %q", user)
	}
	return castsIn(UserDir(user))
}

// FindCentral locates a session by id (filename or its stem) across all users
// in the central store. Returns the full path and the owning user.
func FindCentral(id string) (path, user string, err error) {
	id = strings.TrimSuffix(id, ".cast")
	// id is attacker-controlled (CLI arg) and is later used both for filename
	// comparison and as a path component (id+".ajsonl") under each user's
	// ansible dir; reject traversal/separator values up front so it can never
	// probe paths outside the central store.
	if !safeComponent(id) {
		return "", "", fmt.Errorf("invalid session id %q", id)
	}
	users, err := Users()
	if err != nil {
		return "", "", err
	}
	for _, u := range users {
		names, err := UserSessions(u)
		if err != nil {
			continue
		}
		for _, n := range names {
			if strings.TrimSuffix(n, ".cast") == id {
				return filepath.Join(UserDir(u), n), u, nil
			}
		}
	}
	// Check if the id matches an ansible run — give a useful hint.
	for _, u := range users {
		ansiblePath := AnsiblePath(u, id)
		if _, serr := os.Stat(ansiblePath); serr == nil {
			return "", "", fmt.Errorf("session %q is an Ansible run — use: ghostshell ansible show %s", id, id)
		}
	}
	return "", "", fmt.Errorf("session %q not found in %s", id, CentralDir())
}

func castsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".cast" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

func started(h cast.Header) string {
	if h.Timestamp > 0 {
		return time.Unix(h.Timestamp, 0).Format("2006-01-02 15:04:05")
	}
	return "?"
}

func readHeader(path string) (cast.Header, error) {
	rc, err := OpenCast(path)
	if err != nil {
		return cast.Header{}, err
	}
	defer rc.Close()
	return cast.ReadHeader(bufio.NewReader(rc))
}

// Header reads and returns a cast file's header (exported for CLI use).
func Header(path string) (cast.Header, error) { return readHeader(path) }

// Started formats a header's start time (exported for CLI use).
func Started(h cast.Header) string { return started(h) }

// Duration returns the recording's length formatted (e.g. "1m05s").
// For ACTIVE sessions it returns live elapsed time from the cast header's
// start timestamp so idle shells don't show a frozen "last activity" value.
// For completed sessions it returns the last event timestamp. "-" if unreadable.
func Duration(path string) string {
	rc, err := OpenCastSnapshot(path)
	if err != nil {
		return "-"
	}
	defer rc.Close()
	r := bufio.NewReader(rc)
	hdr, herr := cast.ReadHeader(r)
	if herr != nil {
		return "-"
	}
	// Stream events tracking only the last timestamp. This is intentionally
	// bounded-memory: events are read one line at a time via the bufio.Reader
	// and discarded, so duration of an arbitrarily large recording never
	// buffers the whole file.
	var last float64
	for {
		ev, rerr := cast.ReadEvent(r)
		if rerr != nil {
			break
		}
		last = ev.Time
	}
	// For ACTIVE sessions use wall-clock elapsed from the session start time
	// recorded in the cast header. The last-event offset is frozen whenever
	// the shell is idle, making it useless as a "duration so far" indicator.
	if isActive(path) && hdr.Timestamp > 0 {
		elapsed := time.Since(time.Unix(hdr.Timestamp, 0)).Seconds()
		if elapsed > last {
			return humanDuration(elapsed)
		}
	}
	return humanDuration(last)
}

func humanDuration(secs float64) string {
	if secs <= 0 {
		return "0s"
	}
	d := time.Duration(secs * float64(time.Second))
	h := int(d / time.Hour)
	m := int(d/time.Minute) % 60
	s := int(d/time.Second) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// isActive reports whether the recorder that created an auto-named file
// (<timestamp>-<pid>.cast) is still running. Linux-specific via /proc.
func isActive(name string) bool {
	base := strings.TrimSuffix(filepath.Base(name), ".cast")
	i := strings.LastIndex(base, "-")
	if i < 0 {
		return false
	}
	started, err := parseNameTime(base[:i])
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(base[i+1:])
	if err != nil {
		return false
	}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false
	}
	if strings.TrimSpace(string(comm)) != "ghostshell" {
		return false
	}
	procStarted, err := procStartTime(pid)
	if err != nil {
		return false
	}
	// Avoid false ACTIVE states after PID reuse. The recorder process should have
	// started shortly before the daemon-created session filename timestamp.
	return !procStarted.After(started.Add(5 * time.Second))
}

// IsActive is the exported form of isActive for CLI use.
func IsActive(name string) bool { return isActive(name) }

func parseNameTime(s string) (time.Time, error) {
	for _, layout := range []string{"20060102T150405.000000000", "20060102T150405"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid session timestamp %q", s)
}

func procStartTime(pid int) (time.Time, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return time.Time{}, err
	}
	endComm := strings.LastIndexByte(string(stat), ')')
	if endComm < 0 || endComm+2 >= len(stat) {
		return time.Time{}, fmt.Errorf("invalid proc stat for pid %d", pid)
	}
	fields := strings.Fields(string(stat[endComm+2:]))
	if len(fields) <= 19 {
		return time.Time{}, fmt.Errorf("missing proc start time for pid %d", pid)
	}
	startTicks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	btime, err := bootTime()
	if err != nil {
		return time.Time{}, err
	}
	// linuxClockTicks is USER_HZ — the number of scheduler ticks per second.
	// The accurate value requires sysconf(_SC_CLK_TCK) which needs CGO; 100 is
	// correct for virtually all Linux kernels (CONFIG_HZ=100 default) and is the
	// standard CGO-free approach used by procfs libraries.
	const linuxClockTicks = 100
	return btime.Add(time.Duration(startTicks) * time.Second / linuxClockTicks), nil
}

func bootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "btime" {
			secs, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(secs, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("missing btime in /proc/stat")
}

// termWidth returns the terminal width, or 120 if stdout is not a terminal.
func termWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 120
}

// trunc truncates s to at most n bytes, appending "…" if trimmed.
func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// TermWidth is the exported terminal width helper (used by audit and ansible packages).
func TermWidth() int { return termWidth() }

// Trunc is the exported truncate helper.
func Trunc(s string, n int) string { return trunc(s, n) }

// TableCol defines one column in a printed table.
type TableCol struct {
	Width int
}

// PrintTableHeader prints a header row with │ separators and a ─┼─ divider line.
func PrintTableHeader(cols []TableCol, headers []string) {
	parts := make([]string, len(cols))
	for i, h := range headers {
		parts[i] = fmt.Sprintf("%-*s", cols[i].Width, h)
	}
	fmt.Println(" " + strings.Join(parts, " │ "))
	seps := make([]string, len(cols))
	for i, c := range cols {
		seps[i] = strings.Repeat("─", c.Width)
	}
	fmt.Println("─" + strings.Join(seps, "─┼─") + "─")
}

// PrintTableRow prints one data row with │ separators.
func PrintTableRow(cols []TableCol, vals []string) {
	parts := make([]string, len(cols))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%-*s", cols[i].Width, v)
	}
	fmt.Println(" " + strings.Join(parts, " │ "))
}

// Recording/ansible file extensions, centralized so the on-disk naming
// convention lives in one place.
const (
	CastExt    = ".cast"
	AnsibleExt = ".ajsonl"
)

// UserDir returns a user's directory in the central store: <central>/<user>.
func UserDir(user string) string { return filepath.Join(CentralDir(), user) }

// CastPath returns the central path of a recording: <central>/<user>/<id>.cast.
func CastPath(user, id string) string { return filepath.Join(CentralDir(), user, id+CastExt) }

// AnsiblePath returns the central path of an ansible run log:
// <central>/<user>/ansible/<runid>.ajsonl.
func AnsiblePath(user, runID string) string { return filepath.Join(AnsibleDir(user), runID+AnsibleExt) }

// AnsibleDir returns the ansible sub-directory for a given user in the
// central store. Files are named <runid>.ajsonl and encrypted at rest.
func AnsibleDir(user string) string {
	return filepath.Join(CentralDir(), user, "ansible")
}

// AnsibleRuns returns the run ids (without .ajsonl extension) for a user,
// in the order returned by os.ReadDir (alphabetical / by timestamp prefix).
func AnsibleRuns(user string) ([]string, error) {
	dir := AnsibleDir(user)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ajsonl") {
			ids = append(ids, strings.TrimSuffix(e.Name(), ".ajsonl"))
		}
	}
	return ids, nil
}

// IsAnsibleRun reports whether id matches an ansible run in any user's ansible dir.
func IsAnsibleRun(id string) bool {
	// id is used as a path component below; a non-simple id could otherwise
	// turn this into a filesystem path-probe oracle.
	if !safeComponent(id) {
		return false
	}
	users, err := Users()
	if err != nil {
		return false
	}
	for _, u := range users {
		if _, serr := os.Stat(AnsiblePath(u, id)); serr == nil {
			return true
		}
	}
	return false
}
