// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package audit implements the root-only commands that read the central
// store: listing users and their sessions, replaying a session by id, live
// tailing an in-progress session, and a tree view.
package audit

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"ghostshell/internal/cast"
	"ghostshell/internal/config"
	"ghostshell/internal/play"
	"ghostshell/internal/span"
	"ghostshell/internal/store"
)

func daemonSocket() string {
	return config.Load().SocketPath
}

// geteuid is the effective-uid source. It is a var (not a direct os.Geteuid
// call) so tests can simulate running as root or as an unprivileged user when
// exercising the root-enforcement gate below.
var geteuid = os.Geteuid

// requireRoot is the defense-in-depth authorization gate for every command in
// this package that reads the central store. The central store is root:root
// 0700, so a non-root caller is already blocked by filesystem permissions; this
// explicit euid==0 check is a second, independent barrier so a misconfigured or
// loosened store directory (e.g. a relocated GHOSTSHELL_CENTRAL_DIR that is group/
// world-readable) cannot let an unprivileged user enumerate or decrypt another
// user's sessions by guessing ids. It must be called before any store access.
func requireRoot() error {
	if geteuid() != 0 {
		return fmt.Errorf("permission denied: this command reads the root-only central store %s and must be run as root", store.CentralDir())
	}
	return nil
}

func notRoot(err error) error {
	if os.IsPermission(err) || os.IsNotExist(err) {
		return fmt.Errorf("cannot read %s (run as root): %v", store.CentralDir(), err)
	}
	return err
}

// LsUser handles `ghostshell ls-user [username]`.
func LsUser(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 {
		users, err := store.Users()
		if err != nil {
			return notRoot(err)
		}
		if len(users) == 0 {
			fmt.Printf("no recorded users in %s\n", store.CentralDir())
			return nil
		}
		cols0 := []store.TableCol{{Width: 20}, {Width: 8}, {Width: 19}}
		store.PrintTableHeader(cols0, []string{"USER", "SESSIONS", "LAST ACTIVE"})
		for _, u := range users {
			s, _ := store.UserSessions(u)
			last := ""
			if len(s) > 0 {
				// Last session = last element (sorted by name = chronological)
				p := centralPath(u, s[len(s)-1])
				h, _ := store.Header(p)
				last = store.Started(h)
			}
			store.PrintTableRow(cols0, []string{u, fmt.Sprintf("%d", len(s)), last})
		}
		return nil
	}

	user := args[0]
	sessions, err := store.UserSessions(user)
	if err != nil {
		return notRoot(err)
	}
	if len(sessions) == 0 {
		fmt.Printf("no sessions for user %q\n", user)
		return nil
	}
	// Fixed cols: STATUS(7) + TYPE(11) + SESSION(26) + STARTED(19) + DURATION(9) + separators(14) = 86
	const fixedW = 86
	cmdW := store.TermWidth() - fixedW
	if cmdW < 20 {
		cmdW = 20
	}
	cols1 := []store.TableCol{{Width: 7}, {Width: 11}, {Width: 26}, {Width: 19}, {Width: 9}, {Width: cmdW}}
	store.PrintTableHeader(cols1, []string{"STATUS", "TYPE", "SESSION", "STARTED", "DURATION", "COMMAND"})
	for _, name := range sessions {
		p := centralPath(user, name)
		h, herr := store.Header(p)
		status := "SAVED"
		dur := store.Duration(p)
		if store.IsActive(name) {
			status = "ACTIVE"
			dur += "+"
		}
		if herr != nil {
			// Surface a corrupt/unreadable recording instead of a blank row.
			status = "ERROR"
			store.PrintTableRow(cols1, []string{status, "?", name, "?", dur, store.Trunc("(unreadable)", cmdW)})
			continue
		}
		typ := sessionKind(h.Command)
		if typ == "non-interactive" {
			typ = "cmd"
		}
		store.PrintTableRow(cols1, []string{status, typ, name, store.Started(h), dur, store.Trunc(h.Command, cmdW)})
	}
	return nil
}

// PlayUser handles `ghostshell play-user [--speed N] [--idle N] <sessionid>`.
func PlayUser(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("play-user", flag.ContinueOnError)
	speed := fs.Float64("speed", 1.0, "playback speed multiplier")
	idle := fs.Float64("idle", 0, "cap idle gaps to N seconds (default 0 = exact original timing)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ghostshell play-user [--speed N] [--idle N] <sessionid>")
	}
	path, user, err := store.FindCentral(fs.Arg(0))
	if err != nil {
		return notRoot(err)
	}
	fmt.Fprintf(os.Stderr, "--- session %s (user %s) ---\n", fs.Arg(0), user)
	return play.PlayFile(path, *speed, *idle)
}

// Export handles `ghostshell export [-o file] <sessionid>` — decrypts a central
// recording to a plaintext asciinema v2 cast (for offline use / `asciinema play`).
func Export(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	out := fs.String("o", "", "output file (default: stdout)")
	force := fs.Bool("force", false, "overwrite an existing output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ghostshell export [-o file] [--force] <sessionid>")
	}
	path, _, err := store.FindCentral(fs.Arg(0))
	if err != nil {
		return notRoot(err)
	}
	rc, err := store.OpenCast(path)
	if err != nil {
		return err
	}
	defer rc.Close()

	var w io.Writer = os.Stdout
	if *out != "" {
		// Decrypted plaintext can contain secrets, so create the file 0600
		// (never world-/group-readable via os.Create's 0644&umask) and refuse
		// to clobber an existing file unless --force is given.
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if *force {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		f, ferr := os.OpenFile(*out, flags, 0o600)
		if ferr != nil {
			if os.IsExist(ferr) {
				return fmt.Errorf("%s already exists (use --force to overwrite)", *out)
			}
			return ferr
		}
		defer f.Close()
		w = f
	}
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "exported plaintext cast to %s\n", *out)
	}
	return nil
}

// Status handles `ghostshell status` — a one-shot operational health summary of the
// central store and daemon (root). It reports:
//   - whether ghostshell-daemon is reachable right now (dialing its Unix socket),
//   - the number of active/in-progress recording sessions across all users,
//   - the total on-disk size of the central store.
//
// It is read-only and never decrypts a recording: it only stats files and reads
// directory listings, so it is cheap even on a large store.
func Status(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	sock := daemonSocket()
	reachable := daemonDialable(sock)

	users, err := store.Users()
	if err != nil {
		return notRoot(err)
	}

	var (
		totalSessions int
		activeCount   int
		totalSize     int64
	)
	for _, u := range users {
		names, _ := store.UserSessions(u)
		for _, n := range names {
			totalSessions++
			if store.IsActive(n) {
				activeCount++
			}
			if fi, e := os.Stat(centralPath(u, n)); e == nil {
				totalSize += fi.Size()
			}
		}
	}

	daemon := "no"
	if reachable {
		daemon = "yes"
	}
	fmt.Printf("%-22s = %s\n", "central_dir", store.CentralDir())
	fmt.Printf("%-22s = %s\n", "socket_path", sock)
	fmt.Printf("%-22s = %s\n", "daemon_reachable", daemon)
	fmt.Printf("%-22s = %d\n", "users", len(users))
	fmt.Printf("%-22s = %d\n", "sessions_total", totalSessions)
	fmt.Printf("%-22s = %d\n", "sessions_active", activeCount)
	fmt.Printf("%-22s = %s\n", "store_size", humanSize(totalSize))
	return nil
}

// daemonDialable reports whether ghostshell-daemon is currently listening on its socket.
// A successful dial (immediately closed) confirms a live listener; a stale
// socket with no listener fails with ECONNREFUSED.
func daemonDialable(socket string) bool {
	conn, err := net.DialTimeout("unix", socket, config.Load().DialTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Tree handles `ghostshell tree` and `ghostshell tree [--json] <session-id>`.
//
// With no positional argument it prints the whole central store as a
// users -> sessions tree (the original behavior, unchanged). With a
// <session-id> it prints that session's process tree: the commands captured by
// the trace shim, nested by the shell that ran each one, under a synthetic
// "bash (session root)". --json emits the same tree as a machine-readable JSON
// document (see jsonNode) and requires a <session-id>.
func Tree(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("tree", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit a session's process tree as JSON (requires <session-id>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		if *jsonOut {
			return fmt.Errorf("usage: ghostshell tree --json <session-id>  (--json needs a session id)")
		}
		return treeWholeStore()
	}
	return treeSession(fs.Arg(0), *jsonOut)
}

// treeWholeStore prints the central store as a users -> sessions tree — the
// no-argument `ghostshell tree` view. Output is byte-for-byte identical to the
// pre-extension behavior.
func treeWholeStore() error {
	users, err := store.Users()
	if err != nil {
		return notRoot(err)
	}
	fmt.Println(store.CentralDir())
	for ui, u := range users {
		ubranch, uindent := treeBranch(ui == len(users)-1)
		sessions, _ := store.UserSessions(u)
		fmt.Printf("%s %-20s  (%d sessions)\n", ubranch, u, len(sessions))
		printUserSessions(u, uindent)
	}
	return nil
}

func treeBranch(last bool) (mark, indent string) {
	if last {
		return "└─", "   "
	}
	return "├─", "│  "
}

func printUserSessions(user, indent string) {
	sessions, _ := store.UserSessions(user)
	for si, name := range sessions {
		sbranch, _ := treeBranch(si == len(sessions)-1)
		p := centralPath(user, name)
		h, herr := store.Header(p)
		status := "SAVED"
		dur := store.Duration(p)
		if store.IsActive(name) {
			status = "ACTIVE"
			dur += "+"
		}
		// Stem without .cast suffix, type abbreviation, no command (tree is for navigation not inspection)
		stem := strings.TrimSuffix(name, ".cast")
		if herr != nil {
			// Surface a corrupt/unreadable recording instead of a blank row.
			fmt.Printf("%s%s %-28s  %-6s %-5s  %s  %s\n",
				indent, sbranch, stem, "ERROR", "?", "(unreadable)", dur)
			continue
		}
		typ := "shell"
		if sessionKind(h.Command) == "non-interactive" {
			typ = "cmd"
		}
		started := store.Started(h)
		if len(started) > 16 {
			started = started[:16] // trim seconds: "2006-01-02 15:04"
		}
		fmt.Printf("%s%s %-28s  %-6s %-5s  %s  %s\n",
			indent, sbranch, stem, status, typ, started, dur)
	}
}

// sessionKind classifies a recording by its command: a bare shell is an
// interactive login; "<shell> -c ..." is a non-interactive command session.
func sessionKind(command string) string {
	if strings.Contains(command, " -c ") {
		return "non-interactive"
	}
	return "interactive"
}

// --- process-tree view (`ghostshell tree [--json] <session-id>`) -----------

// rootLabel is the synthetic root under which a session's top-level commands
// (spans with no parent) are grouped: the interactive shell itself.
const rootLabel = "bash (session root)"

// maxTreeDepth bounds every recursion over the process tree (sort, render, JSON
// build). The assembled tree is always finite, but capping recursion is a
// defensive guarantee that a corrupt or hostile span set can never exhaust the
// goroutine stack. Real interactive nesting is a handful of levels; 1000 is far
// beyond any legitimate trace.
const maxTreeDepth = 1000

// treeNode is one node of the in-memory process tree. span is nil for the
// synthetic root; every other node points at exactly one captured span.
type treeNode struct {
	span     *span.Span
	children []*treeNode
}

// jsonNode is the machine-readable process-tree node emitted by
// `ghostshell tree --json <session-id>`. It is a STABLE contract consumed by
// `analyze` (Part D) — do NOT rename or drop fields without updating that
// consumer. The whole document is the synthetic root node:
//
//	span_id      "" for the synthetic root; otherwise the span's globally-unique id
//	cmd          the recorded command line ("bash (session root)" for the root)
//	exit_code    the command's exit status (0 for the root)
//	start_ts     start time in unix nanoseconds (0 for the root)
//	end_ts       end time in unix nanoseconds (0 for the root)
//	duration_ns  end_ts - start_ts, clamped to >= 0 (0 for the root)
//	depth        recorded nesting depth (0 at the top interactive shell); -1 for the root
//	children     child nodes, always present (never null), sorted by start_ts ascending
type jsonNode struct {
	SpanID     string     `json:"span_id"`
	Cmd        string     `json:"cmd"`
	ExitCode   int        `json:"exit_code"`
	StartTS    int64      `json:"start_ts"`
	EndTS      int64      `json:"end_ts"`
	DurationNS int64      `json:"duration_ns"`
	Depth      int        `json:"depth"`
	Children   []jsonNode `json:"children"`
}

// treeSession renders (or JSON-emits) the process tree for one recorded session.
// It resolves the session's cast file, reads the trace id stamped in its header,
// decrypts and merges the session's span chunks, and builds the tree. It is
// fail-open throughout: a session recorded without trace data, an absent or
// unreadable span store, or corrupt spans yield a clear message or a partial
// tree, never a crash.
func treeSession(id string, jsonOut bool) error {
	castPath, user, err := store.FindCentral(id)
	if err != nil {
		return notRoot(err)
	}
	h, herr := store.Header(castPath)
	if herr != nil {
		return fmt.Errorf("cannot read session %q: %w", id, herr)
	}
	traceID := ""
	if h.Env != nil {
		traceID = h.Env[span.HeaderTraceKey]
	}
	// No trace id in the header (recorded before tracing existed, a non-bash
	// shell, or tracing disabled) is not an error — there is simply nothing to
	// show. An id that fails validation is treated the same: it could only have
	// come from a tampered header and must never reach the filesystem helpers.
	if traceID == "" || !store.ValidTraceID(traceID) {
		fmt.Printf("no process-trace data recorded for session %q\n", id)
		return nil
	}
	spans := loadSpans(user, traceID)
	root := buildSpanTree(spans)
	if jsonOut {
		return emitTreeJSON(os.Stdout, root)
	}
	renderTree(os.Stdout, root)
	return nil
}

// loadSpans lists, decrypts, and merges every span chunk for a trace, returning
// all spans it can recover. Every step is fail-open: a missing span directory, a
// chunk that will not decrypt, or a corrupt JSON-lines record is skipped rather
// than failing the whole view (span.ReadAll is itself fail-open).
func loadSpans(user, traceID string) []span.Span {
	chunks, err := store.SpanChunks(user, traceID)
	if err != nil {
		return nil
	}
	dir := store.SpanDir(user, traceID)
	var all []span.Span
	for _, name := range chunks {
		rc, oerr := store.OpenCast(filepath.Join(dir, name))
		if oerr != nil {
			continue // unreadable/undecryptable chunk: drop it, keep going
		}
		s, _ := span.ReadAll(rc)
		rc.Close()
		all = append(all, s...)
	}
	return all
}

// buildSpanTree assembles spans into a tree rooted at a synthetic node. A span
// with an empty ParentSpanID (a top-level command) is a direct child of the
// root; otherwise it is attached to the node whose SpanID matches its
// ParentSpanID. A span whose parent is unknown (dropped chunk, corrupt link) or
// that names itself as its parent is reattached to the root so it stays visible
// rather than being silently lost. Each node's children are sorted by StartTS
// (ties broken by SpanID) for a stable, chronological rendering. Because every
// node is linked into exactly one parent list, the structure reachable from the
// root is always a finite tree — there is no cycle to loop on.
func buildSpanTree(spans []span.Span) *treeNode {
	root := &treeNode{}
	byID := make(map[string]*treeNode, len(spans))
	nodes := make([]*treeNode, 0, len(spans))
	for i := range spans {
		n := &treeNode{span: &spans[i]}
		nodes = append(nodes, n)
		if spans[i].SpanID != "" {
			byID[spans[i].SpanID] = n // last write wins if two spans share an id
		}
	}
	for _, n := range nodes {
		parentID := n.span.ParentSpanID
		if parentID == "" {
			root.children = append(root.children, n)
			continue
		}
		if p, ok := byID[parentID]; ok && p != n {
			p.children = append(p.children, n)
		} else {
			root.children = append(root.children, n)
		}
	}
	sortTree(root, 0)
	return root
}

// sortTree orders each node's children chronologically (by StartTS, then SpanID
// for determinism). The depth cap is defensive; the built tree is finite.
func sortTree(n *treeNode, depth int) {
	if depth >= maxTreeDepth {
		return
	}
	sort.SliceStable(n.children, func(i, j int) bool {
		a, b := n.children[i].span, n.children[j].span
		if a.StartTS != b.StartTS {
			return a.StartTS < b.StartTS
		}
		return a.SpanID < b.SpanID
	})
	for _, c := range n.children {
		sortTree(c, depth+1)
	}
}

// renderTree prints the process tree with box-drawing connectors, one command
// per line as "<cmd>  [exit <code>, <dur>s]", nested under the synthetic root.
func renderTree(w io.Writer, root *treeNode) {
	fmt.Fprintln(w, rootLabel)
	if len(root.children) == 0 {
		fmt.Fprintln(w, "(no commands captured for this trace)")
		return
	}
	renderChildren(w, root.children, "", 0)
}

func renderChildren(w io.Writer, children []*treeNode, prefix string, depth int) {
	if depth >= maxTreeDepth {
		fmt.Fprintf(w, "%s...(truncated at depth %d)\n", prefix, depth)
		return
	}
	for i, c := range children {
		last := i == len(children)-1
		branch, indent := "├─ ", "│  "
		if last {
			branch, indent = "└─ ", "   "
		}
		fmt.Fprintf(w, "%s%s%s\n", prefix, branch, nodeLabel(c.span))
		renderChildren(w, c.children, prefix+indent, depth+1)
	}
}

// nodeLabel formats one span as "<cmd>  [exit <code>, <dur>s]". The command is
// sanitized (control characters — including any ANSI escape — stripped and
// newlines/tabs collapsed) so a recorded command line, which is attacker-
// influenced content, cannot inject terminal escapes or extra lines into a root
// operator's tree view.
func nodeLabel(s *span.Span) string {
	return fmt.Sprintf("%s  [exit %d, %.1fs]", sanitizeCmd(s.Cmd), s.ExitCode, durationSeconds(s))
}

// durationSeconds returns a span's duration in seconds, clamped to >= 0 (a
// corrupt span with EndTS < StartTS must not print a negative duration).
func durationSeconds(s *span.Span) float64 {
	d := s.EndTS - s.StartTS
	if d < 0 {
		return 0
	}
	return float64(d) / 1e9
}

// sanitizeCmd makes a recorded command safe to print on one terminal line: tabs
// and newlines collapse to single spaces and every other control character
// (C0/C1/DEL, including ESC) is dropped, defeating terminal-escape injection
// from recorded content, while ordinary printable/UTF-8 text is preserved.
func sanitizeCmd(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// drop other control characters (defeats ANSI/escape injection)
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// emitTreeJSON writes the process tree as an indented JSON document (see
// jsonNode). This is the machine-readable form consumed by `analyze` (Part D).
func emitTreeJSON(w io.Writer, root *treeNode) error {
	doc := toJSONNode(root, 0)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// toJSONNode converts an in-memory treeNode (and its subtree) to the exported
// jsonNode shape. The synthetic root (span == nil) is emitted with the sentinel
// values documented on jsonNode. children is always a (possibly empty) array,
// never null, so consumers can iterate unconditionally.
func toJSONNode(n *treeNode, depth int) jsonNode {
	var jn jsonNode
	if n.span == nil {
		jn = jsonNode{SpanID: "", Cmd: rootLabel, Depth: -1}
	} else {
		s := n.span
		d := s.EndTS - s.StartTS
		if d < 0 {
			d = 0
		}
		jn = jsonNode{
			SpanID:     s.SpanID,
			Cmd:        s.Cmd,
			ExitCode:   s.ExitCode,
			StartTS:    s.StartTS,
			EndTS:      s.EndTS,
			DurationNS: d,
			Depth:      s.Depth,
		}
	}
	jn.Children = []jsonNode{}
	if depth < maxTreeDepth {
		for _, c := range n.children {
			jn.Children = append(jn.Children, toJSONNode(c, depth+1))
		}
	}
	return jn
}

// Prune handles `ghostshell prune` — interactively delete recordings from the
// central store by user and time range. Root only.
func Prune(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the final confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	users, err := store.Users()
	if err != nil {
		return notRoot(err)
	}
	if len(users) == 0 {
		fmt.Printf("no recordings in %s\n", store.CentralDir())
		return nil
	}

	in := bufio.NewReader(os.Stdin)

	// 0. Show what's in the store, then require the prune password.
	printStorageOverview(users)
	if err := prunePasswordGate(in); err != nil {
		return err
	}

	// 1. Which user(s)?
	scope, err := resolveScope(ask(in, "Prune which user? [all / <username>]", "all"), users)
	if err != nil {
		return err
	}

	// 2. How much / time range?
	fmt.Println("What to delete:")
	fmt.Println("  all              every session for the selected user(s)")
	fmt.Println("  days N           sessions older than N days")
	fmt.Println("  range FROM TO    sessions started in [FROM, TO]  (YYYY-MM-DD[ HH:MM])")
	matchFn, err := pruneFilter(ask(in, "Selection?", "all"))
	if err != nil {
		return err
	}

	// 3. Collect matches.
	hits, total := collectPruneTargets(scope, matchFn)
	if len(hits) == 0 {
		fmt.Println("nothing matched — nothing to prune")
		return nil
	}

	// 4. Preview + confirm + delete.
	previewTargets(hits, total)
	if !*yes && !confirm(in, len(hits)) {
		fmt.Println("aborted — nothing deleted")
		return nil
	}
	deleted, freed := deleteTargets(hits)
	// Report only the bytes actually reclaimed: some removals may have failed
	// (skipped non-regular files, permission errors), so printing `total` would
	// overstate what was freed.
	fmt.Printf("pruned %d session(s), freed %s\n", deleted, humanSize(freed))
	return nil
}

func previewTargets(hits []pruneTarget, total int64) {
	fmt.Printf("\nWill delete %d session(s), %s total:\n", len(hits), humanSize(total))
	for i, t := range hits {
		if i >= 20 {
			fmt.Printf("  ... and %d more\n", len(hits)-20)
			break
		}
		fmt.Printf("  %s/%s\n", t.user, t.name)
	}
}

func confirm(in *bufio.Reader, n int) bool {
	// Irreversible bulk delete: require the exact word "yes" as the prompt
	// states. Accepting "y" makes an accidental keystroke destructive.
	c := ask(in, fmt.Sprintf("Delete these %d session(s)? [yes/NO]", n), "no")
	return c == "yes"
}

// deleteTargets removes each target and returns the count and the total bytes
// of the recordings actually removed. Each target is Lstat'd first and anything
// that is not a regular file (symlink, fifo, device, dir) is skipped, so a
// planted symlink in a user dir cannot redirect root's os.Remove to an
// unrelated path. Only successfully removed sizes are summed.
func deleteTargets(hits []pruneTarget) (deleted int, freed int64) {
	for _, t := range hits {
		fi, lerr := os.Lstat(t.path)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "  failed: %s: %v\n", t.path, lerr)
			continue
		}
		if !fi.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "  skipped (not a regular file): %s\n", t.path)
			continue
		}
		if err := os.Remove(t.path); err == nil {
			deleted++
			freed += t.size
		} else {
			fmt.Fprintf(os.Stderr, "  failed: %s: %v\n", t.path, err)
		}
	}
	return deleted, freed
}

type pruneTarget struct {
	user, name, path string
	size             int64
}

func resolveScope(who string, users []string) ([]string, error) {
	if who == "all" {
		return users, nil
	}
	for _, u := range users {
		if u == who {
			return []string{who}, nil
		}
	}
	return nil, fmt.Errorf("no such user %q", who)
}

func pruneFilter(mode string) (func(ts int64) bool, error) {
	switch {
	case mode == "all":
		return func(int64) bool { return true }, nil
	case strings.HasPrefix(mode, "days"):
		n, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(mode, "days")))
		if e != nil || n < 0 {
			return nil, fmt.Errorf("bad 'days' value: %q", mode)
		}
		// "days 0" means "older than now", i.e. everything — that is what the
		// "all" selection is for. Reject it so an operator who meant a real age
		// cutoff cannot accidentally wipe the whole scope.
		if n == 0 {
			return nil, fmt.Errorf("'days 0' would delete everything; use 'all' if that is intended")
		}
		cutoff := time.Now().AddDate(0, 0, -n)
		// Unknown timestamps (ts<=0) are never matched by a time selection — see
		// the shared policy in timeUnknown/inWindow.
		return func(ts int64) bool { return ts > 0 && time.Unix(ts, 0).Before(cutoff) }, nil
	case strings.HasPrefix(mode, "range"):
		parts := strings.Fields(mode)
		if len(parts) < 3 {
			return nil, fmt.Errorf("usage: range FROM TO")
		}
		fromT, e1 := parseTime(parts[1])
		toT, e2 := parseTime(parts[2])
		if e1 != nil || e2 != nil {
			return nil, fmt.Errorf("bad range times")
		}
		return func(ts int64) bool {
			if timeUnknown(ts) {
				return false // unknown start time is never pruned by a range
			}
			t := time.Unix(ts, 0)
			return !t.Before(fromT) && !t.After(toT)
		}, nil
	default:
		return nil, fmt.Errorf("unrecognized selection %q", mode)
	}
}

func collectPruneTargets(scope []string, match func(int64) bool) ([]pruneTarget, int64) {
	var hits []pruneTarget
	var total int64
	for _, u := range scope {
		names, _ := store.UserSessions(u)
		for _, n := range names {
			if store.IsActive(n) {
				continue // never prune an in-progress recording
			}
			p := centralPath(u, n)
			h, _ := store.Header(p)
			if !match(h.Timestamp) {
				continue
			}
			var sz int64
			if fi, e := os.Stat(p); e == nil {
				sz = fi.Size()
			}
			hits = append(hits, pruneTarget{u, n, p, sz})
			total += sz
		}
	}
	return hits, total
}

func printStorageOverview(users []string) {
	fmt.Printf("Central store: %s\n", store.CentralDir())
	fmt.Printf("  %-20s %9s %10s\n", "USER", "SESSIONS", "SIZE")
	var grandSize int64
	var grandN int
	for _, u := range users {
		names, _ := store.UserSessions(u)
		var sz int64
		for _, n := range names {
			if fi, e := os.Stat(centralPath(u, n)); e == nil {
				sz += fi.Size()
			}
		}
		grandSize += sz
		grandN += len(names)
		fmt.Printf("  %-20s %9d %10s\n", u, len(names), humanSize(sz))
	}
	fmt.Printf("  %-20s %9d %10s\n\n", "TOTAL", grandN, humanSize(grandSize))
}

func pruneHashPath() string { return filepath.Join(store.CentralDir(), ".prune.hash") }

// prunePasswordGate requires the prune password. On first use (no password set
// yet, e.g. just after install) it prompts to create one.
func prunePasswordGate(in *bufio.Reader) error {
	data, err := os.ReadFile(pruneHashPath())
	if os.IsNotExist(err) {
		fmt.Println("No prune password set yet — create one now (required to prune).")
		return setPrunePassword(in)
	}
	if err != nil {
		return err
	}
	pw, perr := readPassword(in, "Prune password: ")
	if perr != nil {
		return perr
	}
	if !verifyPassword(string(data), pw) {
		return fmt.Errorf("incorrect prune password")
	}
	return nil
}

func setPrunePassword(in *bufio.Reader) error {
	p1, err := readPassword(in, "New prune password: ")
	if err != nil {
		return err
	}
	if len(p1) < 8 {
		return fmt.Errorf("password too short (min 8 chars)")
	}
	p2, err := readPassword(in, "Confirm password: ")
	if err != nil {
		return err
	}
	if p2 != p1 {
		return fmt.Errorf("passwords do not match")
	}
	rec, err := hashPassword(p1)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pruneHashPath(), []byte(rec), 0o600); err != nil {
		return err
	}
	fmt.Println("prune password set.")
	return nil
}

// TODO: unify with internal/auth — this bcrypt hash/verify machinery duplicates
// auth.SetPassword/auth.Verify. Kept separate for now to avoid a cross-package
// refactor; the prune password and the playback password should share one impl.
func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func verifyPassword(rec, pw string) bool {
	stored := strings.TrimSpace(rec)
	// Bcrypt hashes always start with "$2".
	// Legacy SHA-256 hashes (salt$hash hex) do not — treat as invalid,
	// forcing the operator to re-set the password via "set-prune-password".
	if !strings.HasPrefix(stored, "$2") {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(pw)) == nil
}

// readPassword reads a password from the controlling terminal without echo. It
// refuses to read from a non-terminal stdin: echoing a piped/redirected
// password back through bufio would leak it into logs or scrollback, and a
// prune password must only ever be entered interactively.
func readPassword(_ *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Println()
		return "", fmt.Errorf("refusing to read password from a non-terminal")
	}
	b, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func ask(in *bufio.Reader, prompt, def string) string {
	fmt.Printf("%s ", prompt)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func humanSize(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// TailLive handles `ghostshell tail -f <sessionid>` — live stream from the daemon (root).
func TailLive(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: ghostshell tail <sessionid>")
	}
	conn, err := net.Dial("unix", daemonSocket())
	if err != nil {
		return fmt.Errorf("ghostshell-daemon not reachable: %w", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "TAIL %s\n", args[0]); err != nil {
		return err
	}
	// The daemon's TAIL reply (see daemon protocol) is one of two things, and
	// the first line disambiguates them deterministically:
	//   - an error:  a line beginning with "ERR " (e.g. "ERR no active session")
	//   - a cast:    an asciinema v2 header line (a JSON object, starts with '{')
	//                followed by [t,"o",data] event lines.
	// Read the first line in full and branch on this documented prefix instead
	// of peeking a few raw bytes, which mis-reads a short/partial first read.
	br := bufio.NewReader(conn)
	first, ferr := br.ReadString('\n')
	if ferr != nil && first == "" {
		return ferr
	}
	trimmed := strings.TrimSpace(first)
	if rest, ok := strings.CutPrefix(trimmed, "ERR "); ok {
		return fmt.Errorf("%s", strings.TrimSpace(rest))
	}
	if !strings.HasPrefix(trimmed, "{") {
		return fmt.Errorf("unexpected response from ghostshell-daemon: %q", trimmed)
	}
	// First line was the cast header; we don't need its contents for live
	// rendering, so the remaining stream is event lines. Decode and write each
	// event's raw output bytes so the session renders live (colors, progress
	// bars, cursor moves) instead of dumping the JSON.
	for {
		ev, rerr := cast.ReadEvent(br)
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		if ev.Type == "o" {
			if _, werr := io.WriteString(os.Stdout, ev.Data); werr != nil {
				return werr
			}
		}
	}
}

// TailStatic handles `ghostshell tail <sessionid>` — prints the last N lines of a
// completed (or in-progress) session from the central store. Like `tail -n N`.
func TailStatic(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("tail", flag.ContinueOnError)
	n := fs.Int("n", 20, "number of output lines to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ghostshell tail [-n N] <sessionid>  (live: ghostshell tail -f <sessionid>)")
	}
	path, _, err := store.FindCentral(fs.Arg(0))
	if err != nil {
		return notRoot(err)
	}
	rc, err := store.OpenCast(path)
	if err != nil {
		return err
	}
	defer rc.Close()
	br := bufio.NewReader(rc)
	if _, herr := cast.ReadHeader(br); herr != nil {
		return herr
	}
	// Keep only the last N output lines in a bounded ring buffer instead of
	// accumulating the whole session — memory stays ~N lines regardless of
	// recording size.
	ring := newLineRing(*n)
	for {
		ev, rerr := cast.ReadEvent(br)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if ev.Type == "o" {
			ring.add(ev.Data)
		}
	}
	_, werr := io.WriteString(os.Stdout, ring.String())
	return werr
}

func centralPath(user, name string) string {
	return filepath.Join(store.UserDir(user), name)
}

// lineRing keeps only the last N completed output lines plus the current
// partial (un-terminated) line, so tailing a session uses memory bounded to
// ~N lines regardless of the recording's size. Completed lines are stored
// without their trailing '\n'; String() reconstructs the exact trailing bytes.
type lineRing struct {
	n       int      // max completed lines to keep (>=1)
	lines   []string // ring of completed lines (without '\n')
	start   int      // index of the oldest line in lines
	count   int      // number of completed lines currently held
	partial []byte   // current line being built (no terminating '\n' yet)
}

func newLineRing(n int) *lineRing {
	if n < 1 {
		n = 1
	}
	return &lineRing{n: n, lines: make([]string, n)}
}

// add feeds one output event, splitting it into completed lines on '\n'.
func (r *lineRing) add(s string) {
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			r.partial = append(r.partial, s...)
			return
		}
		r.partial = append(r.partial, s[:i]...)
		r.pushLine(string(r.partial))
		r.partial = r.partial[:0]
		s = s[i+1:]
	}
}

func (r *lineRing) pushLine(line string) {
	if r.count < r.n {
		r.lines[(r.start+r.count)%r.n] = line
		r.count++
		return
	}
	// Full: overwrite the oldest and advance start.
	r.lines[r.start] = line
	r.start = (r.start + 1) % r.n
}

// String reconstructs the last N logical lines as trailing bytes: each
// completed line is followed by '\n'; any trailing partial line has none.
// When a partial line is present it counts toward N (the oldest completed
// line is dropped) so the total stays bounded to N logical lines.
func (r *lineRing) String() string {
	var b strings.Builder
	skip := 0
	if len(r.partial) > 0 && r.count == r.n {
		skip = 1 // drop the oldest completed line to make room for the partial
	}
	for i := skip; i < r.count; i++ {
		b.WriteString(r.lines[(r.start+i)%r.n])
		b.WriteByte('\n')
	}
	if len(r.partial) > 0 {
		b.Write(r.partial)
	}
	return b.String()
}

// Search handles `ghostshell search [--from T] [--to T] [--user U] [-i] <pattern>`.
// It scans the central store for recordings whose output (or recorded command)
// contains the pattern, optionally limited to sessions started in a time range.
func Search(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress flag's own usage; we print our own
	from := fs.String("from", "", "only sessions started at/after this time")
	to := fs.String("to", "", "only sessions started at/before this time")
	userFilter := fs.String("user", "", "limit to one user")
	ignore := fs.Bool("i", false, "case-insensitive match")
	all := fs.Bool("all", false, "list all sessions (no pattern needed)")
	if err := fs.Parse(args); err != nil {
		return searchUsage(err)
	}
	if fs.NArg() < 1 && !*all {
		return searchUsage(nil)
	}
	pattern := ""
	if fs.NArg() >= 1 {
		pattern = fs.Arg(0)
	}
	needle := pattern
	if *ignore {
		needle = strings.ToLower(needle)
	}

	fromT, toT, err := parseRange(*from, *to)
	if err != nil {
		return err
	}
	users, err := store.Users()
	if err != nil {
		return notRoot(err)
	}

	// Build a flat list of scan jobs in deterministic order: users sorted (as
	// returned by store.Users) and sessions in store order within each user.
	var jobs []searchJob
	for _, u := range users {
		if *userFilter != "" && u != *userFilter {
			continue
		}
		names, _ := store.UserSessions(u)
		for _, name := range names {
			jobs = append(jobs, searchJob{user: u, name: name})
		}
	}

	// Scan jobs concurrently with a bounded worker pool, writing each rendered
	// block into its own indexed slot (no shared mutation). Printing happens
	// afterwards in original order, so output stays byte-for-byte deterministic.
	results := make([]string, len(jobs))
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// A panic while scanning one (possibly corrupt) session must not take
			// down the whole search. Recover per worker and surface that session
			// as an "(unreadable)" entry, matching the corrupt-header handling.
			defer func() {
				if r := recover(); r != nil {
					stem := strings.TrimSuffix(jobs[i].name, ".cast")
					results[i] = fmt.Sprintf("user=%s  when=?  session=%s\n    cmd: (unreadable)\n", jobs[i].user, stem)
				}
			}()
			results[i] = scanSession(jobs[i].user, jobs[i].name, needle, *ignore, fromT, toT, *all)
		}(i)
	}
	wg.Wait()

	matched := 0
	for _, block := range results {
		if block == "" {
			continue
		}
		matched++
		fmt.Print(block)
	}
	if matched == 0 {
		if *all {
			fmt.Println("no recordings")
		} else {
			fmt.Printf("no matches for %q\n", pattern)
		}
	}
	return nil
}

type searchJob struct{ user, name string }

func searchUsage(err error) error {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghostshell search: %v\n\n", err)
	}
	fmt.Fprint(os.Stderr, `usage:
  ghostshell search [--from T] [--to T] [--user U] [-i] <pattern>
  ghostshell search --all [--from T] [--to T] [--user U]      list all sessions

flags:
  --from <time>   only sessions started at/after  (YYYY-MM-DD[ HH:MM] or RFC3339)
  --to   <time>   only sessions started at/before
  --user <name>   limit to one user
  -i              case-insensitive match
  --all           list every recorded session (no pattern needed)

examples:
  ghostshell search nginx                         find "nginx" in any recording
  ghostshell search -i ERROR                      case-insensitive
  ghostshell search --user alice sudo             alice's sessions containing "sudo"
  ghostshell search --from 2026-05-01 --to 2026-05-20 deploy
  ghostshell search --all                         list all recorded sessions
  ghostshell search --all --user alice            list all of alice's sessions
`)
	if err != nil {
		return err
	}
	return fmt.Errorf("missing search pattern")
}

func parseRange(from, to string) (fromT, toT time.Time, err error) {
	if from != "" {
		if fromT, err = parseTime(from); err != nil {
			return fromT, toT, fmt.Errorf("bad --from: %w", err)
		}
	}
	if to != "" {
		if toT, err = parseTime(to); err != nil {
			return fromT, toT, fmt.Errorf("bad --to: %w", err)
		}
	}
	return fromT, toT, nil
}

// timeUnknown reports whether a recording's header timestamp is missing/zero.
// Unified policy across audit.go: a recording whose start time is unknown is
// never matched by an *active* time selection (a --from/--to window in search,
// or a days/range selection in prune). With no time filter at all it is still
// listed/considered, so plain `search` and `search --all` see every recording.
func timeUnknown(ts int64) bool { return ts <= 0 }

func inWindow(ts int64, fromT, toT time.Time) bool {
	noBounds := fromT.IsZero() && toT.IsZero()
	if timeUnknown(ts) {
		// Excluded once any bound is set (matches prune's range/days policy);
		// included only when there is no window to filter against.
		return noBounds
	}
	st := time.Unix(ts, 0)
	if !fromT.IsZero() && st.Before(fromT) {
		return false
	}
	if !toT.IsZero() && st.After(toT) {
		return false
	}
	return true
}

// scanSession scans one session and returns the rendered output block (the
// same lines the old inline Printf calls produced), or "" if it doesn't match
// and shouldn't be listed. It is pure aside from reading the cast file, so it
// is safe to call concurrently from the worker pool. A header that can't be
// read is surfaced as an "(unreadable)" block (issue #10) rather than silently
// dropped, so operators see corrupt recordings.
func scanSession(u, name, needle string, ignore bool, fromT, toT time.Time, all bool) string {
	path := centralPath(u, name)
	stem := strings.TrimSuffix(name, ".cast")
	unreadable := func() string {
		return fmt.Sprintf("user=%s  when=?  session=%s\n    cmd: (unreadable)\n", u, stem)
	}

	// In --all (list) mode only the header is needed, so a single store.Header
	// open/decrypt suffices. In match mode we open the cast once and read the
	// header from the same decrypted reader we scan, instead of decrypting once
	// for the header and again for the body.
	var (
		h     cast.Header
		snips []string
	)
	if all {
		var herr error
		if h, herr = store.Header(path); herr != nil {
			return unreadable()
		}
		if !inWindow(h.Timestamp, fromT, toT) {
			return ""
		}
	} else {
		rc, err := store.OpenCast(path)
		if err != nil {
			return unreadable()
		}
		r := bufio.NewReader(rc)
		hh, herr := cast.ReadHeader(r)
		if herr != nil {
			rc.Close()
			return unreadable()
		}
		h = hh
		if !inWindow(h.Timestamp, fromT, toT) {
			rc.Close()
			return ""
		}
		hay := h.Command
		if ignore {
			hay = strings.ToLower(hay)
		}
		cmdMatch := needle != "" && strings.Contains(hay, needle)
		snips = scanOutput(r, needle, ignore)
		rc.Close()
		if !cmdMatch && len(snips) == 0 {
			return ""
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "user=%s  when=%s  session=%s\n", u, store.Started(h), stem)
	fmt.Fprintf(&b, "    cmd: %s\n", clean(h.Command))
	for _, s := range snips {
		fmt.Fprintf(&b, "    > %s\n", s)
	}
	return b.String()
}

func scanOutput(r *bufio.Reader, needle string, ignore bool) []string {
	const maxSnip = 5
	var snips []string
	for len(snips) < maxSnip {
		ev, err := cast.ReadEvent(r)
		if err != nil {
			break
		}
		if ev.Type == "o" {
			snips = appendMatches(snips, ev.Data, needle, ignore, maxSnip)
		}
	}
	return snips
}

func appendMatches(snips []string, data, needle string, ignore bool, max int) []string {
	for _, line := range strings.Split(data, "\n") {
		h := line
		if ignore {
			h = strings.ToLower(h)
		}
		if !strings.Contains(h, needle) {
			continue
		}
		if c := clean(line); c != "" {
			snips = append(snips, c)
		}
		if len(snips) >= max {
			break
		}
	}
	return snips
}

// parseTime accepts any format the system `date -d` command accepts, e.g.
// "yesterday", "2 days ago", "last week", "2026-05-28 17:00", "May 28".
// Built-in Go layouts are tried first for speed; then shells out to date(1).
func parseTime(s string) (time.Time, error) {
	for _, l := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02", time.RFC3339} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, nil
		}
	}
	// Refuse values that GNU date(1) would parse as an option (argument
	// injection): e.g. "-f /etc/shadow" makes date read newline-separated dates
	// from a file. None of the accepted time formats begin with "-", so
	// rejecting such values up front is safe and closes the injection.
	if strings.HasPrefix(s, "-") {
		return time.Time{}, fmt.Errorf("invalid time %q (must not start with '-')", s)
	}
	// Fall back to `date -d "<s>" +%s` — supports natural language on Linux.
	out, cerr := exec.Command("date", "-d", s, "+%s").Output()
	if cerr != nil {
		return time.Time{}, fmt.Errorf("unrecognized time %q (accepts any format 'date -d' supports: YYYY-MM-DD, 'yesterday', '2 days ago', etc.)", s)
	}
	sec, cerr := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if cerr != nil {
		return time.Time{}, fmt.Errorf("unrecognized time %q", s)
	}
	return time.Unix(sec, 0), nil
}

// clean strips CR and ANSI/control sequences for readable snippet display.
func clean(s string) string {
	var b strings.Builder
	ansi := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b {
			ansi = true
			continue
		}
		if ansi {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				ansi = false
			}
			continue
		}
		if c == '\t' || (c >= 0x20 && c < 0x7f) {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}
