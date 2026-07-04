// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package ansible

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"ghostshell/internal/store"
)

// geteuid is the effective-uid source. It is a var so tests can simulate root
// or an unprivileged user when exercising the central-store authorization gate.
var geteuid = os.Geteuid

// isRoot reports whether the process is effectively root. The central store is
// root:root 0700, so only root may enumerate or decrypt other users' ansible
// runs. A non-root caller is restricted to its own user-local fallback dir.
func isRoot() bool { return geteuid() == 0 }

// validUser reports whether s is safe to use as a single path component when
// joined onto the central store root. It rejects empty, ".", "..", and any
// value containing a path separator so a --user flag taken from CLI args can
// never escape the central store via traversal (mirrors the central store's own
// per-user directory check).
func validUser(s string) bool {
	return s != "" && s != "." && s != ".." &&
		!strings.ContainsAny(s, "/\\") && filepath.Base(s) == s
}

// sanitize strips terminal-control bytes from attacker-influenced strings
// before they are printed, so a crafted .ajsonl (playbook/task/host names,
// stdout/stderr, etc.) cannot inject ANSI/OSC escape sequences into the
// operator's terminal. It removes ESC and all C0 control bytes except \t,
// and replaces C1 control bytes (U+0080–U+009F, which can act as 8-bit CSI/OSC
// introducers) with U+FFFD. Newlines are dropped here; callers that intend to
// preserve line structure (e.g. multi-line output) split first, then sanitize
// each line.
func sanitize(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// C0 controls (incl. ESC 0x1b, CR, LF) and DEL: drop.
		case r >= 0x80 && r <= 0x9f:
			// C1 controls (8-bit CSI/OSC/etc.): replace with U+FFFD.
			b.WriteRune(utf8.RuneError)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// statusIcon returns a one-character status indicator with ANSI colour.
func statusIcon(s string) string {
	switch s {
	case "ok":
		return "\x1b[32m✓\x1b[0m" // green
	case "changed":
		return "\x1b[33m~\x1b[0m" // yellow
	case "failed":
		return "\x1b[31m✗\x1b[0m" // red
	case "unreachable":
		return "\x1b[35m!\x1b[0m" // magenta
	case "skipped":
		return "\x1b[90m-\x1b[0m" // dark grey
	default:
		return "?"
	}
}

// humanDur formats a duration into a human-readable string.
func humanDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// ansibleDir returns the ansible sub-directory inside the user's central dir.
func ansibleDir(user string) string {
	return store.AnsibleDir(user)
}

// localAnsibleDir returns the user-local ansible dir (fail-open fallback path).
func localAnsibleDir() string {
	return filepath.Join(store.Dir(), "ansible")
}

// scanDir returns .ajsonl run-ids from dir, newest first.
func scanDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for i := len(entries) - 1; i >= 0; i-- {
		name := entries[i].Name()
		if strings.HasSuffix(name, ".ajsonl") {
			ids = append(ids, strings.TrimSuffix(name, ".ajsonl"))
		}
	}
	return ids, nil
}

// listRuns returns all .ajsonl run-ids for a user from the central store.
func listRuns(user string) ([]string, error) { return scanDir(ansibleDir(user)) }

// openRun opens and decrypts (if needed) a central-store .ajsonl file.
func openRun(user, id string) (*Run, error) {
	if !validUser(user) {
		return nil, fmt.Errorf("invalid user %q", user)
	}
	if !ValidRunID(id) {
		return nil, fmt.Errorf("invalid run id %q", id)
	}
	path := store.AnsiblePath(user, id)
	rc, err := store.OpenCast(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return ParseRun(rc)
}

// openLocalRun opens an .ajsonl from the user-local fallback dir (no decrypt).
func openLocalRun(id string) (*Run, error) {
	if !ValidRunID(id) {
		return nil, fmt.Errorf("invalid run id %q", id)
	}
	path := filepath.Join(localAnsibleDir(), id+".ajsonl")
	rc, err := store.OpenCast(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return ParseRun(rc)
}

// List implements `ghostshell ansible list [--user U]`.
func List(args []string) error {
	fs := flag.NewFlagSet("ansible list", flag.ContinueOnError)
	userFlag := fs.String("user", "", "limit to one user")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *userFlag != "" && !validUser(*userFlag) {
		return fmt.Errorf("invalid user %q", *userFlag)
	}

	// localOnly: true when the central store must not be read. Defense-in-depth:
	// only root may read the root-only central store, so an unprivileged caller
	// is confined to its own user-local fallback dir regardless of --user (which
	// would otherwise reach into another user's central dir). This is a second
	// barrier on top of the filesystem 0700 perms.
	localOnly := !isRoot()
	var users []string
	if !localOnly {
		if *userFlag != "" {
			users = []string{*userFlag}
		} else {
			u, err := store.Users()
			if err != nil {
				if os.IsPermission(err) || os.IsNotExist(err) {
					localOnly = true
				} else {
					return err
				}
			} else {
				users = u
			}
		}
	}

	fmt.Printf("%-28s  %-20s  %-10s  %-6s %-6s %-6s  %-19s  %s\n",
		"RUN", "PLAYBOOK", "CONTROLLER", "OK", "CHG", "FAIL", "STARTED", "HOSTS")

	// Local fallback: show runs from ~/.local/share/ghostshell/ansible/.
	if localOnly {
		ids, _ := scanDir(localAnsibleDir())
		if len(ids) == 0 {
			fmt.Printf("no ansible runs in %s\n", localAnsibleDir())
			return nil
		}
		for _, id := range ids {
			run, err := openLocalRun(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ghostshell: %s: %v\n", id, err)
				continue
			}
			printRunRow(run, id)
		}
		return nil
	}

	for _, u := range users {
		ids, err := listRuns(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ghostshell: %s: %v\n", u, err)
			continue
		}
		for _, id := range ids {
			run, err := openRun(u, id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ghostshell: %s/%s: %v\n", u, id, err)
				continue
			}
			printRunRow(run, id)
		}
	}
	return nil
}

// printRunRow prints one run as a table row.
func printRunRow(run *Run, id string) {
	started := "?"
	if !run.Started.IsZero() {
		started = run.Started.Format("2006-01-02 15:04:05")
	}
	// id, playbook, controller and hosts are all attacker-influenced (filename
	// and file contents): sanitize before any width-based slicing so control
	// bytes cannot survive into the printed row.
	playbook := sanitize(run.Playbook)
	if len(playbook) > 20 {
		playbook = "…" + playbook[len(playbook)-19:]
	}
	ctrl := sanitize(run.Controller)
	if len(ctrl) > 10 {
		ctrl = ctrl[:9] + "…"
	}
	hosts := sanitizeJoin(run.Hosts, ",")
	if len(hosts) > 20 {
		hosts = hosts[:19] + "…"
	}
	fmt.Printf("%-28s  %-20s  %-10s  %-6d %-6d %-6d  %-19s  %s\n",
		sanitize(id), playbook, ctrl,
		run.TotalOK, run.TotalChanged, run.TotalFailed,
		started, hosts)
}

// Show implements `ghostshell ansible show <runid>`.
func Show(args []string) error {
	fs := flag.NewFlagSet("ansible show", flag.ContinueOnError)
	userFlag := fs.String("user", "", "user owning the run (default: search all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: ghostshell ansible show [--user U] <runid>")
	}
	runID := fs.Arg(0)
	if !ValidRunID(runID) {
		return fmt.Errorf("invalid run id %q", runID)
	}
	if *userFlag != "" && !validUser(*userFlag) {
		return fmt.Errorf("invalid user %q", *userFlag)
	}

	// Find the run. The central store is root-only, so an unprivileged caller
	// skips it entirely (defense-in-depth on top of the 0700 perms) and is served
	// only from its own user-local fallback dir below. --user targets a central
	// per-user dir and is therefore meaningful only for root.
	var run *Run
	var foundUser string
	if isRoot() {
		if *userFlag != "" {
			r, err := openRun(*userFlag, runID)
			if err != nil {
				return fmt.Errorf("cannot open run %s for user %s: %w", runID, *userFlag, err)
			}
			run = r
			foundUser = *userFlag
		} else {
			users, err := store.Users()
			if err == nil {
				for _, u := range users {
					r, err := openRun(u, runID)
					if err == nil {
						run = r
						foundUser = u
						break
					}
				}
			}
			// central store inaccessible or run not found — fall through to local
		}
	} else if *userFlag != "" {
		// A non-root caller cannot read another user's central runs; refuse the
		// --user form rather than silently returning the caller's own local run.
		return fmt.Errorf("--user reads the root-only central store and requires root")
	}
	// Fall back to local dir when not found (or not accessible) in central store.
	if run == nil {
		if r, err := openLocalRun(runID); err == nil {
			run = r
			foundUser = "(local)"
		}
	}
	if run == nil {
		return fmt.Errorf("run %s not found in central store or local dir", runID)
	}

	// Header.
	started := "?"
	if !run.Started.IsZero() {
		started = run.Started.Format("2006-01-02 15:04:05")
	}
	// Every field below other than the timestamps/duration is read from the
	// .ajsonl file and is therefore attacker-influenced: sanitize before print
	// so a crafted run cannot inject terminal escape sequences.
	fmt.Printf("Playbook : %s\n", sanitize(run.Playbook))
	fmt.Printf("Run ID   : %s\n", sanitize(run.ID))
	fmt.Printf("User     : %s\n", sanitize(foundUser))
	fmt.Printf("Controller: %s\n", sanitize(run.Controller))
	fmt.Printf("Started  : %s\n", started)
	fmt.Printf("Duration : %s\n", humanDur(run.Duration()))
	fmt.Printf("Hosts    : %s\n", sanitizeJoin(run.Hosts, ", "))
	fmt.Println()

	// Tasks grouped by play.
	currentPlay := ""
	for _, t := range run.Tasks {
		if t.Play != currentPlay {
			currentPlay = t.Play
			fmt.Printf("\x1b[1mPLAY [%s]\x1b[0m\n", sanitize(currentPlay))
		}
		icon := statusIcon(t.Status)
		mod := sanitize(t.Module)
		if mod != "" {
			mod = "(" + mod + ")"
		}
		ts := ""
		if t.T > 0 {
			ts = fmt.Sprintf(" @%s", time.Unix(int64(t.T), 0).UTC().Format("15:04:05"))
		}
		fmt.Printf("  %s %-12s  %-30s %s%s\n", icon, sanitize(t.Host), sanitize(t.Name), mod, ts)
		if t.Status == "failed" || t.Status == "unreachable" || t.Status == "changed" {
			if t.Stdout != "" {
				fmt.Printf("      stdout: %s\n", indentOutput(t.Stdout))
			}
			if t.Stderr != "" {
				fmt.Printf("      stderr: %s\n", indentOutput(t.Stderr))
			}
			if t.RC != 0 {
				fmt.Printf("      rc: %d\n", t.RC)
			}
		}
	}

	// Recap.
	if len(run.Stats) > 0 {
		fmt.Println()
		fmt.Println("\x1b[1mPLAY RECAP\x1b[0m")
		for _, h := range run.Hosts {
			s, ok := run.Stats[h]
			if !ok {
				continue
			}
			fmt.Printf("  %-20s ok=%-4d changed=%-4d failed=%-4d unreachable=%-4d skipped=%d\n",
				sanitize(h), s.OK, s.Changed, s.Failed, s.Unreachable, s.Skipped)
		}
	}
	return nil
}

// Dispatch handles `ghostshell ansible <subcommand> [args...]`.
func Dispatch(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ghostshell ansible <list|show|incoming> [args...]")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		return List(rest)
	case "show":
		return Show(rest)
	case "incoming":
		return Incoming(rest)
	default:
		return fmt.Errorf("ansible: unknown subcommand %q (list|show|incoming)", sub)
	}
}

// indentOutput indents multi-line output for display inside a task block. The
// output is attacker-influenced (task stdout/stderr from the .ajsonl), so each
// line is sanitized to strip terminal-control bytes while line structure is
// preserved.
func indentOutput(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) == 1 {
		return sanitize(lines[0])
	}
	var b strings.Builder
	b.WriteString(sanitize(lines[0]))
	for _, l := range lines[1:] {
		b.WriteString("\n             ")
		b.WriteString(sanitize(l))
	}
	return b.String()
}

// sanitizeJoin sanitizes each element and joins them with sep.
func sanitizeJoin(elems []string, sep string) string {
	out := make([]string, len(elems))
	for i, e := range elems {
		out[i] = sanitize(e)
	}
	return strings.Join(out, sep)
}
