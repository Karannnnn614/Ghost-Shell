package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"ghostshell/internal/ansible"
	"ghostshell/internal/audit"
	"ghostshell/internal/auth"
	"ghostshell/internal/backup"
	"ghostshell/internal/complete"
	"ghostshell/internal/config"
	"ghostshell/internal/initcmd"
	"ghostshell/internal/play"
	"ghostshell/internal/record"
	"ghostshell/internal/store"
)

// Version is set at build time via -ldflags "-X main.Version=x.y.z".
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	rest := os.Args[2:]

	if cmd == "version" || cmd == "-V" || cmd == "--version" {
		fmt.Println("ghostshell", Version)
		return
	}

	if cmd == "-c" || cmd == "--check" {
		os.Exit(runConfigCheck())
	}

	// `ghostshell help [command]` — overall usage, or one command's help.
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		if len(rest) > 0 {
			if h, ok := commandHelp(rest[0]); ok {
				fmt.Print(h)
				return
			}
			fmt.Fprintf(os.Stderr, "ghostshell: no help for %q\n\n", rest[0])
			usage()
			os.Exit(2)
		}
		usage()
		return
	}
	// `ghostshell <command> help|-h|--help` — that command's help. Also handle
	// `ghostshell ansible list --help` etc. (help token in the second position).
	// When a help token is present but no per-command help exists, fall back to
	// generic usage and exit 2 rather than silently *executing* the command.
	helpRequested := (len(rest) > 0 && isHelpToken(rest[0])) ||
		(cmd == "ansible" && len(rest) > 1 && isHelpToken(rest[1]))
	if helpRequested {
		if h, ok := commandHelp(cmd); ok {
			fmt.Print(h)
			return
		}
		fmt.Fprintf(os.Stderr, "ghostshell: no help for %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	var err error
	switch cmd {
	case "init":
		err = initcmd.Run(rest)
	case "rec", "record":
		// Propagate the recorded child's exit status as our own, so scripts that
		// wrap a command in `ghostshell rec` observe its real exit code.
		if rerr := record.Run(rest); rerr != nil {
			var ee *record.ExitError
			if errors.As(rerr, &ee) {
				os.Exit(ee.Code)
			}
			err = rerr
		}
	case "play":
		// Parse play's flags once via a shared FlagSet so the target is the
		// single resolved positional (not "the last arg without a dash", which
		// mis-picks a flag value like `--speed 2` → "2"). The downstream
		// play.Run / audit.PlayUser re-parse the same flags from rest.
		target, perr := resolvePlayTarget(rest)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "ghostshell:", perr)
			os.Exit(2) // usage error
		}
		// Pre-check: if target is not a local file, see if it's an ansible run ID.
		// Give a helpful redirect before the password prompt blocks a TTY.
		_, statErr := os.Stat(target)
		if statErr != nil && store.IsAnsibleRun(target) {
			fmt.Fprintf(os.Stderr, "ghostshell: %q is an Ansible run — use: ghostshell ansible show %s\n", target, target)
			os.Exit(1)
		}
		// Password gate — prompt if playback password is set.
		gatePlayback()
		// Auto-detect on the single resolved target: an existing local file →
		// local play; otherwise → central store id. Both branches receive the
		// original rest so their own flag parsing is unaffected.
		if statErr == nil {
			err = play.Run(rest)
		} else {
			err = audit.PlayUser(rest)
		}
	case "ls", "list":
		// --all → all users in central store; --user <name> → that user; (none) → local.
		// The central-store views reveal other users' session metadata, so gate
		// them behind the playback password like play/search/export. The local
		// view (no --all/--user) is the caller's own data and stays ungated.
		hasAll, userVal := parseLsScope(rest)
		if hasAll {
			gatePlayback()
			err = audit.LsUser(nil)
		} else if userVal != "" {
			gatePlayback()
			err = audit.LsUser([]string{userVal})
		} else {
			err = store.List(rest)
		}
	// Hidden backward-compat aliases — not shown in usage.
	case "ls-user":
		// Same central metadata as `ls --user`; gate it identically.
		gatePlayback()
		err = audit.LsUser(rest)
	case "play-user":
		// Same central playback as `play <id>`; gate it identically.
		gatePlayback()
		err = audit.PlayUser(rest)
	case "tail":
		// Password gate — tail reveals recorded output (live or static).
		gatePlayback()
		if len(rest) > 0 && rest[0] == "-f" {
			err = audit.TailLive(rest[1:])
		} else {
			err = audit.TailStatic(rest)
		}
	case "status":
		// Operational summary of the central store + daemon (root). It reveals
		// only aggregate counts/sizes (no recorded content), but it does read the
		// root-only store, so gate it like the other central views.
		gatePlayback()
		err = audit.Status(rest)
	case "tree":
		// Password gate — tree reveals every user's session metadata.
		gatePlayback()
		err = audit.Tree(rest)
	case "search":
		// Password gate — search reveals matching output snippets.
		gatePlayback()
		err = audit.Search(rest)
	case "export":
		// Password gate — export reveals the full decrypted session.
		gatePlayback()
		err = audit.Export(rest)
	case "prune":
		err = audit.Prune(rest)
	case "ansible":
		err = ansible.Dispatch(rest)
	case "ansible-ingest":
		// Hidden: called by the Ansible callback plugin subprocess.
		err = ansible.Ingest(rest)
	case "backup":
		err = backup.RunCLI(rest)
	case "completion":
		err = complete.Script(rest)
	case "__complete":
		err = complete.Complete(rest)
	default:
		fmt.Fprintf(os.Stderr, "ghostshell: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "ghostshell:", err)
		os.Exit(1)
	}
}

func isHelpToken(s string) bool {
	return s == "help" || s == "-h" || s == "--help"
}

// gatePlayback prompts for the playback password (no-op when none is set) and
// exits 1 on failure. Used by every command that reveals recorded content or
// metadata (play, tail, search, export, and the metadata views ls/tree), so the
// gate is applied consistently in one place.
func gatePlayback() {
	if perr := auth.PromptAndVerify(); perr != nil {
		fmt.Fprintln(os.Stderr, "ghostshell:", perr)
		os.Exit(1)
	}
}

// resolvePlayTarget parses the play subcommand's flags (the same --speed/--idle
// that play.Run and audit.PlayUser accept) and returns the single positional
// target. It is the one source of truth for "what are we playing", so the
// local-vs-central decision and the downstream re-parse cannot disagree. A
// missing positional is a usage error.
func resolvePlayTarget(args []string) (string, error) {
	fs := flag.NewFlagSet("play", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we format our own error/exit code
	fs.Float64("speed", 1.0, "playback speed multiplier")
	fs.Float64("idle", 0, "cap idle gaps to N seconds")
	if err := fs.Parse(args); err != nil {
		return "", fmt.Errorf("usage: ghostshell play [--speed N] [--idle N] <file|id>")
	}
	if fs.NArg() < 1 {
		return "", fmt.Errorf("usage: ghostshell play [--speed N] [--idle N] <file|id>")
	}
	return fs.Arg(0), nil
}

// parseLsScope interprets `ls`/`list` flags: --all/-a selects all users in the
// central store, and --user <name> or --user=<name> selects a single user.
func parseLsScope(args []string) (all bool, user string) {
	for i, a := range args {
		switch {
		case a == "--all" || a == "-a":
			all = true
		case a == "--user" && i+1 < len(args):
			user = args[i+1]
		case strings.HasPrefix(a, "--user="):
			user = strings.TrimPrefix(a, "--user=")
		}
	}
	return all, user
}

func usage() {
	fmt.Fprint(os.Stderr, `Ghost Shell — Linux terminal session tracker

usage:
  ghostshell rec [-q] [-o file] [cmd...]      record a shell session (default: $SHELL)
  ghostshell play [--speed N] <file|id>       replay local file or central session (auto-detect)
  ghostshell ls                               list local recordings
  ghostshell ls --all                         list all users in central store (root)
  ghostshell ls --user <name>                 list one user's sessions in central store (root)

audit commands (central root-only store):
  ghostshell tail [-n N] <id>                 show last N lines of a session (default 20)
  ghostshell tail -f <id>                     live-stream an in-progress session (root)
  ghostshell tree                             users -> sessions tree (root)
  ghostshell status                           daemon health, active sessions, store size (root)
  ghostshell search [opts] <string>           find a string across recordings (root)
  ghostshell export [-o file] [--force] <id>  decrypt a session to a plaintext cast (root)
  ghostshell prune                            interactively delete recordings (root)
  ghostshell backup                           run configured backup immediately (root)
  ghostshell ansible list [--user U]          list Ansible playbook runs (root)
  ghostshell ansible show <runid>             show tasks and recap for a run (root)

  ghostshell init                             first-time setup wizard
  ghostshell init --reset-password            change playback password (requires current)
  ghostshell init --clear-password            remove playback password (requires current)
  ghostshell completion bash                  print the bash completion script
  ghostshell version                          print version
  ghostshell --check                          validate config and show resolved values

search opts: --from / --to <YYYY-MM-DD[ HH:MM]>, --user <name>, -i
recordings in the central store are encrypted at rest (opaque to cat/strings)

local recordings: $GHOSTSHELL_DIR or ~/.local/share/ghostshell
central store:    $GHOSTSHELL_CENTRAL_DIR or /var/lib/ghostshell (root:root 0700)
format: asciinema v2 cast (.cast) — also playable with `+"`asciinema play`"+`

run 'ghostshell help <command>' (or 'ghostshell <command> --help') for command details
`)
}

// commandHelp returns detailed help text for one command. The second result is
// false for an unknown command.
func commandHelp(name string) (string, bool) {
	switch name {
	case "init":
		return `ghostshell init — first-time setup wizard and playback password management

usage: ghostshell init                    run the setup wizard
       ghostshell init --reset-password   change the playback password
       ghostshell init --clear-password   remove playback password protection

The wizard checks:
  [1/4] Config file (/etc/ghostshell/ghostshell.conf)
  [2/4] Daemon (ghostshell-daemon) reachability
  [3/4] Encryption key existence
  [4/4] Playback password status (offers to set one if absent)

--reset-password and --clear-password both require the current password first.
A playback password must be at least 8 characters.
The hash is stored in /etc/ghostshell/.playback_passwd (root:root 0600).
When set, ghostshell play prompts for the password before replaying any session.
`, true
	case "rec", "record":
		return `ghostshell rec — record a terminal session

usage: ghostshell rec [-q] [-o file] [cmd...]

Runs cmd (or $SHELL, default /bin/bash, when none is given) under a PTY and
records its output as an asciinema v2 cast. Streams to the ghostshell-daemon daemon when
reachable, otherwise writes a user-local file (fail-open).

options:
  -o file   write the recording to file (implies local, bypasses the daemon)
  -q        quiet: suppress the banner and saved-path message (also GHOSTSHELL_QUIET=1)
`, true
	case "play":
		return `ghostshell play — replay a recording (local file or central session)

usage: ghostshell play [--speed N] [--idle N] <file|id>

Auto-detects: if the argument is an existing local file path it plays that;
otherwise it looks up the session id in the central store (same as play-user).

options:
  --speed N   playback multiplier (default 1.0; >1 faster, <1 slower)
  --idle N    cap idle gaps to N seconds (default 0 = exact timing)

on a terminal this opens a full-screen player. controls:
  space pause/resume    left/right or h/l seek 5s    up/down or +/- speed
  g jump to a recorded command    0 restart    q or Ctrl-C quit
`, true
	case "ls", "list":
		return `ghostshell ls — list recordings

usage: ghostshell ls                   list local recordings (~/.local/share/ghostshell)
       ghostshell ls --all             list all users in central store (root)
       ghostshell ls --user <name>     list one user's sessions in central store (root)

Columns (local): STATUS, FILE, STARTED, DURATION, COMMAND
Columns (central): STATUS, TYPE, SESSION, STARTED, DURATION, COMMAND
`, true
	case "tail":
		return `ghostshell tail — show session output (tail or live-stream)

usage: ghostshell tail [-n N] <sessionid>   print last N lines of a session (default 20)
       ghostshell tail -f <sessionid>        live-stream an in-progress session (root)

-n N   number of output lines to display (static mode only)
-f     follow: stream live output from the daemon as it arrives
`, true
	case "tree":
		return `ghostshell tree — central store as a users -> sessions tree (root)

usage: ghostshell tree

Each session shows [STATUS TYPE], start time, duration, and command.
`, true
	case "status":
		return `ghostshell status — operational health summary (root)

usage: ghostshell status

Reports a one-shot snapshot of the central store and daemon:
  central_dir        the root-only central store path
  socket_path        the ghostshell-daemon Unix socket path
  daemon_reachable   yes/no — whether ghostshell-daemon is listening right now
  users              number of users with recordings
  sessions_total     total recordings in the central store
  sessions_active    recordings currently in progress
  store_size         total on-disk size of the central store

Read-only: it stats files and lists directories but never decrypts a recording.
`, true
	case "search":
		return `ghostshell search — find a string across recordings (root)

usage: ghostshell search [--from T] [--to T] [--user U] [-i] [--all] <pattern>

Searches recorded commands and output. Prints the owning user, start time,
command, and matching output lines.

options:
  --from T   only sessions started at/after T (YYYY-MM-DD[ HH:MM])
  --to T     only sessions started at/before T
  --user U   restrict to one user
  -i         case-insensitive match
  --all      list every session (no pattern needed)
`, true
	case "export":
		return `ghostshell export — decrypt a session to a plaintext cast (root)

usage: ghostshell export [-o file] [--force] <sessionid>

Writes a plaintext asciinema v2 cast, playable with 'asciinema play'.
The output file is created 0600 (decrypted plaintext can contain secrets) and an
existing file is never overwritten unless --force is given.

options:
  -o file   output file (default: stdout)
  --force   overwrite an existing output file
`, true
	case "prune":
		return `ghostshell prune — interactively delete recordings (root)

usage: ghostshell prune [--yes]

Shows a storage overview, asks which user(s) and what to delete
(all / days N / range FROM TO), previews the targets, and confirms.
Requires the prune password (set on first use). Never deletes active sessions.

options:
  --yes   skip the final confirmation prompt
`, true
	case "ansible":
		return `ghostshell ansible — Ansible playbook tracking (root)

usage: ghostshell ansible list [--user U]
       ghostshell ansible show [--user U] <runid>

Reads Ansible runs recorded by the ghostshell callback plugin.
Runs are stored in the central store under each user's ansible/ directory.

subcommands:
  list       table of runs: RUN PLAYBOOK CONTROLLER OK CHG FAIL STARTED HOSTS
  show       full run detail: plays, tasks with status/output, PLAY RECAP

Enable tracking on the Ansible controller:
  export ANSIBLE_CALLBACK_PLUGINS=/usr/share/ghostshell/ansible
  export ANSIBLE_CALLBACKS_ENABLED=ghostshell

or in ansible.cfg:
  [defaults]
  callback_plugins = /usr/share/ghostshell/ansible
  callbacks_enabled = ghostshell
`, true
	case "completion":
		return `ghostshell completion — print the shell completion script

usage: ghostshell completion bash

Install:
  ghostshell completion bash | sudo tee /usr/share/bash-completion/completions/ghostshell
`, true
	case "backup":
		return `ghostshell backup — run a configured backup immediately (root)

usage: ghostshell backup

Triggers a one-shot backup of the central recording store to the configured
target. Respects the same backup_type and backup_target settings used by the
daemon's periodic backup.

Backup types:
  bucket_aws   shells out to: aws s3 sync <central_dir> <backup_target>
  bucket_gcp   shells out to: gsutil -m rsync -r <central_dir> <backup_target>
  rsync        shells out to: rsync -a --delete <central_dir>/ <backup_target>

Configure in /etc/ghostshell/ghostshell.conf:
  backup_type   = bucket_aws | bucket_gcp | rsync
  backup_target = s3://bucket/prefix | gs://bucket/prefix | user@host:/path

Access is enforced by filesystem permissions (central_dir is root:root 0700).
`, true
	}
	return "", false
}

// daemonReachable reports whether ghostshell-daemon is currently accepting connections on
// its Unix socket. It dials with the configured timeout and immediately closes;
// a successful dial means the daemon is listening (a stale socket file with no
// listener fails with ECONNREFUSED). A non-positive timeout falls back to 1s so
// --check never blocks indefinitely on a wedged socket.
func daemonReachable(socketPath string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = time.Second
	}
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// runConfigCheck validates the config file and prints all resolved values.
// Returns 0 on success, 1 on error (mirrors nginx -t behaviour).
func runConfigCheck() int {
	path := os.Getenv("GHOSTSHELL_CONFIG")
	if path == "" {
		path = config.DefaultPath
	}

	fmt.Fprintf(os.Stderr, "ghostshell: reading config from %s\n", path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "ghostshell: config file not found — using built-in defaults\n")
	}

	cfg := config.Load()

	// Resolved key file for display (may differ from raw KeyFile).
	resolvedKey := cfg.ResolvedKeyFile()

	fmt.Printf("%-22s = %s\n", "socket_path", cfg.SocketPath)
	fmt.Printf("%-22s = %s\n", "central_dir", cfg.CentralDir)
	// Daemon reachability: dial the socket now so --check reports live operational
	// state, not just static config. This is an additive line (existing key=value
	// lines above are unchanged) so output-contract tests keep passing.
	if daemonReachable(cfg.SocketPath, cfg.DialTimeout) {
		fmt.Printf("%-22s = %s\n", "daemon_reachable", "yes")
	} else {
		fmt.Printf("%-22s = %s\n", "daemon_reachable", "no")
	}
	if cfg.KeyFile == "" {
		fmt.Printf("%-22s = %s  (default: relative to central_dir)\n", "key_file", resolvedKey)
	} else {
		fmt.Printf("%-22s = %s  (resolved: %s)\n", "key_file", cfg.KeyFile, resolvedKey)
	}
	fmt.Printf("%-22s = %.3gs\n", "dial_timeout_sec", cfg.DialTimeout.Seconds())
	fmt.Printf("%-22s = %dms\n", "eof_grace_ms", cfg.EOFGrace.Milliseconds())
	fmt.Printf("%-22s = %d\n", "ansible_output_cap", cfg.AnsibleOutputCap)
	fmt.Printf("%-22s = %d\n", "scroll_buffer", cfg.ScrollBuffer)
	fmt.Printf("%-22s = %d  (0=off 1=error 2=warn 3=info 4=debug 5=trace)\n", "log_level", cfg.LogLevel)
	fmt.Printf("%-22s = %s\n", "log_file", cfg.LogFile)
	fmt.Printf("%-22s = %s\n", "backup_type", cfg.BackupType)
	fmt.Printf("%-22s = %s\n", "backup_target", cfg.BackupTarget)
	fmt.Printf("%-22s = %d\n", "backup_interval_sec", cfg.BackupIntervalSec)
	if auth.IsSet() {
		fmt.Printf("%-22s = SET\n", "playback_password")
	} else {
		fmt.Printf("%-22s = not set\n", "playback_password")
	}

	// Warn about active env overrides so user knows values may differ from file.
	overrides := [][2]string{
		{"GHOSTSHELL_DAEMON_SOCK", os.Getenv("GHOSTSHELL_DAEMON_SOCK")},
		{"GHOSTSHELL_CENTRAL_DIR", os.Getenv("GHOSTSHELL_CENTRAL_DIR")},
		{"GHOSTSHELL_KEY_FILE", os.Getenv("GHOSTSHELL_KEY_FILE")},
		{"GHOSTSHELL_DIAL_TIMEOUT_SEC", os.Getenv("GHOSTSHELL_DIAL_TIMEOUT_SEC")},
		{"GHOSTSHELL_EOF_GRACE_MS", os.Getenv("GHOSTSHELL_EOF_GRACE_MS")},
		{"GHOSTSHELL_ANSIBLE_OUTPUT_CAP", os.Getenv("GHOSTSHELL_ANSIBLE_OUTPUT_CAP")},
		{"GHOSTSHELL_SCROLL_BUFFER", os.Getenv("GHOSTSHELL_SCROLL_BUFFER")},
		{"GHOSTSHELL_LOG_LEVEL", os.Getenv("GHOSTSHELL_LOG_LEVEL")},
		{"GHOSTSHELL_LOG_FILE", os.Getenv("GHOSTSHELL_LOG_FILE")},
		{"GHOSTSHELL_BACKUP_TYPE", os.Getenv("GHOSTSHELL_BACKUP_TYPE")},
		{"GHOSTSHELL_BACKUP_TARGET", os.Getenv("GHOSTSHELL_BACKUP_TARGET")},
		{"GHOSTSHELL_BACKUP_INTERVAL_SEC", os.Getenv("GHOSTSHELL_BACKUP_INTERVAL_SEC")},
	}
	for _, ov := range overrides {
		if ov[1] != "" {
			fmt.Fprintf(os.Stderr, "ghostshell: warning: %s=%s overrides config file\n", ov[0], ov[1])
		}
	}

	// Surface unknown keys, malformed lines, and out-of-range values from the
	// config file so a typo'd or rejected setting is visible instead of being
	// silently ignored by the parser.
	for _, w := range config.Validate(path) {
		fmt.Fprintf(os.Stderr, "ghostshell: warning: %s\n", w)
	}

	fmt.Fprintln(os.Stderr, "ghostshell: config OK")
	return 0
}
