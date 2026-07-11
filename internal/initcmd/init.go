// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package initcmd implements `ghostshell init` — the first-time setup wizard and
// playback-password management commands.
package initcmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"ghostshell/internal/auth"
	"ghostshell/internal/config"
)

// Run dispatches the init subcommand.
func Run(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	resetPw := fs.Bool("reset-password", false, "change the playback password (requires current password)")
	clearPw := fs.Bool("clear-password", false, "remove playback password protection (requires current password)")
	enableSSH := fs.Bool("enable-ssh-forcecommand", false, "enable sshd ForceCommand recording of non-interactive SSH commands (root)")
	disableSSH := fs.Bool("disable-ssh-forcecommand", false, "disable sshd ForceCommand recording of non-interactive SSH commands (root)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *enableSSH && *disableSSH {
		return errors.New("--enable-ssh-forcecommand and --disable-ssh-forcecommand are mutually exclusive")
	}
	switch {
	case *resetPw:
		return cmdResetPassword()
	case *clearPw:
		return cmdClearPassword()
	case *enableSSH:
		return cmdEnableSSHForceCommand()
	case *disableSSH:
		return cmdDisableSSHForceCommand()
	default:
		return wizard()
	}
}

// ─── wizard ───────────────────────────────────────────────────────────────────

func wizard() error {
	fmt.Fprintln(os.Stderr, "ghostshell initialization")
	fmt.Fprintln(os.Stderr, "═══════════════════════════════════════")
	fmt.Fprintln(os.Stderr)

	cfg := config.Load()
	ok := true

	// [1/4] Config file
	cfgPath := os.Getenv("GHOSTSHELL_CONFIG")
	if cfgPath == "" {
		cfgPath = config.DefaultPath
	}
	if _, err := os.Stat(cfgPath); err == nil {
		printStep(1, 4, "Config ("+cfgPath+")", "OK")
	} else {
		printStep(1, 4, "Config ("+cfgPath+")", "MISSING — defaults in use")
	}

	// [2/4] Daemon socket
	conn, derr := net.DialTimeout("unix", cfg.SocketPath, time.Second)
	if derr == nil {
		conn.Close()
		printStep(2, 4, "Daemon (ghostshell-daemon) on "+cfg.SocketPath, "RUNNING")
	} else {
		printStep(2, 4, "Daemon (ghostshell-daemon) on "+cfg.SocketPath, "NOT RUNNING — start with: systemctl start ghostshell-daemon")
		ok = false
	}

	// [3/4] Encryption key
	keyPath := cfg.ResolvedKeyFile()
	if _, kerr := os.Stat(keyPath); kerr == nil {
		printStep(3, 4, "Encryption key ("+keyPath+")", "OK")
	} else if os.IsPermission(kerr) {
		// Key exists but not readable by this user (root-only file). Not an error.
		printStep(3, 4, "Encryption key ("+keyPath+")", "OK (root-only — run as root to verify)")
	} else {
		printStep(3, 4, "Encryption key ("+keyPath+")", "MISSING — start ghostshell-daemon to generate")
		ok = false
	}

	// [4/4] Playback password
	if auth.IsSet() {
		printStep(4, 4, "Playback password", "SET")
		fmt.Fprintln(os.Stderr)
		if ok {
			fmt.Fprintln(os.Stderr, "All good. Use --reset-password or --clear-password to change.")
		}
	} else {
		printStep(4, 4, "Playback password", "not set")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  Any root user can replay sessions without a password.")
		if promptYesNo(os.Stdin, "  Set a playback password? [y/N] ") {
			if err := promptSetNewPassword(); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(os.Stderr, "  Skipping — no playback password set.")
		}
	}

	fmt.Fprintln(os.Stderr)
	if ok {
		fmt.Fprintln(os.Stderr, "ghostshell init complete. Run 'ghostshell --check' to verify config values.")
	} else {
		fmt.Fprintln(os.Stderr, "ghostshell init complete with warnings. Resolve the issues above.")
	}
	return nil
}

// ─── password subcommands ─────────────────────────────────────────────────────

func cmdResetPassword() error {
	if !auth.IsSet() {
		// No existing password — allow setting one directly.
		fmt.Fprintln(os.Stderr, "No playback password set. Setting a new one.")
		return promptSetNewPassword()
	}
	if err := verifyCurrentPassword(); err != nil {
		return err
	}
	return promptSetNewPassword()
}

func cmdClearPassword() error {
	if !auth.IsSet() {
		fmt.Fprintln(os.Stderr, "No playback password set — nothing to clear.")
		return nil
	}
	if err := verifyCurrentPassword(); err != nil {
		return err
	}
	if err := auth.Remove(); err != nil {
		return fmt.Errorf("remove password: %w", err)
	}
	fmt.Fprintln(os.Stderr, "✓ Playback password removed. Sessions can be replayed without a password.")
	return nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func verifyCurrentPassword() error {
	for i := 0; i < auth.MaxAttempts; i++ {
		pw, err := auth.ReadPassword("Current password: ")
		if err != nil {
			return err
		}
		if err := auth.Verify(pw); err == nil {
			return nil
		}
		if i < auth.MaxAttempts-1 {
			fmt.Fprintln(os.Stderr, "ghostshell: incorrect password, try again")
		}
	}
	return errors.New("incorrect password — aborting")
}

func promptSetNewPassword() error {
	for {
		pw, err := auth.ReadPassword("New password:     ")
		if err != nil {
			return err
		}
		if len(pw) < 8 {
			fmt.Fprintln(os.Stderr, "ghostshell: password must be at least 8 characters")
			continue
		}
		confirm, err := auth.ReadPassword("Confirm password: ")
		if err != nil {
			return err
		}
		if pw != confirm {
			fmt.Fprintln(os.Stderr, "ghostshell: passwords do not match, try again")
			continue
		}
		if err := auth.SetPassword(pw); err != nil {
			return fmt.Errorf("set password: %w", err)
		}
		fmt.Fprintln(os.Stderr, "✓ Playback password set.")
		return nil
	}
}

func printStep(n, total int, label, status string) {
	fmt.Fprintf(os.Stderr, "[%d/%d] %-44s %s\n", n, total, label, status)
}

// promptYesNo prints prompt to stderr and reads a single answer from r. It
// returns true only for an explicit yes; any read error — a bare Enter
// (unexpected newline) or EOF/closed stdin in a non-TTY context — defaults to
// false so the wizard never silently proceeds on ambiguous input. Checking the
// error (rather than discarding it as before) also avoids leaving a leftover
// token in the buffer to be misread by a later prompt.
func promptYesNo(r io.Reader, prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	var ans string
	if _, err := fmt.Fscanln(r, &ans); err != nil {
		// EOF means stdin is closed/non-interactive; report it so the user
		// understands why no password was requested.
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr, "(no input — assuming no)")
		}
		return false
	}
	switch strings.ToLower(ans) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
