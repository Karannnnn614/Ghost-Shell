// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package complete provides shell completion: a hidden `__complete` helper that
// emits dynamic candidates, and `completion <shell>` that prints the script.
package complete

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ghostshell/internal/store"
)

//go:embed ghostshell.bash
var bashScript string

// Script handles `ghostshell completion <shell>` — prints the completion script.
func Script(args []string) error {
	shell := "bash"
	if len(args) > 0 {
		shell = args[0]
	}
	switch shell {
	case "bash":
		fmt.Print(bashScript)
		return nil
	default:
		return fmt.Errorf("unsupported shell %q (only: bash)", shell)
	}
}

// Complete handles `ghostshell __complete <kind>` — prints newline-separated
// candidates. Errors are swallowed (print nothing) so completion never noisily
// fails, e.g. when a non-root user cannot read the central store.
func Complete(args []string) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "subcommands":
		// Keep in sync with the dispatch switch in cmd/ghostshell/main.go (user-facing
		// commands only; hidden aliases ls-user/play-user/ansible-ingest/__complete
		// are intentionally omitted from completion).
		fmt.Println("init rec play ls tail tree status search export prune backup ansible completion version help")
	case "local-sessions":
		if names, err := castNames(store.Dir()); err == nil {
			fmt.Println(strings.Join(sanitize(names), "\n"))
		}
	case "users":
		if users, err := store.Users(); err == nil {
			fmt.Println(strings.Join(sanitize(users), "\n"))
		}
	case "central-sessions":
		users, err := store.Users()
		if err != nil {
			return nil
		}
		var ids []string
		for _, u := range users {
			names, _ := store.UserSessions(u)
			for _, n := range names {
				ids = append(ids, strings.TrimSuffix(n, ".cast"))
			}
		}
		fmt.Println(strings.Join(sanitize(ids), "\n"))
	}
	return nil
}

// sanitize drops candidate names that contain whitespace or shell/IFS
// metacharacters. Candidates are derived from filenames and are embedded
// unquoted into `compgen -W "..."` in the completion script, so a crafted name
// could otherwise inject word breaks or shell syntax. Defense-in-depth: names
// already pass through store.safeComponent for central candidates, but local
// candidates do not, and word-splitting metacharacters are not path separators.
func sanitize(names []string) []string {
	out := names[:0:0]
	for _, n := range names {
		if n != "" && !strings.ContainsAny(n, unsafeChars) {
			out = append(out, n)
		}
	}
	return out
}

// unsafeChars are characters that must never appear in an unquoted completion
// candidate: ASCII whitespace plus shell metacharacters and IFS-relevant bytes.
const unsafeChars = " \t\n\r\v\f`$&|;<>(){}[]*?!~#'\"\\" + "\x00"

func castNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".cast" {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
