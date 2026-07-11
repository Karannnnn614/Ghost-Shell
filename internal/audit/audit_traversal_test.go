// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// craftedIDs is the adversarial session-id corpus that must be rejected by every
// audit command that resolves an id to a central-store path.
var craftedIDs = []string{
	"../../etc/passwd",
	"/etc/passwd",
	"a/../../b",
	"..",
	".",
	"a/b",
	`a\b`,
	"",
	"\x00etc",
}

// TestAuditCommandsRejectCraftedID drives play-user / export / tail (static)
// with each crafted id while running as root, and asserts every one is refused
// (nothing outside the central store is opened, decrypted, or written). These
// commands funnel their id through store.FindCentral, whose safeComponent guard
// is the choke point; this test pins that end-to-end at the command layer.
func TestAuditCommandsRejectCraftedID(t *testing.T) {
	setupCentral(t) // sets central store + asRoot
	outDir := t.TempDir()

	for _, id := range craftedIDs {
		if err := PlayUser([]string{id}); err == nil {
			t.Errorf("PlayUser(%q) = nil error, want rejection", id)
		}
		if err := TailStatic([]string{id}); err == nil {
			t.Errorf("TailStatic(%q) = nil error, want rejection", id)
		}
		// Export to a file: the resolution must fail before any output file is
		// created, so a crafted id can neither read outside the store nor leave a
		// stray plaintext file behind.
		outFile := filepath.Join(outDir, "out.cast")
		if err := Export([]string{"-o", outFile, id}); err == nil {
			t.Errorf("Export(%q) = nil error, want rejection", id)
		}
		if _, err := os.Stat(outFile); err == nil {
			t.Errorf("Export(%q) created output file for a rejected id", id)
			_ = os.Remove(outFile)
		}
	}
}

// TestSearchUserFilterNeverBecomesPath confirms the search --user filter is only
// ever compared against the real user list (store.Users) and never used as a
// path component, so a crafted --user value cannot enumerate outside the store.
// A traversal --user simply matches no user and yields "no matches" without
// error or panic.
func TestSearchUserFilterNeverBecomesPath(t *testing.T) {
	central := setupCentral(t)
	writeCast(t, central, "alice", "s1", "echo hi", "hi\r\n")
	for _, u := range []string{"../../etc", "..", "a/b", "\x00x"} {
		out := captureStdout(t, func() {
			if err := Search([]string{"--user", u, "hi"}); err != nil {
				t.Errorf("Search --user %q returned error %v, want clean no-match", u, err)
			}
		})
		if out == "" {
			t.Errorf("Search --user %q produced no output at all", u)
		}
	}
}

// TestParseTimeShellMetacharsAreInert proves the --from/--to date parser cannot
// be turned into command injection. parseTime shells out to date(1) via argv
// (exec.Command), never `sh -c`, so shell metacharacters are literal arguments
// to date and cannot execute anything. We assert a canary side-effect file is
// never created for a battery of injection payloads.
func TestParseTimeShellMetacharsAreInert(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "pwned")
	payloads := []string{
		"$(touch " + canary + ")",
		"`touch " + canary + "`",
		"; touch " + canary,
		"x; touch " + canary,
		"| touch " + canary,
		"&& touch " + canary,
		"$(id)",
		"x\n touch " + canary,
	}
	for _, s := range payloads {
		_, _ = parseTime(s) // an error is expected; the point is the side effect
		if _, err := os.Stat(canary); err == nil {
			t.Fatalf("parseTime(%q) executed a shell command (canary created) — command injection!", s)
		}
	}
}
