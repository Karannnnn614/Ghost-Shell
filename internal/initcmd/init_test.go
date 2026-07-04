// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package initcmd

import (
	"strings"
	"testing"
)

// TestPromptYesNo exercises the injectable y/N reader used by the wizard. The
// audit finding was that the previous code discarded the Fscanln error, so a
// bare Enter or a closed/non-TTY stdin would silently default with no explicit
// handling. promptYesNo now returns false on any read error and true only for
// an explicit yes.
func TestPromptYesNo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"lower y", "y\n", true},
		{"upper Y", "Y\n", true},
		{"yes word", "yes\n", true},
		{"YES upper", "YES\n", true},
		{"explicit n", "n\n", false},
		{"explicit no", "no\n", false},
		{"bare enter defaults no", "\n", false},
		{"eof closed stdin defaults no", "", false},
		{"garbage defaults no", "maybe\n", false},
		// Fscanln with a single target errors when extra tokens precede the
		// newline ("expected newline"). We treat that error as no rather than
		// consuming "y" and leaving "extra" in the buffer for a later prompt —
		// exactly the leftover-token hazard the finding called out.
		{"y with trailing junk is no", "y extra\n", false},
		{"leading space then yes", "  y\n", true},
		{"leading space then no", "  no\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := promptYesNo(strings.NewReader(tc.input), "prompt? ")
			if got != tc.want {
				t.Errorf("promptYesNo(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// Note: promptSetNewPassword's length(<8) and mismatch retry loop is not unit
// tested here because it reads via auth.ReadPassword, which calls
// term.ReadPassword on os.Stdin's file descriptor directly and therefore
// requires a real TTY. Making it injectable would require changing the auth
// package, which is outside this change's scope. The validation thresholds
// (minimum 8 chars, confirm-must-match) are covered by manual/interactive use.
