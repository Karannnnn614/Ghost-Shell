// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// traversalVariants is the adversarial id/component corpus every id->path
// resolution entry point must survive without escaping the central store.
// "..%2f" is deliberately included: it contains no real separator (Linux does
// not URL-decode paths), so it is a *safe literal* that can only ever name a file
// inside the user dir — it must therefore resolve inside the store (and simply
// not be found), never traverse.
var traversalVariants = []string{
	"../../etc/passwd",
	"..%2f..%2fetc%2fpasswd",
	"/etc/passwd",
	"a/../../b",
	".",
	"..",
	"a/b",
	`a\b`,
	"sub/",
	"",
	"\x00etc",
}

// underCentral reports whether p, once cleaned, is still rooted inside central.
func underCentral(central, p string) bool {
	c := filepath.Clean(central)
	cp := filepath.Clean(p)
	return cp == c || strings.HasPrefix(cp, c+string(filepath.Separator))
}

// TestPathBuildersNeverEscapeCentral proves the pure path builders (UserDir,
// CastPath, AnsiblePath, AnsibleDir) can never be steered outside the central
// store by a crafted user/id/runid: an unsafe component is replaced by a
// fail-closed sentinel, so the joined path always stays under CentralDir (and
// the subsequent open/stat fails on the NUL sentinel rather than reading an
// attacker-chosen target).
func TestPathBuildersNeverEscapeCentral(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	for _, v := range traversalVariants {
		paths := map[string]string{
			"UserDir":     UserDir(v),
			"AnsibleDir":  AnsibleDir(v),
			"CastPath.u":  CastPath(v, "sess"),
			"CastPath.id": CastPath("alice", v),
			"Ansible.u":   AnsiblePath(v, "run1"),
			"Ansible.id":  AnsiblePath("alice", v),
		}
		for name, p := range paths {
			if !underCentral(central, p) {
				t.Errorf("%s(%q) = %q escapes central store %q", name, v, p, central)
			}
		}
	}
}

// TestPathBuildersPassValidComponentsThrough confirms the fail-closed guard is a
// no-op for legitimate components: valid users/ids build the exact expected path
// (so the daemon/ansible callers that pass already-validated values are
// unaffected).
func TestPathBuildersPassValidComponentsThrough(t *testing.T) {
	_, central, _ := setupTempEnv(t)
	if got, want := UserDir("alice"), filepath.Join(central, "alice"); got != want {
		t.Errorf("UserDir(alice) = %q, want %q", got, want)
	}
	if got, want := CastPath("alice", "sess1"), filepath.Join(central, "alice", "sess1.cast"); got != want {
		t.Errorf("CastPath = %q, want %q", got, want)
	}
	if got, want := AnsiblePath("bob", "run1"), filepath.Join(central, "bob", "ansible", "run1.ajsonl"); got != want {
		t.Errorf("AnsiblePath = %q, want %q", got, want)
	}
	// SafeComponent (exported) agrees with the guard used above.
	if !SafeComponent("alice") || SafeComponent("../etc") || SafeComponent("") {
		t.Errorf("SafeComponent disagrees with path-builder guard")
	}
}

// TestFindCentralRejectsAllTraversalVariants exercises the full corpus against
// FindCentral: against an empty store every variant must fail (either rejected
// as unsafe, or — for the safe-literal "..%2f" case — reported as not-found),
// and none may ever return a path.
func TestFindCentralRejectsAllTraversalVariants(t *testing.T) {
	setupTempEnv(t)
	for _, v := range traversalVariants {
		path, user, err := FindCentral(v)
		if err == nil {
			t.Errorf("FindCentral(%q) = (%q,%q,nil), want error", v, path, user)
		}
		if path != "" {
			t.Errorf("FindCentral(%q) returned path %q, want empty", v, path)
		}
	}
}

// TestIsAnsibleRunRejectsAllTraversalVariants: no crafted id may make
// IsAnsibleRun probe a path outside the store or report true against an empty
// store.
func TestIsAnsibleRunRejectsAllTraversalVariants(t *testing.T) {
	setupTempEnv(t)
	for _, v := range traversalVariants {
		if IsAnsibleRun(v) {
			t.Errorf("IsAnsibleRun(%q) = true, want false", v)
		}
	}
}

// TestUserSessionsRejectsAllTraversalVariants: the user component is validated
// up front, so no crafted user can list a directory outside the store. (The
// safe-literal "..%2f" resolves to a nonexistent in-store dir and errors as
// not-exist; either way nothing outside the store is enumerated.)
func TestUserSessionsRejectsAllTraversalVariants(t *testing.T) {
	setupTempEnv(t)
	for _, v := range traversalVariants {
		if _, err := UserSessions(v); err == nil {
			t.Errorf("UserSessions(%q) = nil error, want rejection/not-exist", v)
		}
	}
}
