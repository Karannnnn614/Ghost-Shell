// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package initcmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupSSH points the SSH ForceCommand helpers at a fresh temp sshd tree and
// simulates running as root with a stubbed validator/reload, so the enable and
// disable flows can be exercised without a real sshd. It returns the drop-in
// directory and the main sshd_config path and restores every package-level var
// on cleanup. Tests using it must not run in parallel (they mutate shared vars).
func setupSSH(t *testing.T) (dropin, mainCfg string) {
	t.Helper()
	base := t.TempDir()
	dropin = filepath.Join(base, "sshd_config.d")
	if err := os.MkdirAll(dropin, 0o755); err != nil {
		t.Fatalf("mkdir drop-in dir: %v", err)
	}
	mainCfg = filepath.Join(base, "sshd_config")

	prevDir, prevEuid, prevVal, prevReload := sshdConfigDir, geteuid, runValidate, runReload
	sshdConfigDir = dropin
	geteuid = func() int { return 0 }
	runValidate = func() error { return nil }
	runReload = func() error { return nil }
	t.Cleanup(func() {
		sshdConfigDir = prevDir
		geteuid = prevEuid
		runValidate = prevVal
		runReload = prevReload
	})
	return dropin, mainCfg
}

func confPathIn(dropin string) string { return filepath.Join(dropin, sshForceConfName) }

// TestEnableSSHForceCommand_Enable covers the happy path: the drop-in is written
// with the ForceCommand and the Include line is added to the main config.
func TestEnableSSHForceCommand_Enable(t *testing.T) {
	dropin, mainCfg := setupSSH(t)
	if err := os.WriteFile(mainCfg, []byte("# main sshd config\nPort 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := cmdEnableSSHForceCommand(); err != nil {
		t.Fatalf("enable: %v", err)
	}

	conf, err := os.ReadFile(confPathIn(dropin))
	if err != nil {
		t.Fatalf("read drop-in: %v", err)
	}
	if !strings.Contains(string(conf), "ForceCommand "+sshForceWrapper) {
		t.Errorf("drop-in missing ForceCommand line:\n%s", conf)
	}
	main, _ := os.ReadFile(mainCfg)
	if !strings.Contains(string(main), includeLine()) {
		t.Errorf("main config missing Include line:\n%s", main)
	}
}

// TestEnableSSHForceCommand_ValidateFailsReverts asserts that when `sshd -t`
// rejects the result, both the drop-in and the Include line THIS run added are
// reverted and the main config is restored byte-for-byte.
func TestEnableSSHForceCommand_ValidateFailsReverts(t *testing.T) {
	dropin, mainCfg := setupSSH(t)
	orig := "# main sshd config\nPort 22\n"
	if err := os.WriteFile(mainCfg, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	runValidate = func() error { return errors.New("simulated bad sshd config") }

	if err := cmdEnableSSHForceCommand(); err == nil {
		t.Fatal("expected an error when sshd -t fails")
	}

	if _, err := os.Stat(confPathIn(dropin)); !os.IsNotExist(err) {
		t.Errorf("drop-in should have been removed on revert (stat err=%v)", err)
	}
	main, _ := os.ReadFile(mainCfg)
	if string(main) != orig {
		t.Errorf("main config not restored on revert:\n got %q\nwant %q", main, orig)
	}
}

// TestEnableSSHForceCommand_ValidateFailsKeepsPreexistingInclude is the
// regression test for the old postinstall bug: when validation fails, a
// pre-existing Include (which we did NOT add) must be preserved.
func TestEnableSSHForceCommand_ValidateFailsKeepsPreexistingInclude(t *testing.T) {
	dropin, mainCfg := setupSSH(t)
	orig := includeLine() + "\nPort 22\n"
	if err := os.WriteFile(mainCfg, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	runValidate = func() error { return errors.New("simulated bad sshd config") }

	if err := cmdEnableSSHForceCommand(); err == nil {
		t.Fatal("expected an error when sshd -t fails")
	}

	if _, err := os.Stat(confPathIn(dropin)); !os.IsNotExist(err) {
		t.Errorf("drop-in should have been removed on revert (stat err=%v)", err)
	}
	main, _ := os.ReadFile(mainCfg)
	if string(main) != orig {
		t.Errorf("pre-existing Include must be preserved on revert:\n got %q\nwant %q", main, orig)
	}
}

// TestEnableSSHForceCommand_Idempotent asserts a second enable changes nothing
// and does not duplicate the Include line.
func TestEnableSSHForceCommand_Idempotent(t *testing.T) {
	dropin, mainCfg := setupSSH(t)
	if err := os.WriteFile(mainCfg, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := cmdEnableSSHForceCommand(); err != nil {
		t.Fatalf("first enable: %v", err)
	}
	firstMain, _ := os.ReadFile(mainCfg)
	firstConf, _ := os.ReadFile(confPathIn(dropin))

	if err := cmdEnableSSHForceCommand(); err != nil {
		t.Fatalf("second enable: %v", err)
	}
	secondMain, _ := os.ReadFile(mainCfg)
	secondConf, _ := os.ReadFile(confPathIn(dropin))

	if string(firstMain) != string(secondMain) {
		t.Errorf("main config changed on re-enable:\n first %q\nsecond %q", firstMain, secondMain)
	}
	if string(firstConf) != string(secondConf) {
		t.Errorf("drop-in changed on re-enable")
	}
	if n := strings.Count(string(secondMain), includeLine()); n != 1 {
		t.Errorf("expected exactly one Include line, got %d", n)
	}
}

func TestEnableSSHForceCommand_RequiresRoot(t *testing.T) {
	setupSSH(t)
	geteuid = func() int { return 1000 }
	if err := cmdEnableSSHForceCommand(); err == nil {
		t.Fatal("expected a permission error when not root")
	}
}

func TestEnableSSHForceCommand_MissingDropinDir(t *testing.T) {
	base := t.TempDir()
	prevDir, prevEuid, prevVal, prevReload := sshdConfigDir, geteuid, runValidate, runReload
	sshdConfigDir = filepath.Join(base, "absent", "sshd_config.d")
	geteuid = func() int { return 0 }
	runValidate = func() error { return nil }
	runReload = func() error { return nil }
	t.Cleanup(func() {
		sshdConfigDir, geteuid, runValidate, runReload = prevDir, prevEuid, prevVal, prevReload
	})

	if err := cmdEnableSSHForceCommand(); err == nil {
		t.Fatal("expected an error when the drop-in directory does not exist")
	}
}

// TestSSHForceCommand_EnableDisableRoundTrip enables, then disables, and checks
// the drop-in is gone while the Include line is deliberately left in place.
func TestSSHForceCommand_EnableDisableRoundTrip(t *testing.T) {
	dropin, mainCfg := setupSSH(t)
	if err := os.WriteFile(mainCfg, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := cmdEnableSSHForceCommand(); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := os.Stat(confPathIn(dropin)); err != nil {
		t.Fatalf("drop-in should exist after enable: %v", err)
	}

	if err := cmdDisableSSHForceCommand(); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := os.Stat(confPathIn(dropin)); !os.IsNotExist(err) {
		t.Errorf("drop-in should be removed after disable (stat err=%v)", err)
	}
	main, _ := os.ReadFile(mainCfg)
	if !strings.Contains(string(main), includeLine()) {
		t.Errorf("disable must NOT remove the Include line:\n%s", main)
	}
}

func TestDisableSSHForceCommand_NoopWhenAbsent(t *testing.T) {
	setupSSH(t)
	if err := cmdDisableSSHForceCommand(); err != nil {
		t.Errorf("disable when already absent should be a no-op, got: %v", err)
	}
}

func TestDisableSSHForceCommand_RequiresRoot(t *testing.T) {
	setupSSH(t)
	geteuid = func() int { return 1000 }
	if err := cmdDisableSSHForceCommand(); err == nil {
		t.Fatal("expected a permission error when not root")
	}
}

func TestRunSSHFlagsMutuallyExclusive(t *testing.T) {
	if err := Run([]string{"--enable-ssh-forcecommand", "--disable-ssh-forcecommand"}); err == nil {
		t.Fatal("expected an error when both SSH ForceCommand flags are given")
	}
}

// TestIncludesDropinDir spot-checks the Include-detection helper across the
// forms sshd accepts and the negatives it must not match.
func TestIncludesDropinDir(t *testing.T) {
	dir := "/etc/ssh/sshd_config.d"
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"exact conf glob", "Include /etc/ssh/sshd_config.d/*.conf\n", true},
		{"star glob", "Include /etc/ssh/sshd_config.d/*\n", true},
		{"leading whitespace", "   Include /etc/ssh/sshd_config.d/*.conf\n", true},
		{"lowercase keyword", "include /etc/ssh/sshd_config.d/*.conf\n", true},
		{"commented out", "# Include /etc/ssh/sshd_config.d/*.conf\n", false},
		{"different dir", "Include /etc/ssh/other.d/*.conf\n", false},
		{"no include", "Port 22\nPermitRootLogin no\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := includesDropinDir(tc.content, dir); got != tc.want {
				t.Errorf("includesDropinDir(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}
