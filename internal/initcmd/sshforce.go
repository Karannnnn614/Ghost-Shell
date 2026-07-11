// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package initcmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SSH ForceCommand session-recording is an EXPLICIT, opt-in admin action. It is
// no longer installed by the package post-install; an administrator turns it on
// with `ghostshell init --enable-ssh-forcecommand` and off with
// `--disable-ssh-forcecommand`. Everything here is written as small, injectable
// helpers so the enable/validate/revert and enable→disable round-trips can be
// unit-tested without a real sshd.

// geteuid is the effective-uid source. It is a var (not a direct os.Geteuid
// call) so tests can simulate root or an unprivileged user when exercising the
// root-enforcement gate on the SSH ForceCommand commands. Mirrors the pattern
// used in internal/audit and internal/ansible.
var geteuid = os.Geteuid

// sshdConfigDir is the sshd drop-in directory. It is a var so tests can point it
// at a temp dir instead of the real /etc/ssh/sshd_config.d.
var sshdConfigDir = "/etc/ssh/sshd_config.d"

// runValidate validates the running sshd configuration. It is a var so tests can
// substitute a fake validator; the real check runs `sshd -t` via argv (no shell)
// so a hostile path/value can never be interpreted by a shell.
var runValidate = func() error {
	return exec.Command("sshd", "-t").Run()
}

// runReload reloads sshd so a config change takes effect. Best-effort in
// production (the config is already validated before we reload). It is a var so
// tests can stub it. Tries `systemctl reload ssh` first (Debian/Ubuntu unit),
// then `systemctl reload sshd` (RHEL/Fedora unit).
var runReload = func() error {
	if err := exec.Command("systemctl", "reload", "ssh").Run(); err == nil {
		return nil
	}
	return exec.Command("systemctl", "reload", "sshd").Run()
}

const (
	sshForceConfName = "zz-ghostshell.conf"
	sshForceWrapper  = "/usr/libexec/ghostshell-ssh-wrap"
)

// sshForceConfBody is written to the drop-in when ForceCommand is enabled.
const sshForceConfBody = `# Enabled by 'ghostshell init --enable-ssh-forcecommand'.
# Records non-interactive SSH commands (ssh host "cmd") via the ghostshell wrapper.
# The wrapper is fail-open: scp/sftp/rsync/git transfers pass through untouched
# and SSH is never blocked. Disable with:
#   sudo ghostshell init --disable-ssh-forcecommand
ForceCommand /usr/libexec/ghostshell-ssh-wrap
`

// sshdMainConfig returns the main sshd_config path, derived from the drop-in
// directory so tests that relocate sshdConfigDir get a matching main config.
func sshdMainConfig() string {
	return filepath.Join(filepath.Dir(sshdConfigDir), "sshd_config")
}

// includeLine is the exact Include directive this command adds to the main
// sshd_config when one is missing (so we can revert precisely).
func includeLine() string {
	return "Include " + sshdConfigDir + "/*.conf"
}

// includesDropinDir reports whether the main sshd_config already has an Include
// directive that covers our drop-in directory. sshd keywords are
// case-insensitive; the glob argument is compared literally against the two
// common forms (`.../*.conf` and `.../*`).
func includesDropinDir(content, dir string) bool {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
			continue
		}
		for _, arg := range fields[1:] {
			if arg == dir+"/*.conf" || arg == dir+"/*" {
				return true
			}
		}
	}
	return false
}

// prependIncludeLine inserts the Include directive at the top of the main
// sshd_config (OpenSSH's own default placement, so drop-ins are processed
// early), preserving the original bytes and file mode otherwise.
func prependIncludeLine(path string, existing []byte) error {
	var buf bytes.Buffer
	buf.WriteString(includeLine())
	buf.WriteByte('\n')
	buf.Write(existing)
	return os.WriteFile(path, buf.Bytes(), fileMode(path, 0o644))
}

// removeIncludeLine deletes the first line equal to the Include directive this
// command adds. It is used only to revert an Include that THIS run introduced —
// never a pre-existing one (deleting a pre-existing Include, which also broke
// every other sshd drop-in on the box, was a real bug in the old postinstall).
func removeIncludeLine(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	target := includeLine()
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	removed := false
	for _, ln := range lines {
		if !removed && strings.TrimSpace(ln) == target {
			removed = true
			continue
		}
		out = append(out, ln)
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), fileMode(path, 0o644))
}

// fileMode returns path's current permission bits, or def if it cannot be
// stat'd, so rewrites preserve the original mode.
func fileMode(path string, def os.FileMode) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return def
}

// cmdEnableSSHForceCommand installs the sshd ForceCommand drop-in that records
// non-interactive SSH commands. It is fail-safe: if `sshd -t` rejects the
// result it reverts ONLY the edits this run made (the drop-in it wrote, and the
// Include line only if it added it) and returns an error, never leaving sshd
// unparseable. It is idempotent: re-running when already enabled changes and
// duplicates nothing.
func cmdEnableSSHForceCommand() error {
	if geteuid() != 0 {
		return errors.New("permission denied: enabling the SSH ForceCommand edits /etc/ssh and must be run as root (try: sudo ghostshell init --enable-ssh-forcecommand)")
	}

	// The drop-in directory must exist; without it sshd has no include mechanism
	// for our config and we must not guess at editing the monolithic file.
	if fi, err := os.Stat(sshdConfigDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s does not exist — this sshd does not support drop-in configs; add %q to %s and install the ForceCommand manually", sshdConfigDir, includeLine(), sshdMainConfig())
	}

	confPath := filepath.Join(sshdConfigDir, sshForceConfName)

	// If the drop-in already exists, leave it as-is (an admin may have customized
	// it, e.g. with a Match block) — this is the idempotent / no-clobber path.
	confExists := false
	if _, err := os.Stat(confPath); err == nil {
		confExists = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", confPath, err)
	}

	// Track exactly what THIS run changes so the validation-failure path reverts
	// only our own edits.
	addedInclude := false
	wroteConf := false
	mainCfg := sshdMainConfig()

	// Ensure the main sshd_config includes the drop-in directory; without it the
	// drop-in is silently ignored. Only add if missing, and remember we added it
	// so a failed validation reverts precisely.
	if data, err := os.ReadFile(mainCfg); err == nil {
		if !includesDropinDir(string(data), sshdConfigDir) {
			if werr := prependIncludeLine(mainCfg, data); werr != nil {
				return fmt.Errorf("add Include directive to %s: %w", mainCfg, werr)
			}
			addedInclude = true
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", mainCfg, err)
	}
	// (If mainCfg is absent entirely, skip — `sshd -t` below surfaces any real
	// problem; on a normal host the main config always exists.)

	if !confExists {
		if werr := os.WriteFile(confPath, []byte(sshForceConfBody), 0o644); werr != nil {
			if addedInclude {
				_ = removeIncludeLine(mainCfg)
			}
			return fmt.Errorf("write %s: %w", confPath, werr)
		}
		wroteConf = true
	}

	// Validate. On failure revert ONLY our own edits, then error — sshd must be
	// left exactly as it was before this command ran.
	if verr := runValidate(); verr != nil {
		if wroteConf {
			_ = os.Remove(confPath)
		}
		if addedInclude {
			_ = removeIncludeLine(mainCfg)
		}
		return fmt.Errorf("sshd rejected the configuration after enabling ForceCommand; reverted every change this command made (sshd left in its previous, valid state): %w", verr)
	}

	// Config is valid — reload sshd so it takes effect (best-effort).
	_ = runReload()

	if confExists {
		fmt.Fprintf(os.Stderr, "✓ SSH ForceCommand already enabled (%s left as-is).\n", confPath)
	} else {
		fmt.Fprintln(os.Stderr, "✓ SSH ForceCommand enabled — non-interactive SSH commands (ssh host \"cmd\") are now recorded.")
		fmt.Fprintf(os.Stderr, "  drop-in: %s\n", confPath)
	}
	fmt.Fprintln(os.Stderr, "  scp/sftp/rsync/git transfers pass through untouched; the wrapper is fail-open (SSH is never blocked).")
	fmt.Fprintln(os.Stderr, "  disable with: sudo ghostshell init --disable-ssh-forcecommand")
	return nil
}

// cmdDisableSSHForceCommand removes the ForceCommand drop-in and reloads sshd.
// It deliberately leaves the Include directive and any other drop-ins in place
// (other files may rely on the Include). It is a no-op — not an error — when the
// drop-in is already absent.
func cmdDisableSSHForceCommand() error {
	if geteuid() != 0 {
		return errors.New("permission denied: disabling the SSH ForceCommand edits /etc/ssh and must be run as root (try: sudo ghostshell init --disable-ssh-forcecommand)")
	}

	confPath := filepath.Join(sshdConfigDir, sshForceConfName)
	if _, err := os.Stat(confPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "SSH ForceCommand is not enabled (%s absent) — nothing to disable.\n", confPath)
			return nil
		}
		return fmt.Errorf("stat %s: %w", confPath, err)
	}

	if err := os.Remove(confPath); err != nil {
		return fmt.Errorf("remove %s: %w", confPath, err)
	}
	// Reload so sshd stops force-wrapping commands (best-effort).
	_ = runReload()

	fmt.Fprintf(os.Stderr, "✓ SSH ForceCommand disabled — removed %s and reloaded sshd.\n", confPath)
	fmt.Fprintln(os.Stderr, "  (The Include directive and any other sshd drop-ins were left untouched.)")
	return nil
}
