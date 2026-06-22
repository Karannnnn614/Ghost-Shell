// Package backup runs periodic and on-demand backups of the central recording
// store to a remote target. All transfer is delegated to an external command
// (aws, gsutil, rsync) — no new SDK dependencies are introduced.
package backup

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"ghostshell/internal/config"
)

// runCommand is the shell-out function. Tests replace it with a spy to verify
// the correct command is assembled without performing actual transfers.
var runCommand = func(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\noutput: %s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

// buildBackupArgs returns the binary name and argument list for the configured
// backup type. Pure — no I/O — so it can be tested without injection.
func buildBackupArgs(cfg *config.Config) (name string, args []string, err error) {
	if cfg.BackupType == "" {
		return "", nil, errors.New("backup disabled: backup_type is not set")
	}
	if cfg.BackupTarget == "" {
		return "", nil, errors.New("backup misconfigured: backup_target is empty")
	}
	switch cfg.BackupType {
	case "bucket_aws":
		return "aws", []string{"s3", "sync", cfg.CentralDir, cfg.BackupTarget}, nil
	case "bucket_gcp":
		return "gsutil", []string{"-m", "rsync", "-r", cfg.CentralDir, cfg.BackupTarget}, nil
	case "rsync":
		// Trailing slash copies directory contents, not a nested sub-directory.
		return "rsync", []string{"-a", "--delete", cfg.CentralDir + "/", cfg.BackupTarget}, nil
	default:
		return "", nil, fmt.Errorf("backup: unknown type %q", cfg.BackupType)
	}
}

// Run executes a backup for the given configuration. ctx cancellation kills
// the external process. Returns an error when the type is disabled,
// misconfigured, or the external command fails.
func Run(ctx context.Context, cfg *config.Config) error {
	name, args, err := buildBackupArgs(cfg)
	if err != nil {
		return err
	}
	return runCommand(ctx, name, args...)
}

// RunCLI is the entry point for `ghostshell backup`. Runs a backup immediately and
// prints a status line. Access enforced by filesystem permissions (CentralDir
// is root:root 0700).
func RunCLI(_ []string) error {
	// Parse() re-reads config fresh rather than returning the cached Load()
	// singleton, so a `ghostshell backup` run immediately after a config edit sees
	// the current backup_type/backup_target values.
	cfg := config.Parse()
	if cfg.BackupType == "" {
		return errors.New("backup is not configured (backup_type is empty in config)")
	}
	if err := Run(context.Background(), cfg); err != nil {
		return err
	}
	fmt.Printf("backup completed (type=%s target=%s)\n", cfg.BackupType, cfg.BackupTarget)
	return nil
}
