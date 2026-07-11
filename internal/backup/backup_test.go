// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package backup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"ghostshell/internal/config"
)

func TestBuildBackupArgs_AWS(t *testing.T) {
	cfg := &config.Config{
		BackupType:   "bucket_aws",
		BackupTarget: "s3://my-bucket/ghostshell",
		CentralDir:   "/var/lib/ghostshell",
	}
	name, args, err := buildBackupArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "aws" {
		t.Errorf("name = %q, want aws", name)
	}
	want := []string{"s3", "sync", "/var/lib/ghostshell", "s3://my-bucket/ghostshell"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestBuildBackupArgs_GCP(t *testing.T) {
	cfg := &config.Config{
		BackupType:   "bucket_gcp",
		BackupTarget: "gs://my-bucket/ghostshell",
		CentralDir:   "/var/lib/ghostshell",
	}
	name, args, err := buildBackupArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "gsutil" {
		t.Errorf("name = %q, want gsutil", name)
	}
	want := []string{"-m", "rsync", "-r", "/var/lib/ghostshell", "gs://my-bucket/ghostshell"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestBuildBackupArgs_Rsync(t *testing.T) {
	cfg := &config.Config{
		BackupType:   "rsync",
		BackupTarget: "user@host:/backups/ghostshell",
		CentralDir:   "/var/lib/ghostshell",
	}
	name, args, err := buildBackupArgs(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "rsync" {
		t.Errorf("name = %q, want rsync", name)
	}
	// Trailing slash on CentralDir is required for rsync to copy contents,
	// not create a nested sub-directory.
	want := []string{"-a", "--delete", "/var/lib/ghostshell/", "user@host:/backups/ghostshell"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

func TestBuildBackupArgs_DisabledTypeReturnsError(t *testing.T) {
	cfg := &config.Config{BackupType: "", BackupTarget: "s3://bucket", CentralDir: "/var/lib/ghostshell"}
	_, _, err := buildBackupArgs(cfg)
	if err == nil {
		t.Fatal("expected error for empty backup_type, got nil")
	}
}

func TestBuildBackupArgs_EmptyTargetReturnsError(t *testing.T) {
	cfg := &config.Config{BackupType: "bucket_aws", BackupTarget: "", CentralDir: "/var/lib/ghostshell"}
	_, _, err := buildBackupArgs(cfg)
	if err == nil {
		t.Fatal("expected error for empty backup_target, got nil")
	}
}

func TestRunInvokesCorrectCommand(t *testing.T) {
	var gotName string
	var gotArgs []string
	orig := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		gotName = name
		gotArgs = args
		return nil
	}
	defer func() { runCommand = orig }()

	cfg := &config.Config{
		BackupType:   "rsync",
		BackupTarget: "user@host:/backup",
		CentralDir:   "/var/lib/ghostshell",
	}
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotName != "rsync" {
		t.Errorf("command = %q, want rsync", gotName)
	}
	wantArgs := []string{"-a", "--delete", "/var/lib/ghostshell/", "user@host:/backup"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("args = %v, want %v", gotArgs, wantArgs)
	}
}

func TestRunDisabledReturnsError(t *testing.T) {
	cfg := &config.Config{BackupType: "", CentralDir: "/var/lib/ghostshell"}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected error for disabled backup, got nil")
	}
}

func TestRunCommandFailurePropagates(t *testing.T) {
	orig := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		return errors.New("simulated transfer failure")
	}
	defer func() { runCommand = orig }()

	cfg := &config.Config{
		BackupType:   "bucket_aws",
		BackupTarget: "s3://bucket",
		CentralDir:   "/var/lib/ghostshell",
	}
	if err := Run(context.Background(), cfg); err == nil {
		t.Fatal("expected error to propagate from runCommand, got nil")
	}
}

// TestRunCLIUsesFreshConfig verifies RunCLI reads config via config.Parse()
// (fresh) rather than the cached config.Load() singleton, so a `ghostshell backup`
// invoked after a config edit sees the current values. It primes the Load()
// singleton with one set of values, then changes the environment and confirms
// RunCLI assembles the command from the new values.
func TestRunCLIUsesFreshConfig(t *testing.T) {
	// Isolate from any real config file.
	t.Setenv("GHOSTSHELL_CONFIG", filepath.Join(t.TempDir(), "nonexistent.conf"))

	// Prime the Load() singleton with stale values that RunCLI must NOT use.
	t.Setenv("GHOSTSHELL_BACKUP_TYPE", "rsync")
	t.Setenv("GHOSTSHELL_BACKUP_TARGET", "user@stale:/old")
	config.Reset()
	_ = config.Load()
	t.Cleanup(config.Reset)

	// Edit the environment after the singleton is cached.
	t.Setenv("GHOSTSHELL_BACKUP_TYPE", "bucket_aws")
	t.Setenv("GHOSTSHELL_BACKUP_TARGET", "s3://fresh-bucket/prefix")

	var gotName string
	var gotArgs []string
	orig := runCommand
	runCommand = func(_ context.Context, name string, args ...string) error {
		gotName = name
		gotArgs = args
		return nil
	}
	defer func() { runCommand = orig }()

	if err := RunCLI(nil); err != nil {
		t.Fatalf("RunCLI: %v", err)
	}
	if gotName != "aws" {
		t.Errorf("command = %q, want aws (fresh value); RunCLI used the stale cached config", gotName)
	}
	if len(gotArgs) == 0 || gotArgs[len(gotArgs)-1] != "s3://fresh-bucket/prefix" {
		t.Errorf("args = %v, want target s3://fresh-bucket/prefix (fresh value)", gotArgs)
	}
}

func TestRunCLIDisabledReturnsError(t *testing.T) {
	t.Setenv("GHOSTSHELL_CONFIG", filepath.Join(t.TempDir(), "nonexistent.conf"))
	t.Setenv("GHOSTSHELL_BACKUP_TYPE", "")
	t.Setenv("GHOSTSHELL_BACKUP_TARGET", "")
	config.Reset()
	t.Cleanup(config.Reset)

	if err := RunCLI(nil); err == nil {
		t.Fatal("expected error when backup_type is empty, got nil")
	}
}

// TestBuildBackupArgsNoShellInterpolation proves the backup_target is passed as
// a single, verbatim argv element and is never handed to a shell. Even a target
// containing shell metacharacters must survive intact as one argument (Run uses
// exec.CommandContext(name, args...) — no `sh -c`), so it cannot be split or
// interpreted into a command injection.
func TestBuildBackupArgsNoShellInterpolation(t *testing.T) {
	const evil = "user@host:/backups; rm -rf / $(whoami) `id`"
	cfg := &config.Config{
		BackupType:   "rsync",
		BackupTarget: evil,
		CentralDir:   "/var/lib/ghostshell",
	}
	name, args, err := buildBackupArgs(cfg)
	if err != nil {
		t.Fatalf("buildBackupArgs: %v", err)
	}
	if name != "rsync" {
		t.Errorf("name = %q, want rsync", name)
	}
	last := args[len(args)-1]
	if last != evil {
		t.Errorf("target argv element = %q; want the raw target verbatim (no shell splitting)", last)
	}
	// The metacharacters must not appear anywhere except as that one element.
	for i, a := range args[:len(args)-1] {
		if a == evil {
			t.Errorf("target unexpectedly duplicated at arg %d", i)
		}
	}
}

// TestRunRsyncAgainstLocalTarget actually EXERCISES the rsync backup path end to
// end against a real local target using the real runCommand (real rsync binary),
// confirming the README's documented mirror-with-delete semantics:
//   - every file in the fake central store appears at the target,
//   - the trailing-slash source copies contents (not a nested sub-dir),
//   - --delete removes files at the target that are not in the source.
//
// Skips when rsync is not installed (e.g. bare Windows host); runs in the Linux
// CI/Docker image where rsync is available.
func TestRunRsyncAgainstLocalTarget(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not installed; skipping real-transfer exercise")
	}

	src := t.TempDir()
	dst := t.TempDir()

	// Fake central store: <user>/<id>.cast plus the at-rest key file.
	userDir := filepath.Join(src, "alice")
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "sess1.cast"), []byte("CAST-DATA-1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".ghostshell.key"), []byte("KEYBYTES"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-seed the destination with a stale file that --delete must remove.
	if err := os.WriteFile(filepath.Join(dst, "stale.cast"), []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		BackupType:   "rsync",
		BackupTarget: dst, // local path target: argv only, never a shell string
		CentralDir:   src,
	}
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("rsync backup failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dst, "alice", "sess1.cast"))
	if err != nil {
		t.Fatalf("expected recording mirrored to target: %v", err)
	}
	if string(got) != "CAST-DATA-1" {
		t.Errorf("mirrored content = %q, want CAST-DATA-1", got)
	}
	if _, err := os.Stat(filepath.Join(dst, ".ghostshell.key")); err != nil {
		t.Errorf("key file not mirrored to target: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "stale.cast")); !os.IsNotExist(err) {
		t.Errorf("--delete did not remove the stale target file (err=%v)", err)
	}
}

func TestRunCancelledContextKillsProcess(t *testing.T) {
	orig := runCommand
	defer func() { runCommand = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	called := false
	runCommand = func(_ context.Context, name string, args ...string) error {
		called = true
		return ctx.Err()
	}

	cfg := &config.Config{
		BackupType:   "rsync",
		BackupTarget: "user@host:/path",
		CentralDir:   "/tmp",
	}
	err := Run(ctx, cfg)
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
	if !called {
		t.Error("runCommand spy was not called")
	}
}
