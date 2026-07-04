// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package backup

import (
	"context"
	"errors"
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
