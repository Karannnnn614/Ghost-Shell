package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(Reset)
	Reset()
}

func TestDefaults(t *testing.T) {
	resetForTest(t)
	// Point at a nonexistent file so defaults are used.
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")

	cfg := Load()
	if cfg.SocketPath != "/run/ghostshell-daemon.sock" {
		t.Errorf("SocketPath = %q, want /run/ghostshell-daemon.sock", cfg.SocketPath)
	}
	if cfg.CentralDir != "/var/lib/ghostshell" {
		t.Errorf("CentralDir = %q, want /var/lib/ghostshell", cfg.CentralDir)
	}
	if cfg.DialTimeout != 1*time.Second {
		t.Errorf("DialTimeout = %v, want 1s", cfg.DialTimeout)
	}
	if cfg.EOFGrace != 500*time.Millisecond {
		t.Errorf("EOFGrace = %v, want 500ms", cfg.EOFGrace)
	}
	if cfg.AnsibleOutputCap != 8*1024 {
		t.Errorf("AnsibleOutputCap = %d, want 8192", cfg.AnsibleOutputCap)
	}
	if cfg.ScrollBuffer != 32*1024 {
		t.Errorf("ScrollBuffer = %d, want 32768", cfg.ScrollBuffer)
	}
	if cfg.LogLevel != 3 {
		t.Errorf("LogLevel = %d, want 3", cfg.LogLevel)
	}
	if cfg.LogFile != "/var/log/ghostshell/ghostshell.log" {
		t.Errorf("LogFile = %q, want /var/log/ghostshell/ghostshell.log", cfg.LogFile)
	}
	if cfg.SessionCap != 10 {
		t.Errorf("SessionCap = %d, want default 10", cfg.SessionCap)
	}
	if cfg.BackupType != "" {
		t.Errorf("BackupType = %q, want empty (disabled)", cfg.BackupType)
	}
	if cfg.BackupTarget != "" {
		t.Errorf("BackupTarget = %q, want empty", cfg.BackupTarget)
	}
	if cfg.BackupIntervalSec != 0 {
		t.Errorf("BackupIntervalSec = %d, want 0", cfg.BackupIntervalSec)
	}
}

func TestSessionCapFromFile(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("session_cap = 25\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.SessionCap != 25 {
		t.Errorf("SessionCap = %d, want 25", cfg.SessionCap)
	}
}

func TestSessionCapEnvOverrides(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("session_cap = 25\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	t.Setenv("GHOSTSHELL_SESSION_CAP", "7")

	if cfg := Load(); cfg.SessionCap != 7 {
		t.Errorf("SessionCap = %d, want 7 (env wins)", cfg.SessionCap)
	}
}

func TestSessionCapInvalidFallsToDefault(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("session_cap = 0\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.SessionCap != 10 {
		t.Errorf("SessionCap = %d, want default 10 for invalid value", cfg.SessionCap)
	}
}

func TestBackupTypeDefault(t *testing.T) {
	resetForTest(t)
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")
	if cfg := Load(); cfg.BackupType != "" {
		t.Errorf("BackupType = %q, want empty string (disabled by default)", cfg.BackupType)
	}
}

func TestBackupTypeFromFile(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_type = bucket_aws\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	if cfg := Load(); cfg.BackupType != "bucket_aws" {
		t.Errorf("BackupType = %q, want bucket_aws", cfg.BackupType)
	}
}

func TestBackupTypeEnvOverrides(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_type = rsync\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	t.Setenv("GHOSTSHELL_BACKUP_TYPE", "bucket_gcp")
	if cfg := Load(); cfg.BackupType != "bucket_gcp" {
		t.Errorf("BackupType = %q, want bucket_gcp (env wins)", cfg.BackupType)
	}
}

func TestBackupTypeInvalidFallsToDefault(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_type = azure\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	if cfg := Load(); cfg.BackupType != "" {
		t.Errorf("BackupType = %q, want empty string for invalid type", cfg.BackupType)
	}
}

func TestBackupTargetDefault(t *testing.T) {
	resetForTest(t)
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")
	if cfg := Load(); cfg.BackupTarget != "" {
		t.Errorf("BackupTarget = %q, want empty string by default", cfg.BackupTarget)
	}
}

func TestBackupTargetFromFile(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_target = s3://my-bucket/ghostshell\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	if cfg := Load(); cfg.BackupTarget != "s3://my-bucket/ghostshell" {
		t.Errorf("BackupTarget = %q, want s3://my-bucket/ghostshell", cfg.BackupTarget)
	}
}

func TestBackupTargetEnvOverrides(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_target = s3://from-file\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	t.Setenv("GHOSTSHELL_BACKUP_TARGET", "gs://from-env/prefix")
	if cfg := Load(); cfg.BackupTarget != "gs://from-env/prefix" {
		t.Errorf("BackupTarget = %q, want gs://from-env/prefix (env wins)", cfg.BackupTarget)
	}
}

func TestBackupIntervalSecDefault(t *testing.T) {
	resetForTest(t)
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")
	if cfg := Load(); cfg.BackupIntervalSec != 0 {
		t.Errorf("BackupIntervalSec = %d, want 0 (disabled by default)", cfg.BackupIntervalSec)
	}
}

func TestBackupIntervalSecFromFile(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_interval_sec = 3600\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	if cfg := Load(); cfg.BackupIntervalSec != 3600 {
		t.Errorf("BackupIntervalSec = %d, want 3600", cfg.BackupIntervalSec)
	}
}

func TestBackupIntervalSecEnvOverrides(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_interval_sec = 3600\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	t.Setenv("GHOSTSHELL_BACKUP_INTERVAL_SEC", "900")
	if cfg := Load(); cfg.BackupIntervalSec != 900 {
		t.Errorf("BackupIntervalSec = %d, want 900 (env wins)", cfg.BackupIntervalSec)
	}
}

func TestBackupIntervalSecInvalidFallsToDefault(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_interval_sec = -5\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	if cfg := Load(); cfg.BackupIntervalSec != 0 {
		t.Errorf("BackupIntervalSec = %d, want 0 for negative value", cfg.BackupIntervalSec)
	}
}

func TestBackupIntervalSecZeroAllowed(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_interval_sec = 0\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	if cfg := Load(); cfg.BackupIntervalSec != 0 {
		t.Errorf("BackupIntervalSec = %d, want 0 (explicit disable)", cfg.BackupIntervalSec)
	}
}

// TestParseIsFreshAndDoesNotMutateSingleton verifies Parse() re-reads the
// current environment on every call and never touches the Load() singleton,
// so the daemon can reload config on SIGHUP without racing other goroutines
// that hold the shared *Config from Load().
func TestParseIsFreshAndDoesNotMutateSingleton(t *testing.T) {
	resetForTest(t)
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")
	t.Setenv("GHOSTSHELL_SESSION_CAP", "3")

	cached := Load()
	if cached.SessionCap != 3 {
		t.Fatalf("Load() SessionCap = %d, want 3", cached.SessionCap)
	}

	// Change the environment as if the operator edited config, then reload.
	os.Setenv("GHOSTSHELL_SESSION_CAP", "9")
	defer os.Unsetenv("GHOSTSHELL_SESSION_CAP")

	fresh := Parse()
	if fresh.SessionCap != 9 {
		t.Errorf("Parse() SessionCap = %d, want 9 (fresh re-read)", fresh.SessionCap)
	}
	// The cached singleton must be untouched.
	if cached.SessionCap != 3 {
		t.Errorf("Load() singleton mutated to %d; Parse() must not touch it", cached.SessionCap)
	}
	if fresh == cached {
		t.Error("Parse() returned the singleton pointer; want a fresh independent *Config")
	}
}

func TestResolvedKeyFile(t *testing.T) {
	tests := []struct {
		name       string
		centralDir string
		keyFile    string
		want       string
	}{
		{"empty key_file uses default", "/var/lib/ghostshell", "", "/var/lib/ghostshell/.ghostshell.key"},
		{"absolute key_file used as-is", "/var/lib/ghostshell", "/etc/ghostshell/key", "/etc/ghostshell/key"},
		{"relative key_file joined with central_dir", "/var/lib/ghostshell", "keys/my.key", "/var/lib/ghostshell/keys/my.key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{CentralDir: tc.centralDir, KeyFile: tc.keyFile}
			got := cfg.ResolvedKeyFile()
			if got != tc.want {
				t.Errorf("ResolvedKeyFile() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPartialFile(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("socket_path = /tmp/test.sock\n# comment\neof_grace_ms = 250\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	cfg := Load()
	if cfg.SocketPath != "/tmp/test.sock" {
		t.Errorf("SocketPath = %q, want /tmp/test.sock", cfg.SocketPath)
	}
	if cfg.EOFGrace != 250*time.Millisecond {
		t.Errorf("EOFGrace = %v, want 250ms", cfg.EOFGrace)
	}
	// Unset keys keep defaults.
	if cfg.CentralDir != "/var/lib/ghostshell" {
		t.Errorf("CentralDir = %q, want default", cfg.CentralDir)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("socket_path = /from/file.sock\nlog_file = /from/file.log\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)
	t.Setenv("GHOSTSHELL_DAEMON_SOCK", "/from/env.sock")
	t.Setenv("GHOSTSHELL_LOG_FILE", "/from/env.log")

	cfg := Load()
	if cfg.SocketPath != "/from/env.sock" {
		t.Errorf("SocketPath = %q, want /from/env.sock (env wins)", cfg.SocketPath)
	}
	if cfg.LogFile != "/from/env.log" {
		t.Errorf("LogFile = %q, want /from/env.log (env wins)", cfg.LogFile)
	}
}

func TestBadValuesFallToDefault(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	// All values are invalid — should silently keep defaults.
	os.WriteFile(f, []byte(
		"dial_timeout_sec = not-a-number\n"+
			"eof_grace_ms = -99\n"+
			"ansible_output_cap = 0\n"+
			"scroll_buffer = 100\n",
	), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	cfg := Load()
	if cfg.DialTimeout != 1*time.Second {
		t.Errorf("DialTimeout = %v, want default 1s", cfg.DialTimeout)
	}
	if cfg.EOFGrace != 500*time.Millisecond {
		t.Errorf("EOFGrace = %v, want default 500ms", cfg.EOFGrace)
	}
	if cfg.AnsibleOutputCap != 8*1024 {
		t.Errorf("AnsibleOutputCap = %d, want default 8192", cfg.AnsibleOutputCap)
	}
	if cfg.ScrollBuffer != 32*1024 {
		t.Errorf("ScrollBuffer = %d, want default 32768", cfg.ScrollBuffer)
	}
}

func TestInlineComment(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	// Inline comments are stripped for non-path (scalar) keys when the "#" is
	// preceded by whitespace.
	os.WriteFile(f, []byte("session_cap = 25 # this is a comment\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	cfg := Load()
	if cfg.SessionCap != 25 {
		t.Errorf("SessionCap = %d, want 25 (inline comment stripped)", cfg.SessionCap)
	}
}

// TestInlineCommentTabPrefixed verifies a tab (not just a space) before "#"
// also delimits an inline comment.
func TestInlineCommentTabPrefixed(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("session_cap = 30\t# tab before hash\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.SessionCap != 30 {
		t.Errorf("SessionCap = %d, want 30 (tab-prefixed inline comment stripped)", cfg.SessionCap)
	}
}

// TestHashWithoutWhitespaceNotStripped verifies a "#" not preceded by
// whitespace is treated as part of the value, not a comment marker. Using a
// path key (backup_target) doubles as a check that path values containing "#"
// survive intact.
func TestHashWithoutWhitespaceNotStripped(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("backup_target = user@host:/path/with#hash\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.BackupTarget != "user@host:/path/with#hash" {
		t.Errorf("BackupTarget = %q, want value with embedded # preserved", cfg.BackupTarget)
	}
}

// TestPathKeyPreservesSpaceHash verifies that a path-valued key whose value
// legitimately contains " #" (space-hash) is NOT silently truncated. This is
// the core HIGH finding: inline comments are disabled for path keys.
func TestPathKeyPreservesSpaceHash(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	// An absolute path containing " #" as part of a directory name.
	os.WriteFile(f, []byte("central_dir = /var/lib/ghostshell #archive\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.CentralDir != "/var/lib/ghostshell #archive" {
		t.Errorf("CentralDir = %q, want the full path including ' #archive' (no truncation)", cfg.CentralDir)
	}
}

func TestSingleton(t *testing.T) {
	resetForTest(t)
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")
	a := Load()
	b := Load()
	if a != b {
		t.Error("Load() returned different pointers — singleton broken")
	}
}

// TestSingletonConcurrentReadsOnce verifies the config file is parsed exactly
// once even when many goroutines call Load() concurrently: every caller observes
// the identical *Config pointer, which is only possible if once.Do executed the
// (file-reading) Parse a single time. Run under -race, it also asserts the
// concurrent access to the singleton is data-race free.
func TestSingletonConcurrentReadsOnce(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	if err := os.WriteFile(f, []byte("session_cap = 25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHOSTSHELL_CONFIG", f)

	const n = 64
	ptrs := make([]*Config, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ptrs[i] = Load()
		}(i)
	}
	wg.Wait()

	first := ptrs[0]
	if first == nil {
		t.Fatal("Load() returned nil")
	}
	for i, p := range ptrs {
		if p != first {
			t.Fatalf("goroutine %d got a distinct *Config (%p != %p) — config parsed more than once",
				i, p, first)
		}
	}
	if first.SessionCap != 25 {
		t.Errorf("SessionCap = %d, want 25 — singleton was not parsed from the config file", first.SessionCap)
	}
}

func TestBackupTypeEnvClearsFileValue(t *testing.T) {
	resetForTest(t)
	f, err := os.CreateTemp("", "ghostshell-cfg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("backup_type = bucket_aws\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Setenv("GHOSTSHELL_CONFIG", f.Name())
	t.Setenv("GHOSTSHELL_BACKUP_TYPE", "") // explicit empty — should disable
	cfg := Parse()
	if cfg.BackupType != "" {
		t.Errorf("BackupType = %q, want empty (disabled)", cfg.BackupType)
	}
}

// TestRelativePathKeyRejected verifies a relative path for an absolute-path key
// is rejected (default kept) rather than resolved against the CWD.
func TestRelativePathKeyRejected(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("central_dir = relative/store\nsocket_path = also/relative.sock\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	cfg := Load()
	if cfg.CentralDir != "/var/lib/ghostshell" {
		t.Errorf("CentralDir = %q, want default (relative path rejected)", cfg.CentralDir)
	}
	if cfg.SocketPath != "/run/ghostshell-daemon.sock" {
		t.Errorf("SocketPath = %q, want default (relative path rejected)", cfg.SocketPath)
	}
}

// TestTraversalPathKeyRejected verifies an absolute path containing ".." is
// rejected so it cannot escape the intended store root.
func TestTraversalPathKeyRejected(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("central_dir = /var/lib/ghostshell/../../etc\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.CentralDir != "/var/lib/ghostshell" {
		t.Errorf("CentralDir = %q, want default (traversal path rejected)", cfg.CentralDir)
	}
}

// TestPathKeyEnvTraversalRejected verifies the same path validation is applied
// to environment overrides, not just the file.
func TestPathKeyEnvTraversalRejected(t *testing.T) {
	resetForTest(t)
	t.Setenv("GHOSTSHELL_CONFIG", "/nonexistent/ghostshell.conf")
	t.Setenv("GHOSTSHELL_CENTRAL_DIR", "../escape")

	if cfg := Load(); cfg.CentralDir != "/var/lib/ghostshell" {
		t.Errorf("CentralDir = %q, want default (relative env value rejected)", cfg.CentralDir)
	}
}

// TestKeyFileRelativeAllowed verifies key_file still accepts a relative path
// (joined against CentralDir by ResolvedKeyFile) but rejects traversal.
func TestKeyFileRelativeAllowed(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("key_file = keys/my.key\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.KeyFile != "keys/my.key" {
		t.Errorf("KeyFile = %q, want keys/my.key (relative allowed)", cfg.KeyFile)
	}
}

func TestKeyFileTraversalRejected(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("key_file = ../../etc/shadow\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	// Default for KeyFile is empty; traversal value must be ignored.
	if cfg := Load(); cfg.KeyFile != "" {
		t.Errorf("KeyFile = %q, want empty (traversal rejected)", cfg.KeyFile)
	}
}

// TestAnsibleOutputCapBelowMinBumped verifies a positive value below the 256
// floor is raised to 256 rather than accepted as-is.
func TestAnsibleOutputCapBelowMinBumped(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("ansible_output_cap = 10\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.AnsibleOutputCap != 256 {
		t.Errorf("AnsibleOutputCap = %d, want 256 (bumped to enforced minimum)", cfg.AnsibleOutputCap)
	}
}

// TestAnsibleOutputCapZeroFallsToDefault verifies a non-positive value is
// ignored (default kept), distinct from the below-min bump.
func TestAnsibleOutputCapZeroFallsToDefault(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("ansible_output_cap = 0\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.AnsibleOutputCap != 8*1024 {
		t.Errorf("AnsibleOutputCap = %d, want default 8192 (non-positive ignored)", cfg.AnsibleOutputCap)
	}
}

// TestNumericUpperBoundClamping verifies absurdly large numeric values are
// rejected back to their defaults instead of being accepted and later used to
// drive allocations or loops.
func TestNumericUpperBoundClamping(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte(
		"scroll_buffer = 999999999999\n"+
			"session_cap = 999999999\n"+
			"ansible_output_cap = 999999999999\n",
	), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	cfg := Load()
	if cfg.ScrollBuffer != 32*1024 {
		t.Errorf("ScrollBuffer = %d, want default 32768 (over-max rejected)", cfg.ScrollBuffer)
	}
	if cfg.SessionCap != 10 {
		t.Errorf("SessionCap = %d, want default 10 (over-max rejected)", cfg.SessionCap)
	}
	if cfg.AnsibleOutputCap != 8*1024 {
		t.Errorf("AnsibleOutputCap = %d, want default 8192 (over-max rejected)", cfg.AnsibleOutputCap)
	}
}

// TestAnsibleOutputCapWithinBoundsAccepted is a sanity check that a normal
// large-but-valid value is still honoured.
func TestAnsibleOutputCapWithinBoundsAccepted(t *testing.T) {
	resetForTest(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("ansible_output_cap = 65536\n"), 0o644)
	t.Setenv("GHOSTSHELL_CONFIG", f)

	if cfg := Load(); cfg.AnsibleOutputCap != 65536 {
		t.Errorf("AnsibleOutputCap = %d, want 65536 (in-range value accepted)", cfg.AnsibleOutputCap)
	}
}

// hasWarningContaining reports whether any warning contains sub.
func hasWarningContaining(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// TestValidateCleanConfigNoWarnings verifies a fully valid file with only known
// keys and in-range values produces no warnings (so --check stays quiet on good
// configs and never hard-fails them).
func TestValidateCleanConfigNoWarnings(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte(
		"# a comment\n"+
			"central_dir = /var/lib/ghostshell\n"+
			"session_cap = 25\n"+
			"scroll_buffer = 65536\n"+
			"backup_type = rsync\n"+
			"backup_interval_sec = 0\n"+
			"log_level = 3\n",
	), 0o644)

	if w := Validate(f); len(w) != 0 {
		t.Fatalf("Validate clean config = %v, want no warnings", w)
	}
}

// TestValidateUnknownKeyWarns verifies an unknown/typo'd key is surfaced (but
// the parser still ignores it so the config loads).
func TestValidateUnknownKeyWarns(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("session_cap = 10\nscroll_buffer = 8192\nbogus_key = x\n"), 0o644)

	w := Validate(f)
	// scroll_buffer = 8192 is a valid key/value and must NOT be flagged; only the
	// typo'd bogus_key should surface as an unknown-key warning.
	if hasWarningContaining(w, "scroll_buffer") {
		t.Errorf("Validate wrongly warned about the valid scroll_buffer key; warnings = %v", w)
	}
	if !hasWarningContaining(w, "bogus_key") {
		t.Errorf("Validate did not warn about unknown key; warnings = %v", w)
	}
}

// TestValidateMalformedLineWarns verifies a line with no "=" is reported.
func TestValidateMalformedLineWarns(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("this is not a pair\nsession_cap = 5\n"), 0o644)

	if w := Validate(f); !hasWarningContaining(w, "not a key") {
		t.Errorf("Validate did not warn about malformed line; warnings = %v", w)
	}
}

// TestValidateInvalidValueWarns verifies a known key with an unparseable or
// out-of-range value is surfaced (it is silently dropped by the parser).
func TestValidateInvalidValueWarns(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte(
		"scroll_buffer = 100\n"+ // below scrollBufferMin (4096) -> rejected
			"session_cap = not-a-number\n"+ // unparseable -> rejected
			"central_dir = relative/path\n", // not absolute -> rejected
	), 0o644)

	w := Validate(f)
	for _, key := range []string{"scroll_buffer", "session_cap", "central_dir"} {
		if !hasWarningContaining(w, key) {
			t.Errorf("Validate did not warn about invalid value for %q; warnings = %v", key, w)
		}
	}
}

// TestValidateBelowMinValueWarns verifies an ansible_output_cap below the floor
// is NOT reported (it is bumped up to the floor, so the value did take effect),
// while a non-positive one IS reported (it is rejected entirely).
func TestValidateClampVsReject(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	os.WriteFile(f, []byte("ansible_output_cap = 10\nlog_level = 99\n"), 0o644)

	w := Validate(f)
	// 10 is bumped to the 256 floor -> the field changes -> no warning.
	if hasWarningContaining(w, "ansible_output_cap") {
		t.Errorf("Validate wrongly warned about clamp-able ansible_output_cap; warnings = %v", w)
	}
	// log_level 99 is out of [0,5] -> rejected -> warning.
	if !hasWarningContaining(w, "log_level") {
		t.Errorf("Validate did not warn about out-of-range log_level; warnings = %v", w)
	}
}

// TestValidateMissingFileNoWarnings verifies a missing file yields no warnings
// (defaults are used).
func TestValidateMissingFileNoWarnings(t *testing.T) {
	if w := Validate(filepath.Join(t.TempDir(), "nonexistent.conf")); len(w) != 0 {
		t.Fatalf("Validate(missing) = %v, want no warnings", w)
	}
}

// TestValidateAllKnownKeysCovered guards against a key being added to applyKey
// but forgotten in knownKeys (which would make Validate wrongly flag it). Every
// key applyKey switches on must be present in knownKeys.
func TestValidateKnownKeysMatchApplyKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ghostshell.conf")
	// One valid value per known config key; none should produce an unknown-key
	// warning.
	os.WriteFile(f, []byte(
		"socket_path = /run/ghostshell-daemon.sock\n"+
			"central_dir = /var/lib/ghostshell\n"+
			"key_file = keys/my.key\n"+
			"dial_timeout_sec = 2\n"+
			"eof_grace_ms = 300\n"+
			"ansible_output_cap = 4096\n"+
			"scroll_buffer = 8192\n"+
			"log_level = 4\n"+
			"log_file = /var/log/ghostshell/ghostshell.log\n"+
			"session_cap = 20\n"+
			"backup_type = rsync\n"+
			"backup_target = user@host:/path\n"+
			"backup_interval_sec = 60\n",
	), 0o644)

	for _, w := range Validate(f) {
		if strings.Contains(w, "unknown key") {
			t.Errorf("known key reported as unknown: %q", w)
		}
	}
}
