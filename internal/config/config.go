// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package config loads ghostshell runtime configuration from /etc/ghostshell/ghostshell.conf
// (overridable by GHOSTSHELL_CONFIG env var). All keys have safe built-in defaults
// so the file is optional. Environment variables always override file values.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPath is the canonical config file location.
const DefaultPath = "/etc/ghostshell/ghostshell.conf"

// Config holds all tuneable runtime settings.
type Config struct {
	// SocketPath is the Unix socket the ghostshell-daemon daemon listens on.
	SocketPath string
	// CentralDir is the root of the root-only central session store.
	CentralDir string
	// KeyFile is the path to the at-rest encryption key (absolute or relative
	// to CentralDir when it doesn't start with "/").
	KeyFile string
	// DialTimeout is how long ghostshell rec waits when connecting to ghostshell-daemon.
	DialTimeout time.Duration
	// EOFGrace is the delay between sending Ctrl-D and force-closing the PTY
	// master when stdin reaches EOF in a non-interactive session.
	EOFGrace time.Duration
	// AnsibleOutputCap is the maximum bytes stored per ansible task output.
	AnsibleOutputCap int
	// ScrollBuffer is the PTY read buffer size in bytes used during recording.
	// Larger values reduce syscall overhead on high-throughput sessions.
	ScrollBuffer int
	// LogLevel controls logging verbosity (0=off, 1=error, 2=warn, 3=info, 4=debug, 5=trace).
	// Default 3 (INFO). Set to 0 to silence all log output.
	LogLevel int
	// LogFile is the daemon log file path. Empty disables file logging.
	LogFile string
	// SessionCap is the maximum number of concurrent recording sessions the
	// daemon accepts per UID. Guards against a single user exhausting the
	// daemon's file descriptors / goroutines.
	SessionCap int
	// BackupType is the backup mechanism: "bucket_aws", "bucket_gcp", "rsync",
	// or "" (disabled). Invalid values silently fall back to "" (disabled).
	BackupType string
	// BackupTarget is the destination: s3://bucket/prefix, gs://bucket/prefix,
	// or user@host:/path. Empty disables backup even when BackupType is set.
	BackupTarget string
	// BackupIntervalSec is the interval between automatic backups in seconds.
	// 0 disables periodic backup. Negative values are silently ignored (0 kept).
	BackupIntervalSec int
}

// defaults returns a Config populated with factory defaults.
func defaults() Config {
	return Config{
		SocketPath:       "/run/ghostshell-daemon.sock",
		CentralDir:       "/var/lib/ghostshell",
		KeyFile:          "", // resolved to CentralDir/.ghostshell.key when empty
		DialTimeout:      1 * time.Second,
		EOFGrace:         500 * time.Millisecond,
		AnsibleOutputCap: 8 * 1024,
		ScrollBuffer:     32 * 1024,
		LogLevel:         3,
		LogFile:          "/var/log/ghostshell/ghostshell.log",
		SessionCap:       10,
	}
}

// ResolvedKeyFile returns the absolute path to the encryption key, resolving
// a relative KeyFile against CentralDir.
func (c *Config) ResolvedKeyFile() string {
	if c.KeyFile == "" {
		return filepath.Join(c.CentralDir, ".ghostshell.key")
	}
	if filepath.IsAbs(c.KeyFile) {
		return c.KeyFile
	}
	return filepath.Join(c.CentralDir, c.KeyFile)
}

var (
	mu     sync.Mutex
	once   sync.Once
	global *Config
)

// Load returns the process-wide config singleton, parsed on first call.
// The config file path is taken from GHOSTSHELL_CONFIG env var, falling back to
// DefaultPath. A missing or unreadable file is silently ignored (defaults used).
func Load() *Config {
	mu.Lock()
	o := &once
	mu.Unlock()
	o.Do(func() {
		cfg := Parse()
		mu.Lock()
		global = cfg
		mu.Unlock()
	})
	mu.Lock()
	defer mu.Unlock()
	return global
}

// Parse reads config from the current environment + config file and returns a
// freshly-allocated *Config every call. Unlike Load it does not cache and never
// touches the Load() singleton, so the daemon can call it on SIGHUP to pick up
// edited values without racing goroutines that already hold the Load() pointer.
func Parse() *Config {
	cfg := defaults()
	path := os.Getenv("GHOSTSHELL_CONFIG")
	if path == "" {
		path = DefaultPath
	}
	_ = parseFile(path, &cfg)
	applyEnv(&cfg)
	return &cfg
}

// Reset clears the singleton so the next Load() re-reads the config. Intended
// for use in tests only. The singleton swap is guarded by a mutex so a stray
// concurrent Load() cannot observe a torn once/global pair.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	once = sync.Once{}
	global = nil
}

// parseFile reads key=value pairs from path into cfg. Unknown keys and parse
// errors for individual values are silently skipped so a partial file still
// applies its valid entries.
func parseFile(path string, cfg *Config) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		// Strip inline comments, but only when "#" is preceded by whitespace
		// (space or tab) so values legitimately containing "#" are preserved.
		// Path-valued keys disallow inline comments entirely: their values may
		// legitimately contain " #" (e.g. directory names), and silently
		// truncating a path/secret is dangerous. Such keys must not carry a
		// trailing comment in the config file.
		if !isPathKey(k) {
			v = stripInlineComment(v)
		}
		applyKey(cfg, k, v)
	}
	return sc.Err()
}

// Numeric bounds. Values outside [min,max] are clamped/rejected back to the
// built-in default so an absurd config entry can't drive a huge allocation or
// an unbounded loop later. ansibleOutputCapMin is an enforced floor: anything
// below it (but still positive) is bumped up to it.
const (
	ansibleOutputCapMin = 256
	ansibleOutputCapMax = 64 * 1024 * 1024 // 64 MiB
	scrollBufferMin     = 4096
	scrollBufferMax     = 64 * 1024 * 1024 // 64 MiB
	sessionCapMax       = 100000
	logLevelMax         = 5
	// backupIntervalSecMax caps the periodic-backup interval at one year so a
	// fat-fingered value can't effectively disable backups forever while still
	// reading as "enabled".
	backupIntervalSecMax = 365 * 24 * 60 * 60
)

// pathKeys are config keys whose values are filesystem paths or path-like
// destinations that must be absolute. They get traversal/absoluteness checks
// and are exempt from inline-comment stripping.
var pathKeys = map[string]bool{
	"socket_path":   true,
	"central_dir":   true,
	"key_file":      true,
	"log_file":      true,
	"backup_target": true,
}

func isPathKey(k string) bool { return pathKeys[k] }

// knownKeys is the set of every config key applyKey recognises. It is used only
// by Validate to surface unknown (typo'd or obsolete) keys; the parser itself
// still silently ignores them so a stray key can never prevent a valid config
// from loading.
var knownKeys = map[string]bool{
	"socket_path":         true,
	"central_dir":         true,
	"key_file":            true,
	"dial_timeout_sec":    true,
	"eof_grace_ms":        true,
	"ansible_output_cap":  true,
	"scroll_buffer":       true,
	"log_level":           true,
	"log_file":            true,
	"session_cap":         true,
	"backup_type":         true,
	"backup_target":       true,
	"backup_interval_sec": true,
	// playback_password is not parsed into config.Config (the playback password
	// lives in its own root-only file managed by the auth package), but it is a
	// recognised ghostshell concept; whitelist it so Validate never reports it as a
	// typo when an operator references it in the file.
	"playback_password": true,
}

// stripInlineComment removes a trailing "# comment" only when the "#" is
// preceded by whitespace (space or tab), leaving embedded "#" intact.
func stripInlineComment(v string) string {
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}

// hasTraversal reports whether p contains a ".." path-traversal component.
// It inspects the raw, un-cleaned path because filepath.Clean lexically
// resolves ".." against earlier segments (e.g. "/a/b/../../etc" -> "/etc"),
// which would hide a traversal that escapes the intended root. Any literal
// ".." segment (split on either separator) is treated as unsafe.
func hasTraversal(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == os.PathSeparator
	}) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// isSafeAbsPath reports whether p is an absolute path with no ".." traversal
// component. Empty is rejected by callers as needed.
func isSafeAbsPath(p string) bool {
	return filepath.IsAbs(p) && !hasTraversal(p)
}

// setPath assigns an absolute, traversal-free path to *dst. Empty values are
// ignored (the existing default/value is kept). Relative paths or values that
// escape via ".." are rejected (left unchanged) rather than silently resolved
// against the CWD or allowed to escape the store.
func setPath(dst *string, v string) {
	if v == "" {
		return
	}
	if !isSafeAbsPath(v) {
		return
	}
	*dst = v
}

// setKeyFile is like setPath but permits an empty value (meaning "use the
// default key relative to CentralDir") and permits a relative path, which
// ResolvedKeyFile joins against CentralDir. It still rejects ".." traversal.
func setKeyFile(dst *string, v string) {
	if v == "" {
		*dst = ""
		return
	}
	if hasTraversal(v) {
		return
	}
	*dst = v
}

// setTarget assigns a backup destination to *dst. Unlike setPath it does not
// require an absolute filesystem path, since a target may be a remote spec
// (s3://bucket/prefix, gs://bucket/prefix, user@host:/path). It still rejects
// ".." traversal so a malicious value cannot escape an rsync destination root.
func setTarget(dst *string, v string) {
	if v == "" {
		return
	}
	if hasTraversal(v) {
		return
	}
	*dst = v
}

// setInt parses v as an int and, if it is within [lo,hi], assigns it to *dst.
// Out-of-range or unparseable values are ignored (default kept).
func setInt(dst *int, v string, lo, hi int) {
	if n, err := strconv.Atoi(v); err == nil && n >= lo && n <= hi {
		*dst = n
	}
}

// setIntClampLow parses v as an int and applies an enforced floor: a positive
// value below floor is bumped up to floor. Non-positive or unparseable values,
// and absurd values above max, are rejected (the existing default is kept)
// rather than being clamped to max — an over-max entry is treated as a mistake,
// not an intent to use the ceiling.
func setIntClampLow(dst *int, v string, floor, hi int) {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > hi {
		return
	}
	if n < floor {
		n = floor
	}
	*dst = n
}

// setDurationSec parses v as fractional seconds (>0) into *dst.
func setDurationSec(dst *time.Duration, v string) {
	if s, err := strconv.ParseFloat(v, 64); err == nil && s > 0 {
		*dst = time.Duration(s * float64(time.Second))
	}
}

// setDurationMs parses v as non-negative whole milliseconds into *dst.
func setDurationMs(dst *time.Duration, v string) {
	if ms, err := strconv.ParseInt(v, 10, 64); err == nil && ms >= 0 {
		*dst = time.Duration(ms) * time.Millisecond
	}
}

// setBackupType assigns v to *dst only when it is a recognised backup type.
func setBackupType(dst *string, v string) {
	switch v {
	case "bucket_aws", "bucket_gcp", "rsync", "":
		*dst = v
	}
}

// applyKey applies a single parsed key=value to cfg. Unknown keys are ignored.
// All per-key parse/validate rules live in the shared set* helpers so applyEnv
// stays in lockstep with the file parser.
func applyKey(cfg *Config, k, v string) {
	switch k {
	case "socket_path":
		setPath(&cfg.SocketPath, v)
	case "central_dir":
		setPath(&cfg.CentralDir, v)
	case "key_file":
		setKeyFile(&cfg.KeyFile, v)
	case "dial_timeout_sec":
		setDurationSec(&cfg.DialTimeout, v)
	case "eof_grace_ms":
		setDurationMs(&cfg.EOFGrace, v)
	case "ansible_output_cap":
		setIntClampLow(&cfg.AnsibleOutputCap, v, ansibleOutputCapMin, ansibleOutputCapMax)
	case "scroll_buffer":
		setInt(&cfg.ScrollBuffer, v, scrollBufferMin, scrollBufferMax)
	case "log_level":
		setInt(&cfg.LogLevel, v, 0, logLevelMax)
	case "log_file":
		setPath(&cfg.LogFile, v)
	case "session_cap":
		setInt(&cfg.SessionCap, v, 1, sessionCapMax)
	case "backup_type":
		setBackupType(&cfg.BackupType, v)
	case "backup_target":
		setTarget(&cfg.BackupTarget, v)
	case "backup_interval_sec":
		setInt(&cfg.BackupIntervalSec, v, 0, backupIntervalSecMax)
	}
}

// Validate re-reads the config file at path and returns a list of human-readable
// warnings about lines that the parser would silently ignore: malformed lines
// (no "key = value"), unknown keys (typos / obsolete settings), and values that
// fail to apply for their key (unparseable numbers, out-of-range values that are
// rejected, or paths that are not absolute/contain traversal). It never returns
// an error for a syntactically valid file with only recognised keys, so callers
// such as `ghostshell --check` can surface problems without hard-failing a config
// that still loads with sane (defaulted) values.
//
// Validate is read-only: it does not touch the Load() singleton and does not
// apply environment overrides (those are reported separately by the CLI).
// A missing file yields no warnings (defaults are used).
func Validate(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil // missing/unreadable file: defaults apply, nothing to validate
	}
	defer f.Close()

	var warnings []string
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			warnings = append(warnings, fmt.Sprintf("line %d: not a key = value pair: %q", lineNo, line))
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !isPathKey(k) {
			v = stripInlineComment(v)
		}
		if !knownKeys[k] {
			warnings = append(warnings, fmt.Sprintf("line %d: unknown key %q (ignored)", lineNo, k))
			continue
		}
		// Determine whether the value would actually take effect. A value that
		// equals an existing default must NOT be reported as invalid, so comparing
		// against a single defaults copy is not enough (a rejected value also leaves
		// the field at its default). Apply the key to two different base configs: a
		// valid value drives both fields to the same normalized result, while a
		// rejected value leaves each base's field untouched (and the two bases were
		// chosen to differ on that field). Only the latter is a real problem.
		if rejected(k, v) {
			warnings = append(warnings,
				fmt.Sprintf("line %d: value %q for %q is invalid or out of range (ignored, default kept)", lineNo, v, k))
		}
	}
	if err := sc.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("error reading %s: %v", path, err))
	}
	return warnings
}

// rejected reports whether applying key k with value v would be silently dropped
// by the parser (unparseable number, out-of-range value, or a disallowed path),
// as opposed to taking effect — including the case where v legitimately equals a
// default. It applies the key to two base configs that differ in every field; a
// value that takes effect normalizes both bases to the same result, whereas a
// rejected value leaves each base's differing field unchanged.
func rejected(k, v string) bool {
	a := defaults()
	b := sentinel()
	applyKey(&a, k, v)
	applyKey(&b, k, v)
	// If the value took effect, the two probes now agree on that field, so the
	// whole structs are equal iff every OTHER field also agrees — which they do
	// not, since a and b start fully distinct. Equivalently: the value was applied
	// iff a and b were driven together on the touched field. Compare directly.
	return a == defaults() && b == sentinel()
}

// sentinel returns a Config whose every field differs from defaults(), used by
// rejected to tell "value applied (equals default)" apart from "value dropped".
func sentinel() Config {
	return Config{
		SocketPath:        "/sentinel/sock",
		CentralDir:        "/sentinel/central",
		KeyFile:           "sentinel.key",
		DialTimeout:       123 * time.Second,
		EOFGrace:          123 * time.Millisecond,
		AnsibleOutputCap:  ansibleOutputCapMax,
		ScrollBuffer:      scrollBufferMax,
		LogLevel:          logLevelMax,
		LogFile:           "/sentinel/log",
		SessionCap:        sessionCapMax,
		BackupType:        "rsync",
		BackupTarget:      "sentinel@host:/path",
		BackupIntervalSec: backupIntervalSecMax,
	}
}

// applyEnv overrides cfg fields from environment variables. Env vars always
// win over the config file. It reuses applyKey's shared set* helpers so every
// validation rule (path absoluteness, numeric bounds) is applied identically.
func applyEnv(cfg *Config) {
	if v := os.Getenv("GHOSTSHELL_DAEMON_SOCK"); v != "" {
		setPath(&cfg.SocketPath, v)
	}
	if v := os.Getenv("GHOSTSHELL_CENTRAL_DIR"); v != "" {
		setPath(&cfg.CentralDir, v)
	}
	if v := os.Getenv("GHOSTSHELL_KEY_FILE"); v != "" {
		setKeyFile(&cfg.KeyFile, v)
	}
	if v := os.Getenv("GHOSTSHELL_DIAL_TIMEOUT_SEC"); v != "" {
		setDurationSec(&cfg.DialTimeout, v)
	}
	if v := os.Getenv("GHOSTSHELL_EOF_GRACE_MS"); v != "" {
		setDurationMs(&cfg.EOFGrace, v)
	}
	if v := os.Getenv("GHOSTSHELL_ANSIBLE_OUTPUT_CAP"); v != "" {
		setIntClampLow(&cfg.AnsibleOutputCap, v, ansibleOutputCapMin, ansibleOutputCapMax)
	}
	if v := os.Getenv("GHOSTSHELL_SCROLL_BUFFER"); v != "" {
		setInt(&cfg.ScrollBuffer, v, scrollBufferMin, scrollBufferMax)
	}
	if v := os.Getenv("GHOSTSHELL_LOG_LEVEL"); v != "" {
		setInt(&cfg.LogLevel, v, 0, logLevelMax)
	}
	if v := os.Getenv("GHOSTSHELL_LOG_FILE"); v != "" {
		setPath(&cfg.LogFile, v)
	}
	if v := os.Getenv("GHOSTSHELL_SESSION_CAP"); v != "" {
		setInt(&cfg.SessionCap, v, 1, sessionCapMax)
	}
	if v, ok := os.LookupEnv("GHOSTSHELL_BACKUP_TYPE"); ok {
		setBackupType(&cfg.BackupType, v)
	}
	if v := os.Getenv("GHOSTSHELL_BACKUP_TARGET"); v != "" {
		setTarget(&cfg.BackupTarget, v)
	}
	if v := os.Getenv("GHOSTSHELL_BACKUP_INTERVAL_SEC"); v != "" {
		setInt(&cfg.BackupIntervalSec, v, 0, backupIntervalSecMax)
	}
}
