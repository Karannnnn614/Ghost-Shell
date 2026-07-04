// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package logger provides leveled logging for ghostshell and ghostshell-daemon.
//
// Levels:
//
//	0 = OFF   — no output
//	1 = ERROR — fatal errors, write failures
//	2 = WARN  — retries, recoverable errors, fallback paths
//	3 = INFO  — startup, session open/close  (default)
//	4 = DEBUG — frame details, config loading, connection flow
//	5 = TRACE — every read/write byte count, buffer operations
//
// Under systemd (JOURNAL_STREAM set) timestamps are stripped — journald adds them.
// Standalone: standard log timestamps are used.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Level is a logging verbosity level (0–5).
type Level int32

const (
	LevelOff   Level = 0
	LevelError Level = 1
	LevelWarn  Level = 2
	LevelInfo  Level = 3
	LevelDebug Level = 4
	LevelTrace Level = 5
)

var current atomic.Int32

// outputMu guards baseWriter, currentFile, and the log output swap so that
// concurrent log emission and a SIGHUP-triggered Reopen do not race.
var outputMu sync.Mutex

// baseWriter is the underlying writer (e.g. stderr or the journald stream)
// captured once before any file tee. Every tee rebuilds the log output from
// this single base so successive TeeToFile/Reopen calls never compound
// MultiWriters or leak file descriptors.
var baseWriter io.Writer

// currentFile is the active log file, or nil when output is not teed to a file.
// Reopen closes it after swapping in a replacement. Guarded by outputMu.
var currentFile *os.File

func init() {
	current.Store(int32(LevelInfo))
	// Under systemd journald, timestamps are added automatically.
	if os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != "" {
		log.SetFlags(0)
	}
}

// Set changes the active log level. Thread-safe.
func Set(l Level) { current.Store(int32(l)) }

// Get returns the current log level.
func Get() Level { return Level(current.Load()) }

// openLogFile creates parent directories as needed, repairs directory and file
// modes, and opens the log file for appending. It does not touch global logger
// state.
func openLogFile(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o640); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// TeeToFile sends future log output to the existing logger output and path.
// Parent directories are created when missing. The returned function restores
// the previous output (the base writer captured at the first tee) and closes
// the file.
func TeeToFile(path string) (func() error, error) {
	if path == "" {
		return func() error { return nil }, nil
	}
	f, err := openLogFile(path)
	if err != nil {
		return nil, err
	}

	outputMu.Lock()
	// Capture the base writer once, before any file tee, so successive
	// TeeToFile/Reopen calls always rebuild from the same base instead of
	// wrapping an already-teed MultiWriter.
	if baseWriter == nil {
		baseWriter = log.Writer()
	}
	base := baseWriter
	log.SetOutput(io.MultiWriter(base, f))
	currentFile = f
	outputMu.Unlock()

	// restore tears down file logging on shutdown: it restores output to the
	// base writer and closes whichever file is currently active. Because Reopen
	// swaps currentFile, this correctly closes the live descriptor even after
	// one or more rotations, and is a no-op if already torn down.
	restore := func() error {
		outputMu.Lock()
		f := currentFile
		if f != nil {
			log.SetOutput(base)
			currentFile = nil
		}
		outputMu.Unlock()
		if f != nil {
			return f.Close()
		}
		return nil
	}
	return restore, nil
}

// Reopen closes and reopens the log file at path. Call on SIGHUP so logrotate
// can rename the old file without losing future log lines. Output is rebuilt
// from the saved base writer plus the freshly opened file, then the previous
// file is closed so no descriptor leaks.
func Reopen(path string) error {
	if path == "" {
		return nil
	}
	f, err := openLogFile(path)
	if err != nil {
		return err
	}

	outputMu.Lock()
	if baseWriter == nil {
		baseWriter = log.Writer()
	}
	base := baseWriter
	old := currentFile
	log.SetOutput(io.MultiWriter(base, f))
	currentFile = f
	outputMu.Unlock()

	if old != nil {
		return old.Close() // close old fd; output already points at the new file
	}
	return nil
}

// Errorf logs at level ERROR (1).
func Errorf(format string, args ...any) { emit(LevelError, "ERROR", format, args...) }

// Warnf logs at level WARN (2).
func Warnf(format string, args ...any) { emit(LevelWarn, "WARN", format, args...) }

// Infof logs at level INFO (3).
func Infof(format string, args ...any) { emit(LevelInfo, "INFO", format, args...) }

// Debugf logs at level DEBUG (4).
func Debugf(format string, args ...any) { emit(LevelDebug, "DEBUG", format, args...) }

// Tracef logs at level TRACE (5).
func Tracef(format string, args ...any) { emit(LevelTrace, "TRACE", format, args...) }

func emit(level Level, tag, format string, args ...any) {
	l := Level(current.Load())
	if l == LevelOff || level > l {
		return
	}
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", tag, msg)
}
