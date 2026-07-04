// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package logger

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// resetLoggerState clears the package-level tee state so tests do not leak the
// captured baseWriter or an open currentFile into one another.
func resetLoggerState(t *testing.T) {
	t.Helper()
	outputMu.Lock()
	baseWriter = nil
	currentFile = nil
	outputMu.Unlock()
	t.Cleanup(func() {
		outputMu.Lock()
		baseWriter = nil
		currentFile = nil
		outputMu.Unlock()
	})
}

func TestTeeToFileCreatesParentAndWritesLog(t *testing.T) {
	resetLoggerState(t)
	var stderr bytes.Buffer
	log.SetOutput(&stderr)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	})

	path := filepath.Join(t.TempDir(), "var", "log", "ghostshell", "ghostshell.log")
	closeLog, err := TeeToFile(path)
	if err != nil {
		t.Fatalf("TeeToFile() error = %v", err)
	}

	Infof("file logging works")

	if err := closeLog(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(b), "[INFO] file logging works") {
		t.Fatalf("log file missing message: %q", string(b))
	}
	if !strings.Contains(stderr.String(), "[INFO] file logging works") {
		t.Fatalf("stderr missing message: %q", stderr.String())
	}
}

func TestTeeToFileRepairsExistingDirectoryAndFileModes(t *testing.T) {
	resetLoggerState(t)
	var stderr bytes.Buffer
	log.SetOutput(&stderr)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	})

	dir := filepath.Join(t.TempDir(), "ghostshell")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ghostshell.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o666); err != nil {
		t.Fatal(err)
	}

	closeLog, err := TeeToFile(path)
	if err != nil {
		t.Fatalf("TeeToFile() error = %v", err)
	}
	if err := closeLog(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o750 {
		t.Fatalf("directory mode = %o, want 750", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o640 {
		t.Fatalf("file mode = %o, want 640", got)
	}
}

func TestReopenWritesToNewFileAndClosesOld(t *testing.T) {
	resetLoggerState(t)
	var stderr bytes.Buffer
	log.SetOutput(&stderr)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	})

	dir := t.TempDir()
	// oldPath is the file before rotation; newPath is the file Reopen swaps to.
	// Using two paths exercises Reopen's open-new/swap/close-old sequence the
	// same way a logrotate rename does, without depending on rename-while-open
	// semantics that differ across platforms.
	oldPath := filepath.Join(dir, "ghostshell.log")
	newPath := filepath.Join(dir, "ghostshell.log.new")

	closeLog, err := TeeToFile(oldPath)
	if err != nil {
		t.Fatalf("TeeToFile() error = %v", err)
	}
	t.Cleanup(func() { _ = closeLog() })

	Infof("before reopen")

	// Grab the file handle in use before the rotation so we can confirm Reopen
	// closes exactly that descriptor (no leak).
	outputMu.Lock()
	oldFile := currentFile
	outputMu.Unlock()
	if oldFile == nil {
		t.Fatal("expected an active log file before Reopen")
	}

	if err := Reopen(newPath); err != nil {
		t.Fatalf("Reopen() error = %v", err)
	}

	Infof("after reopen")

	// The new file must contain only the post-Reopen line.
	newContents, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("read new log: %v", err)
	}
	if !strings.Contains(string(newContents), "[INFO] after reopen") {
		t.Fatalf("new log missing post-reopen line: %q", string(newContents))
	}
	if strings.Contains(string(newContents), "before reopen") {
		t.Fatalf("new log unexpectedly has pre-reopen line: %q", string(newContents))
	}

	// The old file must hold the pre-Reopen line and must NOT receive the
	// post-Reopen line — proving output no longer flows to the old fd.
	oldContents, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read old log: %v", err)
	}
	if !strings.Contains(string(oldContents), "[INFO] before reopen") {
		t.Fatalf("old log missing pre-reopen line: %q", string(oldContents))
	}
	if strings.Contains(string(oldContents), "after reopen") {
		t.Fatalf("old log unexpectedly received post-reopen line: %q", string(oldContents))
	}

	// Reopen must have closed the old descriptor: a second Close returns an
	// error. This guards against the leak the audit flagged.
	if cerr := oldFile.Close(); cerr == nil {
		t.Fatal("old log fd was not closed by Reopen (descriptor leak)")
	}
}

// TestConcurrentLogDuringReopen exercises the output swap against concurrent log
// emission. Intended to be run with -race on Linux to detect data races on the
// output writer and the package-level tee state.
func TestConcurrentLogDuringReopen(t *testing.T) {
	resetLoggerState(t)
	log.SetOutput(&bytes.Buffer{})
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "ghostshell.log")
	closeLog, err := TeeToFile(path)
	if err != nil {
		t.Fatalf("TeeToFile() error = %v", err)
	}
	t.Cleanup(func() { _ = closeLog() })

	stop := make(chan struct{})
	var loggers sync.WaitGroup

	// Loggers hammering the output while rotations happen underneath them.
	for i := 0; i < 4; i++ {
		loggers.Add(1)
		go func() {
			defer loggers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					Infof("concurrent line")
				}
			}
		}()
	}

	// Repeated SIGHUP-style reopens of the same path, racing the loggers.
	for i := 0; i < 50; i++ {
		if err := Reopen(path); err != nil {
			t.Errorf("Reopen() error = %v", err)
			break
		}
	}

	close(stop)
	loggers.Wait()
}
