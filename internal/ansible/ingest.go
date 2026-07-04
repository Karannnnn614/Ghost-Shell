// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package ansible

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostshell/internal/config"
	"ghostshell/internal/store"
)

func daemonSocket() string {
	return config.Load().SocketPath
}

// maxIngestBytes bounds how much of stdin Ingest will buffer before validating.
// A single playbook run's JSON-lines stream is far smaller than this; the cap
// only exists to stop a hostile/runaway producer from exhausting memory.
const maxIngestBytes = 64 * 1024 * 1024 // 64 MiB

// Ingest implements `ghostshell ansible-ingest`.
// The Python callback plugin spawns this as a subprocess, writes JSON-lines
// events to its stdin, and closes stdin when the playbook finishes.
//
// Ingest:
//  1. reads the first line from stdin to get the run id
//  2. tries to connect to ghostshell-daemon and send "ANSIBLE <runid>\n"
//  3. then copies remaining stdin to ghostshell-daemon (or a local file on fail-open)
func Ingest(_ []string) error {
	// Buffer all of stdin so we can re-read it on daemon failure. Bound the
	// read so a hostile/runaway producer cannot exhaust memory: read one byte
	// past the cap and reject anything that long.
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxIngestBytes+1))
	if err != nil {
		return fmt.Errorf("ansible-ingest: read stdin: %w", err)
	}
	if len(data) > maxIngestBytes {
		return fmt.Errorf("ansible-ingest: input exceeds %d bytes", maxIngestBytes)
	}

	// Parse the run event to extract the run ID.
	runID, err := extractRunID(data)
	if err != nil || !ValidRunID(runID) {
		return fmt.Errorf("ansible-ingest: bad run event: %v", err)
	}

	// Try the daemon first.
	if daemonErr := sendToDaemon(runID, data); daemonErr == nil {
		return nil
	}

	// Fail-open: write to user-local ansible dir.
	return writeLocal(runID, data)
}

// extractRunID reads the first non-empty JSON line and returns the "id" field.
func extractRunID(data []byte) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return "", fmt.Errorf("parse: %w", err)
		}
		if ev.Type != "run" {
			return "", fmt.Errorf("first event must be type=run, got %q", ev.Type)
		}
		if ev.ID == "" {
			return "", fmt.Errorf("run event missing id field")
		}
		return ev.ID, nil
	}
	return "", fmt.Errorf("no events in stdin")
}

// ValidRunID allows only safe characters for use in a file path.
// Format produced by the plugin: "<ts>-<pid>", e.g. "20260527T140300-12345".
func ValidRunID(id string) bool {
	if len(id) < 5 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == 'T') {
			return false
		}
	}
	return true
}

// sendToDaemon connects to ghostshell-daemon, sends "ANSIBLE <runid>\n", then streams data.
func sendToDaemon(runID string, data []byte) error {
	conn, err := net.DialTimeout("unix", daemonSocket(), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "ANSIBLE %s\n", runID); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	// Read daemon acknowledgement — ERR means the run was rejected.
	br := bufio.NewReader(conn)
	resp, _ := br.ReadString('\n')
	if strings.HasPrefix(strings.TrimSpace(resp), "ERR") {
		return fmt.Errorf("daemon rejected ansible run: %s", strings.TrimSpace(resp))
	}
	return nil
}

// writeLocal writes the run to ~/.local/share/ghostshell/ansible/<runid>.ajsonl.
func writeLocal(runID string, data []byte) error {
	dir := filepath.Join(store.Dir(), "ansible")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ansible-ingest: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, runID+".ajsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("ansible-ingest: create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("ansible-ingest: write: %w", err)
	}
	fmt.Fprintf(os.Stderr, "ghostshell ansible-ingest: daemon unreachable, saved to %s\n", path)
	return nil
}
