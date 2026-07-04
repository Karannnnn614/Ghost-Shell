// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package ansible records and replays Ansible playbook runs from the ghostshell
// central store. The controller-side Python callback plugin writes JSON-lines
// events via `ghostshell ansible-ingest`, which streams them to ghostshell-daemon over the
// same Unix socket used by `ghostshell rec` (new "ANSIBLE <runid>" command).
//
// JSON-lines schema (one object per line, in order):
//
//	{"type":"run",   "id":"<ts>-<pid>","playbook":"deploy.yml","user":"alice","started":<unix>,"controller":"<host>"}
//	{"type":"play",  "name":"deploy web"}
//	{"type":"task",  "play":"…","name":"…","module":"…","host":"…","status":"ok|changed|failed|unreachable|skipped","rc":<int>,"t":<unix>,"stdout":"…","stderr":"…"}
//	{"type":"stats", "host":"…","ok":<int>,"changed":<int>,"failed":<int>,"unreachable":<int>,"skipped":<int>}
//
// stdout/stderr are omitted (or "<censored>") when no_log: true.
// They are truncated to maxOutput bytes to bound record size.
package ansible

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"ghostshell/internal/config"
)

// ----------------------------------------------------------------------------
// Raw event types (JSON-lines on the wire / in storage)
// ----------------------------------------------------------------------------

type rawEvent struct {
	Type string `json:"type"`

	// "run" fields
	ID         string  `json:"id,omitempty"`
	Playbook   string  `json:"playbook,omitempty"`
	User       string  `json:"user,omitempty"`
	Started    float64 `json:"started,omitempty"`
	Controller string  `json:"controller,omitempty"`

	// "play" fields
	Name string `json:"name,omitempty"`

	// "task" fields
	Play   string  `json:"play,omitempty"`
	Module string  `json:"module,omitempty"`
	Host   string  `json:"host,omitempty"`
	Status string  `json:"status,omitempty"`
	RC     int     `json:"rc,omitempty"`
	T      float64 `json:"t,omitempty"`
	Stdout string  `json:"stdout,omitempty"`
	Stderr string  `json:"stderr,omitempty"`

	// "stats" fields
	OK          int `json:"ok,omitempty"`
	Changed     int `json:"changed,omitempty"`
	Failed      int `json:"failed,omitempty"`
	Unreachable int `json:"unreachable,omitempty"`
	Skipped     int `json:"skipped,omitempty"`
}

// ----------------------------------------------------------------------------
// Rich model types
// ----------------------------------------------------------------------------

// Task is a single Ansible task execution on one host.
type Task struct {
	Play   string
	Name   string
	Module string
	Host   string
	Status string // ok, changed, failed, unreachable, skipped
	RC     int
	T      float64 // Unix timestamp
	Stdout string
	Stderr string
}

// HostStats is the recap for one host at the end of a playbook run.
type HostStats struct {
	Host        string
	OK          int
	Changed     int
	Failed      int
	Unreachable int
	Skipped     int
}

// Run is a complete Ansible playbook execution.
type Run struct {
	ID         string
	Playbook   string
	User       string
	Started    time.Time
	Controller string

	Plays []string // ordered play names
	Tasks []Task

	// Stats indexed by host name.
	Stats map[string]HostStats

	// Derived totals (computed by ParseRun).
	TotalOK          int
	TotalChanged     int
	TotalFailed      int
	TotalUnreachable int
	TotalSkipped     int

	// Hosts that appear in any task or stats (ordered).
	Hosts []string
}

// Duration returns wallclock duration from Run.Started to the latest task
// timestamp. It returns 0 when there are no tasks, no task carries a timestamp,
// or the computed span is negative (e.g. the final task has T==0 or a clock
// skew places a task before Started). The maximum task T is used rather than
// the last task in slice order, since tasks across hosts need not be ordered.
func (r *Run) Duration() time.Duration {
	var last float64
	for _, t := range r.Tasks {
		if t.T > last {
			last = t.T
		}
	}
	d := time.Duration((last-float64(r.Started.Unix()))*1e9) * time.Nanosecond
	if d < 0 {
		return 0
	}
	return d
}

// ----------------------------------------------------------------------------
// ParseRun
// ----------------------------------------------------------------------------

// ParseRun decodes a JSON-lines stream into a Run. Lines that do not parse as
// valid JSON objects are silently skipped (robustness). Returns an error only
// when the stream cannot be read at all.
func ParseRun(r io.Reader) (*Run, error) {
	run := &Run{Stats: map[string]HostStats{}}
	hostSet := map[string]struct{}{}
	playSet := map[string]struct{}{}

	// Read the output cap once; config.Load is a cached singleton but we still
	// avoid touching it per task in the hot loop below.
	maxOutput := config.Load().AnsibleOutputCap

	// Size the scanner's max line to the configured output cap, not a fixed
	// 256 KiB. A single "task" event is one JSON line carrying both stdout and
	// stderr (each up to maxOutput pre-truncation), and JSON escaping can inflate
	// control/quote-heavy output several-fold. If the line exceeds the scanner
	// buffer, Scan stops with bufio.ErrTooLong and the WHOLE run fails to parse —
	// so a legitimately large (but within-cap) output line must not be rejected.
	// Reserve room for two output fields plus ~6x worst-case \uXXXX escaping and a
	// fixed envelope allowance, with a 256 KiB floor for tiny caps.
	const scanFloor = 256 * 1024
	const envelopeHeadroom = 64 * 1024
	maxLine := 2*maxOutput*6 + envelopeHeadroom
	if maxLine < scanFloor {
		maxLine = scanFloor
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, scanFloor), maxLine)
	for sc.Scan() {
		// Use sc.Bytes() (not sc.Text()) to avoid an extra copy per line. The
		// slice is only valid until the next Scan and must not be retained, so
		// every field we keep is copied via string(...) when stored.
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev rawEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}

		switch ev.Type {
		case "run":
			run.ID = ev.ID
			run.Playbook = ev.Playbook
			run.User = ev.User
			run.Controller = ev.Controller
			if ev.Started > 0 {
				run.Started = time.Unix(int64(ev.Started), 0).UTC()
			}

		case "play":
			if ev.Name != "" {
				if _, seen := playSet[ev.Name]; !seen {
					playSet[ev.Name] = struct{}{}
					run.Plays = append(run.Plays, ev.Name)
				}
			}

		case "task":
			t := Task{
				Play:   ev.Play,
				Name:   ev.Name,
				Module: ev.Module,
				Host:   ev.Host,
				Status: ev.Status,
				RC:     ev.RC,
				T:      ev.T,
				Stdout: truncate(ev.Stdout, maxOutput),
				Stderr: truncate(ev.Stderr, maxOutput),
			}
			run.Tasks = append(run.Tasks, t)
			if ev.Host != "" {
				hostSet[ev.Host] = struct{}{}
			}

		case "stats":
			s := HostStats{
				Host:        ev.Host,
				OK:          ev.OK,
				Changed:     ev.Changed,
				Failed:      ev.Failed,
				Unreachable: ev.Unreachable,
				Skipped:     ev.Skipped,
			}
			run.Stats[ev.Host] = s
			run.TotalOK += ev.OK
			run.TotalChanged += ev.Changed
			run.TotalFailed += ev.Failed
			run.TotalUnreachable += ev.Unreachable
			run.TotalSkipped += ev.Skipped
			if ev.Host != "" {
				hostSet[ev.Host] = struct{}{}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ansible: parse: %w", err)
	}

	// Sort hosts for deterministic output.
	for h := range hostSet {
		run.Hosts = append(run.Hosts, h)
	}
	sort.Strings(run.Hosts)
	return run, nil
}

// truncMarker is appended to any output that truncate had to cap.
const truncMarker = "\n[... truncated]"

// truncate caps s so the retained payload is at most maxOutput bytes, then
// appends truncMarker.
//
// Contract:
//   - If len(s) <= maxOutput the input is returned verbatim (no marker).
//   - Otherwise the payload is the longest prefix of s that is <= maxOutput
//     bytes AND ends on a UTF-8 rune boundary (so the result is always valid
//     UTF-8 when s is). Because of the boundary back-walk the payload may be a
//     few bytes shorter than maxOutput.
//   - The returned string therefore EXCEEDS maxOutput by exactly the marker
//     length (len(truncMarker)); maxOutput bounds the payload, not the result.
func truncate(s string, maxOutput int) string {
	if len(s) <= maxOutput {
		return s
	}
	// Back-walk so the cut lands on a rune boundary: while the byte AT the cut is
	// a UTF-8 continuation byte (0b10xxxxxx), move left until it starts a new
	// rune. This drops a straddling rune entirely (including its lead byte), so
	// the result stays valid UTF-8. Index into s directly to avoid an extra copy.
	end := maxOutput
	for end > 0 && s[end]&0xC0 == 0x80 {
		end--
	}
	return s[:end] + truncMarker
}
