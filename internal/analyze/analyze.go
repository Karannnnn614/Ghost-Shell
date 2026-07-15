// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

// Package analyze is the deterministic analysis pass over a recorded process
// trace. It turns a session's flat []span.Span (plus the decrypted pty cast,
// for failure context) into a single compact, JSON-serializable Summary.
//
// Everything here is pure Go: no Ollama, no network, no CLI wiring. The point
// is to push as much real work as possible into this layer so the downstream
// local-model pass only has to add human-language judgment (why a failure
// happened, a plain-English run summary, caching suggestions) and never has to
// compute. Failures, retries, redundancy, and latencies are fully determined
// here; the Summary this package emits is exactly what the model is handed.
//
// The four detectors are:
//
//   - retry-loop: same normalized command run >= threshold times in a row
//     within a sliding time window (a human hammering a failing command).
//   - redundant: same normalized command run more than once anywhere in the
//     session (wasted repeated work, cacheable steps).
//   - latency: the slowest commands by wall-clock duration.
//   - failures: every span with a non-zero exit code, each carrying the slice
//     of pty output that was on screen while it ran (see correlate.go).
//
// All detectors are deterministic: the same spans (and cast) always yield the
// same Summary, with every list in a stable, documented order.
package analyze

import (
	"bufio"
	"io"
	"sort"
	"time"

	"ghostshell/internal/span"
)

// Defaults for Options. Exported so Part D (the CLI) can surface them in help
// text and flag defaults without hardcoding a second copy.
const (
	// DefaultRetryThreshold is the minimum run length (identical consecutive
	// invocations within RetryWindow) that counts as a retry loop.
	DefaultRetryThreshold = 3
	// DefaultRetryWindow is the maximum gap between two consecutive invocations
	// for them to belong to the same retry run.
	DefaultRetryWindow = 60 * time.Second
	// DefaultTopLatency is how many of the slowest commands to report.
	DefaultTopLatency = 5
	// DefaultMaxOutputBytes caps the pty-output slice captured per failure. The
	// tail is kept (the error message is almost always last), so a larger run of
	// output is truncated from the front.
	DefaultMaxOutputBytes = 4096
)

// Options tunes the detectors. A zero Options is valid: every zero (or
// negative) field is replaced by its Default* above via withDefaults, so
// callers may pass Options{} for stock behavior or set only the fields they
// care about.
type Options struct {
	// RetryThreshold is the minimum number of consecutive identical
	// invocations (within RetryWindow) to flag as a retry loop. Default 3.
	RetryThreshold int
	// RetryWindow is the maximum gap between two consecutive invocations of the
	// same normalized command for them to count as part of one retry run.
	// Default 60s.
	RetryWindow time.Duration
	// TopLatency is the number of slowest commands to include in
	// Summary.SlowestCommands. Default 5.
	TopLatency int
	// MaxOutputBytes caps each failure's captured pty-output slice; the last
	// MaxOutputBytes bytes are kept. Default 4096.
	MaxOutputBytes int
}

func (o Options) withDefaults() Options {
	if o.RetryThreshold <= 0 {
		o.RetryThreshold = DefaultRetryThreshold
	}
	if o.RetryWindow <= 0 {
		o.RetryWindow = DefaultRetryWindow
	}
	if o.TopLatency <= 0 {
		o.TopLatency = DefaultTopLatency
	}
	if o.MaxOutputBytes <= 0 {
		o.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return o
}

// Summary is the complete deterministic analysis of one recorded session. It
// is JSON-serializable and is exactly the payload handed to the local model in
// Part D — the model adds judgment, it does not recompute any of this. Every
// slice is emitted in a stable order (documented on each field); an empty
// result is an empty (non-nil after JSON round-trip) list, never a sentinel.
type Summary struct {
	// CommandCount is the number of valid spans analyzed (spans failing
	// span.Valid are dropped up front and never counted).
	CommandCount int `json:"command_count"`
	// FailureCount is the number of analyzed spans with ExitCode != 0. It
	// equals len(Failures).
	FailureCount int `json:"failure_count"`
	// TotalDurationNanos is the session's wall-clock span: max(EndTS) minus
	// min(StartTS) across all analyzed spans, in nanoseconds. It is a wall-clock
	// range (not a sum of durations), so overlapping/nested spans are not
	// double-counted. Zero when there are no spans.
	TotalDurationNanos int64 `json:"total_duration_nanos"`
	// TotalDurationHuman is TotalDurationNanos rendered by time.Duration.String
	// (e.g. "2m3.4s"), for the model and for display.
	TotalDurationHuman string `json:"total_duration_human"`

	// RetryLoops holds each detected retry loop, ordered by FirstStartTS
	// ascending (ties broken by NormalizedCmd).
	RetryLoops []RetryLoop `json:"retry_loops"`
	// RedundantCommands holds every normalized command run more than once,
	// ordered by Count descending (ties broken by NormalizedCmd).
	RedundantCommands []Redundant `json:"redundant_commands"`
	// SlowestCommands holds up to Options.TopLatency spans, ordered by duration
	// descending (ties broken by StartTS then SpanID).
	SlowestCommands []Latency `json:"slowest_commands"`
	// Failures holds every non-zero-exit span with its correlated pty output,
	// ordered by StartTS ascending (ties broken by SpanID).
	Failures []Failure `json:"failures"`
}

// RetryLoop is a maximal run of the same normalized command invoked
// >= Options.RetryThreshold times, each within Options.RetryWindow of the
// previous. It signals a human (or script) hammering a command that keeps
// misbehaving.
type RetryLoop struct {
	// NormalizedCmd is the whitespace-normalized command shared by the run.
	NormalizedCmd string `json:"normalized_cmd"`
	// SampleCmd is the raw Cmd of the first invocation in the run (verbatim,
	// before normalization).
	SampleCmd string `json:"sample_cmd"`
	// Count is the number of invocations in the run (>= RetryThreshold).
	Count int `json:"count"`
	// FailureCount is how many invocations in the run exited non-zero.
	FailureCount int `json:"failure_count"`
	// FirstStartTS / LastStartTS are the start timestamps (unix nanos) of the
	// first and last invocation in the run.
	FirstStartTS int64 `json:"first_start_ts"`
	LastStartTS  int64 `json:"last_start_ts"`
	// SpanHuman is the wall time from the first to the last invocation's start,
	// via time.Duration.String.
	SpanHuman string `json:"span_human"`
	// ExitCodes is the exit code of each invocation, in run order.
	ExitCodes []int `json:"exit_codes"`
	// SpanIDs is the SpanID of each invocation, in run order.
	SpanIDs []string `json:"span_ids"`
}

// Redundant is a normalized command that was run more than once anywhere in
// the session (no time constraint). A retry loop is a time-clustered special
// case, so a command may appear in both RetryLoops and RedundantCommands;
// RedundantCommands is the broader "you ran this N times total" view and is
// the natural place for the model to suggest caching or deduplication.
type Redundant struct {
	// NormalizedCmd is the whitespace-normalized command.
	NormalizedCmd string `json:"normalized_cmd"`
	// SampleCmd is the raw Cmd of the first occurrence (verbatim).
	SampleCmd string `json:"sample_cmd"`
	// Count is the total number of invocations (>= 2).
	Count int `json:"count"`
	// TotalDurationNanos is the summed duration (EndTS-StartTS) of all
	// invocations — the aggregate time spent on this repeated command.
	TotalDurationNanos int64 `json:"total_duration_nanos"`
	// TotalDurationHuman is TotalDurationNanos via time.Duration.String.
	TotalDurationHuman string `json:"total_duration_human"`
	// SpanIDs is every invocation's SpanID, in start-time order.
	SpanIDs []string `json:"span_ids"`
}

// Latency is one of the slowest commands by wall-clock duration.
type Latency struct {
	// SpanID identifies the span.
	SpanID string `json:"span_id"`
	// Cmd is the raw command (verbatim).
	Cmd string `json:"cmd"`
	// DurationNanos is EndTS-StartTS in nanoseconds.
	DurationNanos int64 `json:"duration_nanos"`
	// DurationHuman is DurationNanos via time.Duration.String.
	DurationHuman string `json:"duration_human"`
	// ExitCode is the span's exit code (so the model can tell a slow success
	// from a slow failure).
	ExitCode int `json:"exit_code"`
}

// Failure is a span that exited non-zero, together with the pty output that was
// produced while it ran. Output is correlated from the cast by time window (see
// correlate.go); it is empty when no cast was supplied or nothing was on screen
// during the span's window.
type Failure struct {
	// SpanID identifies the span.
	SpanID string `json:"span_id"`
	// Cmd is the raw command that failed (verbatim).
	Cmd string `json:"cmd"`
	// ExitCode is the non-zero exit status.
	ExitCode int `json:"exit_code"`
	// StartTS / EndTS are the span window (unix nanos).
	StartTS int64 `json:"start_ts"`
	EndTS   int64 `json:"end_ts"`
	// DurationNanos is EndTS-StartTS.
	DurationNanos int64 `json:"duration_nanos"`
	// DurationHuman is DurationNanos via time.Duration.String.
	DurationHuman string `json:"duration_human"`
	// Output is the correlated pty-output slice for this failure, capped to
	// Options.MaxOutputBytes (tail kept). It is raw terminal bytes as a string,
	// escape sequences and all; the model is expected to read through them.
	Output string `json:"output"`
	// OutputTruncated is true when the captured output exceeded
	// Options.MaxOutputBytes and leading bytes were dropped.
	OutputTruncated bool `json:"output_truncated"`
}

// Analyze runs the deterministic analysis over spans and returns a Summary.
//
// spans is the flat, merged span list for one session (as produced by
// span.ReadAll over the decrypted chunks). Spans failing span.Valid are
// dropped before anything else, so malformed/truncated records never skew the
// result. The order of the input does not matter; Analyze sorts internally.
//
// castReader, when non-nil, must be positioned at the very start of the
// DECRYPTED asciinema v2 cast (its header line first). Analyze reads and
// consumes the header, then streams the event lines to correlate pty output to
// each failure's time window. Analyze does NOT decrypt — the caller (Part D)
// passes an already-decrypted reader. Pass nil to skip output correlation
// entirely (the non-failure detectors and the failure list itself still work;
// each Failure.Output is just empty).
//
// sessionStartUnix is the session start in unix SECONDS, used to map a span's
// unix-nanosecond window onto the cast's session-relative event times. Pass the
// value the caller already read from the cast header (span/cast header
// Timestamp). If sessionStartUnix <= 0, Analyze falls back to the Timestamp in
// the cast header it just read.
//
// The returned Summary is ALWAYS fully populated for the deterministic
// detectors (run stats, retries, redundancy, latency, and the failure list
// with exit codes), regardless of the cast. A non-nil error means only that
// failure-output correlation could not be performed (the cast header was
// unparseable, or no session start was available) — the Summary is still valid
// and usable, just with empty Failure.Output fields. Callers that do not care
// about failure output may ignore the error.
func Analyze(spans []span.Span, castReader io.Reader, sessionStartUnix int64, opts Options) (Summary, error) {
	opts = opts.withDefaults()

	valid := validSorted(spans)

	sum := Summary{
		CommandCount:      len(valid),
		RetryLoops:        detectRetryLoops(valid, opts.RetryThreshold, opts.RetryWindow.Nanoseconds()),
		RedundantCommands: detectRedundant(valid),
		SlowestCommands:   detectLatency(valid, opts.TopLatency),
		Failures:          collectFailures(valid),
	}
	sum.FailureCount = len(sum.Failures)
	sum.TotalDurationNanos = wallDuration(valid)
	sum.TotalDurationHuman = humanDuration(sum.TotalDurationNanos)

	var err error
	if castReader != nil && len(sum.Failures) > 0 {
		err = correlateOutput(bufio.NewReader(castReader), sessionStartUnix, sum.Failures, opts.MaxOutputBytes)
	}
	return sum, err
}

// validSorted returns the subset of spans satisfying span.Valid, sorted by
// StartTS ascending (ties broken by SpanID) so every downstream detector sees a
// deterministic order. The input is not mutated.
func validSorted(spans []span.Span) []span.Span {
	out := make([]span.Span, 0, len(spans))
	for _, s := range spans {
		if s.Valid() {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartTS != out[j].StartTS {
			return out[i].StartTS < out[j].StartTS
		}
		return out[i].SpanID < out[j].SpanID
	})
	return out
}

// wallDuration returns max(EndTS) - min(StartTS) over spans (0 for none).
func wallDuration(spans []span.Span) int64 {
	if len(spans) == 0 {
		return 0
	}
	minStart := spans[0].StartTS
	maxEnd := spans[0].EndTS
	for _, s := range spans[1:] {
		if s.StartTS < minStart {
			minStart = s.StartTS
		}
		if s.EndTS > maxEnd {
			maxEnd = s.EndTS
		}
	}
	if maxEnd < minStart {
		return 0
	}
	return maxEnd - minStart
}

// humanDuration renders a nanosecond count via time.Duration.String.
func humanDuration(nanos int64) string {
	return time.Duration(nanos).String()
}
