// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ghostshell/internal/analyze"
	"ghostshell/internal/ollama"
	"ghostshell/internal/span"
	"ghostshell/internal/store"
)

// Analyze handles `ghostshell analyze [--no-ai] [--model NAME] [--allow-remote] <session-id>`.
//
// It runs the deterministic analysis pass over a recorded session's process
// trace (retry loops, redundant commands, latency ranking, and failures with
// the pty output captured while each failed) and ALWAYS prints that report.
// Then, unless --no-ai is given, it hands the compact deterministic Summary to a
// LOCAL Ollama model for the judgment parts (a plain-English run summary, likely
// causes of each failure, and caching/efficiency suggestions). The model call is
// fully optional and fully local: the Ollama endpoint must be loopback unless
// --allow-remote is passed, and if Ollama isn't running the deterministic report
// still prints with a hint to install it. Nothing ever leaves the machine.
func Analyze(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	noAI := fs.Bool("no-ai", false, "skip the local model pass; print only the deterministic report")
	model := fs.String("model", ollama.DefaultModel, "local Ollama model to use for the AI pass")
	allowRemote := fs.Bool("allow-remote", false, "allow a non-loopback Ollama endpoint (OLLAMA_HOST); off by default to keep session data on this machine")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ghostshell analyze [--no-ai] [--model NAME] [--allow-remote] <session-id>")
	}
	id := fs.Arg(0)

	castPath, user, err := store.FindCentral(id)
	if err != nil {
		return notRoot(err)
	}
	h, herr := store.Header(castPath)
	if herr != nil {
		return fmt.Errorf("cannot read session %q: %w", id, herr)
	}
	traceID := ""
	if h.Env != nil {
		traceID = h.Env[span.HeaderTraceKey]
	}
	// No usable trace id: the session was recorded without process tracing (a
	// non-bash shell, tracing disabled, or a pre-tracing recording). There is
	// nothing to analyze — say so plainly and exit 0, matching `tree`.
	if traceID == "" || !store.ValidTraceID(traceID) {
		fmt.Printf("no process-trace data recorded for session %q — nothing to analyze\n", id)
		return nil
	}
	spans := loadSpans(user, traceID)
	if len(spans) == 0 {
		fmt.Printf("no process-trace spans recovered for session %q — nothing to analyze\n", id)
		return nil
	}

	// Deterministic pass. Open the decrypted cast so failures can carry the pty
	// output that was on screen while they ran; if the cast is unreadable we still
	// analyze the spans (failures without their output slice). analyze.Analyze is
	// fail-open — its only error concerns failure-output correlation, which we
	// intentionally ignore here since the deterministic result is still valid.
	var summary analyze.Summary
	if rc, oerr := store.OpenCast(castPath); oerr == nil {
		summary, _ = analyze.Analyze(spans, rc, h.Timestamp, analyze.Options{})
		rc.Close()
	} else {
		summary, _ = analyze.Analyze(spans, nil, h.Timestamp, analyze.Options{})
	}

	renderSummary(os.Stdout, id, user, summary)

	if *noAI {
		return nil
	}
	runModelPass(os.Stdout, summary, *model, *allowRemote)
	return nil
}

// renderSummary prints the deterministic analysis as a readable report: a header
// line, then Failures, Retry loops, Redundant commands, and Slowest commands —
// each section omitted when empty. Command lines are sanitized (control/ANSI
// stripped) before printing, since recorded commands are attacker-influenced
// content and must not inject escapes into a root operator's terminal.
func renderSummary(w io.Writer, id, user string, s analyze.Summary) {
	fmt.Fprintf(w, "Session %s  (user %s)\n", id, user)
	fmt.Fprintf(w, "  %d commands, %d failed, %s wall-clock\n", s.CommandCount, s.FailureCount, s.TotalDurationHuman)

	if len(s.Failures) > 0 {
		fmt.Fprintf(w, "\nFailures (%d):\n", len(s.Failures))
		for _, f := range s.Failures {
			fmt.Fprintf(w, "  - %s  [exit %d, %s]\n", sanitizeCmd(f.Cmd), f.ExitCode, f.DurationHuman)
			if line := lastOutputLine(f.Output); line != "" {
				fmt.Fprintf(w, "      last output: %s\n", store.Trunc(line, 100))
			}
		}
	}

	if len(s.RetryLoops) > 0 {
		fmt.Fprintf(w, "\nRetry loops (same command run %d+ times in a row):\n", analyze.DefaultRetryThreshold)
		for _, r := range s.RetryLoops {
			fmt.Fprintf(w, "  - %s  x%d (%d failed) over %s\n", sanitizeCmd(r.SampleCmd), r.Count, r.FailureCount, r.SpanHuman)
		}
	}

	if len(s.RedundantCommands) > 0 {
		fmt.Fprintf(w, "\nRepeated commands (candidates for caching/dedup):\n")
		for _, rc := range s.RedundantCommands {
			fmt.Fprintf(w, "  - %s  x%d (%s total)\n", sanitizeCmd(rc.SampleCmd), rc.Count, rc.TotalDurationHuman)
		}
	}

	if len(s.SlowestCommands) > 0 {
		fmt.Fprintf(w, "\nSlowest commands:\n")
		for _, l := range s.SlowestCommands {
			status := ""
			if l.ExitCode != 0 {
				status = fmt.Sprintf(" [exit %d]", l.ExitCode)
			}
			fmt.Fprintf(w, "  - %-8s %s%s\n", l.DurationHuman, sanitizeCmd(l.Cmd), status)
		}
	}
}

// lastOutputLine returns the last non-empty, ANSI-stripped line of a failure's
// captured pty output — a compact one-line error snippet for the deterministic
// report. Empty when there is no usable output.
func lastOutputLine(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if c := clean(lines[i]); c != "" {
			return c
		}
	}
	return ""
}

// runModelPass sends the deterministic Summary to a local Ollama model and
// prints its narrative. It is best-effort and never fails the command: a
// non-loopback endpoint without --allow-remote, or Ollama not running, prints an
// explanatory note (the deterministic report has already been shown) and returns.
func runModelPass(w io.Writer, summary analyze.Summary, model string, allowRemote bool) {
	client, err := ollama.New(normalizeOllamaHost(os.Getenv("OLLAMA_HOST")), model, allowRemote)
	if err != nil {
		// Configuration/guard error (e.g. non-loopback host without --allow-remote).
		fmt.Fprintf(w, "\nAI analysis skipped: %v\n", err)
		return
	}
	payload, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fmt.Fprintf(w, "\nAI analysis skipped: could not encode summary: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	text, gerr := client.Generate(ctx, analyzeSystemPrompt, analyzeUserPrompt(payload))
	if gerr != nil {
		if errors.Is(gerr, ollama.ErrUnavailable) {
			fmt.Fprintf(w, "\nAI analysis unavailable: Ollama is not running.\n"+
				"Install it from https://ollama.com, then `ollama pull %s` to enable local, offline analysis.\n"+
				"(Pass --no-ai to silence this and print only the deterministic report.)\n", client.Model())
		} else {
			fmt.Fprintf(w, "\nAI analysis error: %v\n", gerr)
		}
		return
	}
	if text == "" {
		return
	}
	fmt.Fprintf(w, "\n--- AI analysis (local model: %s) ---\n%s\n", client.Model(), text)
}

// normalizeOllamaHost turns an OLLAMA_HOST value into a URL the client can
// parse. An empty value yields "" (the client falls back to its default
// loopback endpoint). A bare host or host:port gets an http:// scheme; a value
// that already has a scheme is passed through unchanged.
func normalizeOllamaHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		return h
	}
	return "http://" + h
}

// analyzeSystemPrompt frames the local model as a reviewer of a pre-computed
// analysis, not a recomputation engine — the deterministic layer already did the
// counting and detection.
const analyzeSystemPrompt = `You are a senior site-reliability engineer reviewing a recorded terminal session. You are given a deterministic, pre-computed JSON summary of the session's process tree: command counts, failures (each with the terminal output that was on screen while it ran), retry loops, repeated commands, and the slowest commands. All the numbers and detection are already done — do NOT recompute them, and do NOT invent commands that are not in the data.

Write a short, plain-English review in three parts:
1. Summary: 2-3 sentences on what the session did and whether it succeeded.
2. Failures: for each failed command, the most likely cause given its command line and captured output, plus a concrete fix.
3. Efficiency: call out any retry loops, repeated/cacheable commands, and slow steps, each with a specific suggestion.

Be concrete and terse. Do not restate the raw numbers back. If the run was clean and efficient, say so in two sentences rather than padding.`

// analyzeUserPrompt embeds the deterministic Summary JSON as the review input.
func analyzeUserPrompt(summaryJSON []byte) string {
	return "Here is the deterministic session summary (JSON):\n\n" + string(summaryJSON) + "\n\nWrite the review."
}
