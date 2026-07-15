// Ghost Shell - terminal session recorder and audit tool for Linux.
// Copyright (C) 2026 Karannnnn614
// Licensed under the GNU General Public License v2.0 (see LICENSE).

package analyze

import (
	"sort"
	"strings"

	"ghostshell/internal/span"
)

// normalizeCmd collapses a command to a canonical form for grouping: leading
// and trailing whitespace is trimmed and every internal run of whitespace
// becomes a single space. So "ls   -la" and " ls -la " both normalize to
// "ls -la". Normalization is intentionally conservative — it only touches
// whitespace, never arguments — so distinct commands are never merged; the
// tradeoff is that two invocations differing only in a variable argument are
// treated as different commands. strings.Fields splits on any Unicode space and
// drops empty fields, giving trim + collapse in one pass.
func normalizeCmd(cmd string) string {
	return strings.Join(strings.Fields(cmd), " ")
}

// duration returns a span's wall-clock duration in nanoseconds. Inputs are
// pre-filtered by span.Valid, so EndTS >= StartTS and this is non-negative.
func duration(s span.Span) int64 { return s.EndTS - s.StartTS }

// group holds the spans sharing one normalized command, kept in the input's
// start-time order.
type group struct {
	norm  string
	spans []span.Span
}

// groupByNormalized buckets spans by normalized command. spans is assumed
// already sorted by StartTS (validSorted guarantees this), so each bucket
// preserves start-time order. The returned groups are sorted by normalized
// command for a deterministic starting point; individual detectors re-sort
// their own output as documented.
func groupByNormalized(spans []span.Span) []group {
	idx := make(map[string]int)
	var groups []group
	for _, s := range spans {
		n := normalizeCmd(s.Cmd)
		i, ok := idx[n]
		if !ok {
			idx[n] = len(groups)
			groups = append(groups, group{norm: n, spans: []span.Span{s}})
			continue
		}
		groups[i].spans = append(groups[i].spans, s)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].norm < groups[j].norm })
	return groups
}

// detectRetryLoops flags maximal runs of the same normalized command invoked
// >= threshold times, where each invocation starts within windowNanos of the
// previous one. A single group may contain several separated runs (e.g. three
// retries now and three more an hour later); each qualifying run is reported
// independently. Results are ordered by FirstStartTS, ties broken by
// NormalizedCmd.
func detectRetryLoops(spans []span.Span, threshold int, windowNanos int64) []RetryLoop {
	var loops []RetryLoop
	for _, g := range groupByNormalized(spans) {
		gs := g.spans
		for i := 0; i < len(gs); {
			j := i + 1
			for j < len(gs) && gs[j].StartTS-gs[j-1].StartTS <= windowNanos {
				j++
			}
			if run := gs[i:j]; len(run) >= threshold {
				loops = append(loops, buildRetryLoop(g.norm, run))
			}
			i = j
		}
	}
	sort.Slice(loops, func(i, j int) bool {
		if loops[i].FirstStartTS != loops[j].FirstStartTS {
			return loops[i].FirstStartTS < loops[j].FirstStartTS
		}
		return loops[i].NormalizedCmd < loops[j].NormalizedCmd
	})
	return loops
}

func buildRetryLoop(norm string, run []span.Span) RetryLoop {
	rl := RetryLoop{
		NormalizedCmd: norm,
		SampleCmd:     run[0].Cmd,
		Count:         len(run),
		FirstStartTS:  run[0].StartTS,
		LastStartTS:   run[len(run)-1].StartTS,
		ExitCodes:     make([]int, 0, len(run)),
		SpanIDs:       make([]string, 0, len(run)),
	}
	for _, s := range run {
		if s.ExitCode != 0 {
			rl.FailureCount++
		}
		rl.ExitCodes = append(rl.ExitCodes, s.ExitCode)
		rl.SpanIDs = append(rl.SpanIDs, s.SpanID)
	}
	rl.SpanHuman = humanDuration(rl.LastStartTS - rl.FirstStartTS)
	return rl
}

// detectRedundant flags every normalized command run more than once anywhere in
// the session (no time constraint). Results are ordered by Count descending,
// ties broken by NormalizedCmd, so the biggest offenders come first.
func detectRedundant(spans []span.Span) []Redundant {
	var out []Redundant
	for _, g := range groupByNormalized(spans) {
		if len(g.spans) < 2 {
			continue
		}
		r := Redundant{
			NormalizedCmd: g.norm,
			SampleCmd:     g.spans[0].Cmd,
			Count:         len(g.spans),
			SpanIDs:       make([]string, 0, len(g.spans)),
		}
		for _, s := range g.spans {
			r.TotalDurationNanos += duration(s)
			r.SpanIDs = append(r.SpanIDs, s.SpanID)
		}
		r.TotalDurationHuman = humanDuration(r.TotalDurationNanos)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].NormalizedCmd < out[j].NormalizedCmd
	})
	return out
}

// detectLatency ranks spans by wall-clock duration and returns the top n
// slowest. Order is duration descending; ties broken by StartTS ascending then
// SpanID so the ranking is stable. n <= 0 yields no results; fewer than n
// spans yields all of them.
func detectLatency(spans []span.Span, n int) []Latency {
	if n <= 0 || len(spans) == 0 {
		return nil
	}
	ranked := make([]span.Span, len(spans))
	copy(ranked, spans)
	sort.Slice(ranked, func(i, j int) bool {
		di, dj := duration(ranked[i]), duration(ranked[j])
		if di != dj {
			return di > dj
		}
		if ranked[i].StartTS != ranked[j].StartTS {
			return ranked[i].StartTS < ranked[j].StartTS
		}
		return ranked[i].SpanID < ranked[j].SpanID
	})
	if n > len(ranked) {
		n = len(ranked)
	}
	out := make([]Latency, 0, n)
	for _, s := range ranked[:n] {
		d := duration(s)
		out = append(out, Latency{
			SpanID:        s.SpanID,
			Cmd:           s.Cmd,
			DurationNanos: d,
			DurationHuman: humanDuration(d),
			ExitCode:      s.ExitCode,
		})
	}
	return out
}

// collectFailures returns every span with a non-zero exit code, in start-time
// order (spans is pre-sorted by StartTS). Output fields are left empty here;
// correlateOutput fills them in when a cast is available.
func collectFailures(spans []span.Span) []Failure {
	var out []Failure
	for _, s := range spans {
		if s.ExitCode == 0 {
			continue
		}
		d := duration(s)
		out = append(out, Failure{
			SpanID:        s.SpanID,
			Cmd:           s.Cmd,
			ExitCode:      s.ExitCode,
			StartTS:       s.StartTS,
			EndTS:         s.EndTS,
			DurationNanos: d,
			DurationHuman: humanDuration(d),
		})
	}
	return out
}
