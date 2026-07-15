# Ghost Shell - process-trace shim (bash DEBUG/EXIT-trap command tracer).
# Copyright (C) 2026 Karannnnn614
# Licensed under the GNU General Public License v2.0 (see LICENSE).
#
# This file is SOURCED, never executed. The recorder wires a traced shell to it
# two ways:
#   * interactive bash:      bash --rcfile /usr/share/ghostshell/trace-shim.sh
#   * non-interactive child: BASH_ENV=/usr/share/ghostshell/trace-shim.sh
#
# It installs a DEBUG trap that opens a span for each simple command and a
# matching EXIT trap that flushes the last one, capturing $BASH_COMMAND, start
# and end nanosecond timestamps, and the exit code (read as $? at the TOP of the
# next DEBUG firing). Spans are piped to `ghostshell __report-span`, which fails
# open. Every step is defensive: a failure anywhere in the tracer leaves the
# user's command execution untouched.
#
# Coverage is bash-only by design. sh/dash/zsh/fish do not read BASH_ENV as bash
# does and set no BASH_VERSION, so the guard below makes the shim a no-op for
# them — those shells get transcript-only recording, no structured trace.

# --- Guard 1: bash only. Sourced by a non-bash shell (sh/dash/zsh) -> no-op. ---
if [ -z "${BASH_VERSION:-}" ]; then
	return 0 2>/dev/null || exit 0
fi

# --- Guard 2: only trace inside a ghostshell-recorded session. Without a trace
# id there is nothing to correlate to, so a stray BASH_ENV pointing here (e.g.
# a normal login shell) is a clean no-op. ---
if [ -z "${GHOSTSHELL_TRACE_ID:-}" ]; then
	return 0 2>/dev/null || exit 0
fi

# --- Guard 3: install once per bash process. __gs_installed is NOT exported, so
# each nested bash child re-installs its own traps (with its own BASHPID and
# counter) while a re-source within the same shell is a no-op. ---
if [ -n "${__gs_installed:-}" ]; then
	return 0 2>/dev/null || exit 0
fi

# --- Interactive (--rcfile) path: we REPLACED the user's rc, so source the real
# rc files first to preserve their environment, THEN install traps. A
# non-interactive child (sourced via BASH_ENV) skips this and only installs
# traps. `$-` contains 'i' exactly for interactive shells. ---
case $- in
*i*)
	if [ -r /etc/bash.bashrc ]; then
		. /etc/bash.bashrc
	fi
	if [ -r "${HOME:-}/.bashrc" ]; then
		. "${HOME}/.bashrc"
	fi
	;;
esac

# Per-process trace state (plain shell vars, never exported).
__gs_counter=0            # per-command counter; combines with TRACE_ID+BASHPID
__gs_pending_span_id=""   # the currently-open span, or "" when none
__gs_pending_parent=""
__gs_pending_cmd=""
__gs_pending_start=""
__gs_busy=""              # reentrancy guard (also inherited=1 by emit subshells)
__gs_last_emit_cmd=""     # cmd of the most recently emitted span (phantom guard)

# The base parent/depth are the values INHERITED from the environment at shim
# load, snapshotted once. Every command in THIS shell attributes to __gs_base_parent
# (so siblings stay siblings), while each command separately exports its own
# span_id as GHOSTSHELL_PARENT_SPAN for CHILD processes to attach under. The
# depth children see is fixed at base+1, so export it once here.
__gs_base_parent="${GHOSTSHELL_PARENT_SPAN:-}"
__gs_base_depth="${GHOSTSHELL_TRACE_DEPTH:-0}"
case $__gs_base_depth in
'' | *[!0-9]*) __gs_base_depth=0 ;;
esac
export GHOSTSHELL_TRACE_DEPTH="$((__gs_base_depth + 1))"

# __gs_now sets __gs_ns to the current time in unix nanoseconds without forking
# in the common case (EPOCHREALTIME is a bash>=5 builtin var, "seconds.micros"
# using the locale radix). Falls back to `date` when EPOCHREALTIME is absent.
__gs_now() {
	local t sec us
	t="${EPOCHREALTIME:-}"
	if [ -n "$t" ]; then
		sec="${t%%[.,]*}"
		us="${t#*[.,]}"
		if [ "$us" = "$t" ]; then
			us=0
		fi
		us="${us}000000"
		__gs_ns="${sec}${us:0:6}000"
	else
		__gs_ns="$(date +%s%N 2>/dev/null)"
		case $__gs_ns in
		'' | *[!0-9]*) __gs_ns="$(date +%s 2>/dev/null)000000000" ;;
		esac
	fi
}

# __gs_json_escape sets __gs_esc to a JSON-string-safe form of $1: escape
# backslash and quote, convert newline/tab/CR to their JSON escapes, and drop
# any remaining C0 control byte so the emitted object is always valid JSON.
__gs_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/\\r}"
	s="${s//[$'\x01'-$'\x1f']/}"
	__gs_esc="$s"
}

# __gs_json builds one JSON-lines span object into __gs_json_result.
# args: span_id parent_span_id cmd start_ts end_ts exit_code depth
__gs_json() {
	local esid epar ecmd
	__gs_json_escape "$1"
	esid="$__gs_esc"
	__gs_json_escape "$2"
	epar="$__gs_esc"
	__gs_json_escape "$3"
	ecmd="$__gs_esc"
	printf -v __gs_json_result \
		'{"span_id":"%s","parent_span_id":"%s","cmd":"%s","start_ts":%s,"end_ts":%s,"exit_code":%s,"depth":%s}' \
		"$esid" "$epar" "$ecmd" "${4:-0}" "${5:-0}" "${6:-0}" "${7:-0}"
}

# __gs_emit fires one span to the reporter, fail-open and (by default)
# non-blocking. The reporter carries its own short timeout. Running it in a
# `( ... & )` subshell detaches it so no job-control message reaches the
# interactive shell and the shell never waits on it. GHOSTSHELL_TRACE_SYNC=1
# forces a synchronous send (used by tests for determinism).
__gs_emit() {
	command -v ghostshell >/dev/null 2>&1 || return 0
	__gs_json "$@"
	if [ -n "${GHOSTSHELL_TRACE_SYNC:-}" ]; then
		printf '%s\n' "$__gs_json_result" | ghostshell __report-span >/dev/null 2>&1
	else
		(printf '%s\n' "$__gs_json_result" | ghostshell __report-span >/dev/null 2>&1 &)
	fi
	# Remember the command just emitted so the EXIT trap can recognize (and drop)
	# the phantom span bash's pre-EXIT DEBUG firing leaves pending (see __gs_exit).
	__gs_last_emit_cmd="$3"
	return 0
}

# __gs_debug is the DEBUG trap. It runs before every simple command. It reads
# $? FIRST (the previous command's exit), finalizes the pending span with it,
# then opens a new pending span for $BASH_COMMAND. It always restores $? via
# `return $ec` so the command about to run sees the correct previous status.
__gs_debug() {
	local ec=$?
	# Reentrancy guard. A subshell forked while we are BUSY (e.g. the emit
	# subshell, or a command substitution inside a helper) inherits __gs_busy=1
	# and so short-circuits here, which prevents the tracer from tracing itself.
	if [ -n "$__gs_busy" ]; then
		return $ec
	fi
	__gs_busy=1
	local cmd="$BASH_COMMAND"

	# 1) Finalize the pending span (previous command) with its real exit code.
	if [ -n "$__gs_pending_span_id" ]; then
		__gs_now
		__gs_emit "$__gs_pending_span_id" "$__gs_pending_parent" "$__gs_pending_cmd" \
			"$__gs_pending_start" "$__gs_ns" "$ec" "$__gs_base_depth"
		__gs_pending_span_id=""
	fi

	# 2) Never trace our own reporter/shim internals.
	case $cmd in
	__gs_* | *ghostshell\ __report-span* | *__report-span*)
		__gs_busy=""
		return $ec
		;;
	esac

	# 3) Open a new pending span for the command about to run. It attributes to
	# the SNAPSHOT base parent (so commands in this shell are siblings), while we
	# export THIS span_id as GHOSTSHELL_PARENT_SPAN so a bash child it spawns
	# attaches its own commands under this span at depth base+1.
	__gs_counter=$((__gs_counter + 1))
	local sid="${GHOSTSHELL_TRACE_ID}.${BASHPID}.${__gs_counter}"
	__gs_now
	__gs_pending_span_id="$sid"
	__gs_pending_parent="$__gs_base_parent"
	__gs_pending_cmd="$cmd"
	__gs_pending_start="$__gs_ns"
	export GHOSTSHELL_PARENT_SPAN="$sid"

	__gs_busy=""
	return $ec
}

# __gs_exit is the EXIT trap, a safety net for the last span. On bash >=4 a DEBUG
# trap fires once more just before EXIT, re-presenting the LAST command (verified:
# `trap dbg DEBUG; echo x` fires DEBUG a final time with $BASH_COMMAND="echo x").
# That firing already finalized the real last span AND left a PHANTOM span pending
# for the same command — so a naive flush here double-reports every scope's last
# command. Guard against it: only emit if the pending command differs from the one
# most recently emitted. That drops the phantom on bash >=4 while still flushing a
# genuinely un-emitted last span on any shell that does NOT fire the pre-EXIT DEBUG
# (fail-open: worst case a duplicate is avoided; a real last span is not lost).
# PROMPT_COMMAND is not usable here — it never fires in a non-interactive script.
__gs_exit() {
	local ec=$?
	if [ -n "$__gs_pending_span_id" ] && [ "$__gs_pending_cmd" != "$__gs_last_emit_cmd" ]; then
		__gs_now
		__gs_emit "$__gs_pending_span_id" "$__gs_pending_parent" "$__gs_pending_cmd" \
			"$__gs_pending_start" "$__gs_ns" "$ec" "$__gs_base_depth"
		__gs_pending_span_id=""
	fi
	return $ec
}

# Install the EXIT trap and mark installed FIRST, then install the DEBUG trap
# LAST. A DEBUG trap fires before the NEXT command, so installing it last means
# the shim's own setup lines are never traced — the first span is the traced
# shell's first real command.
trap '__gs_exit' EXIT
__gs_installed=1
trap '__gs_debug' DEBUG
