# ghostshell auto-record hook — install to /etc/profile.d/ghostshell-autorec.sh
#
# Starts a ghostshell recording for interactive login sessions and logs out when
# the recorded shell exits. Skips nested shells (sudo su -, su -, subshells)
# so a session is recorded once, not re-wrapped at each level.
#
# Safety: fail-open. If anything is off (non-interactive, no TTY, ghostshell
# missing, or the recorder cannot start) the normal shell continues. Never
# blocks login.

# Interactive shells only.
case $- in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac

# Real TTY on stdin (skip scp/sftp/cron/pipes).
[ -t 0 ] || return 0 2>/dev/null || exit 0

# ghostshell must be installed and on PATH.
command -v ghostshell >/dev/null 2>&1 || return 0 2>/dev/null || exit 0

# Fast path: env flag set by an outer ghostshell-wrapped shell.
[ -n "${GHOSTSHELL_REC:-}" ] && { return 0 2>/dev/null || exit 0; }

# Robust re-entrancy guard: skip if a ghostshell process is already an ancestor.
# Survives env-stripping sudo (the recorder stays in the process tree across
# sudo / su), so nested `sudo su -` does not start a second recording.
_ghostshell_in_ancestry() {
  _p=$PPID
  while [ -n "$_p" ] && [ "$_p" -gt 1 ] 2>/dev/null; do
    if [ "$(cat /proc/"$_p"/comm 2>/dev/null)" = "ghostshell" ]; then
      return 0
    fi
    _p=$(awk '/^PPid:/{print $2}' /proc/"$_p"/status 2>/dev/null)
  done
  return 1
}
if _ghostshell_in_ancestry; then
  unset -f _ghostshell_in_ancestry
  return 0 2>/dev/null || exit 0
fi
unset -f _ghostshell_in_ancestry

# Mark this environment so direct child shells take the fast path above.
export GHOSTSHELL_REC=1

# Silence the recording banner / saved-path message for auto-login recording.
export GHOSTSHELL_QUIET=1

# Record the session. On a normal recorder run, log out afterwards so the
# whole login is captured as one session. If the recorder fails to start
# (non-zero exit), fall through to a normal interactive shell — fail-open.
ghostshell rec && exit
