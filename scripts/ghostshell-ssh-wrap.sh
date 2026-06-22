#!/bin/sh
# ghostshell sshd ForceCommand wrapper.
#
# Wire it in sshd_config:  ForceCommand /usr/libexec/ghostshell-ssh-wrap
#
# Behavior:
#   - Interactive login (no SSH command): exec the user's login shell. The
#     profile.d hook records interactive sessions, so we do not double-wrap.
#   - File-transfer / subsystem requests (scp, sftp, rsync, git pack): exec
#     them UNTOUCHED so transfers keep working.
#   - Any other remote command (`ssh host "cmd"`): record it with ghostshell.
#
# Fail-open: on any doubt, exec the original command / login shell so SSH is
# never broken.

cmd="$SSH_ORIGINAL_COMMAND"
shell="${SHELL:-/bin/bash}"

# Interactive login — hand off to the login shell (profile.d does recording).
if [ -z "$cmd" ]; then
    exec "$shell" -l
fi

# Pass file-transfer / subsystem commands through untouched.
case "$cmd" in
    ghostshell\ rec*|*/ghostshell\ rec*| \
    scp\ *|*/scp\ *| \
    sftp-server*|*/sftp-server*|internal-sftp*| \
    rsync\ --server*|*/rsync\ --server*| \
    git-receive-pack*|git-upload-pack*|git-upload-archive*)
        exec "$shell" -c "$cmd"
        ;;
esac

# Record the command session if ghostshell is available; else run it plainly.
if command -v ghostshell >/dev/null 2>&1; then
    exec ghostshell rec -q "$shell" -c "$cmd"
fi
exec "$shell" -c "$cmd"
