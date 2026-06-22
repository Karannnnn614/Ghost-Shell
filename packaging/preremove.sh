#!/bin/sh
# ghostshell pre-remove: ensure SSH is never broken when the package is removed.
#
# Strategy (belt-and-suspenders):
# 1. Replace ghostshell-ssh-wrap with a safe passthrough FIRST — so even if
#    sshd reload is delayed or the sshd config removal fails, any new SSH
#    connection will still work (just without recording).
# 2. Remove the sshd ForceCommand drop-in and reload sshd.
# 3. Remove the passthrough (dpkg removes the real binary next).
#
# This survives corrupt dpkg states, slow sshd reloads, and force-removes.

WRAP=/usr/libexec/ghostshell-ssh-wrap
SSHD_CONF=/etc/ssh/sshd_config.d/zz-ghostshell.conf

# Step 1: install safe passthrough wrapper (overwrite real binary).
# If sshd reads ForceCommand before we remove the conf, SSH still works.
cat > "$WRAP" << 'PASSTHROUGH_EOF'
#!/bin/sh
# ghostshell-ssh-wrap safety passthrough — ghostshell is being removed.
# SSH_ORIGINAL_COMMAND is user-supplied. Passing it to bash -c is intentional
# (required for scp/sftp/git semantics) and equivalent to what ghostshell-ssh-wrap does.
# This passthrough is only active during the brief removal window.
if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
else
    exec ${SHELL:-/bin/bash}
fi
PASSTHROUGH_EOF
chmod 755 "$WRAP"

# Step 2: remove sshd ForceCommand drop-in and reload sshd.
if [ -f "$SSHD_CONF" ]; then
    rm -f "$SSHD_CONF"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    fi
fi

exit 0
