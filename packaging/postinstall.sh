#!/bin/sh
# ghostshell post-install: create the root-only central store and enable ghostshell-daemon.
set -e

# Central store: root-only so normal users cannot read recordings.
mkdir -p /var/lib/ghostshell
chown root:root /var/lib/ghostshell
chmod 0700 /var/lib/ghostshell

# Log directory: root-owned normal logfile for ghostshell-daemon alongside journald.
mkdir -p /var/log/ghostshell
chown root:root /var/log/ghostshell
chmod 0750 /var/log/ghostshell

# Install default config on first deploy (never overwrite existing config).
GHOSTSHELL_CONF=/etc/ghostshell/ghostshell.conf
if [ ! -f "$GHOSTSHELL_CONF" ]; then
    mkdir -p /etc/ghostshell
    if [ -f /usr/share/ghostshell/ghostshell.conf.example ]; then
        cp /usr/share/ghostshell/ghostshell.conf.example "$GHOSTSHELL_CONF"
        chmod 644 "$GHOSTSHELL_CONF"
    fi
fi

# Older/manual installs may have placed a full ghostshell-daemon unit in /etc/systemd,
# which shadows the packaged unit in /lib/systemd and prevents upgrades from
# applying service fixes. Retire only units that look like ghostshell's own legacy
# unit; administrators should use drop-ins for local overrides.
ETC_UNIT=/etc/systemd/system/ghostshell-daemon.service
PKG_UNIT=/lib/systemd/system/ghostshell-daemon.service
if [ -f "$ETC_UNIT" ] && [ -f "$PKG_UNIT" ] &&
    grep -q 'ghostshell session recording collector' "$ETC_UNIT" &&
    grep -q '^ExecStart=/usr/libexec/ghostshell-daemon$' "$ETC_UNIT"; then
    if ! cmp -s "$ETC_UNIT" "$PKG_UNIT"; then
        cp -a "$ETC_UNIT" "${ETC_UNIT}.bak.$(date +%Y%m%d%H%M%S)" || true
        rm -f "$ETC_UNIT"
    fi
fi

# Install ForceCommand sshd config to capture non-interactive SSH sessions.
# Idempotent: only write if not already present (preserves manual edits).
SSHD_MAIN=/etc/ssh/sshd_config
SSHD_CONF=/etc/ssh/sshd_config.d/zz-ghostshell.conf
if [ -d /etc/ssh/sshd_config.d ]; then
    # SSH recording is an OPTIONAL, fail-open feature. Everything below is
    # best-effort: a failure here must never abort the package install (which
    # would leave dpkg half-configured), so each mutation is guarded rather
    # than left to `set -e`. Track exactly what THIS run changes so the
    # validation-failure path can revert only our own edits.
    added_include=0
    wrote_conf=0

    # Ensure main sshd_config includes the drop-in directory; without this
    # line the drop-in files are silently ignored by sshd. Only inject if no
    # Include for that directory already exists (e.g. Ubuntu ships its own).
    if [ -f "$SSHD_MAIN" ] && ! grep -qE '^Include\s+/etc/ssh/sshd_config\.d/\*' "$SSHD_MAIN"; then
        if sed -i '1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|' "$SSHD_MAIN" 2>/dev/null; then
            added_include=1
        fi
    fi
    if [ ! -f "$SSHD_CONF" ]; then
        if cat > "$SSHD_CONF" << 'SSHD_EOF'
# Installed by ghostshell package. Remove this file to disable SSH session recording.
# The wrapper is fail-open: scp/sftp/rsync pass through untouched.
ForceCommand /usr/libexec/ghostshell-ssh-wrap
SSHD_EOF
        then
            wrote_conf=1
        fi
    fi
    # Validate sshd config — revert ONLY what this run added if broken.
    if ! sshd -t 2>/dev/null; then
        # Remove the ForceCommand drop-in only if we created it this run —
        # never delete a pre-existing / admin-edited file.
        if [ "$wrote_conf" -eq 1 ]; then
            rm -f "$SSHD_CONF"
        fi
        # Revert the Include line ONLY if this run added it. Deleting any
        # matching Include unconditionally would also strip Ubuntu's own
        # pre-existing `Include /etc/ssh/sshd_config.d/*.conf`, silently
        # breaking every other sshd drop-in on the box when sshd -t fails for
        # an unrelated reason.
        if [ "$added_include" -eq 1 ]; then
            sed -i '/^Include \/etc\/ssh\/sshd_config\.d\/\*\.conf$/d' "$SSHD_MAIN" 2>/dev/null || true
        fi
        echo "ghostshell: WARNING: sshd config validation failed — ForceCommand not installed" >&2
        exit 0  # non-fatal: package installs but SSH recording disabled
    fi
fi
# Reload sshd now that config is known valid.
if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi

# Enable and (re)start the collector daemon if systemd is present.
# The daemon generates the per-server encryption key on first start.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable ghostshell-daemon.service || true
    systemctl restart ghostshell-daemon.service || true
    # Wait briefly for the daemon to create the key.
    i=0
    while [ ! -f /var/lib/ghostshell/.ghostshell.key ] && [ "$i" -lt 30 ]; do
        sleep 1
        i=$((i + 1))
    done
fi

# Lock the key immutable (chattr +i): cannot be removed/modified by
# rm/vi/sed/>/tee, even by root, until `chattr -i`. Idempotent with the daemon.
if command -v chattr >/dev/null 2>&1 && [ -f /var/lib/ghostshell/.ghostshell.key ]; then
    chattr +i /var/lib/ghostshell/.ghostshell.key 2>/dev/null || true
fi

exit 0
