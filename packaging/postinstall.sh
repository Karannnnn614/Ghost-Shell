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

# SSH ForceCommand session-recording is now OPT-IN — it is no longer installed
# automatically here. An administrator enables it explicitly with:
#     sudo ghostshell init --enable-ssh-forcecommand
# and turns it off with:
#     sudo ghostshell init --disable-ssh-forcecommand
# The wrapper binary (/usr/libexec/ghostshell-ssh-wrap) is still shipped by the
# package; it simply stays inactive until the admin opts in.

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
