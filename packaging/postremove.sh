#!/bin/sh
# ghostshell post-remove: stop and disable ghostshell-daemon. Recordings in /var/lib/ghostshell
# are intentionally left in place (audit data is not deleted on uninstall).

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable ghostshell-daemon.service || true
    systemctl stop ghostshell-daemon.service || true
    systemctl daemon-reload || true
fi

exit 0
