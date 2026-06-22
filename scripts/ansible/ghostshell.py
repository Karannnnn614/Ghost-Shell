"""
ghostshell Ansible callback plugin
==============================

Records Ansible playbook runs into the ghostshell central store so they can be
reviewed with ``ghostshell ansible list`` / ``ghostshell ansible show``.

Each task execution (ok, changed, failed, unreachable, skipped) is sent as a
JSON-lines event to ``ghostshell ansible-ingest``, which streams them to the
local ghostshell-daemon daemon (encrypts + stores) or falls back to a user-local file.

Enable
------
Either set env vars on the controller before running ansible-playbook::

    export ANSIBLE_CALLBACK_PLUGINS=/usr/share/ghostshell/ansible
    export ANSIBLE_CALLBACKS_ENABLED=ghostshell

Or add to ansible.cfg::

    [defaults]
    callback_plugins = /usr/share/ghostshell/ansible
    callbacks_enabled = ghostshell

Requirements
------------
* ``ghostshell`` binary on PATH on the controller
* ghostshell-daemon running (or fail-open: saves to ~/.local/share/ghostshell/ansible/)

Fail-open guarantee
-------------------
Any error spawning or writing to the subprocess is caught and logged as a
warning; the playbook run is never aborted.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from typing import Optional

try:
    from ansible.plugins.callback import CallbackBase
    from ansible.utils.display import Display
    ANSIBLE_AVAILABLE = True
except ImportError:
    ANSIBLE_AVAILABLE = False

DOCUMENTATION = r"""
    name: ghostshell
    type: notification
    short_description: Record Ansible playbook runs to ghostshell central store
    description:
        - Sends playbook events to ghostshell for audit and replay.
    requirements:
        - ghostshell binary on PATH
    options: {}
"""

CALLBACK_VERSION = 2.0
CALLBACK_TYPE = "notification"
CALLBACK_NAME = "ghostshell"
CALLBACK_NEEDS_ENABLED = True

# Maximum bytes of stdout/stderr to capture per task (mirrors Go cap).
MAX_OUTPUT = 8 * 1024

_display: Optional[object] = None
if ANSIBLE_AVAILABLE:
    _display = Display()


def _warn(msg: str) -> None:
    if _display is not None:
        _display.warning(f"[ghostshell] {msg}")
    else:
        print(f"[ghostshell WARNING] {msg}", file=sys.stderr)


class CallbackModule(CallbackBase if ANSIBLE_AVAILABLE else object):
    """ghostshell callback: streams playbook events to ghostshell ansible-ingest."""

    CALLBACK_VERSION = CALLBACK_VERSION
    CALLBACK_TYPE = CALLBACK_TYPE
    CALLBACK_NAME = CALLBACK_NAME
    CALLBACK_NEEDS_ENABLED = CALLBACK_NEEDS_ENABLED

    def __init__(self, *args, **kwargs):
        if ANSIBLE_AVAILABLE:
            super().__init__(*args, **kwargs)
        self._proc: Optional[subprocess.Popen] = None
        self._run_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def v2_playbook_on_start(self, playbook) -> None:  # type: ignore[override]
        now = time.time()
        pid = os.getpid()
        self._run_id = f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime(now))}-{pid}"

        try:
            self._proc = subprocess.Popen(
                ["ghostshell", "ansible-ingest"],
                stdin=subprocess.PIPE,
                close_fds=True,
            )
        except Exception as exc:
            _warn(f"cannot spawn ghostshell ansible-ingest: {exc} — tracking disabled")
            self._proc = None
            return

        self._emit({
            "type": "run",
            "id": self._run_id,
            "playbook": os.path.basename(getattr(playbook, "_file_name", "") or ""),
            "user": os.environ.get("USER", os.environ.get("LOGNAME", "")),
            "started": now,
            "controller": socket.gethostname(),
        })

    def v2_playbook_on_play_start(self, play) -> None:  # type: ignore[override]
        self._emit({
            "type": "play",
            "name": play.get_name(),
        })

    def v2_playbook_on_stats(self, stats) -> None:  # type: ignore[override]
        for host in sorted(stats.processed):
            s = stats.summarize(host)
            self._emit({
                "type": "stats",
                "host": host,
                "ok": s.get("ok", 0),
                "changed": s.get("changed", 0),
                "failed": s.get("failures", 0),
                "unreachable": s.get("unreachable", 0),
                "skipped": s.get("skipped", 0),
            })
        self._close()

    # ------------------------------------------------------------------
    # Task results
    # ------------------------------------------------------------------

    def v2_runner_on_ok(self, result, **kwargs) -> None:  # type: ignore[override]
        changed = result._result.get("changed", False)
        self._task_event(result, "changed" if changed else "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False, **kwargs) -> None:  # type: ignore[override]
        self._task_event(result, "failed")

    def v2_runner_on_unreachable(self, result, **kwargs) -> None:  # type: ignore[override]
        self._task_event(result, "unreachable")

    def v2_runner_on_skipped(self, result, **kwargs) -> None:  # type: ignore[override]
        self._task_event(result, "skipped")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _task_event(self, result, status: str) -> None:
        task = result._task
        no_log = getattr(task, "no_log", False)

        stdout = ""
        stderr = ""
        rc = 0

        if not no_log:
            res = result._result
            stdout = _cap(str(res.get("stdout", res.get("msg", ""))))
            stderr = _cap(str(res.get("stderr", "")))
            rc = int(res.get("rc", 0))
        else:
            stdout = "<censored: no_log>"
            stderr = "<censored: no_log>"

        ev: dict = {
            "type": "task",
            "play": task.get_path().split(":")[0] if hasattr(task, "get_path") else "",
            "name": task.get_name(),
            "module": task.action,
            "host": result._host.get_name(),
            "status": status,
            "t": time.time(),
        }
        if rc != 0:
            ev["rc"] = rc
        if stdout:
            ev["stdout"] = stdout
        if stderr:
            ev["stderr"] = stderr

        self._emit(ev)

    def _emit(self, obj: dict) -> None:
        if self._proc is None or self._proc.stdin is None:
            return
        try:
            line = json.dumps(obj, ensure_ascii=False) + "\n"
            self._proc.stdin.write(line.encode())
            self._proc.stdin.flush()
        except Exception as exc:
            _warn(f"emit failed: {exc}")
            self._proc = None  # disable further writes

    def _close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=10)
        except Exception as exc:
            _warn(f"close ingest process: {exc}")
        finally:
            self._proc = None


def _cap(s: str) -> str:
    """Truncate to MAX_OUTPUT bytes (UTF-8 safe)."""
    encoded = s.encode("utf-8")
    if len(encoded) <= MAX_OUTPUT:
        return s
    truncated = encoded[:MAX_OUTPUT].decode("utf-8", errors="ignore")
    return truncated + "\n[... truncated]"
