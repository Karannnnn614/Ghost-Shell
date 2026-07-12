<div align="center">

# 👻 Ghost Shell

### Every shell session on your Linux box — recorded, encrypted, replayable.

A terminal session recorder and root audit daemon. It captures every shell session (including SSH),
encrypts it at rest with **AES-256-GCM**, and lets operators **replay, search, and live-tail** from a
**root-only** central store.

**One static Go binary. No agent, no database, no runtime dependencies.**

[![CI](https://img.shields.io/github/actions/workflow/status/Karannnnn614/Ghost-Shell/ci.yml?style=for-the-badge&label=CI)](https://github.com/Karannnnn614/Ghost-Shell/actions)
[![Release](https://img.shields.io/github/v/release/Karannnnn614/Ghost-Shell?style=for-the-badge)](https://github.com/Karannnnn614/Ghost-Shell/releases)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=for-the-badge&logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux-333333?style=for-the-badge&logo=linux&logoColor=white)](#requirements)
[![License](https://img.shields.io/github/license/Karannnnn614/Ghost-Shell?style=for-the-badge)](LICENSE)

</div>

---

## Why Ghost Shell?

`~/.bash_history` lies — it's user-writable, drops pipes, and never records output.
`script(1)` writes plaintext anyone can read. `asciinema` is built for demos, not audit.

Ghost Shell exists for the case where you actually need to answer **"what happened on that box?"**

|  |  |
|---|---|
| 🔒 **Encrypted at rest** | AES-256-GCM. `cat`, `strings`, `grep` on a recording reveal only ciphertext. |
| 👑 **Root-only store** | Every user's sessions land in `/var/lib/ghostshell` (`root:root 0700`). Users can't read *anyone's* recordings — not even their own. |
| 📡 **Live tail** | Watch a session as it happens: `ghostshell tail -f <id>`. |
| 🎬 **Real replay** | Full-screen player — seek, variable speed, jump-to-command, original timing preserved. |
| 🔎 **Search everything** | Grep across every recording on the host, with natural-language date filters (`--from "2 days ago"`). |
| 🪶 **Single static binary** | ~3.5 MB, `CGO_ENABLED=0`, zero runtime deps. Ships as `.deb` / `.rpm` with a systemd unit. |
| 🛟 **Fail-open by design** | If the daemon is down, busy, or out of disk, recording falls back to a local file and is ingested later. It never blocks a login — and never silently loses a session. |

**Built to be deployed unattended:** [security-audited](AUDIT.md), race-tested, `staticcheck` + `golangci-lint` clean, and systemd-hardened (`systemd-analyze security` rates the daemon **3.9 OK**). The full pre-production review — including a real Ubuntu install, cross-user isolation, disk-full and symlink-attack tests — is in [DEPLOYMENT.md](DEPLOYMENT.md).

> ⚠️ **Honest limitation:** Ghost Shell is an audit/visibility tool, **not** a tamper-proof enforcement boundary. A determined user with shell access can start a shell that was never wrapped. See the [Security model](#security-model) for the real threat model.

## Table of contents

- [Why Ghost Shell?](#why-ghost-shell)
- [Features](#features)
- [Demo](#demo)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Audit mode (central root-only store)](#audit-mode-central-root-only-store)
- [Security model](#security-model)
- [Auto-record on login](#auto-record-on-login-optional)
- [Record non-interactive SSH](#record-non-interactive-ssh-optional)
- [Shell completion](#shell-completion)
- [Configuration](#configuration)
- [File format](#file-format)
- [Troubleshooting](#troubleshooting)
- [Building and packaging](#building-and-packaging)
- [Project structure](#project-structure)
- [Ansible tracking](#ansible-tracking)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Record & replay** any interactive shell session (`script(1)` / `asciinema`-style).
- **Full-screen player** for replay: a thin-line seek/progress bar, pause, variable speed, jump-to-command, mouse click-to-seek, and a bar toggle for full-height playback.
- **asciinema v2 cast** output (local recordings are inspectable JSON-lines and play with `asciinema play`; central recordings are encrypted — `export` them first).
- **Central audit store** via the `ghostshell-daemon` root daemon: all users' sessions in `/var/lib/ghostshell`, `root:root 0700` — normal users cannot read recordings.
- **Encrypted at rest** — central recordings are AES-256-GCM encrypted; `cat`/`strings`/`grep` on a `.cast` reveal only ciphertext.
- **Live tail** an in-progress session (`ghostshell tail -f <id>`, root); or show last N lines of any session (`ghostshell tail [-n N] <id>`).
- **Unified commands**: `ghostshell play` auto-detects local file or central session ID; `ghostshell ls --all` / `--user <name>` covers both local and central listings.
- **Flexible search dates**: `--from`/`--to` accept any format `date -d` understands — `"yesterday"`, `"2 days ago"`, `"last week"`, or `"YYYY-MM-DD HH:MM"`.
- **Config file** at `/etc/ghostshell/ghostshell.conf` with all defaults visible; `ghostshell --check` validates and prints resolved values.
- **Ansible tracking** — records playbook runs (plays, tasks, per-host status, output) on the controller via a callback plugin.
- **Auto-record on login** via an optional `profile.d` hook (skips nested `sudo su -`).
- **Fail-open**: if the daemon is down, busy (per-user session cap), out of disk, or wedged, recording falls back to a user-local file and is ingested into the central store when the daemon restarts — a recording is never silently lost.
- **Bash tab-completion** for subcommands, flags, sessions, and users.
- Ships as `rpm` and `deb` packages with a systemd unit.

## Demo

**As a normal user** — just work. The session records itself.

```console
$ ghostshell rec
ghostshell: recording to ghostshell-daemon (central) — type 'exit' or Ctrl-D to stop
$ sudo systemctl restart nginx
$ exit

$ ghostshell play 20260711T142031-4471        # full-screen replay, original timing
```

**As root** — audit the whole host.

```console
# Who has been on this box?
$ sudo ghostshell ls --all
USER                  SESSIONS   LAST ACTIVE
alice                 12         2026-07-11 14:20
deploy                3          2026-07-11 09:02

# Did anyone touch nginx in the last two days?
$ sudo ghostshell search --from "2 days ago" nginx
user=alice  when=2026-07-11 14:20:31  session=20260711T142031-4471
    cmd: -bash
    > sudo systemctl restart nginx
    > Job for nginx.service failed because the control process exited with error code.

# Watch a session live, while it's still happening.
$ sudo ghostshell tail -f 20260711T142031-4471

# And on disk? Opaque.
$ sudo strings /var/lib/ghostshell/alice/20260711T142031-4471.cast | head -1
TTEC2                     # ← AES-256-GCM ciphertext, not alice's commands
```

> Full CLI reference: `ghostshell --help`, or `ghostshell help <command>` for per-command detail (including every player control).

## Requirements

- Linux (uses `/proc` and `SO_PEERCRED`).
- To build from source: Go 1.25.

## Installation

### From a released package

Each `vX.Y.Z` tag publishes an `rpm`, a `deb`, and static binaries on the [releases page](https://github.com/Karannnnn614/Ghost-Shell/releases). Download the current version directly:

**Debian / Ubuntu (.deb):**

```bash
VER=$(curl -fsSL https://api.github.com/repos/Karannnnn614/Ghost-Shell/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')
curl -fLO "https://github.com/Karannnnn614/Ghost-Shell/releases/download/v${VER}/ghostshell_${VER}_amd64.deb"
sudo apt install "./ghostshell_${VER}_amd64.deb"
```

**RHEL / Rocky / AlmaLinux / Fedora (.rpm):**

```bash
VER=$(curl -fsSL https://api.github.com/repos/Karannnnn614/Ghost-Shell/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')
curl -fLO "https://github.com/Karannnnn614/Ghost-Shell/releases/download/v${VER}/ghostshell-${VER}-1.x86_64.rpm"
sudo dnf install "./ghostshell-${VER}-1.x86_64.rpm"
```

**Static binary (any distro):**

```bash
VER=$(curl -fsSL https://api.github.com/repos/Karannnnn614/Ghost-Shell/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+')
curl -fL -o ghostshell "https://github.com/Karannnnn614/Ghost-Shell/releases/download/v${VER}/ghostshell-${VER}-linux-amd64"
chmod +x ghostshell && sudo install -m755 ghostshell /usr/bin/ghostshell
```

> **Note:** releases are published when a `vX.Y.Z` tag is pushed (see `.github/workflows/release.yml`). The commands above always fetch the latest.

Packages install `ghostshell` to `/usr/bin`, the `ghostshell-daemon` daemon to `/usr/libexec`, a systemd unit, the bash completion, and the auto-record login hook. The post-install step creates `/var/lib/ghostshell` (root-only), creates `/var/log/ghostshell` for daemon logs, writes `/etc/ghostshell/ghostshell.conf` with all defaults visible, and enables `ghostshell-daemon`.

### From source

```bash
git clone https://github.com/Karannnnn614/Ghost-Shell.git
cd Ghost Shell
make build          # builds bin/ghostshell and bin/ghostshell-daemon
sudo make install   # installs binaries, man page, systemd unit, completion
```

## Quick start

Record a session, list it, and replay it:

```text
$ ghostshell rec /bin/bash -c 'echo "hello from ghostshell"; uname -sr'
ghostshell: recording to /home/alice/.local/share/ghostshell/20260526T145029-1413696.cast — type 'exit' or Ctrl-D to stop
hello from ghostshell
Linux 5.14.0-611.55.1.el9_7.x86_64

ghostshell: session saved to /home/alice/.local/share/ghostshell/20260526T145029-1413696.cast

$ ghostshell ls
STATUS   FILE                          STARTED              DURATION   COMMAND
SAVED    20260526T145029-1413696.cast  2026-05-26 14:50:29  2s         /bin/bash -c echo "hello from ghostshell"; uname -sr

$ ghostshell play --speed 100 20260526T145029-1413696.cast
--- ghostshell replay start ---
hello from ghostshell
Linux 5.14.0-611.55.1.el9_7.x86_64
--- ghostshell replay end ---
```

With no command, `ghostshell rec` records your `$SHELL` interactively until you `exit`.

## Commands

### Personal commands

| Command | Description |
|:--------|:------------|
| `ghostshell rec [-q] [-o file] [cmd...]` | Record a session. Runs `$SHELL` (fallback `/bin/bash`) with no command. |
| `ghostshell play [--speed N] [--idle N] <file\|id>` | Replay a recording. Auto-detects: existing local file → local play; otherwise → central store session ID (requires root). |
| `ghostshell ls` | List local recordings (`STATUS`, `FILE`, `STARTED`, `DURATION`, `COMMAND`). |
| `ghostshell ls --all` | List all users in the central store with session counts (root). |
| `ghostshell ls --user <name>` | List one user's sessions in the central store (root). |
| `ghostshell init` | First-time setup wizard; `--reset-password` / `--clear-password` manage the playback password (both require the current password). |
| `ghostshell --check` | Validate `/etc/ghostshell/ghostshell.conf` and print all resolved values. |
| `ghostshell completion bash` | Print the bash completion script. |
| `ghostshell version` | Print the version. |
| `ghostshell help [command]` | Overall usage, or one command's detailed help. |

`rec` flags: `-o <file>` writes a local file at that path; `-q` (or `GHOSTSHELL_QUIET=1`) suppresses the recording banner and saved-path message.

`play` flags: `--speed N` playback multiplier (default `1.0`); `--idle N` caps idle gaps to N seconds — default `0` = exact original timing.

**Player UI.** On a terminal, `play` opens a full-screen player (alternate screen):

```
 > 01:23 / 05:00 [####      ]  27%  1x   <-/-> seek  pgup scroll  g goto  spc play  q quit
```

Controls:

| Key / action | Effect |
|:----|:-------|
| `space` | Pause / resume |
| `→` / `←` | Seek forward / backward 5 s |
| `↑` / `↓` | Double / halve playback speed (range: 1/64× – 64×) |
| `g` | Go to time — type `MM:SS` or seconds, Enter to jump |
| `pgup` | Enter scroll view — browse past output a page at a time |
| click the bar | Seek to that point (Shift+click selects text instead) |
| `b` | Hide/show the status bar |
| `0` | Restart from the beginning |
| `q` / `Ctrl-C` | Quit |

### Audit commands (root)

These read the central root-only store and require root:

| Command | Description |
|:--------|:------------|
| `ghostshell ls --all` | List all users and their session counts. |
| `ghostshell ls --user <name>` | List a user's sessions (STATUS, TYPE, SESSION, STARTED, DURATION, COMMAND). |
| `ghostshell play <sessionid>` | Replay a session by id, searched across all users (auto-detect). |
| `ghostshell tail [-n N] <id>` | Show last N lines of a session's recorded output (default 20). |
| `ghostshell tail -f <id>` | Live-stream an in-progress session from the daemon. |
| `ghostshell tree` | Print a users → sessions tree. |
| `ghostshell search [--from T] [--to T] [--user U] [-i] <pattern>` | Find a string across recordings. `--from`/`--to` accept any `date -d` format. |
| `ghostshell export [-o file] <id>` | Decrypt a recording to a plaintext asciinema cast. |
| `ghostshell prune [--yes]` | Interactively delete recordings by user and time. |
| `ghostshell backup` | Run the configured backup of the central store immediately (respects `backup_type`/`backup_target`). |

## Audit mode (central root-only store)

When `ghostshell-daemon` runs (it does after package install), `ghostshell rec` streams the cast
to it over `/run/ghostshell-daemon.sock` and the recording is written by root to
`/var/lib/ghostshell/<user>/<sessionid>.cast` (`root:root 0600`, dirs `0700`). Normal
users cannot read other users' — or their own — recordings.

```text
$ sudo ghostshell ls --all
USER                  SESSIONS   LAST ACTIVE
root                  1          2026-05-28 17:09
alice                 7          2026-05-27 14:03

$ sudo ghostshell ls --user alice
STATUS   TYPE             SESSION                       STARTED              DURATION   COMMAND
SAVED    non-interactive  20260526T145020-1413240.cast  2026-05-26 14:50:19  3s         /bin/bash -c echo deploy-step-1; whoami

$ sudo ghostshell tree
/var/lib/ghostshell
├─ root
│  └─ 20260526T124229-1909275.cast  [SAVED interactive]  2026-05-26 12:42:29  17m28s  /bin/bash
└─ alice
   └─ 20260526T145020-1413240.cast  [SAVED non-interactive]  2026-05-26 14:50:19  3s  /bin/bash -c echo deploy-step-1; whoami
```

The `TYPE` column distinguishes an **interactive** login shell from a **non-interactive** command session. `DURATION` is the recorded length; an in-progress session shows elapsed-so-far with a trailing `+`.

Search recordings for a string, with flexible date filtering:

```text
$ sudo ghostshell search nginx
user=alice  when=2026-05-26 14:59:18  session=20260526T145918-1420180
    cmd: /bin/bash -c echo starting deploy; systemctl restart nginx; echo deploy done
    > Failed to restart nginx.service: Unit nginx.service not found.

$ sudo ghostshell search --from "2 days ago" --to yesterday --user alice -i DEPLOY
user=alice  when=2026-05-26 14:59:18  session=20260526T145918-1420180
    cmd: /bin/bash -c echo starting deploy; ...
```

`--from`/`--to` accept any format the system `date -d` command understands: `"yesterday"`, `"2 days ago"`, `"last week"`, `"2026-05-28"`, `"2026-05-28 17:00"`.

Show the tail of a completed session, or watch a live one:

```bash
sudo ghostshell tail alice/20260526T145020-1413240.cast      # last 20 lines
sudo ghostshell tail -n 50 20260526T145020-1413240.cast     # last 50 lines
sudo ghostshell tail -f 20260526T145020-1413240.cast        # live stream
```

Delete old recordings interactively:

```text
$ sudo ghostshell prune
Users with recordings: alice, root
Prune which user? [all / <username>] alice
What to delete:
  all              every session for the selected user(s)
  days N           sessions older than N days
  range FROM TO    sessions started in [FROM, TO]
Selection? days 90

Will delete 4 session(s), 2.1 MiB total:
  alice/20260101T...cast
  ...
Delete these 4 session(s)? [yes/NO] yes
pruned 4 session(s), freed 2.1 MiB
```

### Encryption at rest

Central recordings are encrypted with AES-256-GCM. On disk a `.cast` is opaque —
`cat`, `strings`, and `grep` show only ciphertext. `ghostshell` decrypts transparently
for `play`, `search`, `tail`, and `export` using the key at
`/var/lib/ghostshell/.ghostshell.key` (`root:root 0600`), created by the daemon on first run.

```text
$ sudo strings /var/lib/ghostshell/alice/20260526T151022-1426734.cast | head -1
TTEC1                          # magic prefix; the rest is ciphertext

$ sudo ghostshell export -o session.cast 20260526T151022-1426734
exported plaintext cast to session.cast      # now asciinema-compatible
```

The key is **unique per server** and set **immutable** (`chattr +i`): it cannot be deleted, renamed, or modified by `rm`/`vi`/`sed`/`>`/`tee` — even by root — until someone runs `chattr -i`. This depends on the filesystem: ext4/xfs support the immutable attribute, but overlayfs, tmpfs and many network mounts silently ignore it. The daemon verifies the flag actually stuck and logs a loud warning if it did not (see [Security model](#security-model)).

> **Back up `/var/lib/ghostshell/.ghostshell.key`** — if it is lost, every encrypted recording is permanently unreadable. The daemon refuses to start if the key is missing while encrypted recordings exist.

**Fail-open:** if the daemon is unreachable — or *rejects* the session (per-user session cap reached, central store full) or is wedged — `ghostshell rec` records to the user-local directory; on its next startup `ghostshell-daemon` ingests those files into the central store. The daemon replies `OK` only once a session is actually registered, so the recorder can tell a real central session from a rejection and never streams a recording into a doomed connection.

See [Security model](#security-model) for the full trust boundary, the integrity caveat, and the threat model.

## Security model

Read this before relying on ghostshell for audit. It explains what ghostshell does and—just as important—what it does **not** protect against.

### Trust boundary (who can read recordings)

- The central store lives at `/var/lib/ghostshell`, `root:root 0700`; recordings are `root:root 0600`. **Only root can read other users' (or even their own) central recordings.**
- The recorder reaches the daemon over the Unix socket `/run/ghostshell-daemon.sock`. The socket mode is `0666` (any user can connect to *submit* their own session), but the daemon authenticates the peer with **`SO_PEERCRED`** and attributes every session to the kernel-reported UID of the connecting process — a user cannot forge another user's identity or read back data over the socket. Privacy is enforced by **filesystem permissions on the store, not by the socket mode.**
- The audit/read commands (`play`, `tail`, `tree`, `search`, `export`, `ls --all`/`--user`, `ansible`) all require root because they read the root-only store directly.

### Encryption at rest and key immutability

- Central recordings are **AES-256-GCM** encrypted; on disk a `.cast` is opaque to `cat`/`strings`/`grep`.
- The key (`/var/lib/ghostshell/.ghostshell.key`, `root:root 0600`) is **unique per server** and made **immutable** with `chattr +i` so it cannot be removed, renamed, or rewritten by `rm`/`vi`/`sed`/`>`/`tee` — even by root — until someone explicitly runs `chattr -i`.
- **Immutability depends on the filesystem.** ext4/xfs support the immutable attribute; **overlayfs, tmpfs and many network mounts silently ignore it**, leaving the key deletable. The daemon reads the flag back after setting it and, if it did not stick, logs `WARNING: ... the at-rest key is NOT protected from deletion/modification`. If you see that line, the store is on a filesystem that cannot protect the key — move it to ext4/xfs or accept the reduced guarantee.
- **Back up the key.** If it is lost, every encrypted recording is permanently unreadable; the daemon refuses to start if the key is missing while encrypted recordings exist.

### Optional playback password

- An optional playback password (hashed in `/etc/ghostshell/.playback_passwd`, `root:root 0600`) gates every content/metadata-revealing command (`play`, `tail`, `tree`, `search`, `export`, and the central `ls` views). A separate prune password gates deletion. This is a second factor *on top of* root, not a replacement for filesystem permissions.

### Integrity caveat (important)

**ghostshell is not tamper-proof against a user who simply avoids it.** It provides root-only access to recordings plus live tail, but a malicious user with shell access can run a shell that was never wrapped by `ghostshell` (the auto-record hook and the sshd `ForceCommand` wrapper are both deliberately fail-open and can be sidestepped). Non-circumventable capture requires **PAM- or kernel-stage hooks**, which this project does not implement. Treat ghostshell as an audit/visibility tool for cooperative environments, not as an enforcement boundary against a determined adversary on the box.

### Path-traversal and permission posture

- Session ids are validated and resolved within the central store; the ingest sweep admits only regular `.cast` files and rejects symlinks/irregular entries, so a crafted home-directory entry cannot redirect the root ingest at an arbitrary target.
- The daemon writes recordings `0600` and store directories `0700`, and runs under a hardened systemd unit (`NoNewPrivileges`, `ProtectSystem=full`, `SystemCallFilter=@system-service`, `ProtectKernelModules`/`ProtectKernelLogs`, `LockPersonality`, `RestrictNamespaces`/`RestrictRealtime`, `ProtectClock`/`ProtectHostname`, `RestrictAddressFamilies=AF_UNIX`, `UMask=0077` — `systemd-analyze security` rates it **3.9 OK**). It intentionally does **not** enable `ProtectHome`, because it must read and delete each user's `~/.local/share/ghostshell` spool during ingest.

### Fail-open semantics

Every capture path is **fail-open by design** so ghostshell can never lock a user out or break a login/SSH session:

- If the daemon is down, **rejects** the session (per-user `session_cap` reached, central store full, id collision), or is **wedged** (accepted the connection but stopped responding), `ghostshell rec` writes a user-local file (`~/.local/share/ghostshell`, `0600`) and the daemon ingests it on next startup. The daemon sends an `OK` acknowledgement only once a session is registered, and the recorder waits for it with a bounded timeout — so a rejection or a hung daemon can never silently swallow a recording, nor block a login.
- If the central store fills up mid-session, the daemon logs a `DISK FULL` error naming the path, terminates that session cleanly, and keeps serving other users.
- The `profile.d` login hook and the sshd `ForceCommand` wrapper fall through to a normal shell on any error, and pass `scp`/`sftp`/`rsync`/git transfers through untouched.

The flip side of fail-open is the integrity caveat above: availability is prioritized over guaranteed capture.

## Auto-record on login (optional)

The package installs a `profile.d` hook that records every interactive login and logs
out when the recorded shell exits. To enable manually:

```bash
sudo install -m644 scripts/profile.d/ghostshell-autorec.sh /etc/profile.d/ghostshell-autorec.sh
```

The hook only triggers for interactive shells with a real TTY and skips when `ghostshell` is absent. It skips nested shells (`sudo su -`, `su -`, subshells) two ways: an exported `GHOSTSHELL_REC=1` marker that the hook sets before recording (inherited by child shells, robust against process-name spoofing) and, as a fallback, detecting a `ghostshell` process in the ancestry. It is fail-open: if the recorder cannot start, a normal shell continues. Remove the file to disable.

## Record non-interactive SSH (optional, opt-in)

The login hook records interactive sessions only. To also record **non-interactive** SSH commands (`ssh host "cmd"`), enable the sshd `ForceCommand` wrapper. **This is opt-in and is NOT installed by default** — installing the package ships the wrapper binary but leaves it inactive so an unattended server is never silently reconfigured to wrap every SSH login. Turn it on explicitly, as root:

```bash
sudo ghostshell init --enable-ssh-forcecommand
```

This writes `/etc/ssh/sshd_config.d/zz-ghostshell.conf` (a `ForceCommand /usr/libexec/ghostshell-ssh-wrap` drop-in), ensures the main `sshd_config` has an `Include /etc/ssh/sshd_config.d/*.conf` line, validates with `sshd -t`, and reloads sshd. If validation fails it reverts only the edits it made (never touching a pre-existing `Include`), so sshd is always left parseable. It is idempotent — re-running when already enabled changes nothing.

Turn it off again with:

```bash
sudo ghostshell init --disable-ssh-forcecommand
```

which removes the drop-in and reloads sshd, leaving the `Include` directive and any other drop-ins untouched.

- `scp` / `sftp` / `rsync` / git transfers pass through untouched.
- Interactive logins keep recording via the profile.d hook (no double-wrap).
- Fail-open: if anything is off, the command runs normally — SSH is never blocked.

To exclude an account, edit the generated `/etc/ssh/sshd_config.d/zz-ghostshell.conf` to use a `Match` block instead of the global `ForceCommand`, then `sudo sshd -t && sudo systemctl reload ssh`:

```text
Match User *,!adminuser
    ForceCommand /usr/libexec/ghostshell-ssh-wrap
```

## Shell completion

Bash completion is installed by the package to `/usr/share/bash-completion/completions/ghostshell`. To enable manually:

```bash
ghostshell completion bash | sudo tee /usr/share/bash-completion/completions/ghostshell
```

It completes subcommands, flags, local sessions (for `play`), and — when run as root — users and central session ids.

## Configuration

ghostshell reads `/etc/ghostshell/ghostshell.conf` on startup (override path with `GHOSTSHELL_CONFIG`). The file ships with all defaults active (uncommented) so it is immediately editable. Validate with:

```bash
ghostshell --check
```

Output:

```
ghostshell: reading config from /etc/ghostshell/ghostshell.conf
socket_path            = /run/ghostshell-daemon.sock
central_dir            = /var/lib/ghostshell
key_file               = .ghostshell.key  (resolved: /var/lib/ghostshell/.ghostshell.key)
dial_timeout_sec       = 1s
eof_grace_ms           = 500ms
ansible_output_cap     = 8192
scroll_buffer          = 32768
log_level              = 3  (0=off 1=error 2=warn 3=info 4=debug 5=trace)
log_file               = /var/log/ghostshell/ghostshell.log
ghostshell: config OK
```

### Config keys

| Key | Default | Env override | Purpose |
|:----|:--------|:------------|:--------|
| `socket_path` | `/run/ghostshell-daemon.sock` | `GHOSTSHELL_DAEMON_SOCK` | Daemon Unix socket |
| `central_dir` | `/var/lib/ghostshell` | `GHOSTSHELL_CENTRAL_DIR` | Root of central session store |
| `key_file` | `.ghostshell.key` | `GHOSTSHELL_KEY_FILE` | Encryption key path (relative to `central_dir` or absolute) |
| `dial_timeout_sec` | `1` | `GHOSTSHELL_DIAL_TIMEOUT_SEC` | Seconds to wait when connecting to daemon |
| `eof_grace_ms` | `500` | `GHOSTSHELL_EOF_GRACE_MS` | Ms before force-closing PTY on stdin EOF |
| `ansible_output_cap` | `8192` | `GHOSTSHELL_ANSIBLE_OUTPUT_CAP` | Max bytes stored per Ansible task output |
| `scroll_buffer` | `32768` | `GHOSTSHELL_SCROLL_BUFFER` | PTY read buffer size in bytes (min 4096) |
| `log_level` | `3` | `GHOSTSHELL_LOG_LEVEL` | Daemon log verbosity (`0` off through `5` trace) |
| `log_file` | `/var/log/ghostshell/ghostshell.log` | `GHOSTSHELL_LOG_FILE` | Daemon logfile path; empty disables file logging |

Restart `ghostshell-daemon` after editing: `sudo systemctl restart ghostshell-daemon`.

### Environment variables

| Variable | Default | Used by | Description |
|:---------|:--------|:--------|:------------|
| `GHOSTSHELL_DIR` | `~/.local/share/ghostshell` | `ghostshell` | User-local recordings dir (fail-open fallback + local `ls`/`play`). |
| `GHOSTSHELL_QUIET` | unset | `ghostshell rec` | Any non-empty value suppresses the banner + saved-path message. |
| `SHELL` | `/bin/bash` | `ghostshell rec` | Shell launched when no command is given. |

### Filesystem layout

| Path | Owner / mode | Purpose |
|:-----|:-------------|:--------|
| `/usr/bin/ghostshell` | `root 0755` | CLI |
| `/usr/libexec/ghostshell-daemon` | `root 0755` | daemon |
| `/etc/ghostshell/ghostshell.conf` | `root 0644` | runtime config (conffile — preserved on upgrade) |
| `/var/lib/ghostshell/` | `root:root 0700` | central store |
| `/var/lib/ghostshell/<user>/<id>.cast` | `root:root 0600` | encrypted recording |
| `/var/lib/ghostshell/.ghostshell.key` | `root:root 0600`, `chattr +i` | per-server AES key (immutable) |
| `/var/log/ghostshell/` | `root:root 0750` | daemon log directory |
| `/var/log/ghostshell/ghostshell.log` | `root:root 0640` | daemon logfile |
| `/run/ghostshell-daemon.sock` | `root 0666` | recorder connect socket |
| `/etc/profile.d/ghostshell-autorec.sh` | `root 0644` | optional auto-record login hook |
| `~/.local/share/ghostshell/` | the user | local fail-open recordings |

### Daemon service

```bash
sudo systemctl status ghostshell-daemon
sudo systemctl restart ghostshell-daemon
sudo tail -f /var/log/ghostshell/ghostshell.log
sudo journalctl -u ghostshell-daemon --no-pager
```

To override settings at the systemd level (takes precedence over config file):

```bash
sudo systemctl edit ghostshell-daemon
# [Service]
# Environment=GHOSTSHELL_CENTRAL_DIR=/srv/ghostshell
```

## File format

Recordings are asciinema v2 cast files (UTF-8, JSON-lines):

```text
{"version":2,"width":80,"height":24,"timestamp":1779776263,"command":"/bin/bash","env":{"SHELL":"/bin/bash","TERM":"xterm-256color"}}
[0.131000, "o", "hello\r\n"]
```

The first line is a header; each subsequent line is `[time_seconds, "o", data]`.
Local (plaintext) recordings are viewable with `asciinema cat` and playable with
`asciinema play`. Central recordings are encrypted — run `ghostshell export` first.

## Troubleshooting

**`ghostshell --check` shows config file not found.** The daemon still uses built-in defaults. Install the package to get `/etc/ghostshell/ghostshell.conf`, or create it manually by copying `/usr/share/ghostshell/ghostshell.conf.example`.

**`ghostshell` hangs or does not record.** Check the daemon:

```bash
sudo systemctl status ghostshell-daemon
sudo tail -n 100 /var/log/ghostshell/ghostshell.log
sudo journalctl -u ghostshell-daemon --since '5 min ago' --no-pager
```

If the daemon is stopped, `ghostshell rec` still works (fail-open: saves to `~/.local/share/ghostshell`). Start `ghostshell-daemon` and those files are ingested on next start.

**`ghostshell play` says "no such session".** The argument is treated as a central store session ID when no local file matches. Run `sudo ghostshell ls --all` to list available IDs, or pass the full local file path.

**Replaying a full-screen app (vim, less, htop) looks fine.** `ghostshell play` reproduces TUI redraws exactly. Multibyte/box-drawing characters survive even when a PTY read splits a rune across chunks.

**Scroll view shows garbled lines.** The scrollback viewer (`pgup` during replay) parses terminal output heuristically. Cursor-movement sequences are treated as line breaks. Full-screen TUIs may look approximate in scroll view, but the main player renders them exactly.

**`man ghostshell` shows an old version.** A manual install may have left a stale man page at `/usr/local/man/man1/ghostshell.1`. Remove it:

```bash
sudo rm -f /usr/local/man/man1/ghostshell.1
man ghostshell
```

## Building and packaging

```bash
make build          # bin/ghostshell and bin/ghostshell-daemon (static, CGO disabled)
make test           # run unit tests
make rpm            # build an rpm into release/
make deb            # build a deb into release/
make packages       # both
make VERSION=1.2.3 packages
```

Packaging uses [`nfpm`](https://github.com/goreleaser/nfpm) (`go install` it first).

**Releases are automated.** Every push to `main` runs the `Auto Release` workflow, which bumps the patch version from the latest tag and publishes a GitHub Release with `rpm`, `deb`, the static binary, and `SHA256SUMS`.

```bash
make test           # unit tests (go test ./...)
```

## Project structure

```
cmd/
  ghostshell/           CLI (rec/play/ls/tail/tree/search/export/ansible/--check)
  ghostshell-daemon/          root collector daemon
docs/
  superpowers/
  wiki/
internal/
  ansible/          Ansible tracking (model, ingest, commands)
  audit/            root-only audit commands
  auth/
  backup/
  cast/             asciinema v2 cast read/write
  complete/         shell completion
  config/           runtime config file parser + singleton
  crypto/           at-rest AES-256-GCM encryption (+ tests)
  daemon/           ghostshell-daemon socket server, live tail fan-out, ingest, key mgmt
  initcmd/
  logger/
  play/             replay (snapshot-bounded)
  record/           PTY capture for `ghostshell rec`
  store/            storage paths + transparent decrypt
man/
  ghostshell.1          man page
packaging/
  postinstall.sh
  postremove.sh
  preremove.sh
scripts/
  ansible/
  profile.d/
  systemd/
CONTRIBUTING.md
LICENSE
Makefile
go.mod
nfpm.yaml
```

## Ansible tracking

ghostshell records Ansible playbook runs on the **controller** host (the machine running `ansible-playbook`). Each task — its name, module, host, status (`ok`/`changed`/`failed`/`unreachable`/`skipped`), output, and rc — is captured and stored encrypted in the central store.

### Enable the callback plugin

**Via environment variables (per-run):**
```bash
export ANSIBLE_CALLBACK_PLUGINS=/usr/share/ghostshell/ansible
export ANSIBLE_CALLBACKS_ENABLED=ghostshell
ansible-playbook site.yml
```

**Via `ansible.cfg` (persistent):**
```ini
[defaults]
callback_plugins  = /usr/share/ghostshell/ansible
callbacks_enabled = ghostshell
```

The plugin is installed at `/usr/share/ghostshell/ansible/ghostshell.py` by the deb/rpm packages.

### Browse runs

```bash
sudo ghostshell ansible list
sudo ghostshell ansible show <runid>
```

Example `ghostshell ansible list`:

```
RUN                           PLAYBOOK             CONTROLLER   OK     CHG    FAIL   STARTED              HOSTS
20260527T140300-12345         deploy.yml           ctrl.host    8      3      1      2026-05-27 14:03:00  web1,web2
```

Example `ghostshell ansible show 20260527T140300-12345`:

```
Playbook : deploy.yml
Run ID   : 20260527T140300-12345

PLAY [Install web server]
  ✓ web1          install nginx            (ansible.builtin.dnf) @14:03:01
  ✗ web2          fail intentionally       (ansible.builtin.command) @14:03:03
      stderr: command not found
      rc: 1

PLAY RECAP
  web1                 ok=8    changed=3    failed=1    unreachable=0    skipped=0
```

### Fail-open

If `ghostshell-daemon` is unreachable, the run is saved to `~/.local/share/ghostshell/ansible/<runid>.ajsonl`. The playbook run is **never aborted** due to ghostshell failures.

### Limitation

Only controllers with `ghostshell` installed produce Ansible records. Managed hosts still receive raw Ansible SSH execs (captured by the sshd `ForceCommand` wrapper if configured, but those carry no task name or status).

## Documentation

| Resource | Description |
|:---------|:------------|
| [README](README.md) | This file — installation, quick start, full command reference |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Bug reports, PR workflow, project layout, and test instructions |
| [man ghostshell](man/ghostshell.1) | Manual page — installed to `/usr/share/man/man1/ghostshell.1` by packages |
| [LICENSE](LICENSE) | GNU General Public License v2.0 |
| [Releases](https://github.com/Karannnnn614/Ghost-Shell/releases) | Pre-built `.rpm`, `.deb`, and static binaries |

## Contributing

ghostshell is **100% open source** and community-driven — contributions of all sizes are welcome.

- **Found a bug or want a feature?** [Open an issue](https://github.com/Karannnnn614/Ghost-Shell/issues).
- **Want to contribute code?** Fork, branch, and open a pull request. Run `make fmt`, `make vet`, `make test`, `make build` first — CI enforces all of them.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide (bug reports, PR workflow, project layout, tests).

<a href="https://github.com/Karannnnn614/Ghost-Shell/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Karannnnn614/Ghost-Shell" />
</a>

## Author

Ghost Shell is created and maintained by [Karannnnn614](https://github.com/Karannnnn614).

## License

Copyright © 2026 Karannnnn614.

Licensed under the GNU General Public License v2.0. See [LICENSE](LICENSE).

---

<div align="center">

### 👻 Ghost Shell — know what actually happened on your box.

If this is useful to you, a ⭐ helps other operators find it.

[Report a bug](https://github.com/Karannnnn614/Ghost-Shell/issues) · [Request a feature](https://github.com/Karannnnn614/Ghost-Shell/issues) · [Contribute](CONTRIBUTING.md)

</div>
