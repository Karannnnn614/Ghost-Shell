# Configuration

`ghostshell` and `ghostshell-daemon` need no config file. Behavior is controlled by environment variables, filesystem locations, and the systemd unit.

## Environment variables

| Variable | Default | Used by | Description |
|:---------|:--------|:--------|:------------|
| `GHOSTSHELL_DIR` | `~/.local/share/ghostshell` | `ghostshell` | User-local recordings directory (fail-open fallback + local `ls`/`play`). |
| `GHOSTSHELL_CENTRAL_DIR` | `/var/lib/ghostshell` | `ghostshell`, `ghostshell-daemon` | Central root-only store. |
| `GHOSTSHELL_DAEMON_SOCK` | `/run/ghostshell-daemon.sock` | `ghostshell`, `ghostshell-daemon` | Daemon unix socket path. |
| `GHOSTSHELL_QUIET` | unset | `ghostshell rec` | Any non-empty value suppresses the recording banner and saved-path message. |
| `SHELL` | `/bin/bash` | `ghostshell rec` | Shell launched when no command is given. |

## Filesystem layout

| Path | Owner / mode | Purpose |
|:-----|:-------------|:--------|
| `/usr/bin/ghostshell` | `root 0755` | CLI binary |
| `/usr/libexec/ghostshell-daemon` | `root 0755` | daemon |
| `/var/lib/ghostshell/` | `root:root 0700` | central store (no non-root access) |
| `/var/lib/ghostshell/<user>/<id>.cast` | `root:root 0600` | encrypted recording |
| `/var/lib/ghostshell/.ghostshell.key` | `root:root 0600`, `chattr +i` | per-server AES-256-GCM key (immutable) |
| `/run/ghostshell-daemon.sock` | `root 0666` | recorder connect socket |
| `/etc/profile.d/ghostshell-autorec.sh` | `root 0644` | optional auto-record login hook |
| `~/.local/share/ghostshell/` | the user | local fail-open recordings |

## Daemon systemd unit

```bash
sudo systemctl status ghostshell-daemon
sudo systemctl restart ghostshell-daemon
sudo journalctl -u ghostshell-daemon --no-pager --since '10 min ago'
```

Override store or socket path with a systemd drop-in:

```bash
sudo systemctl edit ghostshell-daemon
```

Add in the editor:

```ini
[Service]
Environment=GHOSTSHELL_CENTRAL_DIR=/srv/ghostshell
Environment=GHOSTSHELL_DAEMON_SOCK=/run/ghostshell-daemon.sock
```

## Encryption key

The daemon creates a unique random key on first start: `/var/lib/ghostshell/.ghostshell.key` (`root:root 0600`, `chattr +i`).

**Back it up offsite.** Losing it makes every encrypted recording permanently unreadable. The daemon refuses to start if the key is missing while encrypted recordings exist.

To rotate the key:

```bash
# 1. Export all existing recordings to plaintext first
for id in $(sudo ghostshell ls-user --all --ids); do
  sudo ghostshell export -o "${id}.cast" "$id"
done

# 2. Remove the immutable flag, then the key
sudo chattr -i /var/lib/ghostshell/.ghostshell.key
sudo rm /var/lib/ghostshell/.ghostshell.key

# 3. Restart the daemon — generates a fresh key
sudo systemctl restart ghostshell-daemon
```

New recordings use the new key. Exported `.cast` files are plaintext asciinema.

## Bash completion

Installed by the package to `/usr/share/bash-completion/completions/ghostshell`. Enable manually:

```bash
ghostshell completion bash | sudo tee /usr/share/bash-completion/completions/ghostshell
```

Completes subcommands, flags, local sessions (for `play`), and — as root — users and central session ids.

## Auto-record on login

The package installs `/etc/profile.d/ghostshell-autorec.sh`. It:
- Triggers only for interactive shells with a real TTY.
- Skips nested shells (`sudo su -`, subshells) by detecting a `ghostshell` process in the process ancestry — a session is recorded exactly once.
- Is fail-open: if the recorder cannot start, a normal shell continues.

Remove the file to disable:

```bash
sudo rm /etc/profile.d/ghostshell-autorec.sh
```

## Non-interactive SSH recording

```bash
sudo cp /usr/share/doc/ghostshell/sshd-forcecommand.conf.example \
        /etc/ssh/sshd_config.d/zz-ghostshell.conf
sudo sshd -t && sudo systemctl reload ssh
```

- `scp`/`sftp`/`rsync`/git transfers pass through untouched.
- Interactive logins keep recording via the profile.d hook (no double-wrap).
- Fail-open: if anything is wrong, the command runs normally — SSH is never blocked.

Exclude a specific account (e.g. automation bot):

```
Match User *,!deploy-bot
    ForceCommand /usr/libexec/ghostshell-ssh-wrap
```

Disable by removing `/etc/ssh/sshd_config.d/zz-ghostshell.conf` and reloading sshd.
