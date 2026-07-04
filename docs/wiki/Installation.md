# Installation

## Requirements

- Linux (uses `/proc` and `SO_PEERCRED`).
- To build from source: Go 1.25+.

## From a released package

Every push to `main` publishes an `rpm`, a `deb`, and a static binary on the [releases page](https://github.com/Karannnnn614/Ghost-Shell/releases).

### Debian / Ubuntu (.deb)

```bash
VER=$(curl -fsSL https://api.github.com/repos/Karannnnn614/Ghost-Shell/releases/latest \
  | grep -oP '"tag_name":\s*"v\K[^"]+')
curl -fLO "https://github.com/Karannnnn614/Ghost-Shell/releases/download/v${VER}/ghostshell_${VER}_amd64.deb"
sudo apt install "./ghostshell_${VER}_amd64.deb"
```

### RHEL / Rocky / Fedora (.rpm)

```bash
VER=$(curl -fsSL https://api.github.com/repos/Karannnnn614/Ghost-Shell/releases/latest \
  | grep -oP '"tag_name":\s*"v\K[^"]+')
curl -fLO "https://github.com/Karannnnn614/Ghost-Shell/releases/download/v${VER}/ghostshell-${VER}-1.x86_64.rpm"
sudo dnf install "./ghostshell-${VER}-1.x86_64.rpm"
```

### Static binary (any distro)

```bash
VER=$(curl -fsSL https://api.github.com/repos/Karannnnn614/Ghost-Shell/releases/latest \
  | grep -oP '"tag_name":\s*"v\K[^"]+')
curl -fL -o ghostshell "https://github.com/Karannnnn614/Ghost-Shell/releases/download/v${VER}/ghostshell-${VER}-linux-amd64"
chmod +x ghostshell && sudo install -m755 ghostshell /usr/bin/ghostshell
```

## What the package installs

| Path | Purpose |
|:-----|:--------|
| `/usr/bin/ghostshell` | CLI binary |
| `/usr/libexec/ghostshell-daemon` | root collector daemon |
| `/usr/libexec/ghostshell-ssh-wrap` | optional sshd ForceCommand wrapper |
| `/lib/systemd/system/ghostshell-daemon.service` | systemd unit (auto-enabled) |
| `/usr/share/bash-completion/completions/ghostshell` | bash tab-completion |
| `/etc/profile.d/ghostshell-autorec.sh` | optional auto-record login hook |
| `/usr/share/doc/ghostshell/sshd-forcecommand.conf.example` | example sshd config snippet |
| `/usr/share/ghostshell/ansible/ghostshell.py` | Ansible callback plugin |
| `/usr/share/man/man1/ghostshell.1.gz` | man page |

The post-install script creates `/var/lib/ghostshell` (`root:root 0700`) and starts `ghostshell-daemon`.

## Verify the install

```bash
ghostshell --version
```

```
ghostshell v1.0.5
```

```bash
sudo systemctl status ghostshell-daemon
```

```
● ghostshell-daemon.service - ghostshell session collector daemon
     Loaded: loaded (/lib/systemd/system/ghostshell-daemon.service; enabled)
     Active: active (running) since Wed 2026-05-28 09:00:01 UTC; 1h ago
   Main PID: 1024 (ghostshell-daemon)
```

```bash
man ghostshell   # opens the man page
```

## From source

```bash
git clone https://github.com/Karannnnn614/Ghost-Shell.git
cd Ghost Shell
make build           # produces build/ghostshell and build/ghostshell-daemon
sudo make install    # installs to /usr/bin, /usr/libexec, systemd, completion, man
```

## Uninstall

```bash
# deb
sudo apt remove ghostshell

# rpm
sudo dnf remove ghostshell

# manual / source install
sudo rm /usr/bin/ghostshell /usr/libexec/ghostshell-daemon /usr/libexec/ghostshell-ssh-wrap
sudo systemctl disable --now ghostshell-daemon
sudo rm /lib/systemd/system/ghostshell-daemon.service
```
