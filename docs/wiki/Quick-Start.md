# Quick Start

## Record your first session

```bash
ghostshell rec
```

```
ghostshell: recording to /home/alice/.local/share/ghostshell/20260528T093012-1428810.cast — type 'exit' or Ctrl-D to stop
alice@host:~$ echo "hello from ghostshell"
hello from ghostshell
alice@host:~$ uname -sr
Linux 5.14.0-611.55.1.el9_7.x86_64
alice@host:~$ exit
exit

ghostshell: session saved to /home/alice/.local/share/ghostshell/20260528T093012-1428810.cast
```

## List your recordings

```bash
ghostshell ls
```

```
STATUS   FILE                          STARTED              DURATION   COMMAND
SAVED    20260528T093012-1428810.cast  2026-05-28 09:30:12  14s        /bin/bash
```

## Replay it

```bash
ghostshell play 20260528T093012-1428810.cast
```

The player opens full-screen. The status bar at the bottom shows:

```
 > 00:00 / 00:14 [          ]   0%  1x   <-/-> seek  pgup scroll  g goto  spc play  q quit
```

As playback progresses it fills in:

```
 > 00:07 / 00:14 [#####     ]  50%  1x   <-/-> seek  pgup scroll  g goto  spc play  q quit
```

Press `space` to pause (bar shows `||`), `q` to quit. See [[Player-Controls]] for all keys.

## Record a specific command (non-interactive)

```bash
ghostshell rec /bin/bash -c 'df -h; free -h'
```

```
ghostshell: recording to /home/alice/.local/share/ghostshell/20260528T093101-1430210.cast — type 'exit' or Ctrl-D to stop
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        40G   12G   26G  32% /
tmpfs           3.8G     0  3.8G   0% /dev/shm

               total        used        free      shared  buff/cache   available
Mem:            7.6G        1.2G        5.1G         23M        1.3G        6.1G
Swap:           2.0G          0B        2.0G

ghostshell: session saved to /home/alice/.local/share/ghostshell/20260528T093101-1430210.cast
```

## Enable auto-recording on every login

The package installs the hook automatically. To enable manually:

```bash
sudo install -m644 /usr/share/doc/ghostshell/ghostshell-autorec.sh.example \
                   /etc/profile.d/ghostshell-autorec.sh
```

After this, every interactive SSH login is automatically recorded into the central store (requires `ghostshell-daemon` running).

## View all users' sessions as root

```bash
sudo ghostshell ls-user
```

```
USER                  SESSIONS
root                  3
alice                 12
bob                   5
```

```bash
sudo ghostshell tree
```

```
/var/lib/ghostshell
├─ root
│  └─ 20260528T090001-1024000.cast  [SAVED interactive]  2026-05-28 09:00:01  5m12s  /bin/bash
├─ alice
│  ├─ 20260528T093012-1428810.cast  [SAVED interactive]  2026-05-28 09:30:12  14s    /bin/bash
│  └─ 20260528T093101-1430210.cast  [SAVED non-interactive]  2026-05-28 09:31:01  3s  /bin/bash -c df -h; free -h
└─ bob
   └─ 20260528T095500-1460000.cast  [SAVED interactive]  2026-05-28 09:55:00  8m44s  /bin/bash
```

See [[Audit-Mode]] for the full audit command reference.
