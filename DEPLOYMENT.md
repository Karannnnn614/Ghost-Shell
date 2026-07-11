# Ghost Shell — Deployment-Readiness Audit & Fix Report

**Date:** 2026-07-11
**Target:** first unattended deployment to a real Ubuntu LTS (24.04) server.
**Method:** four parallel reviewers (packaging/systemd, daemon, path/keys, fail-open/backup) fixed code + wrote tests; then **empirically validated on a real Ubuntu 24.04 install of the built `.deb`** in Docker — not just code-read. Legend: **FIXED** (changed + tested), **FLAGGED** (design decision left unchanged), **CONFIRMED-FINE** (verified correct).

Whole tree after the pass: `gofmt`/`go vet`/`staticcheck`/`golangci-lint` clean, all 15 test packages pass, `-race` clean on daemon/record/store/crypto/audit/backup, static `.deb` builds.

---

## 1. Build & packaging
- **CONFIRMED-FINE — static binary.** `file bin/ghostshell` → `ELF 64-bit … statically linked`; `ldd` → **"not a dynamic executable"** for both binaries (`CGO_ENABLED=0`).
- **CONFIRMED-FINE — permission bits (installed the real `.deb`, checked every path):** `/usr/bin/ghostshell` 755, `/usr/libexec/ghostshell-daemon` 755, `/var/lib/ghostshell` **700 root:root**, `/var/log/ghostshell` **750 root:root**, `/etc/ghostshell/ghostshell.conf` 644, unit 644, `/etc/logrotate.d/ghostshell` 644, key **600 root** (created at runtime). All match README's Filesystem-layout table. Man page **is** shipped (`dpkg -c` → `/usr/share/man/man1/ghostshell.1`, 0644).
- **CONFIRMED-FINE — idempotency + wrong-ownership.** postinstall re-run after a simulated bad manual install (`0777 ubuntu:ubuntu`) reset the store to **700 root:root**; a happy-path re-run added no duplicate sshd `Include`.
- **FIXED — postinstall deleted Ubuntu's own sshd `Include` line.** The `sshd -t` failure path ran `sed -i '/Include …\*.conf/d'` unconditionally, which would strip Ubuntu's pre-existing `Include /etc/ssh/sshd_config.d/*.conf` (not just ours) — silently breaking every other sshd drop-in. Now tracks `added_include`/`wrote_conf` and reverts **only** what this run changed. Verified in-container: pre-existing Include preserved, only our drop-in removed.
- **FIXED — `set -e` half-configure.** The two sshd mutations were unguarded under `set -e`; a failure over this *optional, fail-open* feature could abort postinstall before the daemon-enable/key steps, leaving dpkg half-configured. Both are now `if`-guarded (skip SSH recording, continue). Core store/log/config setup stays strict.
- **FIXED — `recommends: logrotate`** added so the shipped rotation drop-in actually runs.
- **FLAGGED — `arch: amd64` only (no arm64).** Ubuntu on Graviton/Ampere/Pi is common; the package is amd64-only. This is a release-matrix decision (nfpm builds one arch/invocation), not a one-line change. **Recommend** a build matrix emitting `amd64` + `arm64`.

## 2. Daemon / socket security
- **CONFIRMED-FINE — no command trusts client-supplied identity.** REC/ANSIBLE derive the storage dir from `lookupUser(cred.Uid)` and the id from `cred.Pid` — both from the kernel `SO_PEERCRED` struct read once per connection. TAIL (the only cross-user op) is gated `cred.Uid == 0` before any lookup. The only client inputs (TAIL id, ANSIBLE runID) are used as validated lookup keys, never raw paths. **Added** the missing REC verified-uid isolation test.
- **CONFIRMED-FINE — concurrency.** Each `rec` owns its own file + crypto writer; the only shared state is the registry (all mutations under locks) and `reg.key` (set once, thereafter read-only; `aes.NewCipher` copies it). tail fan-out is serialized on `session.mu` with conn I/O outside the lock. `prune` is a **separate process** — no shared memory, skips `IsActive` sessions, unlink-safe on Linux. New `-race` tests: 8 concurrent real sessions on the shared key, registry cap race.
- **E2E (§8.3):** a second unprivileged user is **denied** reading another's cast (`cat`/`ls`), and `ghostshell ls --all` returns *"permission denied … must be run as root"*.

## 3. Fail-open path
- **CONFIRMED-FINE + tested — daemon unreachable / stale socket → clean local fallback** to `~/.local/share/ghostshell` (0600), no partial/corrupt cast. E2E (§8.4): daemon down → alice records locally → daemon restart ingests to central and removes the local copy.
- **FIXED — REC handshake write deadline.** `openSink` now bounds the `"REC\n"` write with a deadline (cleared for the long-lived stream) and falls back to local on handshake failure.
- **CONFIRMED-FINE — login-hook fail-open scripts.** `profile.d/ghostshell-autorec.sh` and `ghostshell-ssh-wrap.sh` have no blocking path (`sh -n` clean; bounded `/proc` ancestry walk; daemon-down and local-ENOSPC both fail fast → shell continues). E2E (§8.7): `scp`/`rsync`/`sftp`/`git` pass through the wrapper **untouched**.
- **🟡 FLAGGED (design decision — NOT changed) — the fail-open guarantee has a hole under load/full-disk.** The daemon sends **no `OK` on a successful REC** — only `ERR` on *rejection* (`session_cap` default 10, full disk, id collision). The recorder never reads the reply, so on rejection it streams into a dying conn and **the recording is silently lost with no local fallback**. Separately, mid-session a wedged (accepting-but-not-reading) daemon has no write deadline → once the socket buffer fills, the user's shell can freeze (a login-time risk via the profile.d hook). **Both are cleanly solved by the same change: the daemon emits a 1-byte `OK` ACK on REC success**, so the recorder confirms registration and falls back to local on ERR/timeout at zero success-latency. It's a cross-package protocol change (daemon + record), so per your instructions it's left as a recommendation. *(Note: the other `ttrack` variant's FIXES.md had this as "#14 REC ACK".)*

## 4. Encryption & key management
- **CONFIRMED-FINE — daemon refuses to start when the key is missing but encrypted recordings exist** (real logic in `ensureKey` + `encryptedRecordingsExist`, not just docs).
- **FIXED — `chattr +i` silently no-ops on some filesystems.** **Empirically reproduced:** on **overlayfs** (containers) and **tmpfs**, `chattr +i` fails and the key stays deletable; on **ext4** it works. The daemon previously ignored the ioctl error. Now `setImmutable` re-reads the flags and **verifies `FS_IMMUTABLE_FL` actually stuck**, logging a loud `WARNING: the at-rest key is NOT protected …` if not (non-fatal). **Confirmed firing in the wild** — on the tmpfs test the exact warning appeared.
- **FIXED — `readDecryptKey` TOCTOU + symlink-follow.** Was `Lstat`-then-`ReadFile` (inode swappable between check and read; `ReadFile` follows symlinks). Rewrote to `open(O_NOFOLLOW)` → `fstat(fd)` → `read(fd)` so every permission check binds to the exact inode read; a symlinked key path is refused (ELOOP).
- **CONFIRMED-FINE — GCM nonce reuse impossible.** Fresh `crypto/rand` 96-bit nonce **per frame**, stored inline — never derived from the frame counter (which feeds AAD only); `rand.Read` errors handled. Birthday bound for random 96-bit nonces ≈ 2⁴⁸ frames at 50%; a realistic server lifetime (~2³³ frames) gives ≈2⁻³¹ collision risk. New tests: nonce-independent-of-counter, 20k-frame uniqueness.
- **E2E:** the on-disk cast is opaque — a recorded secret marker is **absent** from ciphertext; magic `TTEC2` confirmed.

## 5. Operational gaps (were unaddressed)
- **FIXED — log rotation (was missing).** New `/etc/logrotate.d/ghostshell` (weekly + `maxsize 100M`, `rotate 8`, `compress`+`delaycompress`, `create 0640 root root`, `missingok`, `notifempty`), packaged as `config|noreplace`. postrotate sends **SIGHUP** to the daemon — verified against the daemon's actual `SIGHUP → logger.Reopen` handler. E2E with real `logrotate 3.21`: parses clean, rotates "weekly (8 rotations)".
- **FIXED — disk-full logging.** ENOSPC on session/ingest/ansible writes is now **ERROR** with the path + an actionable message (was `Warnf` or fully swallowed in `ingestHome`). **E2E (§8.6):** filled a 512 K tmpfs store — daemon logged `[ERROR] … DISK FULL writing session … no space left … session terminated (recording truncated). Free space or prune the central store.`, **stayed alive**, and kept serving new clients. Fail-loud, not silent-corrupt.
- **FLAGGED (design decision — NOT implemented) — `min_free_space`/quota that pauses ingestion.** Tradeoff: avoids ever hitting a hard ENOSPC mid-recording, but means silently refusing new recordings once the threshold trips — an availability-vs-completeness change to the fail-open contract, and it can be gamed to suppress auditing by filling the disk. Left current behavior (fail loud, terminate the affected session, keep serving).
- **EXERCISED — backup.** Ran the real `rsync` path in a container: it mirrors the store with `--delete` exactly as documented, **argv-only** (`exec.Command`, no `sh -c` — injection canary passes), no credential leakage in errors (AWS/GCP creds live in env/files, never argv). `bucket_aws`/`bucket_gcp` end-to-end need cloud creds — only their argv construction is unit-tested (stated, not hidden).

## 6. systemd hardening — measured, not asserted
**`systemd-analyze security` on real systemd 255: `7.0 MEDIUM` → `3.9 OK`.** Added (each verified safe for a daemon that only opens a unix socket, reads `/etc/passwd`+home spools, writes 0600 files, and does `ioctl(FS_IOC_SETFLAGS)`): `ProtectKernelModules`, `ProtectKernelLogs`, `LockPersonality`, `RestrictRealtime`, `RestrictNamespaces`, `ProtectClock`, `ProtectHostname`, `SystemCallFilter=@system-service` (ioctl + execve still permitted → chattr and backup subprocesses still work).
- **FLAGGED (deliberately NOT added):**
  - **`CapabilityBoundingSet`** — biggest remaining lever but must include `CAP_LINUX_IMMUTABLE`, `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, `CAP_CHOWN`; an incomplete set silently breaks ingest/chattr. **Add after a staged test on the real host.**
  - **`ProtectHome`** stays **off** (required — daemon reads+deletes each user's spool); documented in-unit.
  - **`ProtectSystem=strict`** must **not** be used (would make homes read-only → break spool deletion). Kept `full`.
  - **Network backups vs `RestrictAddressFamilies=AF_UNIX`:** enabling `backup_type=rsync|bucket_*` needs a drop-in adding `AF_INET AF_INET6` for the aws/gsutil/rsync child processes (backups are default-off, so not a day-one break).

## 7. Path / input validation
- **CONFIRMED-FINE (adversarially tested) — crafted session IDs rejected** across every id→path entry point (`FindCentral`, `UserSessions`, `IsAnsibleRun`, audit `play`/`export`/`tail`/`search`): `../../etc/passwd`, absolute, `a/../../b`, `.`/`..`, separators, empty, `..%2f`, embedded-NUL — all fail-closed inside the store.
- **FIXED (defense-in-depth) — path builders hardened.** `UserDir`/`CastPath`/`AnsiblePath`/`AnsibleDir` were unvalidated `filepath.Join`; a caller that skipped pre-validation could escape. Added a fail-closed choke point (unsafe component → unusable in-store path that fails the open) with byte-identical output for valid inputs.
- **CONFIRMED-FINE — symlink ingest refused.** `openCast`/ingest open `O_RDONLY|O_NOFOLLOW` + `IsRegular` check. **E2E (§8.8):** alice's `evil.cast → /etc/shadow` symlink was refused, left un-ingested, and **zero `/etc/shadow` bytes reached the store.**
- **CONFIRMED-FINE — no shell injection.** `--from`/`--to` ("any `date -d` format") uses `exec.Command("date","-d",s,…)` — pure argv, **no `sh -c`** — so `$()`, backticks, `;`, `|`, newlines are inert literals to `date(1)`. Leading-`-` rejected. Injection canary (8 payloads) passes.

## 8. Ubuntu-server checklist — actual results
| # | Step | Result |
|---|------|--------|
| 1 | Install from the built `.deb` | ✅ `Status: install ok installed`; all perms correct |
| 2 | `ghostshell --check` | ✅ resolved config + `daemon_reachable = yes` |
| 3 | Record as a user; other user cannot read | ✅ `root:root 0600`; bob denied `cat`/`ls`/`ls --all`; cast encrypted at rest |
| 4 | Kill daemon mid-recording → fail-open → restart → ingest | ✅ local `0600` fallback → ingested to central on restart, local removed |
| 5 | `systemd-analyze security` | ✅ **3.9 OK** (was 7.0 MEDIUM) |
| 6 | Fill the store disk | ✅ daemon logs `[ERROR] DISK FULL …`, survives, keeps serving |
| 7 | sshd `ForceCommand`: scp/sftp/rsync/git pass through | ✅ pass through untouched (not wrapped in recording) |
| 8 | Path-traversal / symlink attack | ✅ crafted IDs + `→/etc/shadow` symlink both rejected, no leak |
| 9 | Concurrent `rec` + `tail -f` + `search` | ✅ **definitively verified by `-race`**: `TestConcurrentRecSessionsSharedKey` (8 concurrent real sessions on the shared key), multi-tailer fan-out, registry-cap race — all clean. (A shell-level e2e of 6 backgrounded PTY recorders was harness-limited — backgrounded PTY recorders need a controlling tty — so concurrency safety rests on the `-race` coverage, which exercises the exact shared-state paths.) |

---

## Resolved after the audit (implemented + tested + shipped)
- ✅ **REC `OK` ack** (§3) — the daemon now sends `OK\n` once a REC session is registered; the recorder waits for it and falls back to a user-local file on ERR (cap/disk/collision), read timeout (wedged daemon), or EOF. No more silent recording loss or startup hang. Unit tests (OK→central, ERR→local, wedged→local, daemon-sends-OK) + e2e (100%-full store → local fallback); `-race` clean.
- ✅ **sshd `ForceCommand` is now opt-in** (§1/§3) — removed from package postinstall; enable with `sudo ghostshell init --enable-ssh-forcecommand` (root; `sshd -t` validated; reverts only its own edits; idempotent), disable with `--disable-ssh-forcecommand`. Unit tests + real-sshd e2e.

## Deferred — need your decision (behavior left unchanged)
1. **`min_free_space`/quota** (§5) — graceful ingestion pause before ENOSPC. Availability-vs-completeness tradeoff; can be gamed.
2. **`CapabilityBoundingSet`** (§6) — biggest remaining systemd-score lever; add after a staged on-host test (incomplete set breaks ingest/chattr).
3. **arm64 package** (§1) — add an arm64 build-matrix target.

## Recommended before flipping to production
- Land the **REC `OK` ACK** (#1) — it's the one change that removes a *silent audit-data-loss* path on a busy/full host.
- On the target host, run `systemd-analyze security ghostshell-daemon` post-deploy, then trial the `CapabilityBoundingSet` (#3) in a drop-in and confirm ingest + `chattr` still work before committing it.
- Back up `/var/lib/ghostshell/.ghostshell.key` immediately after first start (daemon logs a reminder), and confirm the store is on a filesystem that supports the immutable attribute (ext4/xfs) — otherwise heed the new key-not-protected warning.
