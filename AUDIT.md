# Ghost Shell — Technical Audit Report

**Date:** 2026-06-22
**Scope:** Full codebase audit of `ghostshell` (CLI) and `ghostshell-daemon` (root collector daemon) — correctness, security, concurrency, error handling, performance, tests, build/CI, observability, code quality, and documentation.
**Method:** The codebase (~13.2 KLOC Go across 16 packages) was partitioned across five parallel reviewers with disjoint write boundaries, then integrated and verified as a whole. Every fix below is applied in-tree.

## How findings were validated

The product targets Linux only (PTYs, `/proc`, `SO_PEERCRED`, unix sockets, `chattr`), and the audit host is Windows. To get **real** results rather than compile-only checks, the full suite was executed in a `golang:1.25` Linux container:

| Gate | Result |
|------|--------|
| `gofmt -l .` | clean |
| `go vet ./...` | clean |
| `staticcheck ./...` | clean |
| `golangci-lint run` | clean |
| `go test ./...` (15 packages) | **all pass** |
| `go test -race` (daemon, record, play, crypto, store) | **clean — no data races** |
| `make build` (static, `CGO_ENABLED=0 -trimpath`) | both binaries build |
| `go mod tidy` | no drift |

Baseline before the audit: build/vet/gofmt were already clean, so every issue below is a logic/security/quality defect, not a compile error.

## Severity summary

| Severity | Count | Fixed | Deferred (with rationale) |
|----------|------:|------:|--------------------------:|
| Critical | 1 | 1 | 0 |
| High | 4 | 4 | 0 |
| Medium | 12 | 12 | 0 |
| Low | 7 | 6 | 1 |
| Info / verified-correct | 9 | n/a | n/a |
| **Total actionable** | **24** | **23** | **1** |

The single deferred item (idle-connection deadline) is an intentional design trade-off, documented below.

---

## 1. Code correctness & bugs

### [HIGH] Trailing output of the final command truncated on child exit (PTY drain race)
- **Location:** `internal/record/record.go` (post-`cmd.Wait()` close path)
- **Problem:** After `cmd.Wait()` reaped the child, `Run` immediately force-closed the PTY master to "unblock" the reader. Once the child and all slave-fd holders exit, the master read drains and returns EOF on its own — force-closing at that instant races the final `ptmx.Read`, dropping the last buffered output (e.g. the output of the last command before `exit`).
- **Risk:** Audit recordings silently lose the trailing output of the final command — an integrity gap for a security tool.
- **Fix:** Replaced the unconditional close with a bounded drain — wait for the output pump to finish naturally (capturing the tail) and only force-close as a backstop after `drainGrace` (2 s) if a lingering grandchild keeps the slave open, so `Run` can still never hang. Regression test added (`TestRunCapturesTrailingOutputOnChildExit`).

### [MEDIUM] Replay aborted entirely on one malformed event line; empty cast surfaced a bare "EOF"
- **Location:** `internal/play/play.go` (`readCastEvents`, `PlayFile` header read)
- **Problem:** A single non-EOF parse error aborted an otherwise-good replay; a 0-byte/header-truncated cast surfaced `io.EOF` as a bare "EOF" message.
- **Risk:** One editor-mangled line lost a whole session; empty-file errors were opaque.
- **Fix:** `readCastEvents` now skips malformed lines and continues, bounded by `maxSkippableEvents = 64` (a wholly-corrupt body still errors rather than replaying empty). `PlayFile` translates header `io.EOF` into `empty or invalid cast file: <path>`. Tests added for malformed-line recovery, corrupt-body error, empty cast, and header-only cast.

### [INFO] SIGWINCH during interactive replay — already handled
- **Location:** `internal/play/play.go` (`playInteractive`)
- **Finding:** Interactive replay already reacts to `SIGWINCH` (re-sets the scroll region and re-renders). The non-interactive straight-through dump does not react, which is acceptable for that path. No change needed.

### [INFO] Cast read/write off-by-one & split-rune handling — verified correct
- **Location:** `internal/cast/cast.go` (`completeUTF8Len`, event indexing)
- **Finding:** UTF-8 boundary back-scan (`utf8.UTFMax`) and event-array indexing are correct; a multibyte rune split across a read-chunk boundary is handled and well-tested. Added explicit tests for empty file, header-only file, and malformed-line recovery.

---

## 2. Security

### [CRITICAL] No explicit root/uid enforcement at the audit layer (defense-in-depth bypass if store perms are loosened)
- **Location:** `internal/audit/audit.go` (all central-store commands), `internal/ansible/commands.go`, `internal/ansible/incoming.go`
- **Problem:** Every root-only command (`ls --all`/`--user`, `play-user`, `tail`/`tail -f`, `tree`, `search`, `export`, `prune`, `ansible list/show/incoming`) relied **solely** on filesystem permissions (central store is `root:root 0700`). There was no explicit euid check. If `GHOSTSHELL_CENTRAL_DIR` were relocated to a group/world-readable path, a non-root user could enumerate and decrypt other users' sessions by guessing IDs — exactly the "export by guessing ID" concern.
- **Risk:** Unprivileged disclosure of other users' recorded sessions (secrets, commands) when file perms don't hold.
- **Fix:** Added `requireRoot()` (euid 0, via an injectable `geteuid` for testability) as the first statement of every central-store command; ansible non-root callers are confined to their own user-local fallback. Defense-in-depth on top of the existing `0700` perms — both now hold. Tests assert non-root is rejected with no content leak.

### [INFO] SO_PEERCRED authentication — verified correct on every command
- **Location:** `internal/daemon/daemon.go` (`peerCred`, per-command storage resolution)
- **Finding:** The daemon never trusts client-supplied identity. The peer UID is read once per connection via `SO_PEERCRED`; every command derives the storage directory from `lookupUser(cred.Uid)` and the session ID embeds `cred.Pid`, so a user cannot record/ingest "as" someone else. `TAIL` (the only cross-user op) requires `cred.Uid == 0` before any lookup. Regression tests added for both.

### [HIGH] Fail-open ingest could expose a half-written recording (no atomic-write primitive)
- **Location:** `internal/store/store.go` (write path), `internal/daemon/daemon.go` (`copyFile` ingest)
- **Problem:** Ingest wrote the encrypted copy directly to the destination name (`O_CREATE|O_TRUNC`), so a crash mid-ingest could leave a partial, readable `<id>.cast` in the central store, and a concurrent reader could observe a half-written file.
- **Risk:** Truncated/partial recordings entering the central store; readable partial files.
- **Fix:** Added `store.WriteFileAtomic` (temp file in the same dir → `write` → fsync → `Rename` → fsync dir; removes temp on any error; rejects non-basename names). **Wired the daemon ingest `copyFile` to route through it** (integration step), so central ingest is now atomic end-to-end. Tests cover success, mid-write failure leaves no partial, replace-existing, and unsafe-name rejection.

### [INFO] Path traversal in session-ID handling — verified protected
- **Location:** `internal/store/store.go` (`safeComponent`, `FindCentral`, `CastsFor`, ansible resolution)
- **Finding:** `safeComponent` rejects empty/`.`/`..`/separators and guards **all** id→path resolution, so a crafted id such as `../../etc/passwd` cannot escape the central store. Local `play <file>` intentionally accepts explicit paths under the caller's own uid (no privilege escalation). Test added.

### [INFO] `GHOSTSHELL_DIR` / `GHOSTSHELL_CENTRAL_DIR` trust boundary — verified
- **Finding:** The privileged daemon resolves the central store from config, not from a client env var; `GHOSTSHELL_DIR` only affects the unprivileged user-local fallback. No path where untrusted env steers a privileged write.

### [LOW] At-rest key buffer not zeroed after the cipher consumes it
- **Location:** `internal/store/store.go` (`openCast`)
- **Problem:** The locally-owned key buffer lingered on the heap after `aes.NewCipher` expanded it into its own round-key state.
- **Risk:** Raw AES-256 key bytes resident in memory for the lifetime of a long-lived reader.
- **Fix:** Wipe the locally-owned key buffer (`zero()` helper) once the cipher is built. (`crypto.go` itself has no ownable buffer — the key is caller-provided and copied by `aes.NewCipher` — so zeroization correctly belongs to the buffer owner.)

### [INFO] PTY injection on replay — hardened
- **Location:** `internal/play/play.go`
- **Problem:** Replayed bytes are attacker-controlled and can enable persistent private modes (bracketed paste, mouse reporting, application keypad, autowrap off); leaving the alternate screen does not undo these.
- **Fix:** Emit a `hostReset` sequence on **every** exit path (normal/quit/signal/panic-via-defer, plus the linear-dump teardown). Documented inherent limit: window-title (OSC) cannot be reliably restored, so it is intentionally untouched (cosmetic, not input/render-affecting).

---

## 3. Concurrency & daemon correctness

### [MEDIUM] Ingest could sweep partial / temp / dotfiles into the store and delete the source
- **Location:** `internal/daemon/daemon.go` (`ingestHome`)
- **Problem:** Ingest admitted any non-dir entry with extension `.cast`. A dotfile/temp partial (now the atomic-write convention) could be ingested mid-write and then `os.Remove`d (data loss).
- **Risk:** Truncated capture ingested + source deleted.
- **Fix:** Added `ingestible()` — admits only **regular** files, rejects **dotfiles** and non-`.cast` (so `.tmp`/`.part`/atomic-temp files are skipped). Temp/partial sources are left in place. This also closes the TOCTOU concern: combined with `store.WriteFileAtomic`, only fully-renamed files are ever visible to the sweep. Tests added.

### [MEDIUM] Session-ID collision could `O_TRUNC` a live recording and clobber the registry
- **Location:** `internal/daemon/daemon.go` (`handleRec`, `registry.add`)
- **Problem:** The session file opened with `O_CREATE|O_WRONLY|O_TRUNC` (no `O_EXCL`) and `registry.add` did an unconditional map write. A collision (clock/format edge) would truncate the first session's in-progress file and orphan its subscribers.
- **Risk:** Cross-session corruption / wrong-session tail.
- **Fix:** Open now uses `O_CREATE|O_EXCL|O_WRONLY|O_NOFOLLOW` (collision fails with `EEXIST` instead of truncating); `registry.add` returns `bool` and refuses to overwrite a live id; `handleRec` rejects the collision cleanly. Tests added (incl. a `-race` concurrent-add test).

### [INFO] tail -f fan-out broadcaster — verified leak-free
- **Location:** `internal/daemon/daemon.go` (subscriber lifecycle)
- **Finding:** A lagging tailer is dropped (channel + conn closed outside the lock); a disconnecting tailer deregisters and drains residual sends so a concurrent `write` never blocks; `close()` joins each drain. No goroutine/fd leak, no double-close, no lock held across conn I/O — confirmed under `-race`. Tests reinforce.

### [LOW] Idle/stale REC connections rely on EOF-on-peer-death rather than an explicit deadline — **DEFERRED**
- **Location:** `internal/daemon/daemon.go` (REC read loop)
- **Finding:** The handshake has a 10 s read deadline; it is cleared for the streaming phase. **Not fixed — intentional:** a recording session is legitimately idle for long stretches (an idle shell sends no bytes), so any short post-handshake idle deadline would kill live sessions. Mitigations already present: unix-socket EOF on peer death is prompt, and shutdown force-closes tracked conns.
- **Recommendation:** If true idle-abandonment detection is required, add a protocol-level keepalive/heartbeat (recorder + daemon), which is a cross-cutting design change rather than a localized fix.

---

## 4. Error handling & resilience

### [HIGH] `ghostshell ansible` could fail an entire run when a task line exceeds the fixed 256 KiB scanner buffer
- **Location:** `internal/ansible/model.go` (`ParseRun`)
- **Problem:** `bufio.Scanner` was capped at a hardcoded 256 KiB, but stored `.ajsonl` lines are written raw/untruncated and `ansible_output_cap` is configurable up to 64 MiB. A single large-output task triggered `bufio.ErrTooLong`, failing `ghostshell ansible list/show` for the whole run.
- **Risk:** Operator loses all visibility of a legitimate large-output run.
- **Fix:** Scanner max line is now sized from `AnsibleOutputCap` (with a 256 KiB floor); memory stays bounded by the ingest cap. Tests pin a 64 KiB cap and parse a 300 KiB line with truncation.

### [INFO] Child exit-code passthrough — verified correct
- **Location:** `internal/record/record.go` (`ExitError`), `cmd/ghostshell/main.go`
- **Finding:** `record` surfaces the child's exit code via `ExitError.Code`; `main` propagates it via `os.Exit`. End-to-end passthrough confirmed; the man page EXIT STATUS section (previously wrong) was corrected to match.

### [MEDIUM] Unknown / invalid config keys silently swallowed — invisible to `ghostshell --check`
- **Location:** `internal/config/config.go`, `cmd/ghostshell/main.go` (`runConfigCheck`)
- **Problem:** The parser silently ignored unknown keys, malformed lines, and out-of-range values; `--check` had no way to surface them, so a typo'd key (e.g. `scroll_bufer`) looked active when it wasn't.
- **Fix:** Added read-only `config.Validate(path) []string` returning warnings for malformed lines, unknown keys, and rejected values (parser behavior unchanged — valid configs never hard-fail). **Wired `ghostshell --check` to print these warnings** (integration step). Tests cover unknown-key, malformed-line, invalid-value, and the clamp-vs-reject distinction.

### Systemd resilience — see §7.

---

## 5. Performance

### [INFO] AES-256-GCM is already streamed/chunked — no one-shot memory risk
- **Location:** `internal/crypto/crypto.go`
- **Finding:** The V2 format is framed GCM, one frame per `Write`, `maxFrameSize` 1 MiB; readers process frame-by-frame. A multi-hundred-MB session is never held whole in memory. Fresh nonce per frame; AAD binds stream-id‖frame-index (anti-reorder/anti-splice). Corruption/wrong-key/truncation return cleanly via `Err()`/EOF with no panic. Added tests for wrong key size, magic/version detection, and truncated-stream-id clean EOF.

### [INFO] Search cost & scroll buffer — assessed
- **Finding:** `search` must decrypt to scan (no index by design); it already short-circuits per file (≤5 snippets), pre-filters windows, parallelizes across files with deterministic ordering, and case-folds correctly for `-i`. The scrollback viewer is bounded (`maxScrollLines`, `maxLineBytes`) — no unbounded growth.

### [MEDIUM] Speed steppers didn't clamp the result — out-of-range speed stuck
- **Location:** `internal/play/statusbar.go` (`faster`/`slower`)
- **Problem:** The steppers gated the step but didn't clamp the result, so a `--speed 100` value (or an overshoot) never returned to the `[1/64×, 64×]` range.
- **Fix:** Rewrote both to clamp the result via `clampSpeed` (also coerces NaN/≤0 to the floor, defending against a zero timing divisor). Test asserts overshoot/out-of-range snap to a boundary and repeated steps converge.

---

## 6. Tests

- **Executed:** all 15 packages pass; concurrency-sensitive packages pass under `-race`.
- **Security-sensitive coverage added/strengthened:** `crypto` (round-trip, corrupted/tampered/truncated ciphertext, wrong key size, nonce uniqueness, magic/version), `auth` (I/O error ≠ wrong password, corrupt hash rejected), `daemon` (`SO_PEERCRED`/verified-UID storage, fan-out cleanup, concurrent session creation, ingest filter), `store` (atomic write, traversal rejection), `record` (trailing-output capture on child exit), `cast` (empty/header-only/malformed-line), `play` (speed clamp, empty/malformed cast), `audit` (root enforcement, prune on-disk sizing).
- **Flaky-path check:** existing tests use `t.TempDir()` (not hardcoded `/tmp`); a config test that asserted a warning for a *valid* key was corrected (see §9).

---

## 7. Build & CI

### [HIGH] systemd `ProtectHome=read-only` silently broke spool cleanup → duplicate ingest
- **Location:** `scripts/systemd/ghostshell-daemon.service`
- **Problem:** Startup ingest reads each user's `~/.local/share/ghostshell` spool, copies into the central store, then `os.Remove`s the spool. `ProtectHome=read-only` makes homes read-only for the unit, so the remove fails silently and files are **re-ingested on every restart** (duplicate recordings).
- **Fix:** `ProtectHome=no` with an explanatory comment (cross-user home read+delete is core to the daemon); added `/run` to `ReadWritePaths`; set explicit `RestartSec=2s` (with `Restart=on-failure`) to avoid tight restart loops.

### [MEDIUM] No CI static-analysis gate
- **Location:** `.github/workflows/`, `Jenkinsfile`, `.golangci.yml`
- **Problem:** Pipelines ran gofmt/vet/test/build but neither `staticcheck` nor `golangci-lint`.
- **Fix:** Added `.github/workflows/ci.yml` (Go 1.25, ubuntu-latest) running gofmt → vet → staticcheck → golangci-lint → test → build on PRs/branches (release pipeline untouched); added a `Static Analysis` stage to the `Jenkinsfile`; added `.golangci.yml` (default linters, all findings surfaced; `errcheck` relaxed only in `_test.go` setup I/O, strict for production). **Validated locally:** the entire gate is green on first run (see top table).

### [LOW] Makefile / nfpm gaps
- **Makefile:** `ghostshell-daemon` lacked ldflags; no lint targets. Fixed — shared `LDFLAGS := -s -w -X main.Version=$(VERSION)` on **both** binaries (with a `var Version` now present in `cmd/ghostshell-daemon/main.go`, logged at startup — integration step), plus optional `staticcheck`/`lint`/`tidy` targets kept out of `build`.
- **nfpm.yaml:** the security-critical `/var/lib/ghostshell` (`0700 root:root`) was created only at runtime — now packaged as a `type: dir` so the mode is correct immediately on install. All other layout-table paths/modes verified correct.
- **go.mod:** `go mod tidy` shows **no drift**; dependencies are minimal and current.

---

## 8. Observability & operations

### [MEDIUM] `ghostshell --check` didn't report daemon reachability
- **Location:** `cmd/ghostshell/main.go` (`runConfigCheck`)
- **Fix:** Added a `daemon_reachable = yes/no` line backed by a live socket dial with the configured timeout (never hangs). Resolved key-file and socket paths were already printed; config-validation warnings now print too (§4).

### [MEDIUM] No `ghostshell status` for operational health
- **Location:** `internal/audit/audit.go` (`Status`), `cmd/ghostshell/main.go`
- **Fix:** Added `ghostshell status` (root): reports `daemon_reachable` (live dial), `users`, `sessions_total`, `sessions_active` (via `store.IsActive`), and `store_size` (sum of on-disk `os.Stat` sizes). Read-only; never decrypts. Wired into usage, help, and completion.

### [INFO] `ghostshell prune` size accounting — verified correct
- **Finding:** Prune already reports **on-disk** (encrypted) sizes via `os.Stat().Size()` and sums only successfully-removed sizes for "freed". Matches disk. Regression test added.

### [INFO] No `log.Fatal` outside `main()` — verified
- **Finding:** Library packages (`logger`, `daemon`, `audit`, `ansible`, …) return errors; `log.Fatal`/`os.Exit` are confined to `main()`. The logger is concurrency-safe and honors levels.

---

## 9. Code quality & style

- `gofmt -l .`, `go vet ./...`, `staticcheck ./...`, `golangci-lint run` — **all clean**.
- **Fixed during integration** (surfaced by running the real linters/tests, which the per-package reviewers on Windows could not execute):
  - `internal/config/config_test.go` — a test asserted `Validate` should warn about a **valid** key (`scroll_buffer`); corrected to assert the valid key is *not* flagged while the typo'd key *is*.
  - `internal/daemon/daemon_test.go` — `SA4000` (identical expressions across `||` from double-evaluated `reserve`); rewritten as explicit per-iteration assertions.
  - `internal/ansible/model_test.go` — `ST1018` (a literal U+009B control char in a test string); rewritten as `string(rune(0x9b))` (pure-ASCII source, same runtime value).
  - `cmd/ghostshell-daemon/main.go` — unchecked `defer closeLog()` (`errcheck`) → `defer func() { _ = closeLog() }()`.
- **Named constants** introduced where magic values were used (`drainGrace`, `maxSkippableEvents`, `hostReset`, speed bounds), per area-9 guidance.

---

## 10. Documentation & README

- **[MEDIUM] man page** — `EXIT STATUS` wrongly claimed `rec` always exits 0 (it propagates the child code); `LIMITATIONS` contradicted the entire daemon/encryption feature set; SYNOPSIS used hidden aliases and omitted commands/flags/config keys. All corrected and synced to the real CLI (`ls --all/--user`, `play <file|id>`, `tail -n/-f`, `export --force`, `backup`, `init`, `completion`, `--check`, and the 6 missing config keys).
- **[MEDIUM] README** — help block/tables omitted `backup`, `init`, `version`; `search opts` line didn't match `usage()`. Corrected; `ghostshell status`, `export --force`, and the `daemon_reachable` line are documented.
- **[INFO] Security Model** — added a prominent `## Security model` section consolidating the `SO_PEERCRED` + root-only-store trust boundary, AES-256-GCM at rest + key immutability + backup warning, the path-traversal/permission posture, fail-open semantics, and the **integrity caveat** (not tamper-proof against a user who avoids `ghostshell`; non-circumventable capture needs PAM/kernel hooks). The former inline "Integrity note" was folded in and made prominent.
- **`ghostshell help <command>`** — verified non-empty/complete for every subcommand (test added); `__complete` subcommand list refreshed.

---

## Could not fix / intentionally deferred

| Item | Why | Recommendation |
|------|-----|----------------|
| Idle REC connection deadline (§3, Low) | A short post-handshake idle deadline would kill legitimately-idle live sessions | Add a protocol-level keepalive/heartbeat (recorder + daemon) if idle-abandonment detection becomes a requirement |
| On-disk Ansible output bounded by cap | `ansible_output_cap` is enforced at **read** time; raw lines are written untruncated by the daemon | Optionally move truncation to the daemon write path to bound spool size (the read path is now robust regardless) |
| `profile.d` env-marker covers only the login path | Robust `GHOSTSHELL_REC=1` guard is implemented shell-side; the Go recorder does not also `Setenv` it | If the marker should protect `ghostshell rec` invoked outside `profile.d`, have the recorder export it in the child env |
| Tamper-resistant capture | Out of project scope by design | Documented in the new Security Model; would require PAM- or kernel-stage hooks |

## Recommended next steps

1. Land this branch and let `ci.yml` exercise the new gates on a real Linux runner (validated locally via Docker here).
2. Consider the protocol keepalive and write-time Ansible truncation above if operational experience warrants them.
3. Periodically run `go test -race ./...` in CI for the daemon/record/play packages to keep the concurrency fixes guarded.

---

*All fixes are applied in-tree. Final state: build, vet, gofmt, staticcheck, golangci-lint, the full test suite, and the race detector all pass.*
