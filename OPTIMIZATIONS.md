# Ghost Shell — Refactor & Optimization Pass

**Date:** 2026-06-22
**Goal:** Reduce duplication, simplify hot paths, cut binary size — **without behavior change**. Every claim below is backed by a measurement taken on Linux (`golang:1.25` container; AMD64, 16 logical CPUs). After each change: `go test ./... -race` was run and is clean.

## Summary of what changed (and what deliberately didn't)

| Area | Outcome |
|------|---------|
| 1. Dead code | Removed 1 genuinely-dead function (`lastNonFlagArg`) + its test. Corrected the premise: escape analysis ≠ dead-code analysis; most `deadcode` hits are per-binary false positives. |
| 2. Package consolidation | Added 3 path helpers + 2 extension consts to `store`; migrated **15** ad-hoc path-construction sites across daemon/ansible/audit/store. Byte-identical paths. |
| 3. Hot path (PTY capture) | **Measured, then declined** the background-encrypt change — it would be a regression. Encryption isn't in the record path; the pipeline is I/O-bound. Added 2 benchmarks. |
| 4. Binary size | Already met (3.0–3.6 MiB ≪ 12 MB). Confirmed `-s -w` savings; `govulncheck`: clean. |
| 5. Config singleton | Already a `sync.Once` cache. Added a concurrent "read-once" test (passes under `-race`). |
| 6. Test speed | No test exceeds 1 s. Slowest are bcrypt (intentional security cost) — not mockable without defeating the test. |
| 7. Makefile | Added `make check` (fail-fast, mirrors CI) and extended `make clean`. |

---

## 1. Dead code

**Premise corrected.** The prompt asked to "strip functions that escape analysis shows are never heap-allocated." Escape analysis (`-gcflags=-m`) reports whether *values* escape to the heap — it has nothing to do with whether a *function* is dead, and a function that avoids heap allocation is desirable, not removable. Dead code is found by reachability/usage analysis (`staticcheck unused`, `deadcode`), which is what was used here.

**`staticcheck unused` was already clean** → no unused unexported symbols. To find dead *exported* code, `golang.org/x/tools/cmd/deadcode` was run, but its output is **per-binary** and misleading for this two-binary repo:

- `deadcode ./cmd/ghostshell` reports `crypto.NewWriter`, `crypto.GenerateKey`, `store.WriteFileAtomic` as "unreachable" — but these are **daemon-only** (the CLI never encrypts/creates keys). Reachable from `ghostshell-daemon`. Not dead.
- `config.Reset` is **test-only** → "unreachable from main" but not dead.
- The large `ghostshell-daemon` list (`internal/ansible/*`, `internal/cast` writers, `backup.RunCLI`, …) is all **CLI-side** code unused by the daemon. Not dead.

**Truly dead = unreachable from *both* binaries AND untested.** Exactly one qualifies:

- **`lastNonFlagArg`** (`cmd/ghostshell/main.go`) — superseded by `parseLsScope` + `resolvePlayTarget` (the remaining test comment even said "unlike the *old* `lastNonFlagArg`"). It was referenced only by its own test. **Removed** the function and `TestLastNonFlagArg`; reworded the one stale comment.

Effect on binary size: negligible (one 8-line helper); binaries are dominated by the Go runtime + dependencies. Cleanliness, not size.

## 2. Package consolidation (DRY)

**Investigated the claimed `store`/`crypto`/`daemon` overlap:**
- `crypto` does **no** key loading or path resolution (the key is caller-provided; `aes.NewCipher` copies it). It is not part of the overlap — the premise was partly inaccurate.
- Key handling is **not** duplicated in a mergeable way: `daemon.ensureKey` *creates* the key and sets it immutable (`chattr +i`); `store.readDecryptKey` *reads + verifies* (root-owned, `0600`) for decryption. Different security responsibilities — deliberately **not** merged.

**Real duplication found & fixed: central-store path construction.** `filepath.Join(store.CentralDir(), user, …)`, `<id>+".cast"`, `<runid>+".ajsonl"`, and `…/"ansible"` were rebuilt ad-hoc in 15 places (daemon ×6, ansible ×4, audit ×1, store ×4), and `store.AnsibleDir()` already existed but was re-implemented inline.

Added to `internal/store/store.go`:
```go
const ( CastExt = ".cast"; AnsibleExt = ".ajsonl" )
func UserDir(user string) string          // <central>/<user>
func CastPath(user, id string) string      // <central>/<user>/<id>.cast
func AnsiblePath(user, runID string) string // <central>/<user>/ansible/<runid>.ajsonl
```
Migrated all 15 sites to these helpers / the existing `AnsibleDir`. Each helper expands to exactly the prior `filepath.Join` expression, so **every produced path is byte-identical** — verified by the full suite (`TestFindCentral`, `TestHandleAnsibleStoresUnderVerifiedUID`, `TestStatusReportsCountsAndSize`, prune/search/tree tests) passing unchanged, plus `-race`. Security checks (`safeComponent`, `O_NOFOLLOW`, perms) were untouched. Left alone: `pruneHashPath` (a central-root file, not a `<user>` path) and the user-local ansible fallback.

## 3. Hot path: PTY capture loop — measured, then **declined** the proposed change

**The premise rests on code that doesn't exist.** `internal/record`'s pipeline is `ptmx.Read → os.Stdout.Write + cast.WriteOutput` to the sink. The sink is the **daemon socket** (central) or a **local plaintext file** (fail-open). **Encryption happens in `ghostshell-daemon` (`handleRec` → `crypto.NewWriter`), not in the record loop.** So "move encrypt to a background goroutine in the read→encrypt→write pipeline" cannot apply to `internal/record`.

**Benchmarks added** (`internal/cast/cast_test.go`, `internal/crypto/crypto_test.go`):

| Benchmark | ns/op | Throughput | Allocs |
|-----------|------:|-----------:|-------:|
| `BenchmarkWriterWriteOutput` (4 KB chunk — record-side encode) | 11,579 | **353.75 MB/s** | 3 |
| `BenchmarkEncryptThroughput` (32 KB chunk — daemon AES-256-GCM) | 40,013 | **818.94 MB/s** | 4 |

**CPU profile** of the record-side per-chunk work (`go tool pprof -top`):
```
38.69%  encoding/json.appendString   <- asciinema JSON string escaping (the actual cost)
11.90%  runtime.futex
10.71%  runtime.memmove
```
The per-chunk CPU cost is **JSON encoding of the asciinema event**, not encryption. Both stages run at **hundreds of MB/s**; a terminal produces **KB/s to low MB/s**. The pipeline is bounded by `ptmx.Read` (kernel PTY) and stdout, i.e. **I/O-bound**.

**Decision: do not move encryption (or encoding) to a background goroutine.** Rationale:
1. **No measurable gain** — encryption has 3–4 orders of magnitude of headroom over real data rates.
2. **Durability regression** — a buffering channel would create a window where captured-but-unencrypted/unwritten bytes are lost on crash. This is an *audit tool*; losing the tail of a session is exactly the HIGH-severity bug fixed in the last audit (`internal/record` synchronous drain). The synchronous `pumpOutput → wg.Wait → drain` is load-bearing for that guarantee.
3. **Complexity** — it would reintroduce concurrency the audit just verified race-free, for no benefit.

(Considered and also declined: reusing the per-frame buffer in `crypto` to drop the 4 allocs/write — same reasoning: invisible at terminal rates, and it touches the encrypt-at-rest write path.)

## 4. Binary size

Both binaries are **already far under the 12 MB target**; `-s -w -trimpath` (added in the prior pass) is applied to both.

| Binary | Unstripped | `-s -w -trimpath` | Saving | Target |
|--------|-----------:|------------------:|-------:|:------:|
| `ghostshell`  | 5,573,256 B (5.31 MiB) | **3,748,024 B (3.57 MiB)** | −32.7% | <12 MB ✓ |
| `ghostshell-daemon` | 4,727,464 B (4.51 MiB) | **3,154,104 B (3.01 MiB)** | −33.3% | <12 MB ✓ |

`govulncheck ./...` → **No vulnerabilities found** (no vulns introduced by trimming; dependency set is minimal: `creack/pty`, `golang.org/x/{term,sys,crypto}`). No further action needed. UPX-style compression was *not* applied — it harms startup, breaks reproducibility, and trips antivirus heuristics; not worth it for a 3 MB root daemon.

## 5. Config singleton

**Already cached.** `config.Load()` uses `sync.Once` to parse the file exactly once per process and return a shared `*Config`; only `config.Parse()` (used by the daemon on SIGHUP) re-reads, by design. There is no per-invocation re-parse to fix. (Each CLI invocation is a separate process — one parse per process is correct and unavoidable.)

The existing triple-locking in `Load()` is intentional: it lets the test-only `Reset()` swap the `sync.Once` without racing a concurrent `Load()` under `-race`. **Left as-is** (it works and the new test passes under `-race`).

**Added** `TestSingletonConcurrentReadsOnce`: 64 goroutines call `Load()` concurrently and must all observe the **identical `*Config` pointer** — only possible if `once.Do` ran the parse a single time. Passes under `-race` (1.25 s for the config package), confirming single-read + data-race freedom.

## 6. Test speed

`go test ./... -v` timing: **no single test exceeds 1 s.** The slowest:

| Test | Time | Cause | Action |
|------|-----:|-------|--------|
| `TestVerify` (auth) | 0.71 s | bcrypt `CompareHashAndPassword` (cost 12) | **None** — the cost *is* the security property under test; lowering it weakens production or invalidates the test. Not I/O; cannot be "mocked" without testing nothing. |
| `TestSetPasswordAndIsSet` / `…TightensExistingFileMode` | 0.26 / 0.21 s | bcrypt hashing | Same as above |
| `TestRunPipeStdinExitsCleanly` (record) | 0.51 s | real PTY + `EOFGrace` (500 ms) on the EOF→close path | Left as-is — it exercises the real grace/close path; shaving it would require injecting `config.Reset()` into the record suite (singleton coupling) for ~0.4 s, not worth the added test fragility. |

The `auth` *package* totals ~1.3 s (sum of bcrypt tests run serially), but per the >1 s-per-test criterion there is nothing to fix. Whole suite wall-clock is ~3 s.

## 7. Makefile

- **`make check`** (new): runs gofmt → vet → staticcheck → golangci-lint → test → build **in order, fail-fast** (each recipe line aborts on non-zero exit). Mirrors `.github/workflows/ci.yml`. Existing granular targets (`vet`, `lint`, `staticcheck`, `test`, `build`, `tidy`) are unchanged.
- **`make clean`** (extended): now also removes `*.cast`, `*.prof`, `*.test`, and `coverage.out` from the working tree in addition to `bin/` and `release/` (scoped to the repo root to avoid touching any future `testdata` fixtures).

---

## Verification (final state)

```
gofmt -l .            clean
go vet ./...          clean
staticcheck ./...     clean
golangci-lint run     clean
go test ./...         all 15 packages pass
go test -race ...     config, daemon, record, store, cast, crypto — no data races
go build (static)     ghostshell 3.57 MiB, ghostshell-daemon 3.01 MiB
govulncheck ./...     no vulnerabilities
go mod tidy           no drift
```

**Net change:** −1 dead function, +5 shared path helpers replacing 15 ad-hoc constructions, +3 tests/benchmarks, +`make check`. No production behavior changed; no dependency changed; binaries unchanged in size (already optimal). The one "optimization" that would have changed behavior (background-encrypt) was measured and correctly rejected as a net regression.
