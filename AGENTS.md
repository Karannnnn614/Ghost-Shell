# AGENTS.md — ghostshell

## Quick Facts
- Go module `ghostshell`; CI uses Go 1.25, builds must be static (`CGO_ENABLED=0`).
- Two binaries: `cmd/ghostshell` (CLI) and `cmd/ghostshell-daemon` (daemon).
- Storage locations:
  - Local: `$GHOSTSHELL_DIR` (default `~/.local/share/ghostshell`).
  - Central (encrypted): `$GHOSTSHELL_CENTRAL_DIR` (`/var/lib/ghostshell`).
  - Encryption key at `<central>/.ghostshell.key` (immutable via `chattr +i`).

## Common Commands
- `make fmt` → `go fmt ./...`
- `make vet` → `go vet ./...`
- `make test` → `go test ./...`
- `make build` → static build (`CGO_ENABLED=0 go build -trimpath`) → `bin/ghostshell`, `bin/ghostshell-daemon`
- `make VERSION=… packages` → `nfpm` builds RPM & DEB in `release/`
- `make install` → installs CLI to `/usr/bin`, daemon to `/usr/libexec/ghostshell-daemon`, systemd unit, completions, man page.

## CI / Jenkins Pipeline (Jenkinsfile)
- Stages: Checkout → Release Version → Format → Vet → Test → Build → Package → **Publish GitHub Release**.
- `options { disableConcurrentBuilds() }` prevents executor dead‑locks.
- **Release Version** stage:
  * Uses `git tag --points-at HEAD` for a `vX.Y.Z` tag; otherwise increments the patch of the latest tag.
  * Sets `env.RELEASE_VERSION` for later stages.
* Updates version strings in `Makefile`, `man/ghostshell.1` (both quoted and unquoted forms), and `README.md` via robust `sed` commands.
- **Publish GitHub Release** stage:
  * Installs `gh` (`go install github.com/cli/cli/v2/cmd/gh@v2.87.3`) if missing.
  * Uses credential `github-release-token`.
  * Creates a GitHub release `v${RELEASE_VERSION}` (if not present) and uploads `release/*.rpm`, `release/*.deb`, binary, and `SHA256SUMS`.
- Environment for Go in Jenkins: `GOROOT`, `GOPATH`, `GOCACHE`, `CGO_ENABLED=0`.
- All stages archive relevant artifacts (`archiveArtifacts`).

## Gotchas
- Central casts are AES‑256‑GCM; read/write only via `store.OpenCast*` APIs.
- Daemon socket (`/run/ghostshell-daemon.sock`) is mode 0666; privacy enforced by file permissions, not socket.
- Tests that touch the store must set `GHOSTSHELL_DIR`, `GHOSTSHELL_CENTRAL_DIR`, and `GHOSTSHELL_DAEMON_SOCK` to temporary locations.
- The daemon creates `.ghostshell.key` as immutable; losing it makes encrypted recordings unreadable.

## Ansible Integration
- Callback plugin `scripts/ansible/ghostshell.py` writes JSON Lines to `~/.local/share/ghostshell/ansible/<runid>.ajsonl` (0600) and to central `/var/lib/ghostshell/...`.
- Enable with:
  ```
  ANSIBLE_CALLBACK_PLUGINS=/usr/share/ghostshell/ansible
  ANSIBLE_CALLBACKS_ENABLED=ghostshell
  ```
- Packaging (nfpm) currently does **not** install the plugin; verify `nfpm.yaml` when adding plugin support.

## Packaging Details
- `nfpm.yaml` builds RPM and DEB containing CLI, daemon, systemd unit, man page, and completions.
- `make packages` expects `VERSION` (set by Release Version stage) and cleans old artefacts before building.
- SHA256 sums are generated in `release/SHA256SUMS` and uploaded to GitHub releases.

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
