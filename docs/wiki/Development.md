# Development

## Build

```bash
git clone https://github.com/Karannnnn614/Ghost-Shell.git
cd Ghost Shell
make build
```

```
go build -o build/ghostshell ./cmd/ghostshell
go build -o build/ghostshell-daemon ./cmd/ghostshell-daemon
```

Binaries land in `build/`. Static, CGO disabled, no runtime dependencies.

## Test

```bash
make test
# equivalent to:
go test ./...

# with race detector (recommended before submitting a PR):
go test -race ./...
```

```
ok  	ghostshell/internal/cast      0.003s
ok  	ghostshell/internal/crypto    0.021s
ok  	ghostshell/internal/play      0.008s
ok  	ghostshell/internal/store     0.005s
ok  	ghostshell/internal/ansible   0.006s
```

## Packages

```bash
# install nfpm first
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

make deb          # → release/ghostshell_<ver>_amd64.deb
make rpm          # → release/ghostshell-<ver>-1.x86_64.rpm
make packages     # both

make VERSION=1.2.3 packages   # pin an explicit version
```

## Project layout

```
cmd/ghostshell/        CLI entry point (subcommand dispatch)
cmd/ghostshell-daemon/       daemon entry point
internal/cast/     asciinema v2 cast read/write
internal/crypto/   at-rest AES-256-GCM encryption (+ tests)
internal/record/   PTY capture for `ghostshell rec`
internal/play/     replay player (snapshot-bounded, scrollback viewer, statusbar)
internal/store/    storage paths + transparent decrypt
internal/audit/    root-only audit commands (ls-user, tree, search, export, prune)
internal/daemon/   ghostshell-daemon socket server, live tail fan-out, ingest, key mgmt
internal/ansible/  Ansible run model + list/show commands
internal/complete/ bash completion
scripts/ansible/   Ansible callback plugin (Python)
scripts/profile.d/ auto-record login hook
man/               ghostshell.1 man page source (troff)
nfpm.yaml          package metadata for deb/rpm
.github/workflows/ CI/CD pipeline
```

## CI/CD pipeline

Every push to `main` runs `.github/workflows/pipeline.yml`:

| Stage | What it does |
|:------|:-------------|
| Build | `make build` |
| Test | `go test -race ./...` |
| Lint | `golangci-lint run` |
| Package | `make packages` — deb + rpm + static binary |
| Release | Bumps patch version from latest tag, creates GitHub Release with artifacts + `SHA256SUMS` |

Pushing an explicit `v*` tag bypasses the auto-bump and publishes a release at that exact version.

## Daemon wire protocol

```
Client connects to /run/ghostshell-daemon.sock and sends one of:

  REC\n              stream a new session cast (asciinema v2 JSON-lines)
  TAIL <id>\n        receive a live-tail stream of session <id>
  ANSIBLE <id>\n     stream a new ansible run JSON-lines
```

Auth via `SO_PEERCRED` (Linux peer credentials). The UID from the credentials determines which user's store directory is written to. Root can read all.

## Encryption internals

`internal/crypto` implements AES-256-GCM streaming encryption:

- Key: 32 random bytes, stored at `/var/lib/ghostshell/.ghostshell.key` (`root:root 0600`, `chattr +i`).
- Each file starts with magic prefix `TTEC1`, followed by a random 12-byte nonce, then ciphertext in chunks.
- `ghostshell export`, `play-user`, `search`, and `tail` decrypt transparently via `crypto.NewReader`.
- The daemon writes via `crypto.NewWriter`; it never touches plaintext after encryption.

## Contributing

1. Fork the repository and create a feature branch (never push directly to `main`).
2. Run `make fmt`, `make vet`, `make test` — CI enforces all three.
3. Add or update tests for any changed behavior. Run with `-race`.
4. Open a pull request; describe what and why (the diff shows how).

See [CONTRIBUTING.md](https://github.com/Karannnnn614/Ghost-Shell/blob/main/CONTRIBUTING.md) for the full guide.
