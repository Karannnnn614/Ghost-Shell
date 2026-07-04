# Contributing to ghostshell

ghostshell is **100% open source** (GPL-2.0) and community-driven. Bug reports,
feature ideas, and pull requests are all welcome.

## Report a bug or request an enhancement

Open an issue: <https://github.com/Karannnnn614/Ghost-Shell/issues>

- **Bug:** include your distro, ghostshell version (`ghostshell --help` / release tag), the
  exact command, what you expected, and what happened. Logs help:
  `journalctl -u ghostshell-daemon --no-pager`.
- **Enhancement:** describe the use case and the behavior you want. Small, focused
  proposals are easiest to land.

## Submit a pull request

1. Fork the repo and create a branch: `git checkout -b feat/short-description`.
2. Make your change. Keep it focused — one logical change per PR.
3. Run the checks CI enforces:

   ```bash
   make fmt
   make vet
   make test
   make build
   ```

4. Commit with a clear message describing the *why*.
5. Push your branch and open a PR against `main`. Describe the change and link any
   related issue.

CI runs `gofmt`, `go vet`, the test suite, a build, and a package build on every
push and PR — green CI is required.

## Project layout

```text
cmd/ghostshell       CLI (rec/play/ls/tail/tree/search/export/ansible/backup/init)
cmd/ghostshell-daemon      root collector daemon
internal/cast    asciinema v2 cast read/write
internal/crypto  at-rest AES-256-GCM encryption (+ tests)
internal/record  PTY capture
internal/play    replay
internal/store   storage paths + transparent decrypt
internal/audit   root-only audit commands
internal/daemon  socket server, live tail fan-out, ingest, key management
internal/complete shell completion
```

## Tests

Unit tests live next to the code (`*_test.go`). Add tests for new behavior,
especially in `internal/crypto` and `internal/cast` where correctness matters.

```bash
go test ./...
```

## License

By contributing you agree your contributions are licensed under the project's
GPL-2.0 license. See [LICENSE](LICENSE).
