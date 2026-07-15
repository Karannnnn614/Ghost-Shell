.PHONY: all build check test fmt vet lint staticcheck tidy install clean rpm deb packages

PREFIX ?= /usr/local
VERSION ?= 1.0.43
NFPM ?= $(shell go env GOPATH)/bin/nfpm

# Linker flags. CGO_ENABLED=0 already yields a fully static binary (no libc
# dependency); -s -w strips the symbol table and DWARF debug info for size, and
# -X stamps the version. -trimpath removes local filesystem paths for
# reproducibility. Both binaries get the same flags so they are equally static.
LDFLAGS := -s -w -X main.Version=$(VERSION)

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ghostshell ./cmd/ghostshell
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ghostshell-daemon ./cmd/ghostshell-daemon

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

# Optional quality gates. These require external tools and are intentionally
# kept out of `build` so a plain `make build` never fails for a missing linter.
# Install: go install honnef.co/go/tools/cmd/staticcheck@latest
#          go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
staticcheck:
	staticcheck ./...

lint:
	golangci-lint run ./...

# Verify go.mod / go.sum are tidy without mutating them (CI-friendly).
# Falls back to a plain `go mod tidy` check on older toolchains.
tidy:
	go mod tidy -diff

# One-shot quality gate: runs every check in order and stops at the first
# failure (fail-fast — each recipe line aborts the target on non-zero exit).
# Mirrors CI (.github/workflows/ci.yml). Requires staticcheck and golangci-lint
# on PATH (see the staticcheck/lint targets for install commands).
check:
	@echo '>> gofmt';       test -z "$$(gofmt -l $$(find . -name '*.go'))" || { echo 'gofmt: needs formatting:'; gofmt -l $$(find . -name '*.go'); exit 1; }
	@echo '>> go vet';      go vet ./...
	@echo '>> staticcheck'; staticcheck ./...
	@echo '>> golangci';    golangci-lint run ./...
	@echo '>> go test';     go test ./... -count=1
	@echo '>> build';       $(MAKE) build

install: build
	install -Dm755 bin/ghostshell $(DESTDIR)$(PREFIX)/bin/ghostshell
	install -Dm755 bin/ghostshell-daemon $(DESTDIR)/usr/libexec/ghostshell-daemon
	install -Dm644 man/ghostshell.1 $(DESTDIR)$(PREFIX)/share/man/man1/ghostshell.1
	install -Dm644 scripts/systemd/ghostshell-daemon.service $(DESTDIR)/lib/systemd/system/ghostshell-daemon.service
	install -Dm644 internal/complete/ghostshell.bash $(DESTDIR)$(PREFIX)/share/bash-completion/completions/ghostshell
	install -Dm755 scripts/ghostshell-ssh-wrap.sh $(DESTDIR)/usr/libexec/ghostshell-ssh-wrap
	install -Dm644 scripts/sshd-forcecommand.conf.example $(DESTDIR)$(PREFIX)/share/doc/ghostshell/sshd-forcecommand.conf.example
	install -Dm644 scripts/trace-shim.sh $(DESTDIR)/usr/share/ghostshell/trace-shim.sh
	install -dm700 $(DESTDIR)/var/lib/ghostshell
	install -dm750 $(DESTDIR)/var/log/ghostshell

packages: rpm deb

rpm: build
	@mkdir -p release
	GHOSTSHELL_VERSION=$(VERSION) $(NFPM) pkg --config nfpm.yaml --packager rpm --target release/

deb: build
	@mkdir -p release
	GHOSTSHELL_VERSION=$(VERSION) $(NFPM) pkg --config nfpm.yaml --packager deb --target release/

clean:
	rm -rf bin release
	rm -f *.cast *.prof *.test coverage.out
