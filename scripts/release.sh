#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# release.sh — manual release script for ghostshell
# Usage: ./scripts/release.sh [VERSION]
# If VERSION is omitted, patch is auto-bumped from latest git tag.
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# --- dependency check -------------------------------------------------------
if ! command -v gh >/dev/null 2>&1; then
    echo "ERROR: gh CLI not found. Install with:"
    echo "  go install github.com/cli/cli/v2/cmd/gh@latest"
    exit 1
fi

# --- working tree must be clean ---------------------------------------------
echo "==> checking git working tree"
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "ERROR: working tree has uncommitted changes. Commit or stash first."
    exit 1
fi

# --- resolve version --------------------------------------------------------
if [ -n "$1" ]; then
    VERSION="$1"
else
    echo "==> auto-bumping patch from latest git tag"
    LATEST_TAG="$(git tag --list 'v*.*.*' --sort=-version:refname | head -1)"
    if [ -z "$LATEST_TAG" ]; then
        echo "ERROR: no v*.*.* tags found and no VERSION argument given"
        exit 1
    fi
    # strip leading 'v'
    LATEST="${LATEST_TAG#v}"
    MAJOR="$(echo "$LATEST" | cut -d. -f1)"
    MINOR="$(echo "$LATEST" | cut -d. -f2)"
    PATCH="$(echo "$LATEST" | cut -d. -f3)"
    PATCH="$((PATCH + 1))"
    VERSION="${MAJOR}.${MINOR}.${PATCH}"
fi

echo "==> releasing version ${VERSION}"
TODAY="$(date +%Y-%m-%d)"

# --- update Makefile --------------------------------------------------------
echo "==> updating Makefile VERSION"
sed -i "s/VERSION ?= [0-9]\+\.[0-9]\+\.[0-9]\+/VERSION ?= ${VERSION}/" Makefile

# --- update man page --------------------------------------------------------
echo "==> updating man/ghostshell.1"
sed -i "s/\.TH GHOSTSHELL 1 \"[^\"]*\" \"ghostshell [0-9]\+\.[0-9]\+\.[0-9]\+\"/.TH GHOSTSHELL 1 \"${TODAY}\" \"ghostshell ${VERSION}\"/" man/ghostshell.1

# --- update README.md -------------------------------------------------------
echo "==> updating README.md"
sed -i \
    -e "s|releases/download/v[0-9]\+\.[0-9]\+\.[0-9]\+|releases/download/v${VERSION}|g" \
    -e "s|ghostshell_[0-9]\+\.[0-9]\+\.[0-9]\+|ghostshell_${VERSION}|g" \
    -e "s|ghostshell-[0-9]\+\.[0-9]\+\.[0-9]\+|ghostshell-${VERSION}|g" \
    README.md

# --- build packages (RPM + DEB) ---------------------------------------------
echo "==> building packages (make packages)"
make packages

# --- copy binary ------------------------------------------------------------
echo "==> copying binary to release/"
mkdir -p release
cp bin/ghostshell "release/ghostshell-${VERSION}-linux-amd64"

# --- SHA256 checksums -------------------------------------------------------
echo "==> generating SHA256SUMS"
(cd release && sha256sum *.rpm *.deb "ghostshell-${VERSION}-linux-amd64" > SHA256SUMS)

# --- git commit -------------------------------------------------------------
echo "==> committing release files"
git add Makefile man/ghostshell.1 README.md
git commit -m "chore: release v${VERSION}"

# --- git tag ----------------------------------------------------------------
echo "==> tagging v${VERSION}"
git tag -a "v${VERSION}" -m "ghostshell v${VERSION}"

# --- git push ---------------------------------------------------------------
echo "==> pushing main and tag"
git push origin main
git push origin "v${VERSION}"

# --- GitHub release ---------------------------------------------------------
echo "==> creating GitHub release"
gh release create "v${VERSION}" \
    --title "v${VERSION}" \
    --notes "ghostshell ${VERSION}" \
    release/*.rpm \
    release/*.deb \
    "release/ghostshell-${VERSION}-linux-amd64" \
    release/SHA256SUMS

echo "==> done — v${VERSION} released"
