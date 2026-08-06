#!/usr/bin/env bash
# Clean-environment installation test (Stage 9).
#
# Extracts the built .deb and .rpm into a pristine temporary root (no
# package manager, no root privileges) and verifies that the installed
# binary runs, that it prints a version, and that the installation creates
# no configuration or data directories.
#
# Usage: scripts/clean-install-test.sh [version-dir]
#
# Requirements: cargo-deb, cargo-generate-rpm (to rebuild), dpkg-deb,
# rpm2cpio + cpio.

set -euo pipefail

version_dir="${1:-.}"
cd "$version_dir"

package_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
deb="$(find target/debian -maxdepth 1 -type f -name "veilroom_${package_version}-*.deb" -print -quit 2>/dev/null || true)"
rpm="$(find target/generate-rpm -maxdepth 1 -type f -name "veilroom-${package_version}-*.rpm" -print -quit 2>/dev/null || true)"
[[ -n "$deb" && -n "$rpm" ]] || {
    echo "error: build both packages first (cargo deb, cargo generate-rpm)" >&2
    exit 1
}

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
failures=0
check() {
    local description="$1"
    shift
    if "$@"; then
        echo "ok: $description"
    else
        echo "FAIL: $description" >&2
        failures=$((failures + 1))
    fi
}

echo "== clean-environment install: .deb =="
mkdir -p "$root/deb"
dpkg-deb -x "$deb" "$root/deb"
bin="$root/deb/usr/bin/veilroom"
check "binary is executable" test -x "$bin"
# Paths are passed as positional arguments, never interpolated into shell
# strings, so no path can inject shell syntax.
check "binary reports its version" \
    bash -c '"$1" --version | grep -q "^veilroom 0.2.0"' _ "$bin"
check "binary rejects unknown arguments" \
    bash -c '! "$1" --bogus' _ "$bin"
check "no config or data directory is installed" \
    bash -c '! find "$1" \( -type d -o -type f \) | grep -qE "etc/veilroom|var/lib/veilroom|var/log/veilroom|\.config/veilroom|\.local/share/veilroom"' _ "$root/deb"
check "no application user or group is created" \
    bash -c '! find "$1" -path "*passwd*" -o -path "*group*" | grep -q .' _ "$root/deb"

echo "== clean-environment install: .rpm =="
mkdir -p "$root/rpm"
if command -v rpm2cpio > /dev/null 2>&1; then
    rpm2cpio "$rpm" | (cd "$root/rpm" && cpio -id > /dev/null 2>&1)
else
    python3 "$(dirname "$0")/rpm_list.py" "$rpm" --extract "$root/rpm"
fi
bin="$root/rpm/usr/bin/veilroom"
check "binary is executable" test -x "$bin"
check "binary reports its version" \
    bash -c '"$1" --version | grep -q "^veilroom 0.2.0"' _ "$bin"
check "binary rejects unknown arguments" \
    bash -c '! "$1" --bogus' _ "$bin"
check "no config or data directory is installed" \
    bash -c '! find "$1" \( -type d -o -type f \) | grep -qE "etc/veilroom|var/lib/veilroom|var/log/veilroom|\.config/veilroom|\.local/share/veilroom"' _ "$root/rpm"
check "no application user or group is created" \
    bash -c '! find "$1" -path "*passwd*" -o -path "*group*" | grep -q .' _ "$root/rpm"

# Runtime hygiene: running --version must not create persistent files.
check "no home-directory artifacts" bash -c '
    root="$1"
    bin="$2"
    home="$root/home"
    mkdir -p "$home"
    HOME="$home" XDG_RUNTIME_DIR="$root/runtime" \
        "$bin" --version > /dev/null 2>&1 || true
    test -z "$(find "$home" -mindepth 1 | head -1)"
' _ "$root" "$root/deb/usr/bin/veilroom"

if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures check(s)" >&2
    exit 1
fi
echo "all clean-environment install checks passed"
