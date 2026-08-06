#!/usr/bin/env bash
# Verifies the contents of the built .deb and .rpm packages (Stage 9).
#
# Usage: scripts/check-package-contents.sh [version-dir]
#
# Requirements: cargo-deb, cargo-generate-rpm (to rebuild), dpkg-deb,
# rpm2cpio + cpio (to inspect), and the host package tools.

set -euo pipefail

version_dir="${1:-.}"
cd "$version_dir"

package_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
deb="$(find target/debian -maxdepth 1 -type f -name "veilroom_${package_version}-*.deb" -print -quit 2>/dev/null || true)"
rpm="$(find target/generate-rpm -maxdepth 1 -type f -name "veilroom-${package_version}-*.rpm" -print -quit 2>/dev/null || true)"

if [[ -z "$deb" ]]; then
    echo "error: no .deb found; run cargo deb first" >&2
    exit 1
fi
if [[ -z "$rpm" ]]; then
    echo "error: no .rpm found; run cargo generate-rpm first" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
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

echo "== .deb: $deb =="
dpkg-deb --contents "$deb" > "$tmp/deb.listing"
check "binary installed to /usr/bin/veilroom" \
    grep -q '/usr/bin/veilroom' "$tmp/deb.listing"
# The bash -c invocations receive paths as positional arguments, never by
# string interpolation, so no value can inject shell syntax.
check "depends on tor" \
    bash -c 'dpkg-deb --field "$1" Depends | grep -q "tor"' _ "$deb"
check "ships README" \
    grep -q 'usr/share/doc/veilroom/README.md' "$tmp/deb.listing"
check "ships protocol document" \
    grep -q 'usr/share/doc/veilroom/protocol-v1.md' "$tmp/deb.listing"
check "ships test vectors" \
    grep -q 'usr/share/doc/veilroom/test-vectors.md' "$tmp/deb.listing"
check "ships the license as copyright" \
    grep -q 'usr/share/doc/veilroom/copyright' "$tmp/deb.listing"
check "ships the license under /usr/share/licenses/veilroom" \
    grep -q 'usr/share/licenses/veilroom/LICENSE' "$tmp/deb.listing"
check "installs no systemd unit" \
    bash -c '! grep -q "lib/systemd\|etc/systemd" "$1"' _ "$tmp/deb.listing"
check "installs no config directory" \
    bash -c '! grep -q "etc/veilroom" "$1"' _ "$tmp/deb.listing"

echo "== .rpm: $rpm =="
if command -v rpm2cpio > /dev/null 2>&1; then
    rpm2cpio "$rpm" > "$tmp/contents.cpio" 2>/dev/null
    (cd "$tmp" && cpio -id < "$tmp/contents.cpio" > /dev/null 2>&1)
    cpio -it < "$tmp/contents.cpio" > "$tmp/rpm.listing" 2>/dev/null
else
    python3 "$(dirname "$0")/rpm_list.py" "$rpm" > "$tmp/rpm.listing"
    while IFS= read -r entry; do
        # Never follow entries that could escape the temp root.
        case "$entry" in
            *..*) continue ;;
        esac
        target="$tmp/${entry#./}"
        mkdir -p "$(dirname "$target")"
        case "$entry" in
            */) mkdir -p "$target" ;;
        esac
    done < "$tmp/rpm.listing"
fi
check "binary installed to /usr/bin/veilroom" \
    grep -q '/usr/bin/veilroom$' "$tmp/rpm.listing"
check "ships README" \
    grep -q '/usr/share/doc/veilroom/README.md$' "$tmp/rpm.listing"
check "ships protocol document" \
    grep -q '/usr/share/doc/veilroom/protocol-v1.md$' "$tmp/rpm.listing"
check "ships test vectors" \
    grep -q '/usr/share/doc/veilroom/test-vectors.md$' "$tmp/rpm.listing"
check "ships the license" \
    grep -q '/usr/share/licenses/veilroom/LICENSE$' "$tmp/rpm.listing"
check "installs no systemd unit" \
    bash -c '! grep -q "lib/systemd\|etc/systemd" "$1"' _ "$tmp/rpm.listing"
check "installs no config directory" \
    bash -c '! grep -q "etc/veilroom" "$1"' _ "$tmp/rpm.listing"

if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures check(s)" >&2
    exit 1
fi
echo "all package-content checks passed"
