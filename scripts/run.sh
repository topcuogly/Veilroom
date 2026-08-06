#!/usr/bin/env bash
# Builds and runs Veilroom from source, without installing a .deb or .rpm.
#
# Usage: scripts/run.sh [veilroom-args...]
#
# Examples:
#   scripts/run.sh                 # build (if needed) and start the TUI
#   scripts/run.sh --version
#   scripts/run.sh --help
#
# The interactive TUI requires a `tor` binary on PATH, a configured
# $XDG_RUNTIME_DIR, and a non-root user, matching the packaged binary.
# `--version` and `--help` run without those checks.

set -euo pipefail

cd "$(dirname "$0")/.."

binary="target/release/veilroom"

# Non-interactive flags need no Tor, no runtime directory, and no root check.
interactive=true
case "${1:-}" in
    --version | -V | --help | -h) interactive=false ;;
esac

if [[ "$interactive" == true ]]; then
    if [[ -z "${XDG_RUNTIME_DIR:-}" ]]; then
        echo "error: \$XDG_RUNTIME_DIR is not set; Veilroom refuses to fall back to /tmp" >&2
        exit 1
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
        echo "error: Veilroom refuses to run as root" >&2
        exit 1
    fi
    if ! command -v tor >/dev/null 2>&1; then
        echo "warning: 'tor' not found on PATH; connections will fail until it is installed" >&2
    fi
fi

# Locate cargo: on PATH, or in the standard rustup locations
# ($CARGO_HOME/bin, ~/.cargo/bin).
cargo_bin="$(command -v cargo || true)"
if [[ -z "$cargo_bin" ]]; then
    for candidate in "${CARGO_HOME:-$HOME/.cargo}/bin/cargo" "$HOME/.cargo/bin/cargo"; do
        if [[ -x "$candidate" ]]; then
            cargo_bin="$candidate"
            break
        fi
    done
fi
if [[ -z "$cargo_bin" ]]; then
    echo "error: cargo not found on PATH, \$CARGO_HOME/bin, or ~/.cargo/bin" >&2
    exit 1
fi

# Rebuild the binary when it is missing or older than the sources.
if [[ ! -x "$binary" ]] || find src Cargo.toml Cargo.lock -newer "$binary" -print -quit | grep -q .; then
    echo "building the release binary..." >&2
    "$cargo_bin" build --release
fi

exec "$binary" "$@"
