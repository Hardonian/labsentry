#!/usr/bin/env bash
# labsentry installer — pure-C, zero-dep. Builds from source (or fetches prebuilt).
# Usage:  PREFIX=/usr/local ./install.sh
#   or:   curl -fsSL https://get.labsentry.dev/install.sh | sh   (after remote is set up)
set -euo pipefail

NAME=labsentry
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
REPO="${REPO:-https://github.com/Hardonian/labsentry}"
RELEASE_BASE="${RELEASE_BASE:-https://github.com/Hardonian/labsentry/releases/download/v0.1.0}"

# resolve script dir so we always build from the right place
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ARCH="$(uname -m)"
OS="$(uname -s)"

say(){ printf '\033[36m[%s]\033[0m %s\n' "$NAME" "$1"; }

# If we are inside the repo (Makefile present), build in place.
if [ -f Makefile ] && command -v make >/dev/null 2>&1; then
  say "building from source in $(pwd)"
  make >/dev/null
  SRC_BIN="./$NAME"
elif [ -n "$RELEASE_BASE" ]; then
  OS_LC=$(echo "$OS" | tr "[:upper:]" "[:lower:]"); url="$RELEASE_BASE/$NAME-$OS_LC-$ARCH-static"
  say "downloading prebuilt $url"
  tmp=$(mktemp)
  curl -fsSL "$url" -o "$tmp" || { echo "download failed"; exit 1; }
  chmod +x "$tmp"
  SRC_BIN="$tmp"
else
  say "no Makefile here; cloning $REPO"
  tmpd=$(mktemp -d)
  git clone --depth 1 "$REPO" "$tmpd/$NAME" >/dev/null 2>&1 || { echo "clone failed (no remote yet)"; exit 1; }
  make -C "$tmpd/$NAME" >/dev/null
  SRC_BIN="$tmpd/$NAME/$NAME"
fi

[ -x "$SRC_BIN" ] || { echo "binary not found: $SRC_BIN"; exit 1; }
install -d "$BIN_DIR"
install -m 0755 "$SRC_BIN" "$BIN_DIR/$NAME"
say "installed: $BIN_DIR/$NAME"
"$BIN_DIR/$NAME" gpu >/dev/null 2>&1 && say "smoke ok (gpu probe works)" || say "installed; run '$NAME doctor'"
