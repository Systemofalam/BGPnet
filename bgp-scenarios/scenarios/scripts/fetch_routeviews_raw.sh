#!/usr/bin/env bash
set -euo pipefail

if [ $# < 2 ]; then
    echo "Usage: $0 <updates_url> <label> [out_dir]" >&2
    echo "Example:" >&2
    echo "  $0 http://archive.routeviews.org/bgpdata/2023.01/UPDATES/updates.20230101.0000.bz2 rv2_20230101_1h" >&2
    exit 1
fi

URL="$1"
LABEL="$2"
OUT_ROOT="${3:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/raw}"

mkdir -p "$OUT_ROOT"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[fetch] Downloading $URL ..."
curl -L "$URL" -o "$TMPDIR/updates.bz2"

if ! command -v bgpdump >/dev/null 2>&1; then
    echo "[fetch] ERROR: bgpdump not found in PATH. Please install it." >&2
    exit 1
fi

echo "[fetch] Converting MRT to text with bgpdump ..."
bgpdump -m "$TMPDIR/updates.bz2" > "$TMPDIR/updates.txt"

RAW_OUT="$OUT_ROOT/${LABEL}_raw.txt"
echo "[fetch] Extracting update lines to $RAW_OUT ..."
grep '^U|' "$TMPDIR/updates.txt" > "$RAW_OUT"

echo "[fetch] Done. RAW file: $RAW_OUT"
