#!/usr/bin/env bash
# Build a release archive, excluding runtime artifacts and macOS AppleDouble files.
#
# Usage:
#   scripts/build-public-package.sh [out_dir]            # public build (no references/l3)
#   scripts/build-public-package.sh [out_dir] --full      # full build (keeps references/ knowledge base)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist}"
FULL=0
[[ "${2:-}" == "--full" ]] && FULL=1
VERSION="$(grep -Eo 'Version\*\*: [0-9]+\.[0-9]+\.[0-9]+' "$ROOT/SKILL.md" | awk '{print $2}' | head -1)"
VERSION="${VERSION:-dev}"
if [[ "$FULL" -eq 1 ]]; then
  ARCHIVE="$OUT_DIR/authorized-appsec-full-$VERSION.tar.gz"
else
  ARCHIVE="$OUT_DIR/authorized-appsec-skill-$VERSION.tar.gz"
fi

mkdir -p "$OUT_DIR"

# Common excludes: runtime artifacts, caches, macOS metadata. These apply to every build.
EXCLUDES=(
  --exclude='./results'
  --exclude='./raw'
  --exclude='./screenshots'
  --exclude='./dist'
  --exclude='./build'
  --exclude='./.git'
  --exclude='./.venv'
  --exclude='./.pytest_cache'
  --exclude='./__pycache__'
  --exclude='*/__pycache__'
  --exclude='*.pyc'
  --exclude='*.pyo'
  --exclude='.DS_Store'
  --exclude='*/.DS_Store'
  --exclude='._*'          # macOS AppleDouble resource-fork metadata
  --exclude='*/._*'        # ... in subdirectories too
  --exclude='*.har'
  --exclude='*.burp'
  --exclude='*.pcap'
  --exclude='*.pcapng'
  --exclude='*.sqlite'
  --exclude='*.sqlite3'
  --exclude='*.db'
  --exclude='*.log'
)

# Public build additionally drops the private knowledge base.
if [[ "$FULL" -eq 0 ]]; then
  EXCLUDES+=(--exclude='./references' --exclude='./l3')
fi

tar "${EXCLUDES[@]}" -czf "$ARCHIVE" -C "$ROOT" .

echo "$ARCHIVE"
