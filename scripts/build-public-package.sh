#!/usr/bin/env bash
# Build a public release archive while excluding private knowledge and runtime artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist}"
VERSION="$(grep -Eo 'Version\*\*: [0-9]+\.[0-9]+\.[0-9]+' "$ROOT/SKILL.md" | awk '{print $2}' | head -1)"
VERSION="${VERSION:-dev}"
ARCHIVE="$OUT_DIR/authorized-appsec-skill-$VERSION.tar.gz"

mkdir -p "$OUT_DIR"

tar \
  --exclude='./references' \
  --exclude='./l3' \
  --exclude='./results' \
  --exclude='./raw' \
  --exclude='./screenshots' \
  --exclude='./dist' \
  --exclude='./build' \
  --exclude='./.git' \
  --exclude='./.venv' \
  --exclude='./.pytest_cache' \
  --exclude='./__pycache__' \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.pyo' \
  --exclude='.DS_Store' \
  --exclude='*.har' \
  --exclude='*.burp' \
  --exclude='*.pcap' \
  --exclude='*.pcapng' \
  --exclude='*.sqlite' \
  --exclude='*.sqlite3' \
  --exclude='*.db' \
  --exclude='*.log' \
  -czf "$ARCHIVE" \
  -C "$ROOT" .

echo "$ARCHIVE"
