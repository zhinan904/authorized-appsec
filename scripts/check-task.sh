#!/usr/bin/env bash
# check-task.sh — Monitor background scan progress and detect failures
#
# Usage:
#   ./scripts/check-task.sh <task_dir> [--skip-connectivity]
#
# Checks:
#   1. Background scan processes (naabu, gobuster, ffuf, nuclei, sqlmap, hydra)
#   2. Output file sizes (zero-byte = failure)
#   3. Tail of recently modified raw/ files
#   4. Target connectivity status
#
# Exit codes: 0 = all healthy, 1 = failures detected

set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

TASK_DIR="${1:-.}"
SKIP_CONNECTIVITY=0
if [[ "${2:-}" == "--skip-connectivity" ]]; then
  SKIP_CONNECTIVITY=1
fi
RAW_DIR="${TASK_DIR}/raw"
TARGET=""
if [[ -f "${TASK_DIR}/task.md" ]]; then
  # task.md uses YAML-style "- target: ..." in the Task Meta section;
  # also accept bare "target:" for compatibility.
  TARGET=$(grep -E '^[[:space:]]*[-[:space:]]*target:' "${TASK_DIR}/task.md" | head -1 | sed -E 's/^[[:space:]]*[-[:space:]]*target:[[:space:]]+//' | tr -d '[:space:]' || true)
fi

failures=0
running=0

echo "=== Task Monitor: ${TASK_DIR} ==="
echo "Target: ${TARGET:-unknown}"
echo ""

# ── 1. Check background processes ──
echo "--- Running Scans ---"
if [[ -f "${TASK_DIR}/.task-pids.json" ]] && command -v jq >/dev/null 2>&1; then
  tracked_pids=$(jq -r '[.main_pid] + (.tool_pids // [] | map(.pid)) | .[] | select(. != null)' "${TASK_DIR}/.task-pids.json" 2>/dev/null || true)
  if [[ -n "$tracked_pids" ]]; then
    while IFS= read -r pid; do
      [[ -n "$pid" ]] || continue
      if ps -p "$pid" >/dev/null 2>&1; then
        cmd=$(ps -p "$pid" -o comm= 2>/dev/null || echo "process")
        echo "  [RUN] tracked: PID $pid ($cmd)"
        running=$((running + 1))
      fi
    done <<< "$tracked_pids"
  fi
else
  task_abs=$(cd "$TASK_DIR" 2>/dev/null && pwd || echo "$TASK_DIR")
  raw_abs=$(cd "$RAW_DIR" 2>/dev/null && pwd || echo "$RAW_DIR")
  for tool in naabu gobuster ffuf nuclei sqlmap hydra nmap masscan; do
    pids=$(ps -eo pid=,args= 2>/dev/null | awk -v tool="$tool" -v task="$task_abs" -v raw="$raw_abs" '
      {
        pid = $1
        line = $0
        sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", line)
      }
      line ~ ("(^|[ /])" tool "([[:space:]]|$)") && (index(line, task) || index(line, raw)) {print pid}
    ' || true)
    if [[ -n "$pids" ]]; then
      count=$(echo "$pids" | wc -l)
      echo "  [RUN] $tool: $count process(es) for this task — PID $(echo $pids | tr '\n' ' ')"
      running=$((running + 1))
    fi
  done
fi
if [[ $running -eq 0 ]]; then
  echo "  (no active scan processes)"
fi
echo ""

# ── 2. Check output file health ──
echo "--- Output Files ---"
if [[ -d "$RAW_DIR" ]]; then
  for f in "$RAW_DIR"/*; do
    [[ -f "$f" ]] || continue
    fname=$(basename "$f")
    fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
    fmtime=$(stat -c%y "$f" 2>/dev/null | cut -d. -f1 || stat -f%Sm "$f" 2>/dev/null || echo "unknown")
    if [[ "$fsize" -eq 0 ]]; then
      echo "  [FAIL] $fname — zero bytes (scan may have failed silently)"
      failures=$((failures + 1))
    elif [[ "$fsize" -lt 100 ]]; then
      echo "  [WARN] $fname — ${fsize} bytes (very small output)"
    else
      echo "  [OK]   $fname — ${fsize} bytes — $fmtime"
    fi
  done
else
  echo "  [WARN] raw/ directory does not exist yet"
fi
echo ""

# ── 3. Tail recent output files ──
echo "--- Recent Results Preview ---"
most_recent=$(find "$RAW_DIR" -type f -name "*.txt" -o -name "*.json" 2>/dev/null | xargs stat -c '%Y:%n' 2>/dev/null | sort -rn | head -3 || true)
if [[ -n "$most_recent" ]]; then
  while IFS=: read -r mtime fpath; do
    echo "  [$fpath]"
    tail -3 "$fpath" 2>/dev/null | while IFS= read -r line; do echo "    | $line"; done
  done <<< "$most_recent"
else
  echo "  (no result files yet)"
fi
echo ""

# ── 4. Target connectivity ──
echo "--- Target Connectivity ---"
if [[ "$SKIP_CONNECTIVITY" -eq 1 ]]; then
  echo "  (connectivity check skipped)"
elif [[ -n "$TARGET" ]]; then
  # Strip protocol prefix for connectivity check
  scheme=$(echo "$TARGET" | sed -nE 's|^(https?)://.*|\1|p')
  host=$(echo "$TARGET" | sed -E 's|^https?://||;s|/.*$||')
  default_port="80"
  if [[ "$scheme" == "https" ]]; then
    default_port="443"
  fi
  port=$(echo "$host" | grep -oE ':[0-9]+' || echo ":${default_port}")
  host=$(echo "$host" | sed 's/:.*//')
  port="${port#:}"
  if timeout 5 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
    echo "  [UP]  ${host}:${port}"
  else
    echo "  [DOWN] ${host}:${port} — port not reachable"
    failures=$((failures + 1))
  fi
else
  echo "  (target unknown, skipping connectivity check)"
fi
echo ""

# ── 5. Summary ──
echo "=== Summary ==="
echo "Running processes: $running"
echo "Failures detected: $failures"
if [[ $failures -gt 0 ]]; then
  echo "Action: re-run failed scans manually or check raw/ output files"
fi

exit $failures
