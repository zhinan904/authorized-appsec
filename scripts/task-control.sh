#!/usr/bin/env bash
# task-control.sh
# Control sub-task execution: monitor, pause, resume, terminate
#
# Usage:
#   ./scripts/task-control.sh monitor <task_dir>
#   ./scripts/task-control.sh terminate <task_dir> [--force]
#   ./scripts/task-control.sh terminate-batch <batch_dir> [--target <target_id>]
#   ./scripts/task-control.sh status <task_dir>
#   ./scripts/task-control.sh list-processes <batch_dir>

set -e

# Check jq dependency for PID file operations
if ! command -v jq >/dev/null 2>&1; then
  echo "Warning: jq is not installed. PID file operations will be limited."
  echo "Install: brew install jq (macOS) or apt install jq (Linux)"
fi

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

COMMAND="${1:-help}"
TARGET="${2:-}"
SPECIFIC_TARGET=""
TOOL_PID=""
TOOL_NAME=""
FORCE_MODE=""
# Support various flag forms
shift 2 2>/dev/null || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target=*)
      SPECIFIC_TARGET="${1#--target=}"
      shift
      ;;
    --target)
      SPECIFIC_TARGET="$2"
      shift 2
      ;;
    --pid=*)
      TOOL_PID="${1#--pid=}"
      shift
      ;;
    --pid)
      TOOL_PID="$2"
      shift 2
      ;;
    --name=*)
      TOOL_NAME="${1#--name=}"
      shift
      ;;
    --name)
      TOOL_NAME="$2"
      shift 2
      ;;
    --force)
      FORCE_MODE="force"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

# PID file location
PID_FILE_NAME=".task-pids.json"

# Help
show_help() {
  echo "Task Control - Sub-task execution management"
  echo ""
  echo "Usage:"
  echo "  $0 monitor <task_dir> [--pid <pid>] - Monitor task, record PID (or use --pid)"
  echo "  $0 terminate <task_dir> [--force] - Terminate task processes"
  echo "  $0 terminate-batch <batch_dir>   - Terminate all batch sub-tasks"
  echo "  $0 terminate-batch <batch_dir> --target <T-XXX> - Terminate specific target"
  echo "  $0 status <task_dir>             - Show task process status"
  echo "  $0 list-processes <batch_dir>    - List all processes in batch"
  echo "  $0 cleanup <task_dir>            - Clean up PID file after task ends"
  echo "  $0 add-tool-pid <task_dir> --pid <pid> --name <name> - Add tool PID"
  echo "  $0 cleanup-tool-pid <task_dir> --pid <pid> - Remove tool PID"
  echo ""
  echo "Process Signals:"
  echo "  SIGTERM (default) - Graceful termination, allow cleanup"
  echo "  SIGKILL (--force) - Immediate termination, no cleanup"
  echo ""
  echo "Target ID Format:"
  echo "  Use T-XXX format (e.g., T-001, T-003) for terminate-batch --target"
  echo ""
  echo "PID Tracking:"
  echo "  Each task directory has .task-pids.json"
  echo "  Records: main_pid, tool_pids[], start_time, status"
}

# Get PID file path
get_pid_file() {
  local task_dir="$1"
  echo "${task_dir}/${PID_FILE_NAME}"
}

# Initialize PID file
init_pid_file() {
  local task_dir="$1"
  local pid_file=$(get_pid_file "$task_dir")

  if [[ ! -f "$pid_file" ]]; then
    echo '{"main_pid": null, "tool_pids": [], "start_time": null, "status": "not_started", "signals_received": []}' > "$pid_file"
    echo -e "${GREEN}✓${NC} Initialized PID file: $pid_file"
  fi
}

# Record process
record_pid() {
  local task_dir="$1"
  local main_pid="$2"
  local pid_file=$(get_pid_file "$task_dir")

  init_pid_file "$task_dir"

  local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  # Update PID file with jq
  if command -v jq >/dev/null 2>&1; then
    jq --arg pid "$main_pid" --arg time "$timestamp" \
       '.main_pid = $pid | .start_time = $time | .status = "running"' \
       "$pid_file" > "${pid_file}.tmp" && mv "${pid_file}.tmp" "$pid_file"
    echo -e "${GREEN}✓${NC} Recorded main PID: $main_pid"
  else
    echo "Warning: jq not installed, PID tracking limited"
    # Sanitize PID to prevent JSON injection
    if [[ "$main_pid" =~ ^[0-9]+$ ]]; then
      echo "{\"main_pid\": $main_pid, \"start_time\": \"$timestamp\", \"status\": \"running\"}" > "$pid_file"
    else
      echo "Error: invalid PID value: $main_pid" >&2
      return 1
    fi
  fi
}

# Add tool PID
add_tool_pid() {
  local task_dir="$1"
  local tool_pid="$2"
  local tool_name="${3:-unknown}"
  local pid_file=$(get_pid_file "$task_dir")

  init_pid_file "$task_dir"

  if [[ ! "$tool_pid" =~ ^[0-9]+$ ]]; then
    echo "Error: invalid PID value: $tool_pid" >&2
    return 1
  fi

  if command -v jq >/dev/null 2>&1; then
    if jq --arg pid "$tool_pid" --arg name "$tool_name" \
       '.tool_pids += [{"pid": $pid, "name": $name, "started": (now | strftime("%Y-%m-%dT%H:%M:%SZ"))}]' \
       "$pid_file" > "${pid_file}.tmp"; then
      mv "${pid_file}.tmp" "$pid_file"
      echo -e "${GREEN}✓${NC} Added tool PID: $tool_pid ($tool_name)"
    else
      rm -f "${pid_file}.tmp"
      echo "Error: failed to update PID file: $pid_file" >&2
      return 1
    fi
  else
    echo "Error: jq is required for tool PID tracking" >&2
    return 1
  fi
}

# Get status
get_status() {
  local task_dir="$TARGET"
  local pid_file=$(get_pid_file "$task_dir")

  if [[ ! -f "$pid_file" ]]; then
    echo -e "${YELLOW}!${NC} No PID file found"
    echo "Status: not_tracked"
    return 1
  fi

  echo "=== Task Process Status ==="
  echo "Task Dir: $task_dir"
  echo ""

  if command -v jq >/dev/null 2>&1; then
    local main_pid=$(jq -r '.main_pid' "$pid_file")
    local status=$(jq -r '.status' "$pid_file")
    local start_time=$(jq -r '.start_time' "$pid_file")
    local tool_count=$(jq '.tool_pids | length' "$pid_file")

    echo "Main PID: $main_pid"
    echo "Status: $status"
    echo "Started: $start_time"
    echo "Tool Processes: $tool_count"

    # Check if main process alive
    if [[ "$main_pid" != "null" ]]; then
      if ps -p "$main_pid" >/dev/null 2>&1; then
        echo -e "Process: ${GREEN}ALIVE${NC}"
      else
        echo -e "Process: ${RED}DEAD${NC}"
        # Update status
        jq '.status = "terminated"' "$pid_file" > "${pid_file}.tmp" && mv "${pid_file}.tmp" "$pid_file"
      fi
    fi

    # Show tool processes
    if [[ "$tool_count" -gt 0 ]]; then
      echo ""
      echo "Tool Processes:"
      jq -r '.tool_pids[] | "  - \(.name): PID \(.pid)"' "$pid_file"

      # Check each tool process
      local alive_count=0
      local dead_count=0
      while IFS= read -r pid; do
        if ps -p "$pid" >/dev/null 2>&1; then
          ((alive_count++)) || true
        else
          ((dead_count++)) || true
        fi
      done < <(jq -r '.tool_pids[].pid' "$pid_file")

      echo "  Alive: $alive_count, Dead: $dead_count"
    fi
  else
    cat "$pid_file"
  fi
}

# Terminate task
terminate_task() {
  local task_dir="${1:-$TARGET}"
  local pid_file=$(get_pid_file "$task_dir")

  if [[ ! -f "$pid_file" ]]; then
    echo -e "${RED}✗${NC} No PID file found: $pid_file"
    echo "Cannot terminate - process not tracked"
    return 1
  fi

  echo "=== Terminating Task ==="
  echo "Task Dir: $task_dir"

  local main_pid=$(jq -r '.main_pid' "$pid_file")
  local status=$(jq -r '.status' "$pid_file")

  if [[ "$main_pid" == "null" ]]; then
    echo -e "${YELLOW}!${NC} No main PID recorded"
    return 0
  fi

  if [[ "$status" == "terminated" ]]; then
    echo -e "${YELLOW}!${NC} Task already terminated"
    return 0
  fi

  # Determine signal
  local signal="TERM"
  if [[ "$FORCE_MODE" == "force" ]]; then
    signal="KILL"
    echo -e "${RED}FORCED TERMINATION${NC} (SIGKILL)"
  else
    echo -e "${YELLOW}Graceful termination${NC} (SIGTERM)"
  fi

  # Kill main process
  echo "Terminating main process: $main_pid"
  if ps -p "$main_pid" >/dev/null 2>&1; then
    kill -s $signal "$main_pid" 2>/dev/null || true

    if [[ "$signal" == "TERM" ]]; then
      # Wait for graceful shutdown
      sleep 2
      if ps -p "$main_pid" >/dev/null 2>&1; then
        echo -e "${YELLOW}!${NC} Process still alive, sending SIGKILL"
        kill -9 "$main_pid" 2>/dev/null || true
      fi
    fi

    echo -e "${GREEN}✓${NC} Main process terminated"
  else
    echo -e "${YELLOW}!${NC} Main process already dead"
  fi

  # Kill tool processes
  local tool_count=$(jq '.tool_pids | length' "$pid_file")
  if [[ "$tool_count" -gt 0 ]]; then
    echo "Terminating tool processes..."
    while IFS= read -r pid; do
      if ps -p "$pid" >/dev/null 2>&1; then
        kill -s $signal "$pid" 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} Killed: $pid"
      fi
    done < <(jq -r '.tool_pids[].pid' "$pid_file")
  fi

  # Update status
  local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  jq --arg time "$timestamp" --arg signal "$signal" \
     '.status = "terminated" | .signals_received += [{"signal": $signal, "time": $time}]' \
     "$pid_file" > "${pid_file}.tmp" && mv "${pid_file}.tmp" "$pid_file"

  # Update task.md
  if [[ -f "${task_dir}/task.md" ]]; then
    local task_md="${task_dir}/task.md"
    # Add stop record
    echo "" >> "$task_md"
    echo "## Stop Record" >> "$task_md"
    echo "- triggered_at: $timestamp" >> "$task_md"
    echo "- condition: manual_termination" >> "$task_md"
    echo "- signal: $signal" >> "$task_md"
    echo "- source: task-control.sh" >> "$task_md"

    # Update status in task.md
    if grep -q "^- status:" "$task_md" 2>/dev/null; then
      sed -i '' 's/^- status: .*/- status: stopped/' "$task_md" 2>/dev/null || \
      sed -i 's/^- status: .*/- status: stopped/' "$task_md"
    elif grep -q "^status:" "$task_md" 2>/dev/null; then
      sed -i '' 's/^status: .*/status: stopped/' "$task_md" 2>/dev/null || \
      sed -i 's/^status: .*/status: stopped/' "$task_md"
    fi
  fi

  echo ""
  echo -e "${GREEN}✓ Task terminated${NC}"
  echo "PID file preserved: $pid_file"
}

# Terminate batch
terminate_batch() {
  local batch_dir="$TARGET"

  if [[ ! -d "$batch_dir" ]]; then
    echo -e "${RED}✗${NC} Batch directory not found: $batch_dir"
    return 1
  fi

  echo "=== Terminating Batch ==="
  echo "Batch Dir: $batch_dir"

  # Find all task directories
  local targets_dir="${batch_dir}/targets"

  if [[ ! -d "$targets_dir" ]]; then
    echo -e "${RED}✗${NC} No targets directory found"
    return 1
  fi

  local terminated_count=0

  # Terminate specific target or all
  for task_dir in "$targets_dir"/T-*; do
    if [[ ! -d "$task_dir" ]]; then
      continue
    fi

    # Extract target_id from directory name (T-001-slug → T-001)
    local dir_name=$(basename "$task_dir")
    local target_id=$(echo "$dir_name" | cut -d- -f1-2)  # T-001

    # Check if specific target requested
    if [[ -n "$SPECIFIC_TARGET" ]]; then
      if [[ "$target_id" != "$SPECIFIC_TARGET" ]]; then
        continue
      fi
      echo "Targeting: $target_id"
    fi

    local pid_file=$(get_pid_file "$task_dir")

    if [[ -f "$pid_file" ]]; then
      local status=$(jq -r '.status' "$pid_file")

      if [[ "$status" == "running" ]]; then
        echo ""
        echo "Terminating: $(basename "$task_dir")"
        terminate_task "$task_dir"
        ((terminated_count++)) || true
      fi
    fi
  done

  echo ""
  echo -e "${GREEN}✓ Terminated $terminated_count tasks${NC}"

  # Update batch.md
  if [[ -f "${batch_dir}/batch.md" ]]; then
    local batch_md="${batch_dir}/batch.md"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    echo "" >> "$batch_md"
    echo "## Batch Termination" >> "$batch_md"
    echo "- triggered_at: $timestamp" >> "$batch_md"
    echo "- terminated_count: $terminated_count" >> "$batch_md"
    echo "- source: manual (task-control.sh)" >> "$batch_md"
  fi

  # Update targets.json
  if [[ -f "${batch_dir}/targets.json" ]]; then
    local targets_json="${batch_dir}/targets.json"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    jq --arg time "$timestamp" \
       '.targets[] |= if .status == "in_progress" then .status = "stopped" | .stop_triggered = "manual_termination" | .stop_details = "Force terminated by user" else . end' \
       "$targets_json" > "${targets_json}.tmp" && mv "${targets_json}.tmp" "$targets_json"
  fi
}

# List processes in batch
list_processes() {
  local batch_dir="$TARGET"

  if [[ ! -d "$batch_dir" ]]; then
    echo -e "${RED}✗${NC} Batch directory not found: $batch_dir"
    return 1
  fi

  echo "=== Batch Process List ==="
  echo "Batch Dir: $batch_dir"
  echo ""

  local targets_dir="${batch_dir}/targets"
  local total_running=0
  local total_stopped=0
  local total_not_started=0

  for task_dir in "$targets_dir"/T-*; do
    if [[ ! -d "$task_dir" ]]; then
      continue
    fi

    local pid_file=$(get_pid_file "$task_dir")
    local task_name=$(basename "$task_dir")

    if [[ -f "$pid_file" ]]; then
      local status=$(jq -r '.status' "$pid_file")
      local main_pid=$(jq -r '.main_pid' "$pid_file")

      if [[ "$status" == "running" ]]; then
        echo -e "  ${GREEN}RUNNING${NC} $task_name (PID: $main_pid)"
        ((total_running++)) || true
      elif [[ "$status" == "terminated" ]]; then
        echo -e "  ${RED}STOPPED${NC} $task_name"
        ((total_stopped++)) || true
      else
        echo -e "  ${YELLOW}OTHER${NC} $task_name ($status)"
      fi
    else
      echo -e "  ${NC}NOT_TRACKED${NC} $task_name"
      ((total_not_started++)) || true
    fi
  done

  echo ""
  echo "Summary: Running=$total_running, Stopped=$total_stopped, NotTracked=$total_not_started"
}

# Monitor - for background execution
monitor_task() {
  local task_dir="$TARGET"
  local pid_file=$(get_pid_file "$task_dir")
  local main_pid="${TOOL_PID:-$$}"

  init_pid_file "$task_dir"

  record_pid "$task_dir" "$main_pid"

  echo "Monitoring enabled for task: $task_dir"
  echo "PID: $main_pid"
  echo "Note: Use add-tool-pid to track specific tool processes"
}

# Cleanup PID file
cleanup_pid() {
  local task_dir="$TARGET"
  local pid_file=$(get_pid_file "$task_dir")

  if [[ -f "$pid_file" ]]; then
    # Update status to completed before cleanup
    jq '.status = "completed"' "$pid_file" > "${pid_file}.tmp" && mv "${pid_file}.tmp" "$pid_file"
    echo -e "${GREEN}✓${NC} Marked task as completed"
  fi
}

# Cleanup specific tool PID
cleanup_tool_pid() {
  local task_dir="$1"
  local tool_pid="$2"
  local pid_file=$(get_pid_file "$task_dir")

  if [[ ! -f "$pid_file" ]]; then
    echo -e "${RED}✗${NC} No PID file found"
    return 1
  fi

  if command -v jq >/dev/null 2>&1; then
    jq --arg pid "$tool_pid" '(.tool_pids |= map(select(.pid != $pid)))' \
       "$pid_file" > "${pid_file}.tmp" && mv "${pid_file}.tmp" "$pid_file"
    echo -e "${GREEN}✓${NC} Removed tool PID: $tool_pid"
  fi
}

# Main command dispatch
case "$COMMAND" in
  monitor)
    if [[ -z "$TARGET" ]]; then
      echo "Error: task_dir required"
      show_help
      exit 1
    fi
    monitor_task
    ;;

  terminate)
    if [[ -z "$TARGET" ]]; then
      echo "Error: task_dir required"
      show_help
      exit 1
    fi
    terminate_task
    ;;

  terminate-batch)
    if [[ -z "$TARGET" ]]; then
      echo "Error: batch_dir required"
      show_help
      exit 1
    fi
    terminate_batch
    ;;

  status)
    if [[ -z "$TARGET" ]]; then
      echo "Error: task_dir required"
      show_help
      exit 1
    fi
    get_status
    ;;

  list-processes)
    if [[ -z "$TARGET" ]]; then
      echo "Error: batch_dir required"
      show_help
      exit 1
    fi
    list_processes
    ;;

  cleanup)
    if [[ -z "$TARGET" ]]; then
      echo "Error: task_dir required"
      show_help
      exit 1
    fi
    cleanup_pid
    ;;

  add-tool-pid)
    if [[ -z "$TARGET" ]]; then
      echo "Error: task_dir required"
      show_help
      exit 1
    fi
    if [[ -z "$TOOL_PID" ]]; then
      echo "Error: tool_pid required (use --pid <pid>)"
      show_help
      exit 1
    fi
    add_tool_pid "$TARGET" "$TOOL_PID" "${TOOL_NAME:-unknown}"
    ;;

  cleanup-tool-pid)
    if [[ -z "$TARGET" ]]; then
      echo "Error: task_dir required"
      show_help
      exit 1
    fi
    if [[ -z "$TOOL_PID" ]]; then
      echo "Error: tool_pid required (use --pid <pid>)"
      show_help
      exit 1
    fi
    cleanup_tool_pid "$TARGET" "$TOOL_PID"
    ;;

  help|--help|-h)
    show_help
    ;;

  *)
    echo "Unknown command: $COMMAND"
    show_help
    exit 1
    ;;
esac
