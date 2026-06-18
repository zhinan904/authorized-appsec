#!/usr/bin/env bash
# cleanup.sh
# Clean up test artifacts and sanitize evidence after penetration testing.
#
# Usage:
#   bash scripts/cleanup.sh <task_dir> [--dry-run] [--batch]
#
# Modes:
#   <task_dir>       Clean a single task directory
#   <batch_dir> --batch  Clean all targets in batch directory
#   --dry-run        Preview actions without executing
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DRY_RUN=false
BATCH=false
TASK_DIR=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --batch) BATCH=true ;;
        *) if [ -z "$TASK_DIR" ]; then TASK_DIR="$arg"; fi ;;
    esac
done

if [ -z "$TASK_DIR" ]; then
    echo "Usage: cleanup.sh <task_dir> [--dry-run] [--batch]"
    exit 1
fi

cleanup_task() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo -e "${RED}[!]${NC} Directory not found: $dir"
        return 1
    fi

    echo ""
    echo "=== Cleaning: $(basename "$dir") ==="

    local session_dir="$dir/sessions"
    if [ -d "$session_dir" ]; then
        local session_files=$(find "$session_dir" -name "*.md" -type f 2>/dev/null)
        if [ -n "$session_files" ]; then
            echo "  Sessions: sanitizing..."
            for f in $session_files; do
                if [ "$DRY_RUN" = true ]; then
                    echo -e "    ${YELLOW}[dry-run]${NC} Would sanitize: $(basename "$f")"
                else
                    if command -v sed &>/dev/null; then
                        sed -i 's/\(cookie_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(cookie_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(token_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(token_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(api_key_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(api_key_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(session_id:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(session_id:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(authorization:\s*Bearer\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(authorization:\s*Bearer\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(password:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(password:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(secret:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(secret:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(credential_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(credential_value:\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                        sed -i 's/\(auth_header:\s*Basic\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || sed -i '' 's/\(auth_header:\s*Basic\s*\)[^<]*/\1<REDACTED>/g' "$f" 2>/dev/null || true
                    fi
                    echo -e "    ${GREEN}✓${NC} Sanitized: $(basename "$f")"
                fi
            done
        else
            echo "  Sessions: none found"
        fi
    fi

    local raw_dir="$dir/raw"
    if [ -d "$raw_dir" ]; then
        local raw_count=$(find "$raw_dir" -type f 2>/dev/null | wc -l | tr -d ' ')
        echo "  Raw evidence: $raw_count files (kept for audit trail)"
        # Sanitize sensitive headers in raw HTTP responses
        if [ "$DRY_RUN" != true ] && command -v sed &>/dev/null; then
            for rf in "$raw_dir"/*; do
                [ -f "$rf" ] || continue
                # Sanitize Set-Cookie header values (keep cookie name)
                sed -i 's/\(Set-Cookie:\s*[^=]*=\)[^;\s]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\(Set-Cookie:\s*[^=]*=\)[^;\s]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
                # Sanitize Authorization header values
                sed -i 's/\(Authorization:\s*\(Bearer\|Basic\)\s*\)[^<\r\n]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\(Authorization:\s*\(Bearer\|Basic\)\s*\)[^<\r\n]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
                # Sanitize token/secret patterns in JSON/XML bodies
                sed -i 's/\("token"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\("token"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
                sed -i 's/\("access_token"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\("access_token"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
                sed -i 's/\("secret"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\("secret"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
                sed -i 's/\("password"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\("password"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
                sed -i 's/\("api_key"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || sed -i '' 's/\("api_key"\s*:\s*"\)[^"]*/\1<REDACTED>/Ig' "$rf" 2>/dev/null || true
            done
        fi
    fi

    local task_md="$dir/task.md"
    if [ -f "$task_md" ]; then
        local now=$(date "+%Y-%m-%d %H:%M")
        if [ "$DRY_RUN" = true ]; then
            echo -e "  ${YELLOW}[dry-run]${NC} Would update $task_md with cleanup status"
        else
            if ! grep -q "cleanup_completed" "$task_md" 2>/dev/null; then
                cat >> "$task_md" << EOF

## Cleanup Status

- cleanup_completed: true
- cleanup_date: $now
- test_accounts_deleted: 0
- test_records_removed: 0
- config_changes_reverted: 0
- evidence_sanitized: true
EOF
                echo -e "  ${GREEN}✓${NC} Updated task.md with cleanup status"
            fi
        fi
    fi

    echo -e "  ${GREEN}Done${NC}"
}

if [ "$BATCH" = true ]; then
    targets_dir="$TASK_DIR/targets"
    if [ ! -d "$targets_dir" ]; then
        echo -e "${RED}[!]${NC} Not a batch directory: $TASK_DIR"
        exit 1
    fi
    for target_dir in "$targets_dir"/*/ ; do
        [ -d "$target_dir" ] || continue
        cleanup_task "$target_dir"
    done
else
    cleanup_task "$TASK_DIR"
fi

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
if [ "$DRY_RUN" = true ]; then
    echo "  (Dry run - no changes made)"
fi