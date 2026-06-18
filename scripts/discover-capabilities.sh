#!/usr/bin/env bash
# discover-capabilities.sh
# Discover available AppSec assessment tools and their binary paths.
# Output: capabilities.json with full binary paths for direct invocation.
#
# Usage:
#   ./scripts/discover-capabilities.sh [output.json] [--mcp http://host:port]
#
# Dependencies: jq (JSON processor)

set -e

# Ensure standard PATH — shell snapshot sessions may have a truncated PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

# Check jq dependency
if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed."
  echo "Install: brew install jq (macOS) or apt install jq (Linux)"
  exit 1
fi

OUTPUT_FILE="${1:-./capabilities.json}"
shift 2>/dev/null || true

MCP_URL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mcp) MCP_URL="$2"; shift 2 ;;
    --mcp=*) MCP_URL="${1#--mcp=}"; shift ;;
    *) shift ;;
  esac
done

VM_ID="$(hostname 2>/dev/null || echo 'vm-local')"

# ── Resolve a tool name to its full binary path ──────────────────
# Prefer `where` (zsh/macOS, shows all resolvable paths),
# fall back to `which` (portable), then `command -v` (bash builtin).
resolve_binary() {
  local tool="$1"

  # `where` returns all matches (zsh builtin)
  if command -v where >/dev/null 2>&1; then
    where "$tool" 2>/dev/null | head -1 && return
  fi

  # `which` is portable (but may be shell builtin on some systems)
  if command -v which >/dev/null 2>&1; then
    local found
    found=$(which "$tool" 2>/dev/null) && echo "$found" && return
  fi

  # Final fallback: bash builtin
  command -v "$tool" 2>/dev/null || true
}

# ── Resolve and record: returns space-separated "name|path" pairs ──
# Skips aliases and shell functions; only accepts real binaries.
resolve_candidates() {
  local candidates="$1"
  local cap_name="$2"

  while IFS= read -r tool; do
    [[ -z "$tool" ]] && continue

    local bin_path
    bin_path=$(resolve_binary "$tool")
    [[ -z "$bin_path" ]] && continue

    # Exclude shell builtins, functions, and aliases
    if [[ "$bin_path" == "$tool" && "$tool" != /* ]]; then
      # command -v returned the bare name (shell builtin/function)
      echo "  [~] $cap_name: $tool is a shell builtin/function, skipping" >&2
      continue
    fi

    echo "  [+] $cap_name: $tool → $bin_path" >&2
    printf '%s\n' "$tool|$bin_path"
  done <<< "$(echo "$candidates" | tr ' ' '\n')"
}

# ── HexStrike MCP server health check ────────────────────────────
check_mcp() {
  local url="$1"
  if [[ -z "$url" ]]; then
    echo "null"
    return
  fi
  local resp
  resp=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 "$url/health" 2>/dev/null || true)
  if [[ "$resp" == "200" ]]; then
    echo "\"$url\""
  else
    echo "null"
  fi
}

# ── Main ─────────────────────────────────────────────────────────
echo "# Discovering capabilities inside VM..."
echo ""

# Capability definitions: name -> candidate tools
CAPABILITIES=(
  "subdomain-discovery:subfinder amass findomain assetfinder"
  "http-probing:httpx httprobe httpcat"
  "port-scanning:naabu nmap masscan rustscan"
  "directory-scanning:spray ffuf dirsearch feroxbuster gobuster"
  "url-extraction:URLFinder gau getallurls waymore katana waybackurls"
  "fingerprinting:Ehole wappalyzer whatweb builtwith"
  "vulnerability-scanning:nuclei nikto wpscan"
  "exploit-search:searchsploit findsploit"
  "waf-detection:wafw00f"
  "brute-force:hydra medusa ncrack patator"
  "oob-callback:interactsh-client dnslog-client ceye burp-collaborator-client"
  "headless-browser:playwright npx-playwright puppeteer chromedp selenium"
  "grpc-client:grpcurl grpcui ghz evans"
  "k8s-client:kubectl kubeadm k9s"
)

# Capabilities that require explicit user approval before invocation.
# "available" in capabilities.json does NOT mean "may run" — these need opt-in.
opt_in_reason() {
  case "$1" in
    vulnerability-scanning) echo "Template-based scanners (nuclei/nikto/wpscan) run only on explicit user request per SKILL.md Nuclei Policy" ;;
    brute-force)            echo "Credential brute-force requires explicit authorization and test accounts" ;;
    oob-callback)           echo "Out-of-band interaction (OOB) channels require explicit authorization" ;;
    k8s-client)             echo "Kubernetes API access requires explicit authorization and scope confirmation" ;;
    *) echo "" ;;
  esac
}

# Initialize JSON structure
json_base=$(jq -n \
  --arg vm "$VM_ID" \
  --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{vm_id: $vm, discovered_at: $time, capabilities: {}, mcp_server: null, wordlists: []}')

# Build capabilities JSON
for entry in "${CAPABILITIES[@]}"; do
  cap_name="${entry%%:*}"
  candidates="${entry#*:}"

  echo "--- $cap_name ---"

  # Resolve each candidate to name|path pairs
  resolved_lines=$(resolve_candidates "$candidates" "$cap_name" || true)

  # Special detection for tools not found by simple command -v
  if [[ "$cap_name" == "headless-browser" ]]; then
    # Playwright Python package (not a binary)
    if python3 -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
      pw_path=$(python3 -c "import playwright; print(playwright.__file__)" 2>/dev/null || echo "python3-playwright")
      echo "  [+] $cap_name: python3-playwright → $pw_path" >&2
      resolved_lines="${resolved_lines:+$resolved_lines$'\n'}python3-playwright|$pw_path"
    fi
    # Puppeteer Node module
    if node -e "require('puppeteer'); process.exit(0)" 2>/dev/null; then
      pp_path=$(node -e "console.log(require.resolve('puppeteer'))" 2>/dev/null || echo "node-puppeteer")
      echo "  [+] $cap_name: node-puppeteer → $pp_path" >&2
      resolved_lines="${resolved_lines:+$resolved_lines$'\n'}node-puppeteer|$pp_path"
    fi
  fi

  if [[ "$cap_name" == "grpc-client" ]]; then
    # grpcui often installed as Go binary but may be at ~/go/bin/
    for extra_bin in "$HOME/go/bin/grpcurl" "$HOME/go/bin/grpcui" "$HOME/go/bin/ghz"; do
      if [[ -x "$extra_bin" ]]; then
        tool_name=$(basename "$extra_bin")
        echo "  [+] $cap_name: $tool_name → $extra_bin" >&2
        resolved_lines="${resolved_lines:+$resolved_lines$'\n'}$tool_name|$extra_bin"
      fi
    done
  fi

  if [[ "$cap_name" == "k8s-client" ]]; then
    # kubectl may be at various paths
    for extra_bin in "$HOME/.local/bin/kubectl" "/usr/local/bin/kubectl" "$HOME/go/bin/kubectl"; do
      if [[ -x "$extra_bin" ]]; then
        echo "  [+] $cap_name: kubectl → $extra_bin" >&2
        resolved_lines="${resolved_lines:+$resolved_lines$'\n'}kubectl|$extra_bin"
        break
      fi
    done
  fi

  available_names=()
  available_paths_json="[]"
  selected_name="null"
  selected_path="null"

  if [[ -n "$resolved_lines" ]]; then
    # Build names array and paths array
    names_json="["
    paths_json="["
    first=true
    while IFS='|' read -r tool_name tool_path; do
      [[ -z "$tool_name" ]] && continue
      available_names+=("$tool_name")
      if $first; then
        names_json+="\"$tool_name\""
        paths_json+="\"$tool_path\""
        selected_name="\"$tool_name\""
        selected_path="\"$tool_path\""
        first=false
      else
        names_json+=",\"$tool_name\""
        paths_json+=",\"$tool_path\""
      fi
    done <<< "$resolved_lines"
    names_json+="]"
    paths_json+="]"

    available_paths_json="$paths_json"
  else
    echo "  [-] $cap_name: no tools available"
    names_json="[]"
  fi

  cap_json=$(jq -n \
    --argjson candidates "$names_json" \
    --argjson binary_paths "$available_paths_json" \
    --argjson selected "$selected_name" \
    --argjson selected_path "$selected_path" \
    '{candidates: $candidates, binary_paths: $binary_paths, selected: $selected, selected_path: $selected_path}')

  # Mark capabilities that require explicit user approval before invocation.
  opt_reason=$(opt_in_reason "$cap_name")
  if [[ -n "$opt_reason" ]]; then
    cap_json=$(echo "$cap_json" | jq \
      --argjson req true \
      --arg reason "$opt_reason" \
      '. + {requires_explicit_approval: $req, approval_reason: $reason}')
  else
    cap_json=$(echo "$cap_json" | jq --argjson req false \
      '. + {requires_explicit_approval: $req}')
  fi

  json_base=$(echo "$json_base" | jq --arg cap "$cap_name" --argjson cap_json "$cap_json" \
    '.capabilities[$cap] = $cap_json')
done

# ── MCP server detection ─────────────────────────────────────────
echo ""
echo "# MCP server detection..."
MCP_CHECKED=$(check_mcp "$MCP_URL")
json_base=$(echo "$json_base" | jq --argjson mcp "$MCP_CHECKED" '.mcp_server = $mcp')
if [[ "$MCP_CHECKED" != "null" ]]; then
  echo "  [+] MCP server reachable: $MCP_URL"
else
  echo "  [-] No MCP server detected (use --mcp http://host:port to check)"
fi

# ── Wordlist discovery ───────────────────────────────────────────
echo ""
echo "# Wordlist discovery:"
wordlists_json="[]"
# Directory-scanning wordlists
for loc in /usr/share/seclists/Discovery/Web-Content /usr/share/dirb/wordlists /usr/share/dirbuster/wordlists; do
  if [[ -d "$loc" ]]; then
    while IFS= read -r f; do
      wordlists_json=$(echo "$wordlists_json" | jq --arg f "$f" '. + [$f]')
      echo "  [+] dir-scan: $f"
    done < <(find "$loc" -name "*.txt" -type f 2>/dev/null | head -8 || true)
  fi
done
# Password wordlists
for loc in /usr/share/seclists/Passwords /usr/share/wordlists; do
  if [[ -d "$loc" ]]; then
    while IFS= read -r f; do
      wordlists_json=$(echo "$wordlists_json" | jq --arg f "$f" '. + [$f]')
      echo "  [+] passwords: $f"
    done < <(find "$loc" -name "*.txt" -type f 2>/dev/null | head -8 || true)
  fi
done
# Other wordlists (Metasploit, etc.)
for loc in /usr/share/metasploit-framework/data/wordlists; do
  if [[ -d "$loc" ]]; then
    while IFS= read -r f; do
      wordlists_json=$(echo "$wordlists_json" | jq --arg f "$f" '. + [$f]')
      echo "  [+] auxiliary: $f"
    done < <(find "$loc" -name "*.txt" -type f 2>/dev/null | head -5 || true)
  fi
done
json_base=$(echo "$json_base" | jq --argjson wl "$wordlists_json" '.wordlists = $wl')

# ── Nuclei templates ─────────────────────────────────────────────
nuclei_templates="[]"
if command -v nuclei >/dev/null 2>&1; then
  echo ""
  echo "# Nuclei templates available:"
  # Template counts by directory for coverage awareness
  for tdir in /root/nuclei-templates/http /root/nuclei-templates/cnvd /root/nuclei-templates/cve /root/nuclei-templates/exposures /root/nuclei-templates/misconfiguration /root/nuclei-templates/technologies /root/nuclei-templates/default-logins; do
    if [[ -d "$tdir" ]]; then
      cnt=$(find "$tdir" -name "*.yaml" -type f 2>/dev/null | wc -l)
      echo "  [+] $(basename "$tdir"): ${cnt} templates"
    fi
  done
  # First 10 template paths as sample
  templates=$(nuclei -tl 2>/dev/null | head -10 || true)
  if [[ -n "$templates" ]]; then
    while IFS= read -r t; do
      [[ -z "$t" ]] && continue
      echo "  [+] $t"
      nuclei_templates=$(echo "$nuclei_templates" | jq --arg t "$t" '. + [$t]')
    done <<< "$templates"
  fi
fi
json_base=$(echo "$json_base" | jq --argjson nt "$nuclei_templates" '.nuclei_templates = $nt')

# ── Write output ─────────────────────────────────────────────────
echo ""
echo "$json_base" | jq . > "$OUTPUT_FILE"

echo ""
echo "# Output: $(realpath "$OUTPUT_FILE" 2>/dev/null || echo "$OUTPUT_FILE")"
echo ""
echo "# Summary:"
jq -r '
  .capabilities | to_entries | sort_by(-(.value.candidates | length)) |
  .[] | "  \(.key): \(.value.candidates | length) tool(s) → \(.value.selected // "none")"  +
        (if .value.selected_path then " @ \(.value.selected_path)" else "" end)
' "$OUTPUT_FILE"

echo ""
echo "# Quick reference — invoke directly:"
jq -r '
  .capabilities | to_entries[] | select(.value.selected_path) |
  "  \(.key): \(.value.selected_path)"
' "$OUTPUT_FILE"
