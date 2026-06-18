#!/usr/bin/env bash
set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

errors=0
warnings=0

echo "=== Authorized AppSec Skill Structure Check ==="
echo ""

# 1. Check core directory structure
echo "[1/7] Checking directory structure..."
required_dirs=(
  "commands"
  "payloads"
  "templates"
  "scripts"
)

for dir in "${required_dirs[@]}"; do
  if [[ -d "$dir" ]]; then
    echo -e "  ${GREEN}✓${NC} $dir/"
  else
    echo -e "  ${RED}✗${NC} Missing directory: $dir/"
    ((errors++)) || true
  fi
done

# 2. Check core documents
echo ""
echo "[2/7] Checking core documents..."
required_docs=(
  "SKILL.md"
  "memory-protocol.md"
  "ARCHITECTURE.md"
  "README.md"
)

for doc in "${required_docs[@]}"; do
  if [[ -f "$doc" ]]; then
    echo -e "  ${GREEN}✓${NC} $doc"
  else
    echo -e "  ${RED}✗${NC} Missing: $doc"
    ((errors++)) || true
  fi
done

# 3. Check command/capability references (capability-first architecture)
echo ""
echo "[3/7] Checking command/capability references..."
required_commands=(
  "commands/capabilities.md"
  "commands/recon.md"
  "commands/ports.md"
  "commands/stack-mapping.md"
  "commands/threat-modeling.md"
  "commands/source-code-review.md"
  "commands/brute-force.md"
  "commands/modern-auth.md"
  "commands/authenticated-testing.md"
)

for cmd in "${required_commands[@]}"; do
  if [[ -f "$cmd" ]]; then
    echo -e "  ${GREEN}✓${NC} $cmd"
  else
    echo -e "  ${RED}✗${NC} Missing: $cmd"
    ((errors++)) || true
  fi
done

# 4. Check scripts (capability-first architecture)
echo ""
echo "[4/7] Checking scripts..."
required_scripts=(
  "scripts/discover-capabilities.sh"
  "scripts/ensure_structured_outputs.py"
  "scripts/generate_report.py"
  "scripts/auto_l3_hypotheses.py"
  "scripts/capture_evidence.py"
  "scripts/exploit_search.py"
  "scripts/check-structure.sh"
  "scripts/check-task.sh"
  "scripts/task-control.sh"
  "scripts/export_to_l3.py"
  "scripts/init_batch.py"
  "scripts/aggregate_batch.py"
  "scripts/generate_batch_report.py"
  "scripts/retrieve_l3.py"
  "scripts/init_task.py"
  "scripts/import_report.py"
  "scripts/cleanup.sh"
  "scripts/smoke-test.sh"
  "scripts/build-public-package.sh"
)

for script in "${required_scripts[@]}"; do
  if [[ -f "$script" ]]; then
    echo -e "  ${GREEN}✓${NC} $script"
    # Check if .sh files have execute permission
    if [[ "$script" == *.sh ]]; then
      if [[ -x "$script" ]]; then
        echo -e "    ${GREEN}✓${NC} Has execute permission"
      else
        echo -e "    ${YELLOW}!${NC} Missing execute permission"
        ((warnings++)) || true
      fi
    fi
  else
    echo -e "  ${RED}✗${NC} Missing: $script"
    ((errors++)) || true
  fi
done

# 5. Check template files
echo ""
echo "[5/7] Checking template files..."
required_templates=(
  "templates/task-template.md"
  "templates/findings-template.md"
  "templates/session-template.md"
  "templates/result-template.md"
  "templates/structured-output-requirements.md"
  "templates/fingerprint-template.md"
  "templates/discovery-template.md"
  "templates/vuln-test-template.md"
  "templates/chain-template.md"
  "templates/severity-classification.md"
  "templates/batch-template.md"
  "templates/targets-schema.md"
  "templates/stop-conditions.md"
  "templates/process-control.md"
  "templates/retest-template.md"
  "templates/rules-of-engagement.md"
  "templates/cleanup-template.md"
  "templates/report-import-rules.md"
)

for template in "${required_templates[@]}"; do
  if [[ -f "$template" ]]; then
    echo -e "  ${GREEN}✓${NC} $template"
  else
    echo -e "  ${RED}✗${NC} Missing: $template"
    ((errors++)) || true
  fi
done

# Check optional business scenario templates (warning level)
optional_templates=(
  "templates/business-scenario-ecommerce.md"
  "templates/business-scenario-payment.md"
  "templates/business-scenario-user-lifecycle.md"
  "templates/business-scenario-sensitive-reporting.md"
)

for template in "${optional_templates[@]}"; do
  if [[ -f "$template" ]]; then
    echo -e "  ${GREEN}✓${NC} $template (optional)"
  else
    echo -e "  ${YELLOW}!${NC} Missing optional: $template"
    ((warnings++)) || true
  fi
done

# 6. Check payload files (warning level)
echo ""
echo "[6/7] Checking payload library..."
payload_count=$(find payloads -maxdepth 1 -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$payload_count" -eq 0 ]]; then
  echo -e "  ${YELLOW}!${NC} No payload files in payloads/"
  ((warnings++)) || true
else
  echo -e "  ${GREEN}✓${NC} payloads/ ($payload_count payload files)"

  # Check if critical payload files exist (warning level)
  critical_payloads=(
    "payloads/sqli.md"
    "payloads/xss.md"
    "payloads/ssrf.md"
    "payloads/api-auth.md"
    "payloads/api-cmdi.md"
    "payloads/api-ssrf.md"
    "payloads/api-xxe.md"
    "payloads/xxe.md"
    "payloads/csrf.md"
    "payloads/jwt.md"
    "payloads/deserialization.md"
    "payloads/open-redirect.md"
    "payloads/ssti.md"
    "payloads/oauth.md"
    "payloads/password-reset.md"
    "payloads/ldap-injection.md"
    "payloads/host-header.md"
    "payloads/rate-limiting.md"
    "payloads/idor.md"
    "payloads/websocket.md"
    "payloads/mfa-bypass.md"
    "payloads/cors.md"
    "payloads/http-smuggling.md"
    "payloads/crlf-injection.md"
    "payloads/cache-poisoning.md"
    "payloads/race-condition.md"
    "payloads/prototype-pollution.md"
    "payloads/subdomain-takeover.md"
    "payloads/dom-xss.md"
    "payloads/api-business-logic.md"
    "payloads/api-config.md"
    "payloads/api-data-exposure.md"
    "payloads/api-graphql.md"
    "payloads/api-nosqli.md"
    "payloads/api-sqli.md"
    "payloads/file-inclusion.md"
    "payloads/file-read.md"
    "payloads/file-upload.md"
    "payloads/default-credentials.md"
    "payloads/error-handling.md"
    "payloads/security-headers.md"
    "payloads/path-traversal.md"
    "payloads/cloud-security.md"
    "payloads/session-management.md"
    "payloads/admin-panel.md"
    "payloads/client-side-review.md"
    "payloads/backup-exposure.md"
    "payloads/http-methods.md"
    "payloads/soap-wsdl.md"
    "payloads/api-mobile.md"
    "payloads/password-policy.md"
  )

  missing_payloads=0
  for payload in "${critical_payloads[@]}"; do
    if [[ ! -f "$payload" ]]; then
      ((missing_payloads++)) || true
    fi
  done

  if [[ "$missing_payloads" -gt 0 ]]; then
    echo -e "    ${YELLOW}!${NC} $missing_payloads critical payload files missing"
    ((warnings++)) || true
  fi

  # Content consistency checks for payloads
  echo ""
  echo "  Content consistency checks:"

  # Check if OOB is marked as requiring authorization (not default)
  # Correct pattern: "OOB | ❌ Not by default" or "OOB.*Requires.*Authorization"
  # Incorrect pattern: "OOB | ✓" or "OOB.*Recommended" without auth requirement
  oob_bad=$(grep -E "OOB.*✓ Recommended|OOB \| ✓" payloads/*.md 2>/dev/null || true)
  if [[ -n "$oob_bad" ]]; then
    echo -e "    ${RED}✗${NC} OOB incorrectly marked as recommended/default"
    echo "      Files: $(echo "$oob_bad" | cut -d: -f1 | sort -u)"
    ((errors++)) || true
  else
    echo -e "    ${GREEN}✓${NC} OOB correctly requires authorization"
  fi

  # Check if cloud metadata is marked as requiring authorization
  cloud_default=$(grep -l "169.254.169.254.*default\|cloud.*✓ Recommended" payloads/*.md 2>/dev/null || true)
  if [[ -n "$cloud_default" ]]; then
    echo -e "    ${RED}✗${NC} Cloud metadata marked as default in: $cloud_default"
    ((errors++)) || true
  else
    echo -e "    ${GREEN}✓${NC} Cloud metadata correctly marked as requiring authorization"
  fi

  # Check if all payload files have security boundary statement
  no_boundary=$(find payloads -name "*.md" -exec grep -L "Security Boundary Statement\|Validation Objectives" {} \; 2>/dev/null || true)
  if [[ -n "$no_boundary" ]]; then
    no_boundary_count=$(echo "$no_boundary" | wc -l)
    echo -e "    ${YELLOW}!${NC} $no_boundary_count payload files missing boundary statement"
    ((warnings++)) || true
  else
    echo -e "    ${GREEN}✓${NC} All payload files have security boundary"
  fi
fi

# 7. Check template content consistency
echo ""
echo "[7/7] Checking template content consistency..."

# Check output path convention consistency
if grep -q "PENTEST_RESULTS_ROOT" templates/structured-output-requirements.md 2>/dev/null && \
     grep -q "~/authorized-appsec/results" templates/structured-output-requirements.md 2>/dev/null; then
  echo -e "  ${GREEN}✓${NC} Output path convention consistent with SKILL.md"
else
  echo -e "  ${YELLOW}!${NC} Output path convention unclear in structured-output-requirements.md"
  ((warnings++)) || true
fi

# Check for Chinese characters in core files (should be English).
# Use Python instead of grep ranges because POSIX collation can reject CJK ranges.
chinese_files=$(python3 - <<'PY' 2>/dev/null || true
from pathlib import Path

paths = [Path("SKILL.md")]
for pattern in ("commands/*.md", "templates/*.md", "scripts/*.py", "payloads/*.md"):
    paths.extend(Path(".").glob(pattern))

for path in paths:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        continue
    if any("\u4e00" <= ch <= "\u9fff" for ch in text):
        print(path)
PY
)
if [[ -n "$chinese_files" ]]; then
  echo -e "  ${RED}✗${NC} Chinese characters found in: $chinese_files"
  ((errors++)) || true
else
  echo -e "  ${GREEN}✓${NC} Core files use English consistently"
fi

# Summary
echo ""
echo "=========================================="
if [[ $errors -eq 0 ]]; then
  echo -e "${GREEN}Structure check passed${NC}"
  echo ""
  echo "Capability-first architecture key files:"
  echo "  - commands/capabilities.md: Capability definitions"
  echo "  - scripts/discover-capabilities.sh: VM tool discovery"
  echo "  - scripts/generate_report.py: Report generation"
  [[ $warnings -gt 0 ]] && echo -e "${YELLOW}Warnings: $warnings items${NC}"
  exit 0
else
  echo -e "${RED}Structure check failed: $errors errors${NC}"
  [[ $warnings -gt 0 ]] && echo -e "${YELLOW}Warnings: $warnings items${NC}"
  exit 1
fi
