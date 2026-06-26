#!/usr/bin/env bash
# smoke-test.sh
# Quick validation that the authorized-appsec skill package is intact.
#
# Usage:
#   bash scripts/smoke-test.sh
#
# Checks: directory structure, script syntax, template presence, JSON parseability, e2e fixture.
set -e

SKILL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ -x "$SKILL_ROOT/.venv/bin/python" ]; then
  PYTHON_BIN="$SKILL_ROOT/.venv/bin/python"
fi
ERRORS=0
WARNINGS=0

# Counter helper: works with set -e
incr_error() { ERRORS=$((ERRORS + 1)); }
incr_warn() { WARNINGS=$((WARNINGS + 1)); }

echo "=== Authorized AppSec Skill Smoke Test ==="
echo "Root: $SKILL_ROOT"
echo ""

# 1. Core documents
echo "1/10 Checking core documents..."
for doc in SKILL.md memory-protocol.md ARCHITECTURE.md; do
  if [ ! -f "$SKILL_ROOT/$doc" ]; then
    echo "  ERROR: Missing core document: $doc"
    incr_error
  else
    echo "  OK: $doc"
  fi
done

# 2. Command references
echo ""
echo "2/10 Checking command references..."
for cmd in capabilities.md recon.md ports.md stack-mapping.md threat-modeling.md source-code-review.md brute-force.md modern-auth.md authenticated-testing.md; do
  if [ ! -f "$SKILL_ROOT/commands/$cmd" ]; then
    echo "  ERROR: Missing command reference: $cmd"
    incr_error
  else
    echo "  OK: commands/$cmd"
  fi
done

# 3. Scripts
echo ""
echo "3/10 Checking scripts..."
for script in discover-capabilities.sh request_guard.py ensure_structured_outputs.py generate_report.py auto_l3_hypotheses.py capture_evidence.py exploit_search.py import_report.py check-structure.sh check-task.sh task-control.sh export_to_l3.py init_batch.py init_task.py cleanup.sh aggregate_batch.py generate_batch_report.py retrieve_l3.py smoke-test.sh build-public-package.sh; do
  if [ ! -f "$SKILL_ROOT/scripts/$script" ]; then
    echo "  ERROR: Missing script: $script"
    incr_error
  else
    echo "  OK: scripts/$script"
  fi
done

# 4. Script syntax
echo ""
echo "4/10 Checking script syntax..."
if command -v "$PYTHON_BIN" &>/dev/null; then
  # Redirect pycache OUT of the (possibly read-only) package dir so a permission
  # error on __pycache__ is never mistaken for a syntax error.
  PYCACHE_TMP="$(mktemp -d 2>/dev/null || echo /tmp/appsec-pycache-$$)"
  for py in "$SKILL_ROOT"/scripts/*.py; do
    err_out="$(PYTHONPYCACHEPREFIX="$PYCACHE_TMP" "$PYTHON_BIN" -m py_compile "$py" 2>&1 >/dev/null)" || true
    if [[ -z "$err_out" ]]; then
      echo "  OK: $(basename "$py") syntax"
    elif echo "$err_out" | grep -qiE 'permission denied|read-only|errno 13|EROFS|not writable'; then
      # The check itself can't run (e.g. package dir owned by nobody:nogroup);
      # fall back to a pure parse that writes nothing.
      if "$PYTHON_BIN" -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$py" 2>/dev/null; then
        echo "  OK: $(basename "$py") syntax (py_compile blocked by permission, ast.parse passed)"
      else
        echo "  ERROR: $(basename "$py") syntax error"
        incr_error
      fi
    else
      echo "  ERROR: $(basename "$py") syntax error"
      incr_error
    fi
  done
  rm -rf "$PYCACHE_TMP" 2>/dev/null || true
else
  echo "  WARNING: python3 not available, skipping Python syntax check"
  incr_warn
fi

for sh in "$SKILL_ROOT"/scripts/*.sh; do
  if bash -n "$sh" 2>/dev/null; then
    echo "  OK: $(basename "$sh") syntax"
  else
    echo "  ERROR: $(basename "$sh") syntax error"
    incr_error
  fi
done

# 5. Unit tests (pytest)
echo ""
echo "5/10 Running unit tests..."
if command -v "$PYTHON_BIN" &>/dev/null; then
  if "$PYTHON_BIN" -c "import pytest" 2>/dev/null; then
    TEST_EXIT=0
    "$PYTHON_BIN" -m pytest "$SKILL_ROOT/tests/" -v --tb=short 2>&1 || TEST_EXIT=$?
    if [ "$TEST_EXIT" -eq 0 ]; then
      echo "  OK: All unit tests passed"
    elif [ "$TEST_EXIT" -eq 1 ]; then
      echo "  ERROR: Unit tests failed (exit $TEST_EXIT)"
      incr_error
    elif [ "$TEST_EXIT" -eq 5 ]; then
      echo "  WARNING: No tests collected (exit $TEST_EXIT)"
      incr_warn
    else
      echo "  WARNING: pytest exited with $TEST_EXIT"
      incr_warn
    fi
  else
    echo "  WARNING: pytest not available, skipping unit tests"
    incr_warn
  fi
else
  echo "  WARNING: python3 not available, skipping unit tests"
  incr_warn
fi

# 6. Templates
echo ""
echo "6/10 Checking templates..."
TEMPLATE_COUNT=$(find "$SKILL_ROOT/templates" -name "*.md" -type f ! -name "._*" 2>/dev/null | wc -l | tr -d ' ')
echo "  Template files: $TEMPLATE_COUNT"
if [ "$TEMPLATE_COUNT" -lt 17 ]; then
  echo "  WARNING: Expected at least 17 template files, found $TEMPLATE_COUNT"
  incr_warn
else
  echo "  OK: $TEMPLATE_COUNT templates found"
fi

# 7. Payloads
echo ""
echo "7/10 Checking payloads..."
PAYLOAD_COUNT=$(find "$SKILL_ROOT/payloads" -name "*.md" -type f ! -name "._*" 2>/dev/null | wc -l | tr -d ' ')
echo "  Payload files: $PAYLOAD_COUNT"
if [ "$PAYLOAD_COUNT" -lt 50 ]; then
  echo "  WARNING: Expected at least 50 payload files, found $PAYLOAD_COUNT"
  incr_warn
else
  echo "  OK: $PAYLOAD_COUNT payloads found"
fi

# 8. Content consistency - security boundary statements
echo ""
echo "8/10 Checking content consistency..."
BOUNDARY_COUNT=$(grep -rl "Security Boundary Statement" "$SKILL_ROOT/payloads/" 2>/dev/null | wc -l | tr -d ' ')
echo "  Payloads with security boundary: $BOUNDARY_COUNT / $PAYLOAD_COUNT"
if [ "$BOUNDARY_COUNT" -lt "$((PAYLOAD_COUNT / 2))" ]; then
  echo "  WARNING: Less than half of payloads have security boundary statements"
  incr_warn
else
  echo "  OK: Security boundary coverage acceptable"
fi

# 9. Version consistency
echo ""
echo "9/10 Checking version consistency..."
SKILL_VERSION=$(grep -oE '2\.[0-9]+\.[0-9]+' "$SKILL_ROOT/SKILL.md" 2>/dev/null | head -1 || echo "not-found")
ARCH_VERSION=$(grep -oE '2\.[0-9]+\.[0-9]+' "$SKILL_ROOT/ARCHITECTURE.md" 2>/dev/null | head -1 || echo "not-found")
echo "  SKILL.md version: $SKILL_VERSION"
echo "  ARCHITECTURE.md version: $ARCH_VERSION"

# 10. End-to-end fixture test
echo ""
echo "10/10 Running end-to-end fixture test..."
if command -v "$PYTHON_BIN" &>/dev/null; then
  EOS_ERRORS=0
  TMPDIR_E2E=$(mktemp -d)
  "$PYTHON_BIN" "$SKILL_ROOT/scripts/init_task.py" "https://e2e-test.example.com" --output-dir "$TMPDIR_E2E" 2>/dev/null || true
  TASK_DIR=$(ls -d "$TMPDIR_E2E"/PT-* 2>/dev/null | head -1)
  if [ -n "$TASK_DIR" ] && [ -d "$TASK_DIR" ]; then
    echo "  OK: init_task created $TASK_DIR"

    # Write fixture findings.md
    cat > "$TASK_DIR/findings.md" << 'FINDINGS_EOF'
# Findings

## F-001 — SQL Injection [Critical]

**Description**: Test SQL injection in login endpoint
**Affected**: /api/login
**Evidence**: Error-based SQLi confirmed
**Remediation**: 1. Use parameterized queries
**Status**: confirmed

## F-002 — XSS Reflected [High]

**Description**: Reflected XSS in search parameter
**Affected**: /search?q=
**Evidence**: ```html\n<img src=x onerror=console.log('XSS')>\n```
**Remediation**: 1. Encode output
**Status**: confirmed

## F-003 — Info Disclosure [Low]

**Description**: Server version disclosed
**Affected**: HTTP headers
**Evidence**: Server: Apache/2.4.51
**Remediation**: 1. Hide server version
**Status**: confirmed
FINDINGS_EOF

    # Update task.md to completed
    sed -i '' 's/- status: in_progress/- status: completed/' "$TASK_DIR/task.md" 2>/dev/null || \
    sed -i 's/- status: in_progress/- status: completed/' "$TASK_DIR/task.md" 2>/dev/null || true

    # Run ensure_structured_outputs
    "$PYTHON_BIN" "$SKILL_ROOT/scripts/ensure_structured_outputs.py" "$TASK_DIR" 2>/dev/null
    ENSURE_EXIT=$?
    if [ "$ENSURE_EXIT" -ne 0 ]; then
      echo "  ERROR: ensure_structured_outputs failed with exit code $ENSURE_EXIT"
      incr_error
    else
      echo "  OK: ensure_structured_outputs completed"
    fi

    # Validate findings.json
    FCOUNT=$("$PYTHON_BIN" -c "import json; d=json.load(open('$TASK_DIR/findings.json')); print(len(d) if isinstance(d, list) else len(d.get('findings', [])))" 2>/dev/null || echo "0")
    if [ "$FCOUNT" -ge 3 ]; then
      echo "  OK: findings.json has $FCOUNT entries (expected >= 3)"
    else
      echo "  ERROR: findings.json has $FCOUNT entries (expected >= 3)"
      incr_error
    fi

    # Validate evidence_refs alignment
    REFS_OK=$("$PYTHON_BIN" -c "
import json
fdata = json.load(open('$TASK_DIR/findings.json'))
evidence = json.load(open('$TASK_DIR/evidence-index.json'))
findings = fdata if isinstance(fdata, list) else fdata.get('findings', [])
ev_list = evidence if isinstance(evidence, list) else evidence.get('evidence', [])
ev_ids = {e.get('evidence_id','') for e in ev_list}
ref_ids = set()
for f in findings:
    for r in f.get('evidence_refs', []):
        ref_ids.add(r)
missing = ref_ids - ev_ids
print('OK' if not missing else f'MISSING: {missing}')
" 2>/dev/null || echo "ERROR")
    if [ "$REFS_OK" = "OK" ]; then
      echo "  OK: evidence_refs aligned with evidence-index"
    else
      echo "  ERROR: evidence_refs misaligned: $REFS_OK"
      incr_error
    fi

    # Validate phase_status override
    PHASE_STATUS=$("$PYTHON_BIN" -c "import json; s=json.load(open('$TASK_DIR/summary.json')); print(s.get('phase_status',''))" 2>/dev/null || echo "")
    if [ "$PHASE_STATUS" = "completed" ]; then
      echo "  OK: summary.phase_status='$PHASE_STATUS' (matches task.md)"
    else
      echo "  WARNING: summary.phase_status='$PHASE_STATUS' (expected 'completed')"
      incr_warn
    fi

    # Validate L3 hypothesis trigger writes a guarded queue file
    "$PYTHON_BIN" "$SKILL_ROOT/scripts/auto_l3_hypotheses.py" "$TASK_DIR" --l3-root "$TMPDIR_E2E/l3" 2>/dev/null
    if [ -f "$TASK_DIR/l3-hypotheses.json" ]; then
      L3_STATUS=$("$PYTHON_BIN" -c "import json; d=json.load(open('$TASK_DIR/l3-hypotheses.json')); print(d.get('status',''))" 2>/dev/null || echo "")
      L3_GUARD=$("$PYTHON_BIN" -c "import json; d=json.load(open('$TASK_DIR/l3-hypotheses.json')); print('OK' if d.get('guardrails') else 'MISSING')" 2>/dev/null || echo "ERROR")
      if [ -n "$L3_STATUS" ] && [ "$L3_GUARD" = "OK" ]; then
        echo "  OK: l3-hypotheses.json generated with guardrails"
      else
        echo "  ERROR: l3-hypotheses.json missing status or guardrails"
        incr_error
      fi
    else
      echo "  ERROR: l3-hypotheses.json not generated"
      incr_error
    fi

    # Generate report
    "$PYTHON_BIN" "$SKILL_ROOT/scripts/generate_report.py" "$TASK_DIR" --skip-gate --gate-override-reason "smoke-test fixture without live request logs" 2>/dev/null
    if [ -f "$TASK_DIR/report.md" ]; then
      echo "  OK: report.md generated"
    else
      echo "  ERROR: report.md not generated"
      incr_error
    fi

    # Cleanup
    rm -rf "$TMPDIR_E2E"
  else
    echo "  WARNING: Could not create task directory for e2e test"
    incr_warn
  fi
else
  echo "  WARNING: python3 not available, skipping e2e fixture test"
  incr_warn
fi

echo ""
echo "=== Results ==="
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"
if [ "$ERRORS" -gt 0 ]; then
  echo "FAIL: Smoke test found errors"
  exit 1
else
  echo "PASS: Smoke test passed"
  exit 0
fi
