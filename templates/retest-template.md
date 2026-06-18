# Retest Template

> **Purpose**: Verify that previously confirmed vulnerabilities have been remediated after a fix cycle.

---

## Retest Task Structure

```text
RETEST-{YYYYMMDD}-{SEQ}-{target_slug}/
├── retest-task.md
├── retest-findings.md
├── retest-summary.json
├── retest-comparison.md
├── raw/
└── screenshots/
```

---

## retest-task.md

```markdown
# Retest Task

- retest_id: RETEST-{YYYYMMDD}-{SEQ}-{target_slug}
- original_task: PT-{YYYYMMDD}-{SEQ}-{target_slug}
- target: https://example.com
- target_type: url
- status: in_progress
- authorization: confirmed_by_user
- scope: Same as original task
- intensity: gentle
- started_at: YYYY-MM-DD HH:MM

## Original Findings to Retest

| Finding ID | Title | Severity | Original Status | Retest Status |
|------------|-------|----------|-----------------|---------------|
| F-001 | SQL Injection - /api/user | High | confirmed | pending |
| F-002 | Missing Security Headers | Low | confirmed | pending |

## Retest Method

- full: Re-validate all original findings from scratch
- targeted: Only test the specific endpoints and payloads from original findings
- differential: Compare original responses with current responses

## Next Actions

1. Read original task findings.md for context
2. Execute targeted retest for each finding
3. Record results in retest-findings.md
```

---

## retest-findings.md

For each original finding, record the retest result:

```markdown
## F-001 — SQL Injection - /api/user [High] — RETEST

**Original Finding**: PT-{YYYYMMDD}-{SEQ}-{target_slug} F-001
**Retest Status**: fixed
**Retest Method**: Targeted — replayed original payload
**Retest Date**: YYYY-MM-DD HH:MM
**Remediation Verified**: Yes
**Evidence**: Request returns 400 Bad Request with parameterized query error, no SQL error echo.
**Boundary**: Retested original payload only, no new injection points tested.
**Notes**: Developer confirmed parameterized queries implemented.

---

## F-002 — Missing Security Headers [Low] — RETEST

**Original Finding**: PT-{YYYYMMDD}-{SEQ}-{target_slug} F-002
**Retest Status**: partially_fixed
**Retest Method**: Full — re-scan response headers
**Retest Date**: YYYY-MM-DD HH:MM
**Remediation Verified**: Partially — X-Frame-Options added, CSP still missing
**Evidence**: X-Frame-Options: DENY present. Content-Security-Policy header absent.
**Boundary**: Header scan only, no application logic testing.
**Notes**: CSP remediation scheduled for next sprint.

---

## Writing Rules

- Only retest findings from the original task
- **Retest Status** values: `fixed`, `partially_fixed`, `not_fixed`, `worsened`, `new_issue`
- **fixed**: Vulnerability completely remediated, original attack no longer works
- **partially_fixed**: Some aspect remediated but residual risk remains
- **not_fixed**: Original vulnerability still present
- **worsened**: Vulnerability still present and severity has increased
- **new_issue**: Retest discovered a new vulnerability not in original scope
- Include original finding ID reference (`PT-XXXXXX-XXX F-XXX`)
- Record which remediation was verified and how
- Do not expand retest scope beyond original findings without user approval
```

---

## retest-summary.json

```json
{
  "retest_id": "RETEST-{YYYYMMDD}-{SEQ}-{target_slug}",
  "original_task_id": "PT-{YYYYMMDD}-{SEQ}-{target_slug}",
  "target": "https://example.com",
  "retest_date": "2026-05-05T10:00:00Z",
  "retest_method": "targeted",
  "total_findings_retested": 2,
  "results": {
    "fixed": 1,
    "partially_fixed": 1,
    "not_fixed": 0,
    "worsened": 0,
    "new_issue": 0
  },
  "findings": [
    {
      "original_finding_id": "F-001",
      "title": "SQL Injection - /api/user",
      "original_severity": "high",
      "retest_status": "fixed",
      "retest_date": "2026-05-05T10:15:00Z"
    },
    {
      "original_finding_id": "F-002",
      "title": "Missing Security Headers",
      "original_severity": "low",
      "retest_status": "partially_fixed",
      "retest_date": "2026-05-05T10:20:00Z"
    }
  ]
}
```

---

## retest-comparison.md

```markdown
# Retest Comparison Report

**Original Task**: PT-{YYYYMMDD}-{SEQ}-{target_slug}
**Retest Task**: RETEST-{YYYYMMDD}-{SEQ}-{target_slug}
**Comparison Date**: YYYY-MM-DD

## Summary

| Finding | Original Severity | Original Status | Retest Status | Change |
|---------|-------------------|----------------|---------------|--------|
| F-001 SQL Injection | High | confirmed | fixed | Resolved |
| F-002 Missing Headers | Low | confirmed | partially_fixed | Partial |

## Severity Impact

- Critical/High fixed: 1
- Critical/High remaining: 0
- New findings: 0

## Recommendations

1. CSP header implementation still pending — schedule follow-up
2. No remaining high-severity findings
```

---

## Retest Workflow

| Step | Action |
|------|--------|
| 1 | Read original `findings.md` and `findings.json` |
| 2 | Create `RETEST-{ID}/` directory |
| 3 | Copy original finding list into `retest-task.md` |
| 4 | For each finding, replay original payload and verify remediation |
| 5 | Record result in `retest-findings.md` with status |
| 6 | Generate `retest-summary.json` with structured results |
| 7 | Write `retest-comparison.md` with before/after comparison |
| 8 | Summarize: what's fixed, what remains, any new findings |

---

## Retest Rules

- **Same scope**: Only test within original scope boundary
- **Same intensity**: Use original or lower intensity
- **Targeted approach**: Default to targeted retest (only original endpoints/payloads)
- **No scope expansion**: Do not test new endpoints unless explicitly approved
- **New findings**: If a retest discovers a new vulnerability, record it as `new_issue` status but do not expand the retest
- **Evidence preservation**: Keep original evidence undisturbed; retest evidence goes in `RETEST-{ID}/raw/`
