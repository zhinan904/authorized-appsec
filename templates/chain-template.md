# Chain Analysis Template

> Phase 4 output template for `04-chain.md`

---

## Template

```markdown
# Vulnerability Chain Analysis - {target}

**Task ID**: {task_id}
**Phase**: phase_4
**Updated At**: {timestamp}

---

## Confirmed Findings Summary

| Finding ID | Title | Severity | Endpoint |
|------------|-------|----------|----------|
| F-001 | SQL Injection | High | /api/users?id= |
| F-002 | IDOR | High | /api/users/:id |
| F-003 | XSS | Medium | /search?q= |

---

## Chain Analysis

### Chain 1: {SQL Injection → Credential Extraction (Hypothesis)}

**Prerequisites**:
- F-001 SQL Injection confirmed
- Database likely MySQL based on error syntax

**Hypothetical Impact**:
- SQL injection could allow credential table enumeration
- Combined with IDOR, attacker could target specific users

**Validation Boundary**:
- NOT validated: credential extraction, table enumeration
- Requires: explicit authorization before UNION/credential testing

**Risk Statement**:
SQL injection on user endpoint combined with IDOR creates credential extraction risk. Validation stopped at injection proof; actual credential extraction not performed.

**Recommendation**:
Fix F-001 and F-002 before any further chain validation. If credential impact needed, obtain explicit authorization.

---

### Chain 2: {XSS → Session Hijacking (Hypothesis)}

**Prerequisites**:
- F-003 Reflected XSS confirmed
- Session stored in cookie without HttpOnly

**Hypothetical Impact**:
- XSS could allow cookie extraction via JavaScript
- Combined with session reuse, attacker could hijack accounts

**Validation Boundary**:
- NOT validated: JavaScript execution in browser, cookie extraction
- Requires: authorization for alert-based XSS test

**Risk Statement**:
Reflected XSS combined with cookie-based session creates session hijacking risk. Payload reflection confirmed; actual JavaScript execution and cookie extraction not tested.

**Recommendation**:
Add HttpOnly flag to session cookie. Fix F-003 XSS. If hijacking proof needed, obtain authorization.

---

### Chain 3: {IDOR → Mass Data Enumeration (Hypothesis)}

**Prerequisites**:
- F-002 IDOR confirmed
- User IDs appear sequential (numeric)

**Hypothetical Impact**:
- Sequential IDs allow mass user data enumeration
- Combined with SQL injection, full database mapping possible

**Validation Boundary**:
- NOT validated: mass enumeration, automated harvesting
- Tested: single cross-user access only

**Risk Statement**:
Sequential ID pattern combined with IDOR creates mass enumeration risk. Only single cross-user access tested; no enumeration script executed.

**Recommendation**:
Implement non-predictable object IDs. Add rate limiting. Fix F-002 authorization.

---

## Safe Follow-up Hypotheses

| Hypothesis | Safe to Validate | Authorization Required |
|------------|------------------|------------------------|
| SQL injection credential impact | ❌ | ✓ UNION testing authorization |
| XSS session hijacking | ❌ | ✓ alert execution authorization |
| IDOR mass enumeration | ❌ | ✓ automated testing authorization |
| Chain to admin access | ❌ | ✓ admin credentials required |

---

## New Endpoints from Chain Analysis

| Endpoint | Discovered Via | Test Priority | Status |
|----------|----------------|---------------|--------|
| {/api/admin/users} | F-001 error hint | P0 | Requires admin auth |
| {/api/v1/export} | F-002 data pattern | P1 | New target |

**Action**: Return to Phase 1-2 if new endpoints discovered and in scope.

---

## Risk Impact Statement

**Overall Risk**: {Critical/High/Medium}

Confirmed findings F-001, F-002, F-003 can combine to form:
1. Credential extraction chain (SQL + IDOR)
2. Account takeover chain (XSS + session)
3. Mass data harvesting chain (IDOR + sequential IDs)

**Validation Stop Point**:
All chains stopped at hypothesis level. No destructive or exploitative validation performed.

**Remediation Priority**:
1. Fix F-001 SQL Injection (highest)
2. Fix F-002 IDOR
3. Fix F-003 XSS
4. Add security headers (HttpOnly, CSP)

---

## Chain Validation Authorization Request

If user needs chain impact proof:

| Chain | Requested Action | Authorization Needed |
|-------|------------------|----------------------|
| SQL credential impact | UNION read test table | User explicit approval |
| XSS session hijacking | Alert execution test | User explicit approval |
| IDOR enumeration | Limited enumeration script | User explicit approval |

---

## Phase 4 Completion Checklist

- [ ] All confirmed findings analyzed for chain potential
- [ ] Hypothetical impact documented
- [ ] Validation boundaries stated
- [ ] New endpoints flagged (return to Phase 1 if applicable)
- [ ] Remediation priority set
- [ ] Authorization requests documented for further validation

---

## Next Actions

1. Generate `report.md` from structured outputs
2. Ask user if chain validation authorization needed
3. If new endpoints: return to Phase 1-2 with documented reason
4. Mark task as completed or paused
```

---

## Usage

1. Create `04-chain.md` after Phase 3 confirmed findings
2. Analyze each confirmed finding for chain potential
3. Document hypothetical impact, NOT actual exploitation
4. Return to earlier phases if new endpoints discovered
5. Request authorization before any chain exploitation validation
6. Keep risk statements focused on what COULD happen, not what WAS done