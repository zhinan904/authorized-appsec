# CSRF Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify CSRF vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual malicious actions are prohibited
> - CSRF payloads are for understanding attack surface only, **no unauthorized actions executed**
> - Validation proves vulnerability existence (craftable cross-origin request), **no actual state change**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test CSRF tokens, SameSite cookies, and origin validation**

---

## Validation Objectives (Within Security Boundary)

CSRF vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Token Presence Check | ✓ Verify if CSRF token exists | - | Execute state-changing request |
| Token Validation Check | ✓ Test if token is validated | - | Bypass and execute action |
| SameSite Cookie Check | ✓ Analyze cookie attributes | - | Execute cross-origin action |
| Origin Header Check | ✓ Test if origin validated | - | Execute forged request |
| Proof of Concept | ❌ Not by default | ✓ Submit harmless test action only | Execute malicious action |

**Safe Validation Method**: Analyze request structure, test token/randomness validation logic, do not execute actual state-changing requests without authorization.

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Token presence/validation analysis, harmless endpoints | No authorization needed |
| **Tier 2: Authorized Extended** | State-changing endpoint PoC execution | User explicit authorization required |
| **Tier 3: Theory Reference** | Malicious CSRF attack concepts | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming CSRF token is missing or not validated (vulnerability exists).

---

## Harmless Test Actions First

Before testing state-changing endpoints, use harmless actions to validate CSRF:

### Preferred Harmless Endpoints

| Endpoint Type | Risk Level | CSRF Test |
|---------------|------------|-----------|
| Search/filter | None | `POST /api/search?q=test` |
| Preferences view | None | `GET /api/preferences` (check if token required) |
| Newsletter subscribe (test account) | Low | `POST /api/newsletter?email=test@example.com` |
| Logout | Low | `POST /api/logout` (no real harm) |
| Add to cart (test session) | Low | `POST /api/cart/add?id=test_item` |

### Safe Token Validation Test

```http
# Test token validation on harmless endpoint
POST /api/search HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

q=test&csrf_token=xyz789

# Remove token and observe response
POST /api/search HTTP/1.1
Host: example.com
Cookie: session=abc123

q=test

# Expected: If server accepts without token -> CSRF vulnerability confirmed
# Safe: Search action has no security impact
```

---

## CSRF Vulnerability Indicators

### Missing CSRF Token

```bash
# Check if form/request includes CSRF token
curl -s <url> | grep -E "csrf|token|nonce|_token"

# If no token found, potentially vulnerable
```

### Weak Token Validation

```bash
# Test if token is validated (remove token, use invalid token)
curl -X POST <url> -d "action=test" -H "Cookie: session=valid"

# If request succeeds without token -> vulnerable
```

### SameSite Cookie Attribute

```bash
# Check cookie SameSite attribute
curl -sI <url> | grep -E "Set-Cookie.*SameSite"

# SameSite=Strict/Lax: CSRF protected
# SameSite=None or missing: potentially vulnerable
```

---

## CSRF Test Cases (Tier 1 - Safe Analysis)

### Token Presence Check (No Execution)

```bash
# Check if form includes CSRF token - no submission
curl -s <url> | grep -E "csrf|token|nonce|_token"

# Analyze HTML form structure:
# <form action="/api/action">
#   <input type="hidden" name="csrf_token" value="xyz789">
# </form>

# If no token found -> potentially vulnerable
```

### Token Validation Logic Test (Harmless Endpoint)

```http
# Use search endpoint to test token validation behavior
# Original request structure
POST /api/search HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

q=test&csrf_token=xyz789

# Test: Remove token
POST /api/search HTTP/1.1
Cookie: session=abc123

q=test

# Test: Invalid token
POST /api/search HTTP/1.1
Cookie: session=abc123

q=test&csrf_token=invalid123

# Test: Token reuse across session
POST /api/search HTTP/1.1
Cookie: session=different_user

q=test&csrf_token=xyz789
```

**Expected**: If server accepts requests without/with invalid token -> CSRF vulnerability confirmed.

**Safe**: Search action has no state change or security impact.

---

## ⚠️ State-Changing Endpoint Testing (Requires Authorization)

**⚠️ IMPORTANT**: Testing CSRF on state-changing endpoints (password change, profile update, etc.) is NOT a default validation step. Submitting these requests even as tests causes actual state changes.

**Default Validation Path** (recommended):
1. Analyze token presence in request structure (curl/grep)
2. Test token validation on harmless endpoints (search, logout)
3. **Stop here** - vulnerability is confirmed if token missing/not validated
4. Document vulnerability existence without executing real state changes

**Authorization Requirements** for state-changing PoC:
1. User explicitly authorizes PoC execution in writing
2. Use test account only, not production accounts
3. Document actual state change in report
4. Mark "State-changing PoC executed with user authorization"

---

### Token Tests on State-Changing Endpoints (Theory Reference - Do Not Execute Without Authorization)

**The following are for understanding request structure only. Do not execute without explicit authorization**:

#### Password Change Token Test (Requires Authorization)

```http
# Request structure analysis - do not execute without authorization
POST /api/change-password HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

current_password=old&new_password=new&csrf_token=xyz789

# If you were authorized to test:
# Test: Remove token and observe response
# Expected: If server accepts -> CSRF vulnerability confirmed
# Note: This causes actual password change
```

#### Profile Update Token Test (Requires Authorization)

```http
# Request structure analysis - do not execute without authorization
POST /api/update-profile HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=new@example.com&csrf_token=xyz789

# If you were authorized to test:
# Test: Token removal, invalid token, cross-session reuse
# Note: This causes actual profile update
```

---

## SameSite Cookie Bypass Scenarios

| SameSite Value | CSRF Protection | Bypass Scenarios |
|----------------|-----------------|------------------|
| Strict | Strong | Redirect-based attacks, subdomain origins |
| Lax | Moderate | POST from top-level navigation, 2-minute window |
| None | None | Any cross-origin request (requires Secure) |
| Missing | Weak | Any cross-origin request |

### Lax Bypass Conditions

```text
# SameSite=Lax allows GET from top-level navigation
# POST requests blocked, but:

1. GET form submission from external site (top-level navigation)
2. 2-minute window after site interaction (Chrome)
3. JavaScript-initiated requests still blocked
```

---

## JSON CSRF Test (Tier 1 - Safe Analysis)

### Content-Type Handling Check

```http
# Test JSON endpoint CSRF protection - use harmless endpoint
POST /api/search HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: text/plain

{"q":"test"}

# If server accepts text/plain with JSON body -> CSRF possible
# Some endpoints reject application/json from cross-origin but accept text/plain
# Safe: search endpoint has no state change
```

### JSON CSRF Theory Reference (Requires Authorization)

**The following example uses a state-changing endpoint. Do not execute without authorization**:

```http
# State-changing JSON endpoint - requires authorization
POST /api/update-profile HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: text/plain

{"email":"attacker@evil.com"}

# This causes actual profile update - requires user authorization
# For understanding only: demonstrates why Content-Type matters
```

---

## Proof of Concept HTML (For Reference Only)

Following PoC demonstrates vulnerability structure; **do not execute without authorization**:

```html
<!-- CSRF PoC - submit harmless test action only with authorization -->
<html>
  <body>
    <form action="https://target.com/api/test-action" method="POST" id="csrf">
      <input type="hidden" name="test_param" value="test_value" />
      <input type="submit" value="Submit Request" />
    </form>
    <script>
      // Auto-submit for demonstration (requires authorization)
      // document.getElementById("csrf").submit();
    </script>
  </body>
</html>
```

---

## Analysis Process

1. Identify state-changing endpoints (password change, profile update, form submissions)
2. Check for CSRF token presence in requests
3. Test token validation (remove, modify, reuse)
4. Analyze cookie SameSite attribute
5. Test origin/referer header validation
6. **Stop validation**, confirm CSRF vulnerability existence
7. If PoC execution needed, obtain user authorization first

---

## Output

```markdown
## Vulnerability: CSRF

### Location
{URL} - {action name}

### Vulnerability Type
{Missing Token / Weak Token Validation / SameSite=None}

### Evidence
- CSRF token: {present/absent}
- Token validation: {validated/not validated}
- SameSite attribute: {Strict/Lax/None/missing}
- Origin validation: {enforced/not enforced}

### Proof
{Token removal/invalid token accepted}

### Risk Level
{see severity rules}

### Severity Classification

CSRF impact depends on**the sensitivity of the affected operation** - cross-origin password/email change or transferis required for high severity; query/search operations without CSRF protection have no security impact by themselves. 

| Affected operation | Severity without protection | Note |
|-----------|------------|------|
| Sensitive state change: password/email/binding/fund operation | **High** | account takeover/financial loss, CSRF chain value is high |
| General state change: nickname/subscription/personal settings | Medium | impact exists but not takeover-level |
| Query/search/filter (no state change)| Info/Low | No security impact, not a CSRF vulnerability |
| Partial protection exists (SameSite=Lax but GET bypassable / token strippable)| Downgrade one level by operation sensitivity | Protection exists but has gaps |

**Boundary coordination**:actual PoC execution against state-changing endpointsis Tier 2 (requires user authorization). Within the default scope (Tier 1)only analyze whether tokens exist/are validated and verify with harmless endpoints - confirming CSRF on sensitive endpoints requires user authorization and PoC execution on a test account. do not report "query interface has no token" as a CSRF vulnerability. 
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Execute real state change | Do not submit actual password change, profile update |
| ❌ Malicious action | Do not craft requests that benefit attacker |
| ❌ Mass CSRF | Do not create scalable attack pages |
| ❌ User manipulation | Do not trick users into triggering PoC |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "OOB exfiltration, internal probing | Ask first"