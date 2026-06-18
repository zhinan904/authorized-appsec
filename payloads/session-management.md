# Session Management Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify session management vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual session hijacking prohibited
> - Session testing is for understanding attack surface only, **no unauthorized account access**
> - Validation proves vulnerability existence (weakness confirmed), **no session fixating other users**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Testing Guide, PayloadAllTheThings

## Manual Testing

**Note: Test session management on authenticated and unauthenticated states**

---

## Validation Objectives (Within Security Boundary)

Session management vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Session Fixation | ✓ Test if session ID persists post-login | - | Fix session for other users |
| Session Timeout | ✓ Verify timeout enforcement | - | Maintain persistent unauthorized access |
| Concurrent Sessions | ✓ Test if multiple sessions allowed | - | Hijack active sessions |
| Token Entropy | ✓ Assess token randomness | - | Predict and forge tokens |
| Cookie Attribute Testing | ✓ Check Secure/HttpOnly/SameSite | - | Steal cookies via XSS |
| Session Regeneration | ✓ Verify session ID changes on login | - | Force sessions on victims |

**Safe Validation Method**: Test session behavior with your own test accounts only. Observe cookie attributes and session patterns without hijacking other users.

---

## Session Fixation Testing

### Pre-Login Session Fixation

```bash
# Step 1: Obtain session ID before login
curl -sI "https://target.com/login" | grep -i "set-cookie"

# Step 2: Use pre-login session ID to attempt authenticated access
curl -s "https://target.com/dashboard" -b "session=PRE_LOGIN_SESSION_ID"

# Step 3: Login with the same session ID
curl -s -X POST "https://target.com/login" \
  -b "session=PRE_LOGIN_SESSION_ID" \
  -d "username=testuser&password=testpass" \
  -c cookies.txt -L

# Step 4: Check if session ID changed
grep -i "set-cookie" cookies.txt

# If session ID does NOT change after login: session fixation vulnerability
```

### URL-Based Session Fixation

```bash
# Test if session ID in URL is accepted
curl -s "https://target.com/dashboard?sid=FIXED_SESSION_ID"

# Check if URL session parameter is used
curl -s "https://target.com/page?PHPSESSID=test123" | grep -i "session"

# Common URL session parameters
# PHPSESSID, sid, session_id, jsessid
```

### Cookie Injection Session Fixation

```bash
# Set a session cookie before authentication
curl -s "https://target.com/login" -b "session=attacker_fixed_id" -c cookies.txt

# After login, check if session ID remains the same
curl -s "https://target.com/dashboard" -b cookies.txt | grep -i "welcome\|dashboard"
```

---

## Session Timeout Testing

### Idle Timeout

```bash
# Step 1: Authenticate and obtain session
curl -s -X POST "https://target.com/login" -d "username=test&password=test" -c cookies.txt -L

# Step 2: Wait and test session validity at intervals
# Test at: 5min, 15min, 30min, 1hr
sleep 300 && curl -s -b cookies.txt "https://target.com/dashboard" -o /dev/null -w "%{http_code}"
sleep 600 && curl -s -b cookies.txt "https://target.com/dashboard" -o /dev/null -w "%{http_code}"
sleep 900 && curl -s -b cookies.txt "https://target.com/dashboard" -o /dev/null -w "%{http_code}"
sleep 3600 && curl -s -b cookies.txt "https://target.com/dashboard" -o /dev/null -w "%{http_code}"

# If session persists beyond expected timeout: weak session timeout
```

### Absolute Timeout

```bash
# Test if absolute session timeout exists
# Login, wait beyond maximum session duration (e.g., 24 hours)

# Check for absolute timeout headers
curl -sI "https://target.com/login" | grep -iE "max-age|expires|session.*timeout|cache-control"
```

---

## Concurrent Session Testing

```bash
# Step 1: Login from "browser 1"
curl -s -X POST "https://target.com/login" \
  -d "username=test&password=test" -c browser1.txt -L

# Step 2: Login from "browser 2" with same credentials
curl -s -X POST "https://target.com/login" \
  -d "username=test&password=test" -c browser2.txt -L

# Step 3: Test if browser 1 session still valid
curl -s -b browser1.txt "https://target.com/dashboard" -o /dev/null -w "%{http_code}"

# Step 4: Test if browser 2 session still valid
curl -s -b browser2.txt "https://target.com/dashboard" -o /dev/null -w "%{http_code}"

# If both sessions valid: concurrent sessions allowed (may be intended or vulnerability)
```

---

## Session Token Entropy

### Token Pattern Analysis

```bash
# Collect multiple session tokens for analysis
for i in $(seq 1 20); do
  curl -sI "https://target.com/login" | grep -i "set-cookie" | grep -oP "session=\K[^;]+"
  sleep 1
done

# Check token characteristics
# Length: Consistent or variable?
# Characters: Base64, hex, alphanumeric?
# Pattern: Sequential, random, predictable?

# Common weak patterns
# Sequential: sess_001, sess_002
# Timestamp-based: 1699999999
# Short length: < 16 characters
# Limited charset: numeric only
```

### Entropy Assessment

| Token Type | Minimum Length | Assessment |
|-----------|---------------|------------|
| Hex-encoded | 32 chars (128 bits) | Adequate |
| Base64-encoded | 24 chars (128 bits) | Adequate |
| UUID/GUID | 36 chars | Adequate |
| Short numeric | < 16 chars | Weak |
| Timestamp | 10 chars | Weak (predictable) |
| Sequential | Any | Weak (predictable) |

---

## Cookie Attribute Testing

### Complete Cookie Analysis

```bash
# Collect all Set-Cookie headers
curl -sI "https://target.com/login" | grep -i "set-cookie"

# Login and collect authenticated session cookie
curl -s -X POST "https://target.com/login" \
  -d "username=test&password=test" -c cookies.txt -L
cat cookies.txt

# Check cookie attributes for each session cookie
```

### Cookie Attribute Checklist

| Attribute | Secure Value | Risk if Missing |
|-----------|-------------|-----------------|
| Secure | `Secure` | Cookie sent over HTTP |
| HttpOnly | `HttpOnly` | JavaScript can read cookie |
| SameSite | `SameSite=Strict` or `Lax` | CSRF via cross-site requests |
| Path | `Path=/` (specific) | Cookie sent to unintended paths |
| Domain | Not set or specific domain | Cookie sent to subdomains |
| Expires/Max-Age | Reasonable duration | Persistent or session-only? |

### SameSite Testing

```bash
# Check SameSite attribute
curl -sI "https://target.com/login" | grep -i "samesite"

# Missing SameSite: cookie sent with all cross-site requests
# SameSite=None: equivalent to no SameSite (requires Secure)
# SameSite=Lax: sent with top-level navigation only
# SameSite=Strict: not sent with any cross-site requests
```

### Secure Flag Testing

```bash
# Check Secure flag
curl -sI "https://target.com/login" | grep -i "set-cookie" | grep -c "secure"

# If Secure flag missing: test if cookie is sent over HTTP
curl -sI "http://target.com/" -b "session=test" | grep -i "cookie"
```

### HttpOnly Testing

```bash
# Check HttpOnly flag
curl -sI "https://target.com/login" | grep -i "set-cookie" | grep -c "httponly"

# If HttpOnly missing: test via XSS
# <script>document.cookie</script> would access cookie
```

---

## Session Regeneration Verification

```bash
# Step 1: Get initial session
curl -sI "https://target.com/login" | grep -i "set-cookie" > pre_login_cookie.txt

# Step 2: Login
curl -s -X POST "https://target.com/login" \
  -d "username=test&password=test" -c post_login_cookie.txt -L

# Step 3: Compare session IDs
diff pre_login_cookie.txt post_login_cookie.txt

# If session ID unchanged: session not regenerated on login (fixation risk)
# If session ID changed: session properly regenerated
```

### Post-Authentication Regeneration

```bash
# Test session regeneration after privilege change
# Login as regular user
curl -s -X POST "https://target.com/login" \
  -d "username=regular&password=pass" -c regular_cookies.txt -L

# Elevate to admin (if possible)
curl -s -X POST "https://target.com/admin/login" \
  -b regular_cookies.txt -c admin_cookies.txt -L

# Compare session IDs - should change on privilege elevation
diff regular_cookies.txt admin_cookies.txt
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A07:2021-Identification and Authentication Failures |
| CWE | CWE-613: Insufficient Session Expiration |
| CWE | CWE-384: Session Fixation |
| CWE | CWE-614: Sensitive Cookie Without 'Secure' Flag |

---

## Analysis Process

1. Collect session cookies from login and unauthenticated requests
2. Analyze cookie attributes (Secure, HttpOnly, SameSite, Path, Domain)
3. Test for session fixation (pre/post login session ID comparison)
4. Evaluate session token entropy and randomness
5. Test session timeout behavior (idle and absolute)
6. Test concurrent session handling
7. Verify session regeneration on privilege changes
8. Document all findings with evidence
9. **Stop validation**, report findings without exploiting sessions

---

## Output

```markdown
## Vulnerability: Session Management Weakness

### Location
{URL} - {session mechanism}

### Weakness Type
{Session Fixation / Weak Timeout / Missing Cookie Attributes / Low Entropy / No Regeneration}

### Evidence
- Session ID unchanged after login: {yes/no}
- Secure flag missing: {yes/no}
- HttpOnly flag missing: {yes/no}
- SameSite attribute: {missing/None/Lax/Strict}
- Session timeout: {none / X minutes / consistent}
- Token length: {X characters}
- Token pattern: {random/sequential/predictable}

### Validation Result
- Session fixation possible: {yes/no}
- Cookie attributes weak: {list missing attributes}
- Session timeout inadequate: {yes/no}
- Concurrent sessions allowed: {yes/no}
- Token entropy insufficient: {yes/no}

### Risk Level
{see severity rules}

### Severity Classification

Session management flaw harm depends on **whether it can actually be exploited to hijack/replay/fix sessions**. Configuration attribute missing itself does not equal exploitable.

| Flaw type | Default | Upgrade condition |
|---------|------|---------|
| Session fixation | Medium | -> High: session id not rotated after login + victim session id can be preset to achieve hijacking |
| Token still valid after logout | Medium | -> High: old token can continue accessing authenticated interface after user logout (replayable)|
| Token not expired / overly long validity | Medium | -> High: stolen token usable long-term, amplifies other vulnerability harm |
| Token insufficient entropy / predictable | Low | -> High: confirmed predictable and forged valid token |
| Cookie missing HttpOnly (JS readable)| Low | Requires XSS prerequisite to exploit (combined with xss.md/dom-xss.md)|
| Cookie missing Secure (HTTP transmission)| Low | Requires MITM position to exploit |
| Cookie missing SameSite | Low | Relevant only in CSRF scenario (combined with csrf.md)|
| Concurrent sessions allowed | Info/Low | Mostly business design, not a flaw |

**Key judgment**: Reporting Medium or above must confirm session flaw **can be exploited to achieve specific harm** (hijack/replay/fixation). Plain cookie attribute missing (HttpOnly/Secure/SameSite) records Low — they are defense-in-depth missing, require XSS/MITM/CSRF to have actual impact, standalone existence does not report High. This is consistent with security-headers.md anti-inflation principle.

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Fixate sessions for other users | Only test with own accounts |
| ❌ Hijack active sessions | Only analyze session patterns |
| ❌ Maintain unauthorized access | Logout after each test |
| ❌ Steal cookies via XSS | Only document missing HttpOnly |
| ❌ Predict and forge tokens | Only assess entropy quality |
| ❌ Brute force session tokens | Only analyze token patterns |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Do not hijack sessions"
- `README.md` -> Prohibited execution checklist