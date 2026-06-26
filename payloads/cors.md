# CORS Misconfiguration Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify CORS misconfiguration vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual data exfiltration is prohibited
> - CORS payloads are for understanding attack surface only, **no unauthorized cross-origin requests**
> - Validation proves vulnerability existence (misconfiguration confirmed), **no sensitive data theft**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test CORS configuration on same-origin and cross-origin requests**

---

## Validation Objectives (Within Security Boundary)

CORS misconfiguration vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Origin Reflection | ✓ Test if origin is reflected | - | Exfiltrate sensitive data |
| Wildcard Origin | ✓ Check for `Access-Control-Allow-Origin: *` | - | Access authenticated endpoints |
| Null Origin | ✓ Test `Origin: null` | - | Bypass authentication |
| Credential Inclusion | ✓ Check `Access-Control-Allow-Credentials` | - | Access cross-origin data |
| Subdomain Wildcard | ✓ Test `*.example.com` patterns | - | Exploit subdomain takeover |

**Safe Validation Method**: Send requests with different Origin headers and observe CORS response headers; do not exfiltrate data.

---

## Detection Methods

### Basic Origin Reflection Test

```bash
# Test if origin is reflected in response
curl -s -I -H "Origin: https://evil.com" https://api.example.com/endpoint

# Check response headers:
# Access-Control-Allow-Origin: https://evil.com (REFLECTED!)
# Access-Control-Allow-Credentials: true (DANGEROUS!)
```

### Wildcard Origin Test

```bash
# Check for wildcard origin
curl -s -I https://api.example.com/endpoint | grep -i "access-control-allow-origin"

# Wildcard without credentials:
# Access-Control-Allow-Origin: *
# Risk: Low (no credentials allowed)

# Wildcard with credentials (invalid per spec):
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
# Risk: Browser will block, but indicates misconfiguration
```

### Null Origin Test

```bash
# Test null origin (common bypass)
curl -s -I -H "Origin: null" https://api.example.com/endpoint

# If reflected:
# Access-Control-Allow-Origin: null
# Risk: Can exploit via sandboxed iframe
```

### Subdomain Wildcard Test

```bash
# Test arbitrary subdomain
curl -s -I -H "Origin: https://anything.example.com" https://api.example.com/endpoint

# If reflected:
# Access-Control-Allow-Origin: https://anything.example.com
# Risk: Exploitable if subdomain takeover exists
```

**Important — separate legitimate own-domain from attacker-controllable.** Reflection of the target org's own real subdomains (`www.example.com`, `m.example.com` that the org legitimately owns) is usually intended config and is **not** a CORS flaw on its own. To prove the vulnerability you must show an **attacker-controllable** origin is accepted — i.e. an unrelated domain, `null`, or a pre-domain suffix like `<target>.attacker.com`. Use the attacker-controllable result as the evidence; treat legitimate own-domain reflection as a contrast/baseline, not as the finding.

---

## CORS Bypass Techniques

### Trusted Subdomain Bypass

```bash
# If CORS allows *.example.com:
# 1. Find subdomain takeover opportunity
# 2. Register taken-over subdomain
# 3. Use as origin for cross-origin request

# Example:
curl -s -I -H "Origin: https://taken-over.example.com" https://api.example.com/endpoint
```

### Pre-domain CORS Bypass

```bash
# Some implementations check if origin ends with domain
# Test with pre-domain:

curl -s -I -H "Origin: https://example.com.evil.com" https://api.example.com/endpoint

# If reflected: regex bypass possible
```

### HTTP to HTTPS Downgrade

```bash
# Test if HTTP origin accepted for HTTPS endpoint
curl -s -I -H "Origin: http://example.com" https://api.example.com/endpoint

# If reflected: enables mixed content attacks
```

---

## Analysis Process

1. Send request with controlled Origin header
2. Check `Access-Control-Allow-Origin` in response
3. Check `Access-Control-Allow-Credentials` in response
4. Test various origin patterns (null, subdomain, pre-domain)
5. Determine if authenticated endpoints are affected
6. **Stop validation**, document misconfiguration
7. Do not exfiltrate actual data

---

## Severity Classification

CORS severity is based on **whether the exploit chain is closed** — this is authoritative, not a mechanical severity score based on configuration type.

Default CORS misconfigurations are **Low**. Only when the following five conditions are **all met**, upgrade to **High**:

1. Origin reflects arbitrary origins / allows null / regex can be bypassed
2. `Access-Control-Allow-Credentials: true`
3. Authentication depends on browser-carried cookies/sessions (rather than frontend manually setting `Authorization` header) — this is the most common chain-break point in modern token-header architectures
4. there is an authenticated endpoint returning sensitive data (profile data/keys/orders/PII, etc.)
5. actual request can pass preflight (OPTIONS does not block, or it is a simple request requiring no preflight)

If any one condition is unmet -> keep Low, and state in the finding the chain-break point (for example, "authentication uses a frontend token header, chain breaks at condition 3").

### Distinguish attacker-controllable origins from legitimate own-domain origins

A critical classification step that is easy to get wrong: **not every reflected Origin is a vulnerability**. Separate the Origin test results into two buckets before assessing severity:

| Bucket | Examples | Counts as a vulnerability? |
|--------|----------|----------------------------|
| **Attacker-controllable** | `<target>.attacker.com` (pre-domain suffix), arbitrary unrelated domains, `null`, attacker-registered subdomain via takeover | **Yes** — these prove the `endsWith`/regex flaw. This is the real evidence. |
| **Legitimate own-domain** | the target org's own real subdomains (`www.example.com`, `m.example.com` when the org owns `example.com`) | **No, on its own.** Reflecting an org's own legitimate frontend subdomain is often intended cross-domain config, not a flaw. Do not use it as the primary evidence for a CORS finding. |

Rule: the finding must rest on **attacker-controllable** origin reflection (bucket 1). Reflecting a legitimate own-domain subdomain alone does not establish a CORS vulnerability — at most it shows the server recognizes its own domains. Mixing legitimate own-domain reflection into the evidence inflates severity and produces false positives.

| configuration type | Default | Only when 5 conditions all met |
|---------|------|------------------|
| Origin reflected (attacker-controllable) + credentials | Low | -> High |
| Null origin allowed | Low | -> High |
| Pre-domain regex bypass | Low | -> High |
| Subdomain wildcard accepting attacker-registered subdomains | Low | -> Medium (also requires a subdomain takeover prerequisite) |
| Legitimate own-domain subdomain reflected only | Info | Info (intended config, not a flaw) |
| Wildcard without credentials | Low | Low (no credentials, no escalation path) |
| Wildcard with credentials | Invalid | Invalid (browser blocks it) |

---

## Output

```markdown
## Vulnerability: CORS Misconfiguration

### Location
{URL} - {endpoint}

### Misconfiguration Type
{Origin Reflection / Null Origin / Subdomain Wildcard}

### Evidence
- Request Origin: {origin}
- Response Header: Access-Control-Allow-Origin: {reflected origin}
- Credentials Allowed: {true/false}

### Validation Result
- Origin reflection confirmed: {yes/no}
- Credentials inclusion: {yes/no}
- Exploitable endpoints: {authenticated endpoints}

### Risk Level
{Low by default. Only High if all 5 chain-closure conditions met — record which conditions hold and where the chain breaks}

### Chain-Closure Assessment
| Condition | Holds? | Evidence |
|-----------|--------|----------|
| 1. Origin/null/regex bypass | {yes/no} | {reflected origin value} |
| 2. Allow-Credentials: true | {yes/no} | {header value} |
| 3. Cookie/session auto-carried auth | {yes/no} | {auth mechanism observed} |
| 4. Sensitive authenticated endpoint | {yes/no} | {endpoint + data type} |
| 5. Preflight passes / simple request | {yes/no} | {OPTIONS response or simple-request note} |

**Chain-break point** (if any): {condition # that fails — e.g., "condition 3: auth is frontend Bearer token, not cookie"}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Exfiltrate sensitive data | Do not access actual user data |
| ❌ Access authenticated endpoints | Do not test with real credentials |
| ❌ Exploit subdomain takeover | Only document possibility, not execute |
| ❌ Modify CORS headers | Only observe, not tamper |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> CORS severity rules