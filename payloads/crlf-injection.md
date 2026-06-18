# CRLF Injection Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify CRLF injection vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual response splitting is prohibited
> - CRLF payloads are for understanding attack surface only, **no header injection for XSS/cache poisoning**
> - Validation proves vulnerability existence (observe injected headers), **no cross-user impact**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test with harmless header injection markers only**

---

## Validation Objectives (Within Security Boundary)

CRLF injection validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Header Injection | ✓ Inject harmless custom header | - | Inject Set-Cookie for session fixation |
| Response Splitting | ✓ Observe extra response headers | - | Inject XSS via response body split |
| Redirect Injection | ✓ Test Location header injection | - | Redirect users to malicious site |
| Log Injection | ✓ Inject newline in logs | - | Poison log files for downstream attacks |

**Safe Validation Method**: Inject a harmless custom header (e.g., `X-Test-Injected: true`) to confirm CRLF; do not inject Set-Cookie, Location, or script content.

---

## Detection Methods

### Basic CRLF in URL Path

```bash
# Test CRLF in URL path
curl -s -I "https://target.com/%0d%0aX-Injected:%20true"

# Check response for:
# X-Injected: true (CONFIRMED!)
```

### CRLF in Query Parameter

```bash
# Test CRLF in redirect parameter
curl -s -I "https://target.com/redirect?url=/home%0d%0aX-Injected:%20true"

# Check for injected header in response
```

### CRLF in HTTP Headers

```bash
# Test CRLF in custom header value
curl -s -I -H "X-Custom: value%0d%0aX-Injected:%20true" https://target.com/

# Check response headers for injection
```

### CRLF in Path Parameter

```bash
# Test CRLF encoded variants
curl -s -I "https://target.com/path%0d%0aX-Injected:%20true/endpoint"
curl -s -I "https://target.com/path%0D%0AX-Injected:%20true/endpoint"

# Unicode encoding bypass
curl -s -I "https://target.com/path%E5%98%8A%0AX-Injected:%20true/endpoint"
```

### Redirect Header Injection

```bash
# Test Location header injection
curl -s -I "https://target.com/redirect?url=https://evil.com%0d%0aX-Injected:%20true"

# If redirect contains injected header, XSS via redirect possible
```

### Response Splitting Detection

```bash
# If server reflects CRLF in response body
curl -s "https://target.com/search?q=test%0d%0a%0d%0a<html>injected</html>"

# Check if response body contains split content
```

---

## Analysis Process

1. Identify parameters that reflect in response headers or body
2. Send CRLF probe with harmless custom header
3. Check response for injected header
4. Test URL encoding variants (%0d%0a, %0D%0A, %E5%98%8A)
5. Test in different contexts: path, query, header value
6. **Stop validation**, document injection point
7. Do not inject XSS, cookies, or redirect to malicious sites

---

## Severity Classification

CRLF injection impact depends on**whether injection can actually affect the response body/cache/other users**, rather than"CRLF can be injected"itself. modern browsers/servers usually defend against response splitting, successful injection does not equal exploitability. 

| Injection Type | Default | Upgrade condition |
|----------------|------|---------|
| Header injection confirmed | Medium | header control only, limited impact |
| Response splitting | Medium | -> High: Only when confirmed that injected content enters the response body and can trigger XSS (modern browsers often block splitting; actual effect must be confirmed)|
| Redirect injection | Medium | -> High:Only whenthe injected redirect is exploitable (for example OAuth callback dependency or sensitive operation redirect)|
| Response splitting cache poisoning | Medium | -> High: injected content is stored by shared cache and affects other users |
| Log injection | Low | limited log-layer impact |
| Blocked by WAF/server | Info | Not exploitable |

**Key judgment**:Reporting High requires confirming CRLF injection creates**observable impact** - response-body XSS works/cache poisoningaffects others/redirect is maliciously usable. Proof onlyinjectability `\r\n` manipulate headers, record as Medium. response splitting is often blocked by modern browsers/frameworks, do not report High unless effectiveness is confirmed. 

---

## Output

```markdown
## Vulnerability: CRLF Injection

### Location
{URL} - Parameter: {param_name}

### Injection Type
{Header Injection / Response Splitting / Redirect Injection}

### Evidence
- Payload: {CRLF payload used}
- Response: {injected header observed}
- Encoding: {URL-encoded / raw}

### Validation Result
- Injection confirmed: {yes/no}
- Response splitting: {yes/no}
- Context: {path / query / header}

### Risk Level
{Medium} - Enables response header manipulation
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Inject XSS payloads | Do not inject `<script>` via CRLF |
| ❌ Set malicious cookies | Do not inject `Set-Cookie` headers |
| ❌ Redirect to malicious sites | Do not inject `Location: https://evil.com` |
| ❌ Poison logs | Do not inject content that affects log analysis |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> CRLF severity rules
