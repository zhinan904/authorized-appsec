# DOM-Based XSS Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify DOM-based XSS vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual JavaScript execution is prohibited
> - DOM XSS payloads are for understanding attack surface only, **no cookie theft or session hijacking**
> - Validation proves vulnerability existence (sink reached with payload), **no malicious script execution**
> - Use `console.log()` or harmless markers by default; `alert()` requires authorization
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PortSwigger, PayloadsAllTheThings

## Manual Testing

**Note: Analyze JavaScript source for sink/source patterns**

---

## Validation Objectives (Within Security Boundary)

DOM-based XSS validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Source Identification | ✓ Identify user-controlled input sources | - | Inject malicious payloads |
| Sink Analysis | ✓ Identify dangerous sinks (innerHTML, eval) | - | Execute arbitrary JS |
| Payload Delivery | ✓ Verify payload reaches sink | - | Cookie theft |
| Taint Tracking | ✓ Trace data flow from source to sink | - | Keylogging / session hijacking |

**Safe Validation Method**: Analyze JavaScript for source-to-sink data flow and verify payload reaches sink using harmless markers; do not execute malicious scripts.

---

## Common Sources

| Source | Description |
|--------|-------------|
| `document.URL` | Full page URL |
| `document.documentURI` | Document URI |
| `document.referrer` | Referrer header |
| `location.href` | Current URL |
| `location.search` | Query string |
| `location.hash` | Fragment identifier |
| `window.name` | Window name |
| `document.cookie` | Cookies |
| `postMessage` | Cross-origin messages |
| `localStorage` / `sessionStorage` | Client storage |

## Common Sinks

| Sink | Risk Level | Notes |
|------|------------|-------|
| `innerHTML` | High | HTML injection |
| `outerHTML` | High | HTML injection |
| `document.write()` | High | HTML injection |
| `eval()` | Critical | JavaScript execution |
| `setTimeout(string)` | High | Delayed JS execution |
| `setInterval(string)` | High | Repeated JS execution |
| `Function()` | High | JS execution |
| `insertAdjacentHTML()` | High | HTML injection |
| `jQuery.html()` | High | HTML injection |
| `jQuery.append()` | Medium | HTML injection |
| `location.href` | Medium | Redirect |
| `location.assign()` | Medium | Redirect |
| `location.replace()` | Medium | Redirect |
| `window.open()` | Medium | Popup/redirect |

---

## Detection Methods

### Source Analysis (JavaScript Review)

```javascript
// Look for user-controlled data flows:
// document.location -> sink
// document.URL -> sink
// document.referrer -> sink
// location.hash -> sink

// Example vulnerable pattern:
var input = location.hash.substring(1);
document.getElementById("output").innerHTML = input;
// -> DOM XSS via hash fragment
```

### Hash-Based DOM XSS

```bash
# Test payload in URL hash
# Browser does not send hash to server
# JavaScript reads it client-side

# Example:
https://target.com/page#<img src=x onerror=console.log('dom-xss')>

# Verify: check if payload appears in DOM
# Use browser DevTools: Elements panel -> search for payload
```

### Query-Based DOM XSS

```bash
# Test payload in query parameter
# If reflected client-side via JavaScript:
https://target.com/page?q=<img src=x onerror=console.log('dom-xss')>

# Check: does JavaScript read location.search and inject into DOM?
```

### postMessage-Based DOM XSS

```javascript
// Test via postMessage
// In browser console on attacker-controlled page:
targetWindow.postMessage("<img src=x onerror=console.log('dom-xss')>", "*");

// Check if target page has message listener that injects into DOM
// Look for: window.addEventListener("message", ...)
```

### URL Fragment Manipulation

```bash
# Common pattern: hash used for client-side routing
# Test: does router sanitize hash before rendering?

https://target.com/#/page?payload=<img src=x onerror=console.log('dom-xss')>
https://target.com/#<img src=x onerror=console.log('dom-xss')>
```

### DOM Clobbering

```html
<!-- DOM clobbering: override JS variables via HTML -->
<!-- If JS reads: window.config.admin -->
<form id="config"><input name="admin" value="true"></form>
<!-- Now: document.config.admin === "true" -->

<a id="config" href="javascript:console.log('dom-xss')">click</a>
```

---

## JavaScript Analysis Checklist

```markdown
## DOM XSS Analysis

### Sources Found
- [ ] document.URL
- [ ] document.documentURI
- [ ] document.referrer
- [ ] location.href / .search / .hash
- [ ] window.name
- [ ] postMessage listeners
- [ ] localStorage / sessionStorage

### Sinks Found
- [ ] innerHTML / outerHTML
- [ ] document.write()
- [ ] eval() / Function()
- [ ] setTimeout(string) / setInterval(string)
- [ ] insertAdjacentHTML()
- [ ] jQuery.html() / .append()
- [ ] location.href / .assign() / .replace()

### Data Flow
- Source: {which source}
- Sanitization: {none / insufficient / proper}
- Sink: {which sink}
- Exploitable: {yes / no / conditional}
```

---

## Analysis Process

1. Obtain JavaScript source (page source, external scripts)
2. Identify all user-controlled sources
3. Identify all dangerous sinks
4. Trace data flow from source to sink
5. Check for sanitization/encoding
6. Verify payload reaches sink with harmless marker
7. **Stop validation**, document DOM XSS pattern
8. Do not execute malicious JavaScript

---

## Severity Classification

DOM XSS Severity is based on**whether JS execution is confirmed**is authoritative, rather than sink type. not all sinks can execute script - `innerHTML` assignment into `<script>` does not execute under HTML5, requires `<img onerror>` or similar alternatives. High requires confirmed popup/JS execution. 

| DOM XSS Type | Default | Only whenconfirmed JS executioncan be achieved |
|--------------|------|---------------------------|
| eval() / Function() / setTimeout(string) sink | Medium | -> High:source is controllable and can pass strings that trigger execution |
| innerHTML / jQuery .html() | Medium | -> High:requires confirmation that injection can insert `<img onerror>` etc.can executevectors (`<script>` does not execute in innerHTML)|
| document.write() | Medium | -> High:written content is confirmed to trigger script execution |
| Location-based redirect | Low | -> Medium: open redirect only, no JS execution |
| Blocked by CSP | Low | CSP blocks execution, not exploitable even if the sink exists |
| source is controllable but source-to-execution chain is not verified | Low | Pending confirmationexecutionchain |

**Key judgment**:Reporting High requires confirming"source-to-JS-execution"the full chain is reachable. Proof only sink exists (for example, can write into innerHTML)does not equal XSS - must verify that written content can actually trigger script (such as `onerror` firing or popup succeeding). unverified execution is Medium or below. 

**Boundary coordination**: This file prohibits actual JS execution by default (`alert()` requires authorization). Therefore DOM XSS is at most Medium in the default scope. "Confirmed JS execution = High" requires user authorization for harmless popup verification (such as `alert(document.domain)`) before recording. Do not raise severity based on possible execution without authorization.

---

## Output

```markdown
## Vulnerability: DOM-Based XSS

### Location
{URL} - Source: {source} -> Sink: {sink}

### Data Flow
- Source: {user-controlled input}
- Processing: {sanitization applied}
- Sink: {dangerous function}
- Vector: {hash / query / postMessage / storage}

### Evidence
- Payload: {test payload}
- Source code: {relevant JS snippet}
- Sink function: {innerHTML / eval / etc.}

### Validation Result
- DOM XSS confirmed: {yes/no}
- Source: {specific source}
- Sink: {specific sink}
- CSP bypass: {yes/no}

### Risk Level
{High} - eval() sink with no sanitization
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Execute malicious JS | Do not run cookie theft, keylogger, or session hijack |
| ❌ Bypass CSP | Do not attempt CSP bypass for exploitation |
| ❌ Phish users | Do not create DOM XSS phishing pages |
| ❌ Access localStorage | Do not read sensitive client storage data |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> XSS severity rules
