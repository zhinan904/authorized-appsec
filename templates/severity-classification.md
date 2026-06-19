# Vulnerability Severity Classification

> **Version**: 2.21.0 | **Updated**: 2026-06-18

This document defines severity classification rules for authorized AppSec assessment findings. The classification prioritizes practical exploitability and attack impact over theoretical CVSS scores.

---

## Severity Levels

| Level | Criteria | Examples |
|-------|----------|----------|
| **Critical** | Direct system control or mass data compromise | RCE, mass credential leak, full database read |
| **High** | Significant attack capability or exploitable information exposure | SQLi with data read, auth bypass, exploitable tech stack exposure |
| **Medium** | Limited impact, requires conditions or user interaction | Single-object IDOR, XSS, SSRF localhost proof |
| **Low** | Minor impact, limited exploitability | Info leakage with low value, missing security headers |
| **Info** | Discovery only, no direct security impact | Endpoint paths, parameter names, non-sensitive config |

---

## Critical Criteria

Assign **Critical** when:

| Condition | Description |
|-----------|-------------|
| Remote Code Execution | Command injection, deserialization RCE, file upload + execution |
| Mass Data Exposure | Database dump, credential file read, >100 user records exposed |
| Full System Control | Admin panel takeover with system modification capability |
| Critical Credential Leak | Cloud metadata credentials, database passwords, API keys with broad access |

**Boundary**: Critical requires actual execution capability or mass data access confirmed, not theoretical.

---

## High Criteria

Assign **High** when:

| Condition | Description |
|-----------|-------------|
| **Exploitable Information Exposure** | Information that enables further critical/high attacks |
| SQL Injection with Data Read | UNION confirmed or time-based with data extraction capability |
| Authentication Bypass | Login bypass, JWT forgery, session manipulation for access |
| Privilege Escalation | Vertical escalation to admin, horizontal to multiple users |
| SSRF with Internal Access | Cloud metadata readable, internal service reachable |
| File Inclusion with Source Read | LFI reading configuration with secrets |

### Exploitable Information Exposure (High)

Information findings qualify as **High** when they enable further attacks:

| Info Type | High Criteria | Reason |
|-----------|---------------|--------|
| Tech Stack + Version | Version has known CVE with public exploit | Enables targeted attack |
| Internal API Paths | Paths expose admin/internal functions | Expands attack surface significantly |
| Admin/Debug Endpoints | Exposed without authentication | Direct attack target |
| Configuration Files | Contain credentials or sensitive settings | Direct credential access |
| Database Connection Info | Host, user, database name exposed | SQLi targeting aid |
| Source Code Exposure | Contains hardcoded secrets or logic flaws | Credential/logic attack |

**Not High (remains Info)**:
- Tech stack without exploitable version
- Non-sensitive path enumeration
- Generic error messages
- Non-secret configuration (timeout, feature flags)

---

## Medium Criteria

Assign **Medium** when:

| Condition | Description |
|-----------|-------------|
| Single-Object IDOR | Access to one other user's object, no mass enumeration |
| Reflected XSS | Payload reflected, requires user click/visit |
| SSRF Basic Proof | Localhost reachable, no internal service exploitation |
| Limited SQLi | Error-based only, no data extraction confirmed |
| File Read (Test File) | `/etc/passwd` readable, no credentials |
| Rate Limiting Missing | Allows moderate brute force, no mass capability |

---

## Low Criteria

Assign **Low** when:

| Condition | Description |
|-----------|-------------|
| Information Leakage | Non-exploitable info (version without CVE, path without function) |
| Missing Security Headers | X-Frame-Options, CSP absent, limited impact |
| Cookie Attribute Issues | Missing Secure/HttpOnly, session not critical |
| Clickjacking Potential | Frame embedding possible, requires user action |
| Error Information | Stack trace, debug info without secrets |

---

## Info Criteria

Assign **Info** when:

| Condition | Description |
|-----------|-------------|
| Discovery Findings | Endpoints, parameters, forms identified |
| Technology Fingerprint | Framework detected, no exploitable version |
| Non-Sensitive Configuration | Feature flags, UI settings, non-secret config |
| Debug Endpoints (No Data) | Endpoint exists but returns no sensitive data |
| Robust Protections | WAF detected, security measures observed |

---

## Vulnerability Type Default Severity

> **Gating principle (core)**: Default Low; upgrade only when the exploit chain is closed / actual harm is confirmed. The "Default" column is each class's starting severity; the "Upgrade condition" column states the **confirmation required** to raise it. Do not upgrade when the condition is unmet. Per-payload `Severity Classification` is authoritative; this table is a summary fallback.

### Injection / Execution

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| RCE (confirmed) | Critical | — |
| SSTI | Low | → High: authorized RCE confirmed; expression echo only = Low |
| Deserialization | Low | → High: authorized RCE confirmed; gadget present but unverified = Low |
| Command injection | Low | → High: command execution confirmed; injection point only = Low |
| SQLi / NoSQLi | Low | → High: data extraction confirmed; blind time/boolean only = Medium; error echo only = Low |
| LDAP injection | Low | → High: auth bypass confirmed; data enumeration = Medium; query manipulation only = Low |
| XXE | Low | → High: sensitive file read / OOB exfil; reading /etc/passwd (capability confirmed) = High; entity parsing only = Low |
| LFI / arbitrary file read | Low | → High: arbitrary read confirmed (reading passwd establishes capability); unreadable = Low |
| Path Traversal | Low | → High: arbitrary read confirmed (same); traversal but unreadable = Low |
| File upload | Low | → Medium: upload successful and reachable; → High: authorized execution/config-overwrite confirmed; unreachable = Low |
| SSRF | Low | → High: reaches internal network / cloud credentials; external callback only = Low |

### Authentication / Authorization

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| Auth bypass | Medium | → High: confirmed access to auth-required resource |
| JWT signature flaw | Low | → High: authorized verification that forged token passes auth; alg=none supported but unverified = Low |
| MFA Bypass | Low | → High: base severity + reachability modifier (bypass = takeover); mechanism-only confirmation = Low |
| OAuth | Low | → High: redirect_uri controllable + state missing + token actually received; single defect = Medium |
| Password reset | Low | → High: token predictability/replay confirmed, or Host-header poisoning actually sent; suspected predictability = Medium |
| CSRF | Low | → High: sensitive state change (password/funds) without protection; general change = Medium; query class = Info |
| IDOR (read) | Medium | → High: sensitive data; non-sensitive = Medium |
| IDOR (modify/delete) | High | Read only → Medium |
| Default credentials | Low | → High: login to real account / admin panel; test account only = Medium; unverified = Low |

### Frontend / Client-side

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| XSS (reflected/stored) | Medium | → High: stored + confirmed execution / widespread; reflected with verification = Medium |
| DOM XSS | Medium | → High: JS execution chain confirmed reachable; sink-only = Medium; CSP blocks = Low |
| CORS | Low | → High: all 5 closure conditions met (reflection + credentials + cookie-auth + sensitive endpoint + preflight passes); any missing = Low |
| Open redirect | Low | → Medium-High: OAuth callback chain; plain redirect = Low |
| Cache poisoning | Low | → High: all 3 conditions met (shared cache + poisoned cached + affects others); no cache = Low |
| CRLF injection | Medium | → High: injection reaches response body / cache poisoning; header-only injection = Medium |
| WebSocket missing auth | Medium | → High: can trigger sensitive operation / privilege escalation; public data = Medium |
| WebSocket missing origin | Medium | → High: cross-origin can trigger sensitive operation |
| Session management flaw | Low | → High: session fixation / replay confirmed; cookie attribute missing = Low |
| Host header injection | Low | → Critical/High: per-scenario gating (reset poisoning / cache poisoning); Host not consumed = Low |
| HTTP method abuse | Low | → High: authorized confirmation that dangerous method actually works; OPTIONS-only display = Low |
| HTTP request smuggling | Low | → High: CL.TE/TE.CL confirmed reproducible; timing-only = Low |

### Information / Exposure (anti-inflation focus)

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| Missing security headers | Info | → High: only when the corresponding vuln is confirmed (e.g., missing CSP AND XSS confirmed); standalone missing = Info |
| Cookie attribute missing | Low | → Medium: requires XSS/CSRF to be exploitable |
| Error message disclosure | Low | → High: leaks keys/credentials/PII; → Medium: SQL/internal structure; version/stack = Low |
| Backup / config exposure | Low | → High: contains keys/source/credentials; directory listing = Medium; harmless file = Low |
| Admin panel exposure | Low | → High: default-credential login / no-auth / bypass entry; path discovery only = Low |
| Rate limit missing | Low | → High: authorized brute-force recovers a password; not brute-forced = Low |
| Version / banner disclosure | Info | → High: version has exploitable known CVE |
| Subdomain takeover | Medium | → High: active dangling CNAME + registrable; resolution error = Low |
| Origin IP exposure | Low | → High: confirmed real origin reachable, bypasses WAF; candidate IP only = Low |

### Business Logic

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| Race condition (assets/funds) | Medium | → High: operation-race bypass confirmed; test-only proof = Medium |
| Price / quantity tampering | Medium | → High: backend actually accepts tampering; proof-only = Medium |
| Payment step skipping | Medium | → High: real skip achieved; proof-only = Medium |
| Payment replay | Medium | → High: real replay succeeds; proof-only = Medium |
| Coupon / limit abuse | Medium | → High: large-scale exploitable |
| OTP bypass (logic) | Medium | → High: account takeover achieved |
| Workflow manipulation | Medium | → High: critical workflow bypassed |

### AI / LLM

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| LLM tool-use executes system commands / destructive API | Critical | — |
| Cross-user memory poisoning (persistent) | Critical | — |
| Vector DB full read (production PII/credentials) | Critical | — |
| Prompt injection bypasses safety controls (confirmed) | High | — |
| Tool-use authorization bypass | High | — |
| System prompt leakage (contains internal logic/schema) | High | harmless greeting-only snippet → Low |
| RAG collection enumeration | Medium | data read → High |
| Cost DoS (single proof) | Medium | sustained → High |
| LLM endpoint exists only | Low | — |

### Cloud Native / K8s

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| K8s API Server unauthenticated access | Critical | — |
| etcd unauthenticated access | Critical | — |
| Container escape (privileged pod) | Critical | — |
| Kubelet API unauthenticated | High | — |
| ServiceAccount Token abuse (cross-namespace) | High | — |
| Cloud metadata credential exposure | High | — |
| China cloud bucket public access (OSS/COS/OBS) | High | — |
| Helm Release info leak | Medium | — |

### Modern Protocol

| Class | Default | Upgrade condition |
|-------|---------|-------------------|
| gRPC auth bypass | High | — |
| gRPC reflection enumeration | Medium | — |
| HTTP/2 single-packet race (assets) | High | — |
| HTTP/2 single-packet race (test-only) | Medium | — |

---

## Business Logic Severity Criteria

Business logic vulnerabilities require special consideration - they often don't fit traditional CVSS patterns but can cause direct financial or operational impact.

### High-Severity Business Logic

Assign **High** when:

| Condition | Description |
|-----------|-------------|
| Race Condition (Assets) | Balance/coupon/credit can be manipulated via concurrent requests |
| Price Tampering | Product price can be modified to $0 or negative |
| Payment Step Skipping | Payment verification step can be bypassed |
| Payment Replay | Payment callback can be replayed for multiple credits |
| Workflow Manipulation | Critical workflow (approval, verification) can be bypassed |

**Proof vs Exploitation**:
- **Proof only**: Demonstrated vulnerability exists but no actual transaction completed → Medium
- **Confirmed exploitable**: Transaction completed or clear exploitation path → High

### Medium-Severity Business Logic

Assign **Medium** when:

| Condition | Description |
|-----------|-------------|
| Coupon Abuse (Single) | One coupon reused or limit exceeded by small amount |
| Quantity Manipulation | Negative quantity accepted but requires conditions |
| OTP Logic Bypass | OTP verification can be bypassed via logic flaw |
| Rate Limit Bypass | Allows moderate brute force capability |
| Step Skipping (Non-Critical) | Non-financial workflow step skipped |

### Severity Decision Flow for Business Logic

```
1. Does vulnerability affect financial assets? → High potential
2. Can it cause account takeover or privilege change? → High
3. Is proof limited to test/demonstration? → Consider Medium
4. Does it require specific conditions or user interaction? → Medium
5. Is impact limited to single object/action? → Medium
```

---

## Chain Impact Consideration

When multiple findings form an attack chain:

| Chain | Combined Severity | Rule |
|-------|-------------------|------|
| Info + Info | Highest individual | No upgrade unless combined enables new attack |
| Info + Exploitable Info | High | If chain enables new attack capability |
| Medium + Medium | High | If chain enables privilege escalation or data access |
| High + High | Critical | If chain enables system control |

**Example**:
- Tech stack (Info) + Version CVE (Info) → **High** (exploitable target identified)
- LFI test file (Medium) + Config path discovered (Info) → **High** (config reading possible)
- XSS (Medium) + CSRF (Medium) → **Medium** (requires user interaction chain)

---

## Classification Process

When classifying a finding:

1. **Identify vulnerability type** from payload category
2. **Check default severity** from table above
3. **Evaluate adjustments** based on:
   - Data volume (mass → Critical)
   - Exploitability (confirmed vs theoretical)
   - Information value (enables further attack → High)
   - User interaction requirement
4. **Consider chain context** if combined with other findings
5. **Document reason** in `fact_summary`

---

## Output Format

In `findings.json`:

```json
{
  "finding_id": "F-001",
  "title": "Tech Stack Exposure - nginx 1.18.0 (CVE-2021-23017)",
  "category": "information_disclosure",
  "severity": "high",
  "severity_reason": "Version has known RCE CVE with public exploit",
  "priority": "P0"
}
```

In `findings.md`:

```markdown
## F-001 — Tech Stack Exposure [High]

**Severity**: High
**Severity Reason**: nginx 1.18.0 has CVE-2021-23017 (RCE) with public exploit
```

---

## Report Presentation

Reports should distinguish:

1. **Critical/High**: Immediate action required
2. **Medium/Low**: Fix in regular cycle
3. **Info (High-value)**: Review for attack surface reduction
4. **Info (Discovery)**: Context for security posture
