# Test Coverage Checklist

> Run this checklist **before declaring Phase 4 / report done**. Its job is to make untested surface visible. Every row must end up `covered`, `degraded`, `not-covered`, or `out-of-scope` — never blank. Blank is the failure mode this checklist exists to prevent.

**Status definitions**:
- `covered` — tested this task with current-task evidence
- `degraded` — attempted but constrained (e.g., single account, tool missing); reason recorded
- `not-covered` — never entered testing; reason recorded
- `out-of-scope` — explicitly excluded in preflight

**Rule**: `degraded` and `not-covered` rows **must** appear in the report's "Test Coverage & Gaps" section. Silently dropping them is forbidden — that is exactly the invisible-gap problem this checklist solves.

---

## Discovery Surface

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Subdomain enumeration | | |
| Port scanning (approved ports) | | |
| Virtual hosts | | |
| Directory / file brute-force | | |
| JavaScript / bundle endpoint extraction | | |
| SPA route / hydration data extraction | | |
| OpenAPI / Swagger / GraphQL introspection | | |
| OSINT (passive, if in scope) | | |

## Unauthenticated Vulnerability Surface

For each class applicable to the confirmed tech stack:

| Class | Status | Evidence / Reason |
|-------|--------|-------------------|
| SQLi / NoSQLi | | |
| Command injection | | |
| SSTI | | |
| XSS (reflected) | | |
| DOM XSS | | |
| Path traversal / LFI | | |
| File upload | | |
| SSRF | | |
| XXE | | |
| Deserialization | | |
| Open redirect | | |
| CRLF / header injection | | |
| HTTP request smuggling | | |
| Race conditions | | |
| Information disclosure / error handling | | |
| Backup / source exposure | | |
| Default credentials | | |
| Security misconfig / headers | | |

## Authenticated Vulnerability Surface

| Face | Status | Evidence / Reason |
|------|--------|-------------------|
| ① Authenticated surface traversal | | |
| ② Vertical privilege escalation | | |
| ③ Horizontal privilege escalation (IDOR/BOLA) | | (degraded if <2 accounts) |
| ④ Session / token lifecycle | | |

If the authenticated branch was skipped (no credentials supplied), mark all four `not-covered` with reason "no session supplied in preflight".

## API-Specific (when API surface confirmed)

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Parameter discovery (active fuzz) | | |
| Mass assignment | | |
| Business logic / BOLA on objects | | |
| Rate limiting / brute-force protection | | |
| GraphQL (introspection, batch, mutation abuse) | | |

## Infrastructure / Contextual (only if in scope)

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Subdomain takeover | | |
| Cloud metadata / cloud misconfig | | |
| WebSocket | | |
| CORS | | |
| Cache poisoning | | |
| Host header abuse | | |

---

## Coverage Summary (for report)

| Category | covered | degraded | not-covered | out-of-scope |
|----------|---------|----------|-------------|--------------|
| Discovery | | | | |
| Unauthenticated | | | | |
| Authenticated | | | | |
| API-specific | | | | |
| Infrastructure | | | | |

The report's "Test Coverage & Gaps" section is generated from the `degraded` + `not-covered` rows above. A task is not "done" until this checklist is filled and gaps are reflected in the report.
