# Test Coverage Checklist

> Run this checklist **before declaring Phase 4 / report done**. Its job is to make untested surface visible. Every row must end up `covered`, `degraded`, `not-covered`, or `out-of-scope` — never blank. Blank is the failure mode this checklist exists to prevent.

**Status definitions**:
- `covered` — tested this task with current-task evidence
- `degraded` — attempted but constrained (e.g., single account, tool missing); reason recorded
- `not-covered` — never entered testing; reason recorded
- `out-of-scope` — explicitly excluded in preflight

**Rule**: `degraded` and `not-covered` rows **must** appear in the report's "Test Coverage & Gaps" section. Silently dropping them is forbidden — that is exactly the invisible-gap problem this checklist solves.

**Truthfulness rule** (enforced by `scripts/check_completeness.py` before a report is allowed): marking a row is not enough — the mark must be backed by evidence.
- `covered` → a matching request must exist in `03-vuln-test.md` for that surface class, or a reason must justify the coverage. "Covered" with no request and no reason is rejected as a claimed-but-not-tested skip.
- `not-covered` / `degraded` → the Reason column **must** be filled. Empty reason = silent drop = gate failure.
- `out-of-scope` → the Reason must use a prescribed phrase (`mechanism not present` / `feature not present` / `protocol not present` / `no LLM endpoint` / `no K8s surface` / `no session supplied` / `explicitly excluded`). Invented excuses are rejected.

**Format requirement**: the report gate (`generate_report.py`) parses this file as **markdown tables** — Status must be in the second column of each `| Surface | Status | Reason |` row, and Scope Adherence Result in the second column of each `| Check | Result | Evidence |` row. Free-form paragraphs or bulleted lists are not parsed; if you write coverage that way, the gate and the report's gap section will not see it.

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
| ④a Session/token lifecycle (fixation, hijack, non-expiry, reuse) | | |
| ④b JWT security (alg=none, weak key, kid/jku jwk, algorithm confusion) | | (only if JWT present) |
| ④c MFA/2FA bypass (TOTP, backup codes, skip, rate-limit, response leak) | | (only if MFA present) |
| ④d OAuth/OIDC flaws (redirect_uri, state, PKCE, code reuse) | | (only if OAuth present) |
| ④e Password reset poisoning (token predictability, host header, step skip) | | (only if reset flow present) |
| ④f CSRF (token presence, bypass, SameSite) | | (on state-changing endpoints) |
| ④g CAPTCHA/lockout bypass (client-side counter, lockout reuse) | | (only if present) |

If the authenticated branch was skipped (no credentials supplied), mark all rows above `not-covered` with reason "no session supplied in preflight". The ④b–④g sub-rows only apply when the corresponding mechanism is actually present — mark `out-of-scope` with reason "mechanism not present" otherwise.

## API-Specific (when API surface confirmed)

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Parameter discovery (active fuzz) | | |
| Mass assignment | | |
| Business logic / BOLA on objects | | |
| Rate limiting / brute-force protection | | |
| GraphQL (introspection, batch, mutation abuse) | | |
| SOAP / WSDL / gRPC-protobuf input validation | | (only if present) |
| Excessive data exposure / field-level authz | | |

## Business Logic Surface (only if the corresponding feature exists)

> These rows apply **only** when fingerprint/discovery confirms the feature exists (e.g. a payment endpoint, a coupon field). If a feature is absent, mark it `out-of-scope` with reason "feature not present". Never mark `covered` for a feature that was never exercised.

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Race condition on assets/funds (concurrent redemption, balance, withdrawal) | | (needs concurrency test) |
| Price / quantity tampering | | (only if cart/order flow present) |
| Payment step skipping / flow bypass | | (only if payment present) |
| Payment / callback replay | | (only if callback present) |
| Coupon / limit / quota abuse | | (only if coupon/quota present) |
| OTP / verification code logic bypass | | (only if OTP present) |
| Workflow manipulation (step order, role-state bypass) | | (only if multi-step workflow present) |

## AI / LLM Surface (only if an LLM endpoint is confirmed)

> Applies when fingerprint/discovery finds a chatbot, LLM API, or agent integration (e.g. Dify, OpenAI proxy, /chat completions). Requires the headless-browser or HTTP capability to interact. If no LLM endpoint exists, mark all rows `out-of-scope` with reason "no LLM endpoint".

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Prompt injection bypassing safety controls (confirmed) | | |
| Indirect prompt injection (untrusted content → tool) | | |
| System prompt leakage (internal logic/schema) | | |
| Tool-use / function-call authorization bypass | | |
| Cross-user memory / RAG poisoning (persistent) | | |
| Vector DB / knowledge base mass read (PII/credentials) | | |
| Tool-use executes system command / destructive API | | |
| Cost / resource DoS (single bounded proof) | | |
| LLM endpoint existence / metadata exposure | | |

## Cloud Native / Infrastructure Surface (only if in scope)

> Cloud-native rows apply when the target exposes cloud/K8s surface (e.g. cloud metadata IP, K8s API, etcd, service-account tokens via SSRF or misconfig). If the target is a pure web app with no cloud surface, mark cloud rows `out-of-scope`.

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| Subdomain takeover | | |
| Cloud metadata credential exposure (169.254.169.254 / metadata API) | | |
| Cloud object storage public access (OSS / COS / OBS / S3 / GCS) | | |
| Kubernetes API server unauthenticated access | | (only if K8s surface) |
| Kubelet API unauthenticated (10250/10255) | | (only if K8s surface) |
| etcd unauthenticated access (2379) | | (only if K8s surface) |
| ServiceAccount token abuse / cross-namespace | | (only if K8s surface) |
| Container escape (privileged pod) | | (only if container access) |
| WebSocket (missing auth / origin) | | |
| CORS misconfiguration | | |
| Cache poisoning | | |
| Host header abuse | | |
| WAF / origin IP discovery (bypass surface mapping) | | |

## Modern Protocol Surface (only if the protocol is confirmed)

> Applies when fingerprint finds gRPC (grpc-web, application/grpc), HTTP/2, or protobuf usage. If absent, mark `out-of-scope` with reason "protocol not present".

| Surface | Status | Evidence / Reason |
|---------|--------|-------------------|
| gRPC auth bypass / reflection enumeration | | (only if gRPC present) |
| Protobuf injection (field type confusion, nested message) | | (only if protobuf present) |
| HTTP/2 single-packet race condition (assets) | | (only if HTTP/2 + race-sensitive op) |
| HTTP/2 single-packet race condition (test-only) | | (only if HTTP/2 present) |

## Scope Adherence (mandatory before report done)

This section proves every request stayed inside the approved preflight `scope`. It is generated by cross-checking the `02-discovery.md` and `03-vuln-test.md` request logs against `task.md` `scope_allowlist`.

The report gate also performs a machine check: request logs must include a host column, and every host must appear in `scope_allowlist`. If `approved_ports` is set to numeric ports, any logged host with an explicit port must use one of those ports. If `approved_ports` is omitted or set to `default-for-target`, the target URL's default or explicit port is enforced. Free-form `scope` text is not used as a machine allowlist.

| Check | Result | Evidence |
|-------|--------|----------|
| All request targets ⊆ scope allowlist | {pass/violation} | {request log cross-check} |
| Discovered-but-out-of-scope hosts recorded, not probed | {pass/violation} | {e.g. actuator `_links` `gateway-enterprise` recorded, not requested} |
| No probe to internal hostnames / sibling subdomains / wildcard-cert SANs beyond scope | {pass/violation} | {list any observed-then-ignored hosts} |

If any row is `violation`, the task is **blocked** — the boundary breach must be reported to the user and the out-of-scope requests disclosed before the report is finalized. Scope adherence is never silently dropped.

---

## Coverage Summary (for report)

| Category | covered | degraded | not-covered | out-of-scope |
|----------|---------|----------|-------------|--------------|
| Discovery | | | | |
| Unauthenticated | | | | |
| Authenticated (incl. JWT/MFA/OAuth/Reset/CSRF/CAPTCHA) | | | | |
| API-specific | | | | |
| Business Logic | | | | |
| AI / LLM | | | | |
| Cloud Native / Infrastructure | | | | |
| Modern Protocol | | | | |

The report's "Test Coverage & Gaps" section is generated from the `degraded` + `not-covered` rows above. A task is not "done" until this checklist is filled and gaps are reflected in the report. Surface sections that do not apply to the target (no LLM endpoint, no K8s surface, no payment flow) must be marked `out-of-scope` with an explicit reason — never left blank, which is the silent-omission failure mode this checklist exists to prevent.
