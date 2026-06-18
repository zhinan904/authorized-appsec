# Authenticated Testing

> Phase 3 parallel branch for testing the **authenticated attack surface** — endpoints reachable only after login. This is where the highest-impact web findings live (IDOR, BOLA, privilege escalation, broken session lifecycle).

---

## When It Runs

Triggered by preflight decision **C1**: when the `credentials` field in preflight confirms at least one usable session (user-level or higher), the authenticated branch is **included by default in Phase 3**. It is not opt-in like nuclei — authenticated testing is non-destructive and covers the surface that matters most.

If no session is supplied, skip this branch entirely and test only the unauthenticated surface; record "authenticated surface: not covered (no credentials)" in the report's non-findings/blockers.

---

## Prerequisites (Decision A1)

| Test Face | Minimum Accounts | If Unmet |
|-----------|------------------|----------|
| ① Authenticated surface traversal | 1 session | Cannot run — branch skipped |
| ② Vertical privilege escalation | 1 low-priv session + known high-priv endpoints | If no low-priv session, skip |
| ③ Horizontal privilege escalation (IDOR/BOLA) | **2 test accounts at the same privilege level** | **Degrade**: run single-account "inferred" check only and explicitly mark "horizontal IDOR: not covered (needs second account)" in findings/report. Do not claim it is tested. |
| ④ Session/token lifecycle | 1 session | Always runnable |

**Account rules**: test accounts only. Synthetic UUID-like values containing `appsec-test`. Sequential/numeric IDs and real-user identifiers are not test data — see SKILL.md Action Policy.

---

## The Four Test Faces

### ① Authenticated Surface Traversal

**Goal**: discover which endpoints exist behind auth — the difference between `401 anonymous` and `200/302 authenticated`.

**Method**:
1. Take every endpoint found in Phase 1-2 (from `02-discovery.md` Endpoints Catalog).
2. Replay each with the session attached (cookie / bearer / token per `session-template.md`).
3. Record the response delta: `anonymous → authenticated`.

| anonymous response | authenticated response | interpretation |
|--------------------|------------------------|----------------|
| 401 / 403 / redirect-to-login | 200 / 2xx / 3xx-to-content | confirmed authenticated endpoint → add to auth-surface queue |
| 401 | still 401 | endpoint may need higher role or is dead |
| 200 | 200 | already public, not part of auth surface |

**Output**: the auth-surface endpoint list feeds faces ② ③ ④. Record in `03-vuln-test.md` under a dedicated "Authenticated Traversal" section.

---

### ② Vertical Privilege Escalation

**Goal**: can a low-privilege session reach high-privilege functionality?

**Permission matrix source (Decision B1 primary, B3 auxiliary)**:
- **B1 (primary)**: extract role→endpoint mapping from JS bundles, frontend router config, SPA hydration data (`__NEXT_DATA__`, `__NUXT__`, Angular router), and OpenAPI/Swagger if present. The user-supplied role map from preflight is authoritative and overrides inferred mappings.
- **B3 (auxiliary)**: for endpoints with no role hint, infer by replay — a low-priv session getting `200` on an admin-labeled path is itself the finding; a `403` confirms the boundary.

**Method**:
1. Build role→endpoint matrix (B1).
2. Identify high-priv endpoints (admin paths, `/manage`, role-gated mutations, user-management APIs).
3. Replay each high-priv endpoint with the **low-priv session**.
4. Compare to expected boundary:
   - expected `403/401`, got `200` → **vertical escalation confirmed**.
   - expected `403`, got `403` → boundary holds.

**Payloads**: `payloads/idor.md`, `payloads/api-auth.md`.

---

### ③ Horizontal Privilege Escalation (IDOR / BOLA)

**Goal**: can user-A access/modify user-B's resources?

**Strict mode (2 accounts, preferred)**:
1. With account-A session, identify resource identifiers owned by A (own user ID, order IDs, document IDs).
2. Replay the same endpoints with account-B session, substituting A's identifiers.
3. If B's session returns A's data → **horizontal IDOR/BOLA confirmed** (read or write).

**Single-account degraded mode (explicitly marked as incomplete)**:
1. Change your own object ID to another value; observe response structure.
2. A different user's data returned → likely IDOR, but without a second account you cannot prove the data belongs to a different user vs. a public/empty record.
3. **Record as "inferred, unverified — needs second account"**, never as confirmed IDOR. Promote to confirmed only after a second account cross-check or explicit user confirmation with the second account.

**Payloads**: `payloads/idor.md`, `payloads/api-business-logic.md`.

**Critical**: degraded-mode results must not be reported as confirmed findings. They go into `03-vuln-test.md` as "needs second account to confirm" and into the report's blockers/non-findings.

---

### ④ Session / Token Lifecycle

**Goal**: find broken session management and token flaws. Runnable with a single session.

| Check | Method | Payload |
|-------|--------|---------|
| JWT signature/alg weakness | test alg=none, RS256→HS256 confusion, weak secret | `payloads/jwt.md` |
| Token not expiring | use old token after TTL; use token after logout | `payloads/session-management.md` |
| Session fixation | does login rotate the session id? | `payloads/session-management.md` |
| MFA bypass | can auth-complete state be reached without 2nd factor? | `payloads/mfa-bypass.md` |
| OAuth flaws | redirect_uri, state, code reuse | `payloads/oauth.md` |
| Password reset poisoning | Host header / token leakage | `payloads/password-reset.md`, `payloads/host-header.md` |

**Boundary**: prove the flaw exists (e.g., old token still returns 200); do not maintain forged access or extract other users' sessions.

---

## Workflow Composition

```
Phase 3
├── Unauthenticated branch (existing)
│   └── validate queue items without session
└── Authenticated branch (this doc)
    ├── ① traversal → builds auth-surface endpoint list
    ├── ② vertical   ─┐
    ├── ③ horizontal ─┼─ run against the auth-surface list
    └── ④ lifecycle ──┘
```

Faces ① must complete before ②③④ (it produces the endpoint list). ②③④ are independent and run against that list in parallel with the existing Phase 3 unauthenticated validation.

---

## Session Handling

- Record every session used in `session-template.md` format (anonymous / user / admin / service).
- Re-attach the session on each replay; refresh per its refresh rules (401 → re-login).
- If a session expires mid-test, pause the authenticated branch, refresh, resume — do not skip affected endpoints silently. Mark them "session expired, pending" if refresh fails.

---

## Output & Coverage

For each face, record in `03-vuln-test.md`:
- which session context was used,
- the endpoint list traversed,
- confirmed findings → `findings.md` (with session context noted),
- **degraded or skipped faces** (e.g., "horizontal IDOR: not covered, needs second account") — these must appear in the final report's non-findings/blockers, not be silently dropped.

Authenticated testing only counts as "done" when all four faces are either completed or explicitly marked as not-covered-with-reason.
