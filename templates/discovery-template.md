# Discovery Report Template

> Phase 1-2 output template for `02-discovery.md`

---

## Template

```markdown
# Attack Surface Discovery - {target}

**Task ID**: {task_id}
**Phase**: {phase_1/phase_2}
**Updated At**: {timestamp}

---

## Discovery Summary

| Category | Count | Status |
|----------|-------|--------|
| Endpoints Found | {n} | {enumerated} |
| Parameters Identified | {n} | {catalogued} |
| Subdomains | {n} | {discovered or N/A} |
| Open Ports | {n} | {scanned or N/A} |
| Hidden Paths | {n} | {discovered or N/A} |

---

## Scope Allowlist & Guard

List the hosts approved in preflight `scope`. Every request in this phase must target a host in this allowlist. Hosts observed but NOT approved go in the "Out-of-Scope (recorded, not probed)" table below — they are never requested.

**Approved scope hosts** (from preflight):

| Host | In Scope? | Notes |
|------|-----------|-------|
| {target host} | yes | primary target |
| {user-added host} | yes | user explicitly added in preflight |

**Out-of-scope hosts observed** (record as evidence only — DO NOT resolve/connect/probe):

| Host | How Observed | Why Out-of-Scope |
|------|--------------|------------------|
| {gateway-enterprise} | actuator `_links` href | internal name; not in preflight scope |
| {sibling.example.com} | wildcard cert SAN / naming inference | single-host scope; user did not add |

---

## Request Log (mandatory — every request made this phase)

Every active request issued in Phase 1-2 is logged here. A discovery phase with zero rows means no discovery was performed. This is the auditable proof of *which hosts were actually probed* and the basis for the Scope Guard check.

Manual single requests must use `python3 scripts/request_guard.py <task_dir> <url> --phase discovery`; it writes this row and stores sanitized raw evidence automatically.

| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |
|---|--------|------------------|------|--------|-----------|------|-------|
| 1 | GET | {target} | {/api/v1/users} | {200} | yes | request_guard | {ref to raw} |
| 2 | GET | {target} | {/actuator} | {200} | yes | request_guard | {ref to raw} |
| {n} | {method} | {host} | {path} | {status} | {yes/no} | {tool} | |

> If any row's Host is not in the Approved scope hosts table, flag it as a boundary violation and stop — escalate to the user. Do not continue probing out-of-scope hosts.

---

## Subdomain Discovery (If In Scope)

**Tool Used**: {subfinder/amass/manual}

| Subdomain | Status | Tech Hint | Priority |
|-----------|--------|-----------|----------|
| {sub.example.com} | {alive/dead} | {hint} | {high/medium/low} |

**Note**: Only test subdomains confirmed in scope.

---

## Port Scan Results (If Approved)

**Tool Used**: {naabu/nmap/nc}

| Host | Port | Service | Web? |
|------|------|---------|------|
| {host} | {80/443/8080} | {http/https} | {yes} |

---

## Endpoints Catalog

### Web Endpoints

| Endpoint | Method | Parameters | Auth Required | Test Priority |
|----------|--------|------------|---------------|---------------|
| {/api/v1/users} | GET | {id} | {yes/no} | {P0/P1/P2} |
| {/api/v1/login} | POST | {username, password} | no | P0 |
| {/admin} | GET | none | {unknown} | P1 |

### API Endpoints

| Path | Method | Request Body | Response Type |
|------|--------|--------------|---------------|
| {/api/v1/search} | POST | {query} | JSON |
| {/api/v1/upload} | POST | multipart | JSON |

---

## Parameters Identified

> `Source` column distinguishes how the parameter was found: `passive` (from JS/API extraction or OpenAPI), `active-fuzz` (from Phase 1-2 parameter fuzzing), `user-supplied`. Active-fuzz parameters often reveal hidden functionality the front end never exposes — prioritize them in the Test Queue.

### Query Parameters

| Parameter | Endpoint | Type | Test Focus | Source |
|-----------|----------|------|------------|--------|
| {id} | {/api/users?id=} | numeric | IDOR, sqli | passive |
| {search} | {/search?q=} | string | sqli, xss | passive |
| {url} | {/fetch?url=} | URL | ssrf | passive |

### POST Parameters

| Parameter | Endpoint | Type | Test Focus | Source |
|-----------|----------|------|------------|--------|
| {username} | {/login} | string | auth bypass, sqli | passive |
| {file} | {/upload} | file | upload bypass | passive |
| {callback_url} | {/webhook} | URL | ssrf | passive |

### Cookie/Header Parameters

| Parameter | Location | Value Pattern | Test Focus | Source |
|-----------|----------|---------------|------------|--------|
| {session} | Cookie | JWT/base64 | session flaws | passive |
| {X-Custom-Header} | Header | {pattern} | header injection | passive |

### Active-Fuzz Parameters (from Phase 1-2 parameter discovery)

Hidden parameters found by fuzzing known endpoints — not present in JS/API extraction. High priority for Phase 3 (often the source of BOLA / mass assignment / injection).

| Parameter | Endpoint | Method | Signal (why it's real) | Source |
|-----------|----------|--------|------------------------|--------|
| {admin} | {/api/profile} | GET | {200 vs 404 baseline} | active-fuzz |
| {format} | {/export} | GET | {reflective / status delta} | active-fuzz |

---

## JavaScript/API Extraction

**Tool Used**: {URLFinder/katana/grep}

### URLs Found in JS/API

| URL | Source | Type |
|-----|--------|------|
| {/api/v1/internal} | {main.js} | hidden API |
| {/admin/config} | {bundle.js} | admin path |

---

## Directory Scanning Results (If Approved)

**Tool Used**: {ffuf/dirsearch/curl}
**Wordlist**: {path/to/wordlist}

| Path | Status | Size | Redirect |
|------|--------|------|----------|
| {/admin} | 403 | {bytes} | no |
| {/backup} | 200 | {bytes} | no |
| {/config.old} | 200 | {bytes} | no |

**If no directory-scanning tool is available** (ffuf/gobuster/dirsearch/feroxbuster all missing): do **not** hand-roll a large `curl` path list. Degrade to passive endpoint extraction only (JS bundles / source maps / OpenAPI / sitemap / robots.txt), mark this capability `degraded` in coverage-checklist with reason "tool unavailable, passive-only", and note it here. A bounded manual check of a handful of known endpoints is acceptable; unbounded batch curling is not.

---

## Test Queue

### P0 Queue (High Priority)

| Item | Vulnerability Class | Endpoint | Status |
|------|--------------------|----------|--------|
| 1 | {auth bypass} | {/api/login} | {pending/in_progress/validated} |
| 2 | {IDOR} | {/api/users/:id} | pending |
| 3 | {sqli} | {/search?q=} | pending |

### P1 Queue (Medium Priority)

| Item | Vulnerability Class | Endpoint | Status |
|------|--------------------|----------|--------|
| 1 | {xss} | {/comment} | pending |
| 2 | {ssrf} | {/fetch?url=} | pending |

### P2 Queue (Low Priority)

| Item | Vulnerability Class | Endpoint | Status |
|------|--------------------|----------|--------|
| 1 | {info disclosure} | {/api/debug} | pending |

---

## Session Context Analysis

| Context | Available | Source | Scope |
|---------|-----------|--------|-------|
| anonymous | {yes} | public endpoints | read-only |
| user | {yes/no} | {login required} | {scope} |
| admin | {unknown/no} | {need credentials} | {scope} |

### Authenticated Surface Seeds (for Phase 3 authenticated branch)

Endpoints that Phase 1-2 flagged as likely auth-only — feed these to face ① traversal, then to ②③④. Record only endpoints with current-task evidence (401/redirect observed, role hint in JS, OpenAPI security scheme); do not infer from path naming alone.

| Endpoint | Evidence (why auth-only) | Expected Role | Status |
|----------|--------------------------|---------------|--------|
| {/api/users/:id} | {401 when anonymous} | {user/admin} | {pending} |
| {/admin/dashboard} | {router config in main.js} | {admin} | {pending} |

### Role → Endpoint Matrix (for face ② vertical escalation)

Primary: user-supplied in preflight or extracted from JS/SPA/OpenAPI. Auxiliary: inferred by replay in Phase 3.

| Role | Representative Endpoints | Source |
|------|--------------------------|--------|
| {user} | {/api/profile, /api/orders} | {JS router / OpenAPI / user-supplied} |
| {admin} | {/admin/users, /api/admin/*} | {JS router / OpenAPI / user-supplied} |

---

## Blocked Items

| Item | Reason | Resolution Needed |
|------|--------|-------------------|
| {/admin} | 403 without auth | Need admin credentials |
| {subdomain scan} | Not approved | Ask user for scope expansion |
| {port 22} | SSH not in scope | Confirm scope boundary |

---

## Deferred Items

| Item | Reason | Deferred To |
|------|--------|-------------|
| {full directory scan} | Rate limit concerns | After approval |
| {nuclei scan} | Opt-in only — not requested by user | Do not run unless explicitly requested |

---

## Discovery Notes

{Additional observations, patterns, anomalies}

---

## Next Actions

1. Begin Phase 3 validation on P0 queue
2. Update session context: {anonymous → user if credentials available}
3. Request scope expansion for: {blocked items}
```

---

## Usage

1. Create `02-discovery.md` after Phase 1-2 discovery
2. Test queue becomes Phase 3 input
3. Update queue status as validation progresses
4. Blocked items may require user decision before Phase 3
5. Keep raw tool output in `raw/`, summarize here
