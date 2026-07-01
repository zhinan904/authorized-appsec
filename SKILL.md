---
name: authorized-appsec
description: Use for authorized Web, API, or application security assessment when the user provides a target and asks for reconnaissance, attack-surface mapping, vulnerability validation, reporting, or resuming a prior test. Before active probing, verify authorization, scope, and allowed intensity. Capabilities are discovered inside the execution VM at runtime; the skill selects available tools per capability rather than assuming specific tool names. Do not use for red-team adversary simulation, phishing, malware, persistence, lateral movement, credential theft, stealth, or post-exploitation.
---

# Authorized AppSec Testing

**Version**: 2.27.0 | **Updated: 2026-07-01**

## Purpose

Run authorized web and application security testing with an evidence-driven workflow. Keep the main context small: record task state in files, load command and payload references only when a phase needs them, and avoid reading historical results by default. This skill is not for red-team or post-exploitation.

## Mandatory Preflight

Before any active probing, establish the boundary:

| Field | Required Decision |
|------|------|
| `target` | URL, domain, IP, IP range, or supplied artifact |
| `authorization` | User confirms they own, operate, or are permitted to test the target |
| `scope` | Hosts, paths, accounts, IP ranges, and excluded systems |
| `intensity` | Passive, gentle, standard, or user-specified limits |
| `automation` | Which capabilities are allowed (subdomain, port, directory, replay). nuclei is opt-in only — exclude it from the approved set unless the user explicitly requests nuclei scanning. |
| `credentials` | Whether supplied sessions or accounts may be used |

Stop immediately if authorization is contradicted, service impact appears, scope is exceeded, or the user asks to stop.

## Input Routing

| Input | Default Route |
|------|------|
| Full URL | Phase 0 on that URL only |
| Domain | Ask about subdomain scope; otherwise test apex only |
| IP | Ask before port discovery |
| IP range | Ask before scanning; let user choose targets |
| Mini Program artifact (`.wxapkg`, extracted source, DevTools export) | Local artifact analysis first; extract backend hosts; confirm whether the same approved backend host also serves a Web frontend (`/`, `/login`, `/admin`, feature paths). If yes, include same-host Web checks unless the user excludes them. |
| Legacy vulnerability report (`.md`, `.html`, `.docx`, `.doc`) | Import into a standard `IMPORTED-*` task first using `scripts/import_report.py`; preserve original report in `raw/`; do not export to L3 until PoC/evidence/boundaries are reviewed. |
| Saved task | Read `task.md` → `findings.md` → current phase file |
| Artifact only | Local analysis, no network activity |

## Results Location

Active testing runs inside the Kali Linux VM or an equivalent isolated execution VM. Capability discovery, network probing, and tool execution happen in that VM, not on the host workstation. Write results to a user-specified directory, the existing task directory when resuming, `$AUTHORIZED_APPSEC_RESULTS_ROOT` when set, or `~/authorized-appsec/results/`. `SKILL_ROOT` is the directory containing this `SKILL.md` file and must be treated as read-only bundled resources. Do not write new tasks inside the skill package or to legacy result roots unless the user explicitly names that path. Read `memory-protocol.md` for task directory structure and state management rules.

## Workflow Phases

| Phase | Purpose | Output File | Template |
|-------|---------|-------------|----------|
| 0: Preflight & Fingerprint | Confirm scope, collect HTTP fingerprint, attack-surface hypothesis, run L3 hypothesis trigger | `01-fingerprint.md`, `l3-hypotheses.json` | `fingerprint-template.md` |
| 1: Attack-Surface Mapping | Build prioritized test queue from fingerprint | `02-discovery.md` | `discovery-template.md` |
| 2: Targeted Discovery | Collect only what the queue needs | `02-discovery.md` (append) | `discovery-template.md` |
| 3: Vulnerability Validation | Two-round loop: **Round 1 breadth** (one request per endpoint, all leave pending) → **Round 2 depth** (exhaust every parameter × class per confirmed endpoint) → loop until `check_completeness.py` passes | `03-vuln-test.md` | `vuln-test-template.md` |
| 4: Chain Analysis & Report | Analyze risk chains, generate report | `04-chain.md`, `report.md` | `chain-template.md`, `result-template.md` |
| 5: Retest (Optional) | Verify remediation of original findings | `RETEST-{ID}/` | `retest-template.md` |

### Mandatory Evidence Trail (no silent discovery)

`02-discovery.md` and `03-vuln-test.md` are **required** outputs, not optional. Every Phase 1-2 discovery request and every Phase 3 validation request must be logged in them. A phase with zero logged requests is treated as "not performed" — it must never be silently skipped.

- **`02-discovery.md` (Phase 1-2)**: log every request made — at minimum the target host, path, method, status, and whether the host is in-scope. This is the only auditable record of *which hosts were actually probed*. Directory brute-force (~150 paths or otherwise) with no logged requests is forbidden — if you ran the requests, they appear here.
- **`03-vuln-test.md` (Phase 3)**: log every validation request including payloads attempted and outcome (per `vuln-test-template.md`).
- The Scope Guard allowlist (above) is checked against these logs. Any request whose host is not in the scope allowlist is a boundary violation and must be flagged, not hidden.

Manual single HTTP requests must go through `python3 scripts/request_guard.py <task_dir> <url> --phase discovery|3`. It verifies preflight/scope, blocks out-of-scope hosts/ports and out-of-scope `Host` headers before sending traffic, stores sanitized raw evidence, and appends the required request-log row. Batch tools still require their selected output files to be reflected in the same request logs.

For each confirmed finding, immediately update: `findings.md` (authority), `findings.json`, `evidence-index.json`, `task.md`.

Keep validation **non-destructive**: no data modification, shell execution, persistence, mass extraction, DoS, or privilege expansion.

### Attack-Surface Discovery Method (Phase 1-2 — read before building the queue)

The single largest cause of missed findings is **incomplete attack-surface discovery**, not shallow testing: every endpoint you never discover is a finding you can never make. Relying on one discovery method (typically JS extraction) leaves the interaction-triggered endpoints — the ones only called when a user walks a business flow — completely invisible. Discovery must layer **four** complementary methods; no single one is sufficient.

**Layer 1 — Static extraction (baseline, has blind spots).** Extract endpoints from JS bundles, source maps (`.js.map` — often left on in prod, far richer than minified JS), OpenAPI/Swagger, HTML forms/links, and inline `fetch`/`XHR` calls. This catches every endpoint the page calls on load. **Blind spot:** endpoints wired into event handlers (button click → checkout, refund, password reset) are NOT called on load and will NOT appear. Treat Layer 1 as a floor, not a ceiling.

**Layer 2 — Runtime traffic recording via business-flow traversal (closes Layer 1's blind spot; mandatory, not optional).** Drive the application as a real user of **each business role** and walk **each complete business flow end to end** — e.g. register → login → browse → add-to-cart → checkout → pay → view order detail → refund → recharge → password-reset; and separately the privileged flows (merchant onboarding/audit, admin user-management). Record every request emitted along the way (proxy via mitmproxy/Burp/Charles, or drive each step through `request_guard.py` so it lands in the Request Log). Interaction-triggered endpoints (refund, order-detail, create-order, balance-records, reset-password) are discoverable **only** this way. Principle: **discovery coverage is proportional to the number of distinct functional paths walked.** Skipping this layer is the #1 reason an assessment stalls at ~15% coverage.

**Layer 3 — Dictionary brute-force (catches what the frontend never exposes).** Some endpoints exist only server-side (internal APIs, debug interfaces, legacy routes). Brute-force each discovered path prefix (`/api/v1/`, `/api/user/`, `/admin/`, …) with a generic API wordlist (SecLists `raft`/`api-endpoints`). Judge by **response differential**, not just 200 — a 401/403/405/500 all prove the endpoint exists and is merely access-gated. A non-empty "Directory Scanning" section in `02-discovery.md` is the auditable record this ran.

**Layer 4 — Historical & associative (cheap, high-yield).** `robots.txt`, `sitemap.xml`, `.well-known/`, `swagger.json`/`openapi.yaml`, error-message leaks (stack traces, internal hostnames, file paths), old snapshots (Wayback Machine), and the target framework's known historical endpoints (Spring `/actuator`, Django `/admin`, etc.).

**Discovery self-check (any "no" = discovery incomplete, go back before Phase 3):**
1. Have I triggered the functional pages of **every business role** (anonymous / regular user / each privileged role)?
2. Have I walked **each complete business flow** end to end and recorded every request it emitted?
3. Did I use **≥2 methods** (Layer 1 + at least one of Layer 2/3/4) and cross-check, rather than relying on one?

The Endpoints Catalog must be the **union** of all four layers' findings, not the output of a single code path. `check_completeness.py` warns when only one discovery method is evident — that warning flags the exact failure mode that sinks coverage.

### Scope Guard (mandatory in every active phase)

The preflight `scope` is a hard constraint, not a suggestion. Discovery, validation, and any active request must stay inside it. The two rules below are enforced at every phase boundary:

1. **Scope allowlist check** — every host you send a request to must be ⊆ the approved scope (`target` plus any hosts the user explicitly added to `scope`). Before issuing any request, confirm the request target host is in the allowlist. Hosts that are merely *observed* (wildcard certificate SANs, sibling subdomains inferred from naming, internal hostnames leaked by actuator/error responses) are **evidence only — never request targets**. A wildcard TLS cert, an `_links` href, or an `X-Forwarded-Host` value does not add that host to scope.
2. **Discovered-but-out-of-scope → record, do not request** — when fingerprint/discovery surfaces a host outside the allowlist (e.g. internal name `gateway-enterprise`, a sibling subdomain `api.example.com` when scope is a single host), record it in the fingerprint/discovery notes as a finding-input, then explicitly mark it out-of-scope. Never resolve, connect to, or probe it. Escalation to "test that host" always requires the user adding it to `scope` in preflight.

If you cannot tell whether a discovered host is in scope, treat it as **out of scope** and ask the user rather than probing.

The same guard applies to paths/ports: a request stays inside the approved `scope` host list and approved ports; do not expand to sibling hosts or new ports under the name of "deeper discovery".

### Authenticated Testing (Phase 3 Branch)

When preflight confirms at least one usable session (`credentials` field), the authenticated surface is tested **by default** in Phase 3 — it is not opt-in. The highest-impact web findings (IDOR, BOLA, privilege escalation, broken session lifecycle) live behind auth, so coverage of this surface is mandatory whenever a session is supplied.

Four faces, in dependency order:

| Face | What | Min. accounts |
|------|------|---------------|
| ① Authenticated surface traversal | replay every discovered endpoint with the session; find the `401→200` delta that reveals auth-only endpoints | 1 |
| ② Vertical privilege escalation | low-priv session reaching high-priv endpoints, checked against a role→endpoint matrix (primary: extracted from JS/SPA/OpenAPI or user-supplied; auxiliary: inferred by replay) | 1 low-priv + known high-priv endpoints |
| ③ Horizontal privilege escalation (IDOR/BOLA) | user-A session accessing user-B resources | **2 accounts** — with only 1 account, run degraded "inferred" check and explicitly mark "not covered, needs second account"; never report as confirmed |
| ④ Session/token lifecycle | JWT flaws, token non-expiry, session fixation, MFA bypass, OAuth/password-reset weaknesses | 1 |

**Account rules**: test accounts only; synthetic UUID-like values containing `appsec-test`; sequential/numeric/real-user IDs are not test data.

Faces ②③④ run against the endpoint list produced by ①, in parallel with the existing unauthenticated Phase 3 validation. Read `commands/authenticated-testing.md` for the full method, session handling, and coverage rules. A face is only "done" when completed or explicitly marked not-covered-with-reason — degraded/skipped faces must appear in the report's non-findings, never silently dropped.

### Full Parameter & Class Coverage (Phase 3 — test each endpoint exhaustively)

A discovered endpoint is not "tested" by validating one parameter against one vuln class. Two failure modes burn the most coverage here: (a) testing only the **visible** parameter and missing hidden ones on the same endpoint, and (b) testing one parameter against the **first vuln class that came to mind**. Exhaust each endpoint on three axes:

- **All parameters, including hidden ones.** A single endpoint often carries several parameters, each a distinct attack surface — e.g. an upload endpoint's `filename` (file-upload) and `category` (path traversal) are two independent findings. Enumerate parameters (frontend form fields are a floor; use parameter discovery / observed request bodies to find the rest), then test every one. Do not cross an endpoint off after one parameter.
- **Parameter × vuln-class matrix.** For each parameter, run the full relevant class list, not the first guess. A value like `order_no` is not just an IDOR target — it may also be SQLi, path traversal, SSRF (if URL-shaped), or mass-assignment. An `image_url` is not just SSRF — it may be XSS, open-redirect, or RFI. Test the matrix.
- **Multi-role + state transitions + boundary values.** Replay each state-changing endpoint across every available role session (the auth-branch faces above), and test state transitions (create → edit → delete → access-after-delete) where IDOR/auth flaws hide. Feed boundary values: negatives, zero, empty, oversized, type confusion (string where int expected).

The rule of thumb: if your 03-vuln-test log shows one request per endpoint, you have under-tested. Aim for one request per **parameter × class** combination that plausibly applies.

### Completeness Loop (test everything before finishing)

Phase 3 is **not** "validate a few queue items and move on". The whole point of an authorized assessment is coverage. Before Phase 3 may end and a report may be emitted, the task must pass a machine-checked **completeness gate** — two hard gates that cannot be talked around by prose:

```bash
python3 scripts/check_completeness.py <task_dir>
```

**Gate 0 — Queue exists & adequate (anti-skip-by-omission).** The `## Test Queue` section in `02-discovery.md` is mandatory. Omitting it (so Gate A has "nothing to drain") is itself a hard failure — you cannot escape the completeness gate by simply never building a queue. The queue must contain at least one item with a status; a queue covering only a tiny fraction of discovered endpoints triggers a warning. Phase 1's job is to build this queue from the fingerprint/Endpoints Catalog — that output is required input for Phase 3's loop.

**Gate A — Queue drained.** Every item in `02-discovery.md`'s Test Queue (P0/P1/P2) **and** every row in the "Authenticated Surface Seeds" table must reach a terminal status. Open statuses (`pending` / `in_progress` / blank) fail the gate. Terminal statuses: `validated`, `confirmed`, `false_positive`, `not_applicable`, `out-of-scope`. `deferred` counts as terminal **only if a reason is given** (e.g. `deferred - need admin creds`); a bare `deferred` is treated as still open. If new endpoints are discovered during Phase 3, add them to the queue first — they must drain too.

**Gate B — Coverage truthful.** For `coverage-checklist.md`:
- A row marked `covered` must have a matching request in `03-vuln-test.md` for that surface class, or carry a reason justifying the coverage. Marking a row `covered` with no evidence request and no reason fails the gate — this is the primary "claimed-but-not-tested" skip mode.
- A row marked `not-covered` or `degraded` **must** state a reason. Empty reason = silent drop = gate failure.
- A row marked `out-of-scope` must carry a non-empty reason explaining why the surface does not apply. Free-text reasons are accepted — they need not use a prescribed phrase, though aligning to one (`mechanism not present` / `feature not present` / `protocol not present` / `no LLM endpoint` / `no K8s surface` / `no session supplied` / `explicitly excluded`) aids categorization and avoids an advisory warning. An empty reason is rejected (the silent-drop loophole).

**Loop protocol — two rounds (breadth then depth).** Phase 3 is a two-round loop, not a single pass. The two rounds target different failure modes: Round 1 prevents the "tested a few endpoints and stopped" skip; Round 2 prevents the "tested each endpoint once but never exhausted its parameters" skip (the larger coverage sink in practice).

**Round 1 — Breadth pass.** Walk every queue item once and give it a preliminary verdict fast. Send the single most-likely-to-hit request per endpoint (the obvious payload for its vuln class), record the result, set a status. The goal of Round 1 is **coverage of endpoints, not depth** — every endpoint should leave `pending` and carry an initial `confirmed` / `false_positive` / `suspicious` / `deferred`. Do not try to exhaust parameters here. Round 1 is done when no queue item is still `pending`/`in_progress`.

**Round 2 — Depth pass.** Now go back and exhaust each endpoint that Round 1 marked `confirmed` or `suspicious`. For **every parameter** the endpoint exposes (including secondary ones Round 1 never touched — e.g. an upload endpoint's `filename` was tested in Round 1 but its `category` parameter was not; a refund endpoint's `order_no` was tested but `refund_amount` was not), run the parameter × vuln-class matrix from the "Full Parameter & Class Coverage" section. Re-examine `false_positive` items to confirm they are genuinely excluded, not just unexplored. Round 2 is done when each confirmed/suspicious endpoint's declared parameters have all been probed. This round is where most findings beyond the obvious ones are made; skipping it is the primary cause of a low coverage score.

```
Round 1 (breadth): one request per endpoint → every queue item leaves pending
  → Round 2 (depth): for each confirmed/suspicious endpoint, exhaust every parameter × class
  → update queue statuses & coverage rows
  → run check_completeness.py
  → if it returns open items: fix exactly those (back to the relevant round)
  → repeat until exit 0
only then proceed to Phase 4
```

Round 1 completion is **not** test completion — an endpoint with a Round-1 verdict still needs Round 2 depth. A report emitted after Round 1 only has tested each endpoint's first guess, which historically captures ~25% of the available surface.

The gate is enforced twice: the report generator (`generate_report.py`'s `check_report_gate`) calls it, so a report cannot be emitted while items remain open. `--skip-gate` overrides the whole gate (preserved for imports/fixtures) but is recorded in the report.

**You may not** satisfy the gate by mass-marking untested rows `not-covered` with no reason, or by marking rows `out-of-scope` with an empty reason — the script rejects both. If a surface genuinely does not apply, mark it `out-of-scope` and state *why* in the reason (free text is fine; a prescribed phrase like "mechanism not present" is recommended for clean categorization but not required).

**The only legitimate "finish without testing everything" exit** is `user_stop`: when the user explicitly says to stop (enough / wrap it up / time's up), set `- user_stop: true` in `task.md`. The queue gate then relaxes — remaining items are listed in the report as "not tested by user decision" rather than blocking it. Coverage truthfulness still applies even under `user_stop`. Never set `user_stop` on your own initiative to escape an unfinished queue; it exists for an explicit user decision only.

### Automatic L3 Hypothesis Trigger

After Phase 0 fingerprinting, run:

```bash
python3 scripts/auto_l3_hypotheses.py <task_dir>
```

The script detects same-system signals from current-task files and writes `l3-hypotheses.json`. L3 matches are **historical hypotheses only**. They may prioritize Phase 1 mapping and Phase 3 validation, but they must not create `findings.md` entries, report conclusions, severity claims, attack-graph nodes, or current-target technology facts by themselves.

Only promote an L3 hypothesis to a confirmed finding after current-task validation produces:

- in-scope target evidence from this task;
- a minimal safe PoC or explicitly documented PoC boundary;
- affected endpoint/object details from the current target;
- status `confirmed` in `findings.md`.

If the target looks like a known system class, say it as a test hypothesis: "L3 suggests checking X because signals A/B/C matched." Do not say or imply the vulnerability exists until Phase 3 evidence confirms it.

#### Low-Confidence Hypothesis Escalation (`hypotheses_queued → phase_1`)

`auto_l3_hypotheses.py` routes low-confidence signal matches to `hypotheses_queued` instead of the Phase 1 queue. These hypotheses must not enter the active testing pipeline without explicit escalation. Promotion to `phase_1` requires **at least one** of:

| Gate | Condition | Evidence Required |
|------|-----------|-------------------|
| **A — Signal Reinforcement** | Additional signals detected in Phase 1/2 that were absent at Phase 0 | Record new signal IDs and matched patterns in `02-discovery.md` |
| **B — User Explicit Confirmation** | Operator manually reviews the hypothesis and approves it | User confirms in task conversation; operator updates `l3-hypotheses.json` queue field to `phase_1` |
| **C — Strong Current-Task Evidence** | Phase 1/2 discovery directly corroborates the hypothesis category | Document corroborating evidence (endpoint, response, behavior) in `02-discovery.md` with cross-reference to the hypothesis |

Without one of these gates, queued hypotheses remain in `hypotheses_queued` and must not drive Phase 3 validation, findings, or report content. The default behaviors this prevents are: (a) silently ignoring low-confidence hypotheses that later evidence might validate, and (b) treating them as confirmed and testing them directly.

### Evidence and PoC Requirements

Every confirmed finding must have a minimal reproducible PoC and traceable evidence:

- Put the operator-facing PoC in `findings.md` under `**PoC**:` or `**Reproduction**:`.
- Store a sanitized copy in `raw/poc-{finding_id}.txt` during structured-output sync.
- Redact secrets, cookies, bearer tokens, real user identifiers, and sensitive response bodies.
- The final report must include the minimal PoC, not only a prose description or evidence ID.
- `raw/` must contain the supporting request/response or PoC artifact for each confirmed finding.

If a finding cannot safely include a live PoC, state the blocked PoC boundary explicitly and include the exact safe validation outline.

### Fingerprint and Attack-Graph Integrity

Technology mappings and L3 history are hints, not facts. Only put a technology, nuclei tag, vulnerability, or attack-tree node into `01-fingerprint.md`, `attack-graph.md`, `findings.md`, or the final report when current-task evidence supports it: headers, cookies, HTML/JS, error bodies, service banners, source code, package metadata, raw responses, and current-task PoC results. Do not infer ThinkPHP, Spring, Nacos, default credentials, token exposure, IDOR, secret leakage, WAF bypass, or any other issue solely from path shape, historical cases, or user-provided examples.

Attack graphs must be generated from the current task's `task.md`, `01-fingerprint.md`, `02-discovery.md`, `findings.md`, and current raw evidence. L3 entries and `l3-hypotheses.json` may appear only in a separate "Historical References Considered" or "Hypotheses Queued" section when they match the current target family, confirmed technology, or confirmed vulnerability class; they must not become graph nodes or validation conclusions by themselves.

## Batch Testing

For multiple targets with unified authorization, use batch mode. See `templates/batch-template.md` for full workflow, `templates/targets-schema.md` for targets.json structure, and `templates/process-control.md` for termination protocol.

| Mode | Description |
|------|------------|
| `one-task-per-target` | Each target gets an independent task |
| `single-batch-task` | One task with strict context budget (load one target slice at a time) |
| `discovery-first` | Run Phase 0-2 on all targets, rank, let user select which proceed to Phase 3+ |

Batch preflight must confirm: `targets`, `scope`, `excluded`, `intensity`, `allowed_capabilities`, `blocked_capabilities`, `batch_mode`. Process control via `scripts/task-control.sh`.

## Action Policy

| Action Type | Default Handling |
|------|------|
| Local artifact review, single low-impact HTTP request, fingerprinting | Allowed after preflight |
| Subdomain discovery, port scanning, directory scanning, replay | Ask first |
| **nuclei and other template-based vulnerability scanners (nikto, wpscan)** | **Do not run by default.** Only run when the user explicitly requests nuclei/scanner-based CVE or template scanning. A silent preflight assumption, L3 signal, fingerprint hint, or Phase 1/2 finding is not sufficient. Record the explicit request in `task.md`. |
| Authenticated testing, batch testing, OOB, cloud metadata, internal probing | Ask first |
| UNION-based SQL extraction, alert-based XSS validation | Ask first |
| Data create/update/delete (with authorization) | Ask first, test data only. Numeric IDs, sequential IDs, `admin`, `test`, or values that could plausibly collide with production records are not test data. Prefer synthetic UUID-like values containing `appsec-test` and stop after proof. |
| File upload, RCE, reverse shell, persistence, credential theft, exfiltration, DoS, evasion | Do not execute |
| Probing hosts discovered only via response leakage (actuator `_links` internal hostnames, error stack internal IPs, wildcard-cert sibling subdomains) | Record as evidence only. Do not resolve, connect to, or probe unless the user explicitly adds that host to `scope`. |

When an action is not safe, provide a risk explanation, bounded manual validation outline, or report-ready statement.

### Nuclei Policy

nuclei (and equivalent template-based scanners such as nikto/wpscan) is **opt-in only** and is excluded from the default workflow:

- **Default behavior**: do not propose, suggest, or run nuclei in any phase. The Phase 0–3 flow does not depend on it; fingerprinting and validation proceed with manual payload testing from `payloads/`.
- **Trigger**: nuclei runs only when the user explicitly asks for it — for example "run nuclei", "nuclei scan", "CVE/template scan with nuclei". General requests like "scan for vulnerabilities" or "check for known issues" do **not** authorize nuclei; treat them as the standard manual workflow.
- **Before running**: still confirm the standard preflight boundary (target, scope, intensity, rate) and record the explicit approval in `task.md` under `## Tools Used` and in `## Automation / Scanners`.
- **Do not** auto-escalate to nuclei from an L3 hypothesis, a fingerprint tag match, or a discovery result. These are inputs to manual validation, not triggers for template scanning.

## Tooling

Capability-first: tools are discovered at runtime, not hardcoded. Before any active probing, run:

```bash
./scripts/discover-capabilities.sh <task_dir>/capabilities.json
```

This generates `capabilities.json` with available candidates per capability. See `commands/capabilities.md` for full definitions, intensity mapping, and manual alternatives.

**Selection rules**: prefer JSON output → prefer rate control → try next candidate → fallback to manual.

`discover-capabilities.sh` records installed template scanners but does not enumerate nuclei templates by default. Use `--include-nuclei-templates` only after the user explicitly approves scanner/nuclei use.

**Missing-tool degradation (no ad-hoc mass curling)**: when a capability has zero available candidates after discovery (e.g. no `ffuf`/`gobuster`/`dirsearch` for directory scanning, no `subfinder` for subdomain discovery), do **not** compensate by hand-rolling a large list of `curl` requests. Ad-hoc batch curling has no bounded scope, no rate control, and no auditable output — it is the primary path to out-of-scope drift and silent discovery. Instead degrade explicitly:

1. Run only the **passive** variant of that capability — e.g. for directory scanning, extract endpoints from JS bundles / source maps / OpenAPI / sitemap / robots.txt; for subdomain discovery, use certificate transparency / DNS records already in the fingerprint. These are read-only and stay on the target host.
2. Mark the capability `degraded` in `coverage-checklist.md` with the reason "tool unavailable, passive-only".
3. Record the degradation in `02-discovery.md` Notes and surface it in the report's Test Coverage & Gaps.

A short, bounded manual check (a handful of known endpoints from the fingerprint) is acceptable only through `request_guard.py`; an unbounded "150-path curl list" is not. If active discovery of a capability is essential and the tool is missing, stop and ask the user — do not silently replace the tool with bulk manual requests.

**Recording**: list selected tools in `task.md` under `## Tools Used`.

### Scan Resilience

Background scans (naabu, gobuster, ffuf, sqlmap, nuclei, hydra) can fail silently — zero-byte output files and dead processes. After launching background scans:

```bash
# Check scan health at any time:
./scripts/check-task.sh <task_dir>
```

This reports running processes, output file sizes, recent results, and target connectivity. Re-run failed scans when the target is confirmed up.

If the target becomes unreachable mid-scan, wait and retry. Do not re-discover capabilities on each retry — use the same `capabilities.json`.

## Reporting

`findings.md` is the human-readable authority. `summary.json`, `findings.json`, and `evidence-index.json` are structured projections. Severity follows `templates/severity-classification.md`.

**Report output is machine-generated only.** `report.md` is produced exclusively by `generate_report.py`. Never hand-write or hand-edit a final report in free prose. Internally, `F-XXX` is the single authority; the generator renders it as the customer-facing `V-XX` (severity-descending: critical→V-01), keeping F-XXX as a small traceability note. The report is in Chinese (中文) with a fixed 6-chapter + 4-appendix structure defined in `templates/result-template.md` (漏洞汇总 / 资产画像 / 漏洞详情 / 测试过程 / 攻击链 / 加固建议 + appendices A-D).

**Evidence in the report**: each confirmed finding embeds its full request/response evidence block (curl + HTTP/JSON) inline, redacted by `redact_response` — session keys, tokens, and 32+ hex values are masked to `***REDACTED***`, while test phone numbers and paths are preserved. This makes the report self-contained and persuasive for the customer. Raw artifacts still persist in `raw/` and `evidence-index.json`. A post-render gate (`check_report_redaction`) warns if any secret-like value survived redaction.

```bash
python3 scripts/ensure_structured_outputs.py <task_dir>
python3 scripts/generate_report.py <task_dir>
```

**Report integrity audit (mandatory, anti-bypass).** Because `report.md` is meant to be machine-generated, an agent can be tempted to hand-write it when the gate fails — sidestepping `check_report_gate` entirely (observed in the wild: a task was left at `phase_3 / in_progress / completeness_checked: false` yet had a report). The backstop is `check_report_integrity.py`, which audits the final artifact against the task's recorded state. Run it **after** generating the report and treat any non-zero exit as a hard stop:

```bash
python3 scripts/check_report_integrity.py <task_dir>
```

It fails (exit 1) if `report.md` exists but the task is not `completed` / `phase_4`, or `completeness_checked` is not `true`, or the completeness gate does not pass **right now** (re-run live, so a stale or forged pass is caught). A report that fails this audit was written without a legitimately-finished test effort — delete it, return to Phase 3, drain the queue through the completeness loop, then regenerate.

**Test coverage gate**: before a report is considered done, fill `templates/coverage-checklist.md` against this task's actual testing. Every surface row must be `covered`, `degraded`, `not-covered`, or `out-of-scope` — never blank. The report's test process section (四、测试过程) is generated from the checklist's per-surface rows; `degraded` and `not-covered` rows must appear explicitly. Silent omission of untested surface is forbidden.

**Scope adherence gate**: the coverage checklist's "Scope Adherence" section must also be filled — cross-check the `02-discovery.md` / `03-vuln-test.md` request logs against the scope allowlist and confirm every request target was in scope. Any boundary violation (a request to a host outside the approved scope) blocks the report until it is disclosed to the user. A report that skipped Phase 1-2 logging (no `02-discovery.md` request log) cannot pass this gate — the requests must be logged first.

The report gate also machine-checks `task.md` preflight fields (`preflight_complete`, `authorization`, `scope`, `scope_allowlist`, `intensity`, `automation`, `credentials`) and request-log hosts. `scope_allowlist` is the machine allowlist; free-form `scope` text does not expand it. `--skip-gate` requires `--gate-override-reason` and must be used only for non-live imports or explicit fixture/debug cases.

For historical reports, import first:

```bash
python3 scripts/import_report.py <report_file> --target <target>
```

Imported reports create `IMPORTED-*` task directories and must be reviewed before L3 export. Import and distillation are local file-processing steps only; they must not execute PoCs or send traffic to the target.

L3 export only when explicitly requested and only when confirmed distillation candidates exist: `python3 scripts/generate_report.py <task_dir> --export-l3 <l3_root>`. Distillation candidates are complex/high-value vulnerabilities or reusable attack chains. Low/info findings, ordinary missing headers, no-WAF observations, TRACE/method checks, banner/version disclosure, and generic cookie/TLS/configuration issues must not be exported unless they are part of a confirmed higher-value chain. Empty/no-finding tasks must not be exported as vulnerability knowledge.

## References

Load **only the file needed for the current phase**:

| Need | Read |
|------|------|
| State management, resume, batch protocol | `memory-protocol.md` |
| Architecture overview, diagrams, counts | `ARCHITECTURE.md` |
| Task structure template | `templates/task-template.md` |
| Recon commands, OSINT, tool flags | `commands/recon.md` |
| Capability definitions, candidates, intensity | `commands/capabilities.md` |
| Web port selection | `commands/ports.md` |
| Tech stack → vulnerability mapping | `commands/stack-mapping.md` |
| STRIDE threat modeling methodology | `commands/threat-modeling.md` |
| Source code review methodology | `commands/source-code-review.md` |
| Authenticated testing (IDOR/BOLA/privilege escalation/session lifecycle) | `commands/authenticated-testing.md` |
| Password / credential brute-force | `commands/brute-force.md` |
| Modern auth: OTP, slider, SSO, MFA, token lifecycle | `commands/modern-auth.md` |
| AI / LLM application security payloads | `payloads/ai-security.md` |
| gRPC / protobuf security | `payloads/grpc-protobuf.md` |
| HTTP/2 single-packet race condition | `payloads/http2-single-packet.md` |
| WAF / CDN origin IP discovery | `payloads/waf-origin-discovery.md` |
| Evidence capture with hash chain | `scripts/capture_evidence.py` |
| Scope-checked request wrapper | `scripts/request_guard.py` |
| Completeness gate (queue drained + coverage truthful) | `scripts/check_completeness.py` |
| Report integrity audit (anti-bypass: report vs. finished task state) | `scripts/check_report_integrity.py` |
| Cleanup and rollback protocol | `templates/cleanup-template.md` |
| Phase 0 output format | `templates/fingerprint-template.md` |
| Phase 1-2 output format | `templates/discovery-template.md` |
| Phase 3 validation log format | `templates/vuln-test-template.md` |
| Phase 4 chain analysis format | `templates/chain-template.md` |
| Severity classification | `templates/severity-classification.md` |
| Structured output schemas (JSON) | `templates/structured-output-requirements.md` |
| Finding format | `templates/findings-template.md` |
| Session handling | `templates/session-template.md` |
| Report format | `templates/result-template.md` |
| Test coverage checklist (run before report done) | `templates/coverage-checklist.md` |
| Legacy report import | `templates/report-import-rules.md`, `scripts/import_report.py` |
| Batch workflow, context budget | `templates/batch-template.md` |
| Target registry schema | `templates/targets-schema.md` |
| Stop conditions | `templates/stop-conditions.md` |
| Process control, termination | `templates/process-control.md` |
| Process control script | `scripts/task-control.sh` |
| Task initialization script | `scripts/init_task.py` |
| L3 hypothesis trigger | `scripts/auto_l3_hypotheses.py` |
| Background scan monitoring | `scripts/check-task.sh` |
| Retest workflow | `templates/retest-template.md` |
| Rules of engagement template | `templates/rules-of-engagement.md` |
| Business scenarios | `templates/business-scenario-*.md` |
| Vulnerability-specific payloads | One file in `payloads/` matching the queue item |
| Optional private deep references | Not included in the public release; use only if a local private `references/` directory exists and the user explicitly requests it |

Do not load the entire payload library. Choose the single file matching the queue item.

### Optional Private References

The public release does not include `references/`. Deep reference material, if maintained locally, is a private extension and not part of the default skill contract. The normal workflow must remain fully usable with `payloads/`, `commands/`, `templates/`, and `scripts/` only.

If a local private `references/` directory exists, load it only when the user explicitly requests deeper methodology for an already authorized, in-scope test. This is a user-gated trigger, not an agent decision. Never load private references for quick scans, unauthenticated recon, default validation, or any context where the boundary-checked payload layer is sufficient.

## Final Response

When finishing a task, summarize scope tested, confirmed findings by severity, important non-findings or blockers, files written, and any actions intentionally not executed.
