# Changelog

## 2.26.0 - 2026-07-01

Attack-surface discovery methodology + exhaustive validation, addressing the root cause of low coverage observed on task PT-003 (15.8% of a 24-vuln range): 54% of the missed findings came from incomplete *discovery* (single-method JS extraction missing interaction-triggered endpoints), 33% from incomplete *validation* (parameters/vuln-classes left untested).

### New: Attack-Surface Discovery Method (SKILL.md Phase 1-2)

A four-layer discovery methodology is now mandated in SKILL.md: (1) static extraction (JS/source-map/OpenAPI) as baseline, (2) runtime traffic recording via business-flow traversal — the mandatory complement that catches interaction-triggered endpoints invisible to static analysis, (3) dictionary brute-force by response differential, (4) historical/associative. A three-question self-check flags incomplete discovery before Phase 3. The Endpoints Catalog must be the union of all layers, not one method's output.

### New: Full Parameter & Class Coverage (SKILL.md Phase 3)

Validation must exhaust each endpoint on three axes: all parameters (including hidden, via parameter discovery), a parameter × vuln-class matrix (one `order_no` tests IDOR + SQLi + path-traversal + auth, not just the first guess), and multi-role + state-transition + boundary-value testing. "One request per endpoint" is the under-testing smell.

### Gate 0: discovery-method diversity check (check_completeness.py)

`_count_discovery_methods` detects which of the four methods left evidence in 02-discovery.md (Endpoints Catalog / directory-scanning section / multi-role request log / historical markers). Fewer than 2 methods triggers a warning — single-method discovery is the #1 coverage sink. Warning, not a block, to avoid false-positives on genuinely static sites.

## 2.25.0 - 2026-07-01

Report integrity + request-log format hardening. Two gaps surfaced by real task PT-003: (a) the agent hand-wrote `report.md` while the task was still `phase_3 / in_progress / completeness_checked: false`, bypassing `check_report_gate` entirely; (b) `03-vuln-test.md` requests were recorded as `GET admin/js/config.js` crammed into a Payload column, which `_extract_request_rows` cannot parse, so the scope check saw zero requests and the gate failed — prompting the bypass.

### New: report integrity audit (`scripts/check_report_integrity.py`)

Independent backstop that audits the final artifact against the task's recorded state. A report is clean only if the task is `completed` / `phase_4`, `completeness_checked: true`, AND `check_completeness.py` passes right now (re-run live, catching stale/forged passes). Mandated in the Phase 4 flow after `generate_report.py`; exit 1 = the report was written without a legitimately-finished test effort.

### Request-log format enforcement (`templates/vuln-test-template.md`)

The per-test `| # | Payload | Result | Evidence |` table is now explicitly labeled payload-detail-only and NOT the request log. The template names the **Guarded Request Log** (maintained by `request_guard.py`: `| # | Method | Host | Path | Status | In Scope? | Tool | Notes |`) as the sole machine-parseable request evidence, with a concrete example. The scope gate and completeness Gate B parse that table; recording requests only in the Payloads table produces zero parseable rows and fails the gate.

## 2.24.0 - 2026-06-30

Completeness gate: force the skill to test everything before finishing, not just a few queue items. Closes the loophole where an agent could validate a handful of P0 items and jump to the report, or mark untested surface `not-covered` with no reason.

### New: completeness gate (`scripts/check_completeness.py`)

A second machine-checked gate, enforced by the report generator (`check_report_gate` now calls it as its 5th check). Two hard gates that must both pass before a report is allowed:

- **Gate A — Queue drained**: every item in `02-discovery.md`'s Test Queue (P0/P1/P2) **and** every "Authenticated Surface Seeds" row must reach a terminal status (`validated` / `confirmed` / `false_positive` / `not_applicable` / `out-of-scope`, or `deferred` **with a reason**). `pending` / `in_progress` / blank items block the report.
- **Gate B — Coverage truthful**: `covered` rows must have a matching request in `03-vuln-test.md` (or a reason); `not-covered` / `degraded` rows **must** state a reason; `out-of-scope` rows must use a prescribed phrase. This is the direct fix for "claimed-but-not-tested" and "silent drop" skip modes.

### Loop protocol (SKILL.md)

Phase 3 is now a loop: run validations → run `check_completeness.py` → if open items remain, go back and test exactly those → repeat until exit 0. The agent cannot talk around the gate; it must actually test. The single legitimate "finish without testing everything" exit is `user_stop` (explicit user decision), under which remaining items are reported as "not tested by user decision" rather than blocking.

### Task metadata (`task-template.md`)

- New `completeness_checked` flag (set true only after `check_completeness.py` exits 0) and `user_stop` flag (explicit user stop only).
- `loop_depth` semantics corrected: it **notifies** the user past depth 3 but no longer hard-stops, since the completeness loop legitimately re-enters Phase 3 many times.

## 2.23.0 - 2026-06-26

Customer-facing Chinese report format + coverage-checklist alignment. This is a major feature update to the report output pipeline.

### Report format overhaul (`generate_report.py`)

The report is now a customer-deliverable Chinese document aligned with standard AppSec reporting, instead of an internal English debug view.

- **V-XX customer numbering**: internal `F-XXX` finding IDs are rendered as `V-XX` (severity-descending: critical → V-01), with the F-XXX kept as a small traceability note. The internal scheme stays the single source of truth.
- **Inline evidence with redaction**: each confirmed finding embeds its full curl + HTTP/JSON evidence block. A new `redact_response()` masks session keys, tokens, Bearer credentials, and 32+ hex values to `***REDACTED***`, while preserving test phone numbers and paths. A post-render gate (`check_report_redaction`) warns if any secret-like value survives.
- **Six-chapter + four-appendix structure**: 一、漏洞汇总 (V-XX + CVSS + Chinese severity) / 二、被测系统资产画像 (8 sub-sections) / 三、漏洞详情 / 四、测试过程 / 五、攻击链 (AP-XXX) / 六、安全加固建议 (14-day / 30-day / ongoing tiers) + appendices A-D (API stats / WAF analysis / test limitations / severity reference).
- **Test process in A.1 / A.1.1 numbering**: `build_test_process()` renders the coverage-checklist as per-category records in the standard 安服 numbering style, with each item annotated 已发现 / 未发现 / 未充分测试 / 受限. The Scope Adherence section is correctly excluded (it appears elsewhere).
- **Appendix D concise**: the severity reference is extracted to level definitions + per-class tables only, instead of dumping the full 200+ line document.

### Coverage checklist alignment (`coverage-checklist.md`)

Expanded from 41 rows / 5 categories to 76 rows / 8 categories, closing the gap where `severity-classification.md` and `payloads/` had been extended but the checklist (the execution driver) had not.

- **Authenticated face ④ expanded** to independent rows: Session/token lifecycle, JWT, MFA/2FA, OAuth/OIDC, Password reset, CSRF, CAPTCHA/lockout.
- **New section: Business Logic Surface** (7 rows: race condition, price/quantity tampering, payment step skip, payment replay, coupon abuse, OTP bypass, workflow manipulation).
- **New section: AI / LLM Surface** (9 rows: prompt injection, indirect injection, system prompt leak, tool-use bypass, memory/RAG poisoning, vector DB read, command execution, cost DoS, endpoint existence).
- **New section: Cloud Native / Infrastructure** (13 rows: subdomain takeover, cloud metadata, object storage, K8s API/Kubelet/etcd, SA token, container escape, WebSocket, CORS, cache poisoning, Host header, WAF origin).
- **New section: Modern Protocol Surface** (4 rows: gRPC auth bypass, protobuf injection, HTTP/2 single-packet race ×2).
- Each conditional section carries a presence prerequisite — features absent from the target are marked `out-of-scope` with reason, never left blank.

### Other

- `request_guard.py`: new mandatory request-logging + scope-check guard for manual HTTP requests.
- `build_recommendations()` ongoing-improvement tier no longer duplicates per-finding remediation.
- Tests: 106 passed (report-format coverage added).

## 2.22.4 - 2026-06-20

Report-gate parsing robustness fixes.

- **Request-log path detection no longer mis-rejects legal paths**: replaced the word-boundary regex (which failed on `/` and `/login`) with cell-level table parsing. A request row is now correctly counted when any cell holds an HTTP method and any cell holds a path starting with `/` (including bare `/`). The gate error message shows the expected row format.
- **03-vuln-test gate tightened**: a validation entry is now counted only by a real `## Test #N` / `## F-N` heading or a method+path table row — a bare keyword like "payload" in prose no longer passes the gate.
- **Coverage-checklist format constraint documented**: the template now states that the gate parses markdown tables (Status in column 2), and the gate error messages explain the expected row shape, so non-table coverage is not silently ignored.

## 2.22.3 - 2026-06-20

Report-gate depth, scope-violation enforcement, and coverage-gap visibility.

- **Deep report gate (was shallow file-existence check)**: `check_report_gate()` now verifies content, not just file presence — `02-discovery.md` must have a Request Log with real logged requests (method + path in table rows), `03-vuln-test.md` must have validation entries, `coverage-checklist.md` must have no blank-status rows. 60-byte garbage files no longer pass the gate.
- **Scope violation blocks the report**: the gate now parses the coverage-checklist Scope Adherence table; any `violation` result blocks report generation (exit 2) until the boundary breach is disclosed, matching the template rule.
- **Coverage gaps in the report**: `generate_report.py` now parses `coverage-checklist.md` degraded/not-covered rows and emits a "Test Coverage & Gaps" section (§5) in the markdown report, with the scope-adherence verdict. Silent gap dropping is no longer possible.
- **Script execute bits**: `check-structure.sh`, `check-task.sh`, `smoke-test.sh`, `build-public-package.sh` now carry +x.

## 2.22.2 - 2026-06-20

Functional defect fixes across the report/validation/tooling pipeline. All fixes verified by reproduction cases.

- **Report gate enforced (issue 1)**: `generate_report.py` now checks that `02-discovery.md`, `03-vuln-test.md`, and `coverage-checklist.md` exist before emitting a report — an empty/incomplete task no longer produces a formal report. `--skip-gate` overrides for structural tests and imported reports.
- **Template placeholder no longer parsed as a finding (issue 2)**: `ensure_structured_outputs.py` now skips unfilled `## F-001 — [Title]` placeholders (detected by literal `[Title]` heading or the multi-option `confirmed / suspicious / false_positive` status), so an empty task's findings.json/evidence-index/report stay clean.
- **Unknown status no longer defaults to `confirmed` (issue 3)**: a finding whose Status field is missing or unrecognized now defaults to `suspicious` (needs review) instead of `confirmed`, preventing half-written or format-drifted entries from becoming confirmed findings.
- **check-task.sh reads `- target:` (issue 4)**: target extraction now matches the YAML `- target:` form used by task.md, so `Target: unknown` no longer appears and connectivity checks run when expected.
- **`--output` honored for markdown reports (issue 5)**: the markdown branch now writes to the `--output` path instead of always writing `report.md`.
- **No more double structured sync (issue 6)**: the markdown branch no longer re-runs `ensure_structured_outputs.py` (it ran once at the top of main and again in the branch), eliminating redundant writes to findings.md/summary.json/raw.
- **SARIF driver version dynamic (issue 7)**: SARIF `driver.version` now reads from SKILL.md instead of the stale hardcoded `2.21.0`.
- **Batch shared-task only for single-batch-task mode (issue 8)**: `init_batch.py` no longer creates a `shared-task/` dir for `one-task-per-target` or `discovery-first` modes, where per-target dirs are the entry point — removing the confusion about which directory to execute in.

## 2.22.1 - 2026-06-20

Packaging and check-script robustness fixes from a real Kali deployment review.

- **smoke-test.sh false "syntax error" fix**: `py_compile` swallowed all stderr, so a read-only package directory (`__pycache__` not writable) was misreported as 12 Python syntax errors. Now detects permission errors, redirects pycache via `PYTHONPYCACHEPREFIX`, and falls back to a write-free `ast.parse`. (issue 2)
- **AppleDouble `._*` handling**: `check-structure.sh` and `smoke-test.sh` `find` calls now exclude `._*` files, so macOS metadata no longer doubles payload/template counts (55→110, 23→46). (issue 3)
- **`build-public-package.sh` excludes `._*`**: release archives no longer ship AppleDouble files; also added a `--full` flag to build the references-included variant. (issue 4)
- **`discover-capabilities.sh` execute permission**: added `+x` so `./scripts/discover-capabilities.sh` works, not only `bash scripts/...`. (issue 5)
- **`process-control.md` paused status**: documented as not produced by any current script (stop conditions surface a pause request instead), fixing the doc/implementation mismatch. (issue 7)
- **Added `DEPLOYMENT.md`**: covers skill registration into the agent skill path, read-only directory handling, and known tool gaps (OOB / gRPC / k8s). (issues 1 & 6)

## 2.22.0 - 2026-06-18

Scope-control and evidence-trail hardening, driven by a real-task review where discovery requests had no auditable log and a CORS finding mixed legitimate own-domain reflection with attacker-controllable evidence.

- **Scope Guard (new, mandatory)**: every active request must target a host in the preflight `scope` allowlist. Hosts observed via response leakage (actuator `_links` internal hostnames, error-stack internal IPs, wildcard-cert sibling subdomains) are evidence only — never resolved, connected, or probed. Added to `SKILL.md` (Workflow Phases + Action Policy) and both phase templates.
- **Mandatory evidence trail**: `02-discovery.md` and `03-vuln-test.md` are now required outputs with a per-request log (host, path, method, status, in-scope flag). A phase with zero logged requests is "not performed", never silently skipped. Added a Request Log section to `discovery-template.md` and a Scope Guard reminder + Target Host field to `vuln-test-template.md`.
- **Scope Adherence gate**: `coverage-checklist.md` gains a mandatory "Scope Adherence" section cross-checking request logs against the scope allowlist; any boundary violation blocks the report until disclosed.
- **CORS classification fix**: `payloads/cors.md` now distinguishes attacker-controllable origins (real evidence) from legitimate own-domain reflection (intended config, not a flaw on its own), preventing false-positive severity inflation.
- **Tool misidentification fix**: removed `spray` from the `directory-scanning` candidates in `discover-capabilities.sh` (it is the macOS NFS tool, not a web fuzzer) and added a system-binary path reject (`/usr/sbin`, `/sbin`, `/usr/libexec`, `/System/*`) so future name collisions no longer report phantom capabilities.
- **Missing-tool degradation policy**: when a capability has no available tool, the skill degrades to passive extraction + coverage gap reporting instead of hand-rolling unbounded batch `curl` requests (the drift/no-audit path). Added to `SKILL.md` and `discovery-template.md`.

## 2.21.0 - 2026-06-18

- Added Apache License 2.0 for public release.
- Converted public skill content to English canonical text.
- Clarified that private deep references and L3 knowledge are excluded from the public release.
- Tightened open-source publishing boundaries for `references/`, `l3/`, task results, raw evidence, and screenshots.
- Kept nuclei and equivalent template scanners opt-in only.
- Preserved evidence-driven reporting, coverage-gap tracking, and L3 hypothesis gating.
- Engineering-consistency polish (no workflow or safety-boundary changes):
  - Synchronized drifted version stamps in `commands/` and `templates/` (`capabilities.md`, `recon.md`, `source-code-review.md`, `threat-modeling.md`, `stack-mapping.md`, `severity-classification.md`) to 2.21.0.
  - Replaced the `rg -P "\p{Han}"` scan in `OPEN_SOURCE_CHECKLIST.md` with a portable BSD/GNU grep fallback; reworked the exclude table into a verified-status table.
  - Removed redundant `l3/experience/` and `l3/internal-knowledge/` lines from `.gitignore` (already covered by `l3/`).
  - Tightened `agents/openai.yaml` URL trigger so a bare "test <url>" no longer auto-invokes the skill without a security context word.
  - Expanded the `capabilities.md` registry-format example to document `binary_paths`, `selected_path`, `requires_explicit_approval`, and `nuclei_templates` fields actually emitted by `discover-capabilities.sh`.
