# Memory Protocol

This protocol keeps authorized-appsec work resumable without turning the skill package into a mutable workspace.

## Core Rules

- Keep only the current working state in model context.
- Write process notes to phase files.
- Write confirmed vulnerabilities to `findings.md`; treat it as the human-readable authority.
- Write task metadata and next actions to `task.md`.
- Use `summary.json`, `findings.json`, and `evidence-index.json` as structured projections, not replacements for the Markdown records.
- Do not create new task results inside the skill package unless the user explicitly chooses that path.
- Do not read historical task directories by default. Resume only the task the user names or the task directory already in use.

## Output Root Selection

Choose the task output root in this order:

1. User-specified directory.
2. Existing task directory when resuming.
3. `$PENTEST_RESULTS_ROOT`, when set.
4. `~/authorized-appsec/results/`.

Never create new task results inside the skill package by default. Never use legacy result roots as implicit defaults. If an existing task contains a legacy absolute path in `task.md`, normalize follow-up writes to the actual task directory unless the user explicitly asks to continue in that legacy root.

Use these names in notes and scripts:

```text
SKILL_ROOT = directory containing SKILL.md; read-only bundled resources
RESULTS_ROOT = selected output root for task directories
TASK_DIR = {RESULTS_ROOT}/PT-{YYYYMMDD}-{SEQ}-{target_slug}
```

`SKILL_ROOT` is only for resources such as `commands/`, `payloads/`, `templates/`, and `scripts/`.

## Task Directory

Each task gets a unique directory:

```text
PT-{YYYYMMDD}-{SEQ}-{target_slug}/
├── task.md
├── findings.md
├── summary.json
├── findings.json
├── evidence-index.json
├── l3-hypotheses.json
├── capabilities.json
├── report.md
├── 01-fingerprint.md
├── 02-discovery.md
├── 03-vuln-test.md
├── 04-chain.md
├── attack-graph.md
├── sessions/
├── raw/
└── screenshots/
```

`SEQ` is an incrementing number for the chosen `RESULTS_ROOT` and date. If no index exists, start at `001`.

Maintain an optional index at:

```text
{RESULTS_ROOT}/index.md
```

Suggested index format:

```md
# Task Index

| Task ID | Target | Type | Status | Created At | Path |
|--------|--------|------|--------|------------|------|
| PT-{YYYYMMDD}-{SEQ}-example-com | https://example.com | url | in_progress | YYYY-MM-DD HH:MM | PT-{YYYYMMDD}-{SEQ}-example-com/ |
```

## Initial Files

When creating a new task:

1. Confirm authorization, scope, intensity, and allowed automation.
2. Create `TASK_DIR`, `raw/`, `sessions/`, and `screenshots/`.
3. Initialize `task.md`, `findings.md`, `summary.json`, `findings.json`, `evidence-index.json`, and `l3-hypotheses.json`.
4. Add or update `{RESULTS_ROOT}/index.md`.
5. Enter Phase 0.

Use templates as needed:

| Template | Purpose |
|----------|---------|
| `templates/task-template.md` | Initial `task.md` structure |
| `templates/fingerprint-template.md` | Phase 0 output format |
| `templates/discovery-template.md` | Phase 1-2 output format |
| `templates/vuln-test-template.md` | Phase 3 validation log format |
| `templates/chain-template.md` | Phase 4 chain analysis format |
| `templates/findings-template.md` | Confirmed finding format |
| `templates/session-template.md` | Session record format |
| `templates/structured-output-requirements.md` | JSON output schemas |

## task.md

`task.md` is the resume entry point. Keep it short enough to read every time.

Suggested shape:

```md
# Task Meta

- task_id: PT-{YYYYMMDD}-{SEQ}-example-com
- target: https://example.com
- target_type: url
- status: in_progress
- current_phase: phase_2
- authorization: confirmed_by_user
- scope: example.com and subpaths only
- intensity: gentle
- automation_allowed: fingerprinting only
- started_at: 2026-05-03 10:30
- updated_at: 2026-05-03 10:45

## Summary
- tech_stack: nginx, php
- waf: unknown
- finding_counts: critical=0, high=0, medium=0, low=0, info=0
- session_contexts: anonymous(valid), user(unavailable), admin(unavailable)
- pending_focus:
  - review login form parameters

## Next Actions
1. finish Phase 2 endpoint review
2. update 02-discovery.md
3. decide whether Phase 3 validation needs credentials
```

Update `task.md` whenever the phase, status, finding counts, session context, scope, or next action changes.

Do not store full cookies, tokens, passwords, raw responses, or full finding bodies in `task.md`.

## l3-hypotheses.json

`l3-hypotheses.json` is an automatically generated queue aid, not evidence. Generate it after Phase 0:

```bash
python3 scripts/auto_l3_hypotheses.py <TASK_DIR>
```

It may contain historical same-system matches and suggested validation categories. These records are not findings and must not appear in the final report as vulnerabilities unless Phase 3 current-task validation confirms them and `findings.md` is updated with evidence and PoC.

Allowed uses:

- prioritize Phase 1/2 mapping;
- choose payload/reference files for Phase 3;
- record "Historical References Considered" separately from current evidence.

Forbidden uses:

- creating confirmed findings from historical matches alone;
- claiming a vulnerability exists because a similar system had it;
- adding L3 hypotheses as attack-graph nodes without current-task evidence;
- reusing historical credentials, tokens, secrets, identifiers, or target-specific payloads.

## findings.md

`findings.md` is the human-readable authority for confirmed vulnerabilities.

Write to `findings.md` only when a finding is confirmed or high-confidence enough to be reported with explicit caveats.

Do not write these to `findings.md`:

- Scanner hits without validation.
- Ordinary discovery output.
- Failed payload attempts.
- Raw HTTP responses.
- Credentials, tokens, or cookies.

Minimum finding fields:

```md
## F-001 - Horizontal BOLA [High]

**Status**: confirmed
**Affected**: GET /api/v1/users/:id
**Source Phase**: phase_3
**Description**: Ordinary users can access another user's object data.
**Evidence**: User A token received a 200 response for User B resource.
**Boundary**: Confirmed object access only; no bulk extraction performed.
**Reproduction**:
1. Authenticate as a normal user.
2. Request another user's object ID.
3. Observe unauthorized data in the response.
**Remediation**: Enforce object-level authorization before returning the object.
**Discovered At**: 2026-05-03 11:05
```

## Structured Files

Maintain these files as projections of `task.md`, `findings.md`, and evidence records:

| File | Purpose |
|------|------|
| `summary.json` | Task-level summary, boundary, status, recommendations |
| `findings.json` | Machine-readable finding list |
| `evidence-index.json` | Evidence IDs pointing to raw files, screenshots, or phase notes |

Rules:

- `fact_summary` contains only observed facts or confirmed conclusions.
- Every confirmed finding must include `boundary`.
- Confirmed findings must reference evidence IDs.
- Confirmed findings must include a minimal PoC or an explicit reason the PoC is safely blocked.
- Raw evidence stays in files; JSON keeps summaries and paths only.
- Reports are generated from these files, with `findings.md` as the authority for details.

## Phase Files

| File | Role |
|------|------|
| `01-fingerprint.md` | Boundary summary, HTTP fingerprint, technology stack, WAF/CDN hints, initial attack surface |
| `02-discovery.md` | Endpoints, parameters, discovery results, test queue, blocked items |
| `03-vuln-test.md` | Validation attempts, outcomes, session context, failed or deferred tests |
| `04-chain.md` | Bounded impact analysis and safe follow-up hypotheses |
| `attack-graph.md` | Current-task evidence graph generated from phase files, findings, and raw evidence only |

Phase files are process records. They do not replace `findings.md`.

`attack-graph.md` must not promote L3 history, stack mappings, or historical templates into current-target facts. If a stale graph contains unrelated target names, legacy stack guesses, or L3 case nodes, regenerate it from the current task files before delivery.

### Retest Phase

When the user requests retesting of previously confirmed findings:

| File | Role |
|------|------|
| `retest-task.md` | Original finding references, retest method, scope |
| `retest-findings.md` | Per-finding retest results (fixed/partially_fixed/not_fixed) |
| `retest-summary.json` | Structured retest results |
| `retest-comparison.md` | Before/after comparison |

Use `templates/retest-template.md` for retest directory structure and writing rules.

Retest directories use: `RETEST-{YYYYMMDD}-{SEQ}-{target_slug}/`

Create only when the user explicitly requests retesting. Retest scope must not exceed original findings without approval.

Flush phase files after meaningful changes and before pausing.

## Raw Evidence

Store raw evidence only when it is useful for audit or report support:

```text
raw/http-responses.txt
raw/tool-output.txt
raw/poc-F-001.txt
screenshots/
```

Do not reload raw evidence during resume unless a finding, report, or user question requires it.

For each confirmed finding, preserve a sanitized PoC artifact in `raw/poc-{finding_id}.txt` or point `evidence-index.json` to an existing raw request/response that contains the PoC. Redact tokens, cookies, real identifiers, and sensitive response bodies, but keep enough request method, path, parameters, and expected observation for reproducibility.

## Sessions

Use `sessions/` for scoped authentication material:

```text
sessions/
├── anonymous.md
├── user.md
├── admin.md
└── service.md
```

Each session record should include source, scope, status, creation/update time, expiration, and refresh rules. Store secrets only when the user explicitly supplied them and the task requires them. Keep secrets out of `task.md`, `summary.json`, `findings.json`, and `report.md`.

Never reuse a session across task directories unless the user explicitly says it is in scope.

## Resume Protocol

Resume in this order:

1. Read the named `task.md`.
2. Read `findings.md`.
3. Read the current phase file named by `task.md.current_phase`.
4. Read other phase files only if needed.
5. Read raw evidence only if needed for a specific finding or report.

Do not infer current state from a directory name alone. Do not load all historical tasks.

## Pause and Completion

Before pausing, handing off, or completing:

1. Update `task.md` with status, current phase, and next actions.
2. Flush the current phase file.
3. Sync confirmed findings into `findings.md` and `findings.json`.
4. Refresh `summary.json` and `evidence-index.json`.
5. Generate or refresh `report.md` when the user needs delivery output.

Use:

```bash
python3 scripts/ensure_structured_outputs.py <task_dir>
python3 scripts/generate_report.py <task_dir>
```

Only export reusable knowledge when explicitly requested:

```bash
python3 scripts/generate_report.py <task_dir> --export-l3 <l3_root>
```

Do not export tasks with zero confirmed distillation candidates into L3 knowledge. A "no vulnerability found" or blocked task can be summarized in the task report, but it is not a vulnerability knowledge entry. Distillation is for complex/high-value vulnerabilities and reusable attack chains; low/info issues and ordinary missing-header, no-WAF, TRACE/method, banner/version, cookie/TLS, or generic configuration findings stay out unless they are part of a confirmed higher-value chain. Import and distillation are local file-processing steps and must not execute PoCs or contact the target.

---

## Batch Protocol

For multi-target penetration testing, use batch-mode workflow with unified authorization boundary and isolated task execution.

### Batch vs Single Task

| Mode | When to Use | Structure |
|------|-------------|-----------|
| Single Task | One target, simple scope | `PT-{YYYYMMDD}-{SEQ}-{target_slug}/` |
| Batch Mode | Multiple targets, unified authorization | `BATCH-{YYYYMMDD}-{SEQ}-{batch_slug}/` |

Use `templates/batch-template.md` for batch-mode workflow.

### Batch Structure

```text
BATCH-{YYYYMMDD}-{SEQ}-{batch_slug}/
├── batch.md                 # Batch entry point
├── targets.json             # Target registry and status
├── index.md                 # Task index (optional)
├── summary.json             # Batch-level summary
├── report.md                # Batch-level report
└── targets/
    ├── T-001-{target_slug}/
    ├── T-002-{target_slug}/
    └── T-003-{target_slug}/
```

Each `T-{SEQ}-{target_slug}/` subdirectory follows the single-task structure defined above.

### Batch Phases

| Phase | Purpose |
|-------|---------|
| Phase 0: Preflight | Confirm batch authorization boundary |
| Phase 1: Initialize | Create batch directory and control files |
| Phase 2: Discovery | Filter candidates (if needed) |
| Phase 3: Selection | User confirms targets for testing |
| Phase 4: Dispatch | Create task directories for selected targets |
| Phase 5: Execute | Run single-target flow for each task |
| Phase 6: Aggregate | Collect results from completed tasks |
| Phase 7: Report | Generate batch-level report |

### Batch Authorization (Preflight)

Before any probing, confirm:

| Field | Description |
|-------|-------------|
| `targets` | Target list or IP ranges |
| `scope` | Allowed domains/IPs/paths/accounts |
| `excluded` | Explicit exclusions |
| `intensity` | Testing intensity level |
| `allowed_capabilities` | Permitted capability types |
| `blocked_capabilities` | Prohibited capability types |
| `credentials_scope` | Credential usage rules |
| `batch_mode` | `one-task-per-target` or `single-batch-task` |

Use `templates/targets-schema.md` for targets.json structure.

### Sub-task Constraints

Each target sub-task must:

- Inherit scope from batch (cannot expand)
- Inherit intensity from batch
- Inherit blocked capabilities (cannot override)
- Use isolated session scope (no sharing)
- Pause on stop condition (report to batch)

### Batch Resume

```markdown
Resume batch in this order:
1. Read batch.md (batch entry point)
2. Read targets.json (target registry)
3. For paused/in-progress targets:
   - Read targets/{target_id}/task.md
   - Read targets/{target_id}/findings.md
4. For specific target deep analysis:
   - Read targets/{target_id}/phase files (only if needed)
   - Read targets/{target_id}/evidence files (only if needed)
```

### Stop Conditions

Unified stop conditions for batch and single-task testing.

Use `templates/stop-conditions.md` for condition definitions.

When stop triggered:

| Level | Action |
|-------|--------|
| Single target | Pause that target, continue others |
| Batch-level | Stop all targets, notify user |

### Batch-Level Output

Generate after all targets completed or user requests:

| File | Source |
|------|--------|
| `BATCH-*/summary.json` | Aggregate from `targets/*/summary.json` |
| `BATCH-*/report.md` | Batch-level report structure |
| `BATCH-*/index.md` | Final target status summary |

### Batch Scripts

```bash
# Initialize batch directory structure from targets file
python3 scripts/init_batch.py <batch_dir> <targets_file>

# Aggregate results from completed targets
python3 scripts/aggregate_batch.py <batch_dir>

# Generate batch-level report
python3 scripts/generate_batch_report.py <batch_dir>
```

### Available Scripts

```bash
# Process control
bash scripts/task-control.sh terminate-batch <batch_dir> --target T-003

# Capability discovery
bash scripts/discover-capabilities.sh capabilities.json

# Structure validation
bash scripts/check-structure.sh

# L3 knowledge retrieval for new tasks
python3 scripts/retrieve_l3.py <l3_root> --target <target_url> --limit 5
```
