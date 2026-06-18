# Structured Output Requirements

Task execution generates the following structured files for case retention, knowledge aggregation, and future reference:

- `summary.json`
- `findings.json`
- `evidence-index.json`

**Output Location**: Task results go to a user-specified directory, the existing task directory when resuming, `$PENTEST_RESULTS_ROOT` when set, or `~/authorized-appsec/results/`. Do not write results into the skill package source files by default.

Directory structure:

```text
{RESULTS_ROOT}/
└── PT-{YYYYMMDD}-{SEQ}-{target_slug}/
    ├── findings.md
    ├── summary.json
    ├── findings.json
    ├── evidence-index.json
    ├── report.md
    ├── 01-fingerprint.md
    ├── 02-discovery.md
    ├── 03-vuln-test.md
    ├── 04-chain.md
    ├── attack-graph.md
    ├── task.md
    ├── sessions/
    ├── raw/
    │   ├── poc-F-001.txt
    │   └── http-responses.txt
    └── screenshots/
```

For details see `README.md` → Default Output and `SKILL.md` → Results Location.

---

## Minimum Examples

### summary.json Minimum Example

```json
{
  "task_id": "PT-{YYYYMMDD}-{SEQ}-{target_slug}",
  "skill_name": "authorized-appsec",
  "target": "https://example.com",
  "target_type": "url",
  "phase_status": "completed",
  "current_phase": "Phase 4",
  "started_at": "2026-04-20T10:00:00+08:00",
  "ended_at": "2026-04-20T11:30:00+08:00",
  "tech_stack": ["nginx", "php", "mysql"],
  "major_findings": [
    {
      "finding_id": "F-001",
      "title": "SQL Injection",
      "severity": "high"
    }
  ],
  "next_recommendations": [
    "Fix SQL injection vulnerability",
    "Strengthen input validation"
  ],
  "boundary_summary": "Authorized scope: Only test example.com and its subpaths, destructive operations prohibited",
  "report_status": "draft",
  "knowledge_ready": true,
  "memory_ready": true,
  "distillation_ready": true,
  "distillation_candidate_count": 1,
  "l3_export_reason": "confirmed distillation candidates exist"
}
```

### findings.json Minimum Example

```json
{
  "findings": [
    {
      "finding_id": "F-001",
      "title": "SQL Injection - /api/user?id=1",
      "category": "sqli",
      "severity": "high",
      "priority": "P0",
      "status": "confirmed",
      "fact_summary": "GET parameter id has SQL injection, single quote triggers error echo",
      "boundary": "Manual verification completed, no database read operation executed",
      "evidence_refs": ["E-001", "E-002"],
      "recommended_next_action": "Recommend using sqlmap for deep exploitation with user confirmation",
      "knowledge_candidate": true,
      "memory_candidate": true,
      "distillation_candidate": true,
      "distillation_reason": "eligible: confirmed high-impact finding with reusable validation pattern",
      "complexity": "complex",
      "chain_value": false,
      "reuse_pattern": "sqli: /api/user?id=1"
    }
  ]
}
```

### evidence-index.json Minimum Example

```json
{
  "evidence": [
    {
      "evidence_id": "E-001",
      "type": "http_response",
      "source_tool": "curl",
      "target": "/api/user?id=1'",
      "summary": "Single quote triggers 500 error, echoes SQL syntax error",
      "raw_ref": {
        "path": "raw/http-responses.txt",
        "line_range": "120-135"
      },
      "timestamp": "2026-04-20T10:30:00Z"
    },
    {
      "evidence_id": "E-002",
      "type": "screenshot",
      "source_tool": "manual",
      "target": "/api/user?id=1'",
      "summary": "Error page screenshot, shows MySQL error information",
      "raw_ref": {
        "path": "screenshots/error-001.png"
      },
      "timestamp": "2026-04-20T10:31:00Z"
    }
  ]
}
```

---

## Field Constraints

### summary.json

Records task-level summary, must contain at minimum:
- `task_id` — Task unique identifier
- `skill_name` — Fixed as `authorized-appsec`
- `target` — Test target
- `target_type` — url/domain/ip/ip_range
- `phase_status` — in_progress/paused/completed/stopped
- `current_phase` — Current phase
- `tech_stack` — Identified tech stack list
- `major_findings` — Major findings summary list
- `next_recommendations` — Next recommendations list
- `boundary_summary` — Test boundary statement
- `report_status` — Final report status (not_generated/draft/final)
- `knowledge_ready` — Suitable for knowledge base retention
- `memory_ready` — Suitable for task experience retention
- `distillation_ready` — Contains at least one confirmed finding worth L3 distillation
- `distillation_candidate_count` — Number of findings that pass the distillation gate
- `l3_export_reason` — Why this task is or is not suitable for L3 export

Constraints:
- For task-level summary, no full report body copy-paste
- Must retain conclusion boundary, no unverified speculation written as confirmed fact
- Can be generated from `task.md` and `findings.md` aggregation

### findings.json

Records structured finding item list. Each finding must contain at minimum:
- `finding_id` — Finding unique identifier (e.g., F-001, F-002)
- `title` — Vulnerability title
- `category` — Vulnerability category (sqli/xss/ssrf/xxe/auth/file/rce/info/prompt_injection/tool_use_abuse/rag_poison/system_prompt_leak/llm_cost_dos/grpc_auth_bypass/protobuf_injection/k8s_priv_esc/kubelet_exposure/etcd_exposure/container_escape/origin_disclosed/cloud_bucket_exposed/http2_race_condition/waf_bypass)
- `severity` — Severity (critical/high/medium/low/info), see `templates/severity-classification.md`
- `severity_reason` — Reason for severity assignment (brief justification)
- `owasp_category` — OWASP API/Top 10 category (e.g., API1:2023-BOLA, A03:2021-Injection)
- `cwe_id` — CWE identifier (e.g., CWE-89, CWE-79, CWE-200)
- `priority` — Handling priority (P0/P1/P2/P3). Auto-populated by `ensure_structured_outputs.py` if omitted: critical/high → P0, medium → P1, low → P2, info → P3
- `status` — Status (confirmed/suspicious/false_positive)
- `fact_summary` — Observed fact summary
- `boundary` — Validation boundary (what done/not done)
- `evidence_refs` — Evidence ID list
- `recommended_next_action` — Recommended next action
- `knowledge_candidate` — Suitable for retention as vulnerability/knowledge entry
- `memory_candidate` — Suitable for retention as task experience sample
- `distillation_candidate` — Eligible for L3 export as a complex/high-value vulnerability or reusable attack-chain pattern
- `distillation_reason` — Brief reason for inclusion or exclusion from distillation
- `complexity` — `direct`, `complex`, `chain`, or `not_applicable`
- `chain_value` — Whether the finding is useful because it captures a multi-step, bypass, or cross-surface attack chain
- `reuse_pattern` — Short reusable pattern key, usually category plus affected endpoint or scenario

Constraints:
- `fact_summary` only writes observed facts or completed validation conclusions
- `boundary` must be retained, cannot be omitted
- Finding not bound to `evidence_refs` cannot be marked as `confirmed`
- Confirmed findings must include `poc` or a `poc_boundary` explaining why live PoC content is unsafe
- High-risk entries in `findings.md` should be one-to-one corresponding with `findings.json`
- **High-value information findings** (exploitable tech version, internal paths, exposed admin endpoints) should be severity `high`, not `info`
- L3 export uses `distillation_candidate`, not `knowledge_candidate` alone.
- Set `distillation_candidate=true` for confirmed complex/high-value findings and confirmed reusable chains: authorization/IDOR/BOLA, authentication/session/JWT/OAuth/MFA/password-reset flaws, business-logic flaws, SQLi/RCE/SSRF/XXE/deserialization/file-upload/path traversal, cloud metadata/internal pivot issues, default/hardcoded credentials, Mini Program to backend/Web cross-surface cases, and multi-step bypass chains.
- Set `distillation_candidate=false` for low/info findings and ordinary low-reuse items: missing headers, no-WAF observations, HTTP TRACE/method checks, version/banner disclosure, generic cookie/TLS flags, and generic configuration hygiene unless they are part of a confirmed higher-value chain.
- Imported report findings remain `distillation_candidate=false` until a human reviews PoC, evidence, boundaries, severity, and duplicate handling.

### evidence-index.json

Records evidence index. Each evidence must contain at minimum:
- `evidence_id` — Evidence unique identifier (e.g., E-001, E-002)
- `type` — Evidence type (http_response/screenshot/raw_output/log/file)
- `source_tool` — Source tool (curl/httpx/nuclei/manual)
- `target` — Evidence corresponding target/path
- `summary` — Evidence summary
- `raw_ref.path` — Raw file path
- `timestamp` — Timestamp

Constraints:
- Raw evidence stored in files, index file only records summary and path
- Evidence must be traceable to raw output, screenshots, response files, or phase records
- Confirmed finding PoCs should be traceable to `raw/poc-{finding_id}.txt` unless an existing raw file already contains the sanitized request and observation
- Evidence summary should serve subsequent case extraction and knowledge base statistics, not copy raw full text

### attack-graph.md

Records current-task attack relationships only.

Constraints:
- Generate from `task.md`, current phase files, `findings.md`, `findings.json`, `evidence-index.json`, and current raw PoC/evidence files.
- Do not include L3 entries, historical tasks, or stack templates as attack nodes unless current-task evidence independently supports them.
- Technology labels must come from current headers, cookies, HTML/JS, errors, service banners, source/package metadata, or raw responses.

---

## Minimum Write Timing

Maintain structured files at this minimum granularity:

1. After Phase 0 completion: Update `summary.json` (tech_stack + phase_status)
2. After each confirmed finding: Append or update `findings.json`
3. After each key evidence captured: Append or update `evidence-index.json`
4. At task end: Refresh `summary.json` to ensure counts, boundaries, and recommendations are final
5. Before delivery: Generate `report.md`, set `report_status` to `draft` or `final`

---

## Generation Principles

- Structured files are **structured projections** of Markdown primary records, not replacements
- Vulnerability details use `findings.md` as the authoritative source; JSON is for indexing and summary
- Boundary statements must remain consistent between `task.md` and `summary.json`
- Evidence index points to raw files; JSON does not duplicate full content
- Final report aggregates from structured data and includes minimal sanitized PoCs for confirmed findings
- `report.md` is a delivery artifact: no full payload history, raw response text, or session-sensitive information, but it must retain enough sanitized PoC detail for reproducibility
- L3 export requires explicit user request plus at least one confirmed `distillation_candidate=true` finding. Empty/no-finding tasks and ordinary low-risk configuration findings are not vulnerability knowledge.
- Distillation is local artifact processing only. It must not execute PoCs, replay requests, or contact the target.
