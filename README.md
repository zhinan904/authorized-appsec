# Authorized AppSec Testing Skill

CLI-friendly workflow for authorized Web, API, and application security assessment.

**Chinese documentation**: [`README.zh-CN.md`](./README.zh-CN.md)

**Entry point**: `SKILL.md` (version and authoritative rules live there).
**State management**: `memory-protocol.md`.

## Runtime Assumption

Run active testing from a Kali Linux VM or an equivalent isolated security-testing VM where this skill directory is available. Capability discovery and network tools must run inside that VM, not from the host workstation. Keep task outputs outside the skill package, using a user-specified output directory, `$AUTHORIZED_APPSEC_RESULTS_ROOT`, or `~/authorized-appsec/results/`.

For installation into the agent skill path, read-only directory handling, and known tool gaps (OOB / gRPC / k8s), see **[DEPLOYMENT.md](DEPLOYMENT.md)**.

## Core Design

- **Evidence-driven**: every confirmed finding backed by current-task raw evidence. No severity from path shape, L3 recall, or historical cases alone.
- **Gating severity model**: default Low; High/Critical only when the exploit chain is confirmed closed. Defect existence ≠ exploitability.
- **Layered knowledge**: `payloads/` (safe, in-flow) → optional private references (not included in the public release) → L3 (local historical hypotheses).
- **Coverage visibility**: the report explicitly surfaces untested/degraded surfaces instead of hiding them.

## Core Files

```text
authorized-appsec/
├── SKILL.md                  # entry point, authoritative rules
├── memory-protocol.md        # task state management
├── commands/                 # methodology & command references
│   ├── capabilities.md       # runtime tool discovery
│   ├── recon.md              # recon workflow by capability
│   ├── ports.md              # web port selection
│   ├── stack-mapping.md      # tech stack → vulnerability mapping
│   ├── threat-modeling.md    # STRIDE methodology
│   ├── source-code-review.md # source review methodology
│   ├── brute-force.md        # credential brute-force
│   ├── modern-auth.md        # OTP/slider/SSO/MFA/token lifecycle
│   └── authenticated-testing.md  # Phase 3 authenticated branch
├── payloads/                 # 55 vulnerability payload files (safe, in-flow)
├── templates/                # 23 output templates (incl. coverage-checklist)
└── scripts/                  # 20 automation scripts
```

The public release intentionally excludes `references/`, private L3 knowledge, raw evidence, historical reports, and task results. The published package contains the workflow, safety boundaries, payload validation guidance, templates, scripts, and tests.

Optional local archives may exist outside this directory, but they are not required for the skill to work:

```text
~/authorized-appsec/results/
~/authorized-appsec/l3/      # optional local private knowledge, not published
```

## Default Output

Use a user-specified directory when provided. When resuming, continue in the existing task directory. Otherwise create task output in `$AUTHORIZED_APPSEC_RESULTS_ROOT` when set, or `~/authorized-appsec/results/`:

```text
results/
└── PT-{YYYYMMDD}-{SEQ}-{target_slug}/
    ├── task.md
    ├── findings.md
    ├── summary.json
    ├── findings.json
    ├── evidence-index.json
    ├── l3-hypotheses.json
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

Do not write task output inside this skill package. Do not use legacy result roots as implicit output roots. A legacy path is valid only when the user explicitly provides it or when resuming an existing task that already lives there.

`attack-graph.md` is regenerated from the current task's phase files, findings, structured evidence, and raw PoC files. Historical L3 entries and stack templates are reference material only; they are not graph nodes or current-target fingerprint facts.

## Scripts

Run capability discovery inside the Kali VM before testing and write the result into the current task directory:

```bash
bash scripts/discover-capabilities.sh <task_dir>/capabilities.json
```

Run structure validation from this directory:

```bash
bash scripts/check-structure.sh
```

For a manual single HTTP request, use the scope-checked wrapper so the request is logged automatically:

```bash
python3 scripts/request_guard.py <task_dir> https://example.com/login --phase discovery
python3 scripts/request_guard.py <task_dir> https://example.com/api/search --phase 3 --method POST --idempotent-post --body '{"q":"appsec-test"}'
```

Manual single requests must use this wrapper. It verifies completed preflight, `scope_allowlist`, approved ports, and scoped `Host` headers before sending traffic, saves sanitized raw evidence under `raw/`, and appends the required request row to `02-discovery.md` or `03-vuln-test.md`. If `approved_ports` is omitted or set to `default-for-target`, the target URL's default or explicit port is enforced.

Generate a report from a task directory:

```bash
# Install test dependencies if needed
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt

# Initialize a single task directory
python3 scripts/init_task.py https://example.com --type url

# Or with custom output directory
python3 scripts/init_task.py https://example.com --type url --output-dir /path/to/results

# Generate structured outputs and report
python3 scripts/ensure_structured_outputs.py <task_dir>
python3 scripts/generate_report.py <task_dir>
```

The generated `report.md` is a customer-deliverable Chinese report (渗透测试报告) with a fixed structure:

| Chapter | Content |
|---------|---------|
| 一、漏洞汇总 | V-XX numbering + Chinese severity + CVSS + status |
| 二、被测系统资产画像 | 8 sub-sections: basics / tech stack / deployment / auth / components / modules / data flow / external deps |
| 三、漏洞详情 | V-XX + full curl/HTTP evidence (session keys redacted) + impact + remediation |
| 四、测试过程 | A.1 / A.1.1 per-item test records (covered / degraded / not-covered) from the coverage checklist |
| 五、攻击链 | AP-XXX chains from chain analysis, F-XXX→V-XX mapped |
| 六、安全加固建议 | Tiered: high (14 days) / medium (30 days) / ongoing (SDL) |
| 附录 A-D | API endpoint stats / WAF analysis / test limitations / severity reference |

Internal `F-XXX` finding IDs are rendered as customer-facing `V-XX` (severity-descending), keeping F-XXX as a traceability note. Evidence blocks are redacted by `redact_response()` (session keys / tokens / 32+ hex → `***REDACTED***`). The report is the only sanctioned output — never hand-written in free prose.

Import a legacy vulnerability report:

```bash
python3 scripts/import_report.py ./old-report.docx --target https://example.com
python3 scripts/import_report.py ./old-report.html --target example.com --default-status suspicious
```

Supported import formats are `.md`, `.html`, `.docx`, and `.doc` when LibreOffice/soffice is available. Imported reports become `IMPORTED-*` task directories with the original report stored under `raw/`.

Export reusable knowledge only when explicitly requested:

```bash
python3 scripts/generate_report.py <task_dir> --export-l3 <l3_root>
```

Process control (terminate running tasks):

```bash
# Terminate single task
bash scripts/task-control.sh terminate <task_dir> [--force]

# Terminate all tasks in batch
bash scripts/task-control.sh terminate-batch <batch_dir>

# Terminate specific target in batch (use T-XXX format)
bash scripts/task-control.sh terminate-batch <batch_dir> --target T-003

# Add tool PID for tracking
bash scripts/task-control.sh add-tool-pid <task_dir> --pid <pid> --name <tool_name>

# Cleanup tool PID
bash scripts/task-control.sh cleanup-tool-pid <task_dir> --pid <pid>

# Check task process status
bash scripts/task-control.sh status <task_dir>

# List all processes in batch
bash scripts/task-control.sh list-processes <batch_dir>
```

**Note**: Target ID format is `T-XXX` (e.g., `T-001`, `T-003`), not slug name.

---

## Batch Testing

For multi-target authorized AppSec assessment, use batch mode:

### Batch Structure

```text
results/
└── BATCH-{YYYYMMDD}-{SEQ}/
    ├── batch.md              # Batch entry point
    ├── targets.json          # Target registry and status
    ├── summary.json          # Batch-level summary
    ├── report.md             # Batch-level report
    └── targets/
        ├── T-001-{slug}/     # Target 1 (single-task structure)
        ├── T-002-{slug}/     # Target 2
        └── T-003-{slug}/     # Target 3
```

### Batch Workflow

| Phase | Purpose |
|-------|---------|
| Preflight | Confirm batch authorization boundary |
| Initialize | Create batch directory and targets.json |
| Discovery | Filter candidates (if needed) |
| Selection | User confirms targets for testing |
| Dispatch | Create task directories for selected targets |
| Execute | Run single-target flow for each task |
| Aggregate | Collect results from completed tasks |
| Report | Generate batch-level report |

### Process Control

Each task tracks processes in `.task-pids.json`:

```json
{
  "main_pid": 12345,
  "tool_pids": [{"pid": 12346, "name": "httpx"}],
  "status": "running"
}
```

Termination signals:
- **SIGTERM** (default): Graceful termination, allows cleanup
- **SIGKILL** (`--force`): Immediate termination, no cleanup

See `templates/batch-template.md` and `templates/process-control.md` for details.

### Batch Scripts

```bash
# Initialize batch from targets file (one target per line: T-001 https://...)
python3 scripts/init_batch.py <batch_dir> <targets_file>

# Aggregate results from completed targets
python3 scripts/aggregate_batch.py <batch_dir>

# Generate batch-level report
python3 scripts/generate_batch_report.py <batch_dir>
```

### Cleanup & Rollback

```bash
# Clean up test artifacts for a single task
bash scripts/cleanup.sh <task_dir>

# Preview cleanup without executing
bash scripts/cleanup.sh <task_dir> --dry-run

# Clean up all targets in a batch
bash scripts/cleanup.sh <batch_dir> --batch
```

See `templates/cleanup-template.md` for full rollback protocol.

### L3 Knowledge Retrieval

```bash
# Search L3 knowledge for relevant context before starting a task
python3 scripts/retrieve_l3.py <l3_root> --target https://example.com --limit 5
python3 scripts/retrieve_l3.py <l3_root> --category sqli --limit 3
```

L3 retrieval results are historical references. They must not be promoted into current findings, fingerprints, or attack graphs unless current-task evidence independently supports them. L3 export is explicit only and requires at least one confirmed `distillation_candidate=true` finding. Distill complex/high-value vulnerabilities and reusable attack chains; do not export ordinary low-risk configuration findings unless they are part of a confirmed higher-value chain.

## Publishing Notes

For a clean published skill, keep `SKILL.md`, `memory-protocol.md`, `commands/`, `payloads/`, `templates/`, `scripts/`, `tests/`, and the open-source project metadata. Exclude `references/`, `l3/`, `.DS_Store`, caches, historical task results, raw evidence, screenshots, HAR/PCAP files, real reports, and platform-specific binaries unless they are intentionally distributed and documented.

Build a public archive:

```bash
bash scripts/build-public-package.sh
```

See `OPEN_SOURCE_CHECKLIST.md` before publishing.

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
