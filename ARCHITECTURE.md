# Authorized AppSec Skill Architecture

> **Version**: 2.21.0 | **Updated: 2026-06-18**

---

## Overall Architecture

```mermaid
flowchart TB
    subgraph Core["Core Documents"]
        SKILL[SKILL.md<br/>Entry Point]
        MEM[memory-protocol.md<br/>State Management]
        README[README.md<br/>Usage Guide]
    end

    subgraph Execution["Execution Modes"]
        SINGLE["Single Task Mode<br/>PT-{ID}/"]
        BATCH["Batch Mode<br/>BATCH-{ID}/"]
    end

    subgraph Workflow["Workflow Phases"]
        P0[Phase 0: Preflight<br/>Authorization + Fingerprint]
        P1[Phase 1: Attack-Surface<br/>Mapping]
        P2[Phase 2: Discovery<br/>Targeted Probing]
        P3[Phase 3: Validation<br/>Vulnerability Testing]
        P4[Phase 4: Chain<br/>Analysis + Report]
    end

    subgraph Resources["Resource Library"]
        CMD[commands/<br/>Capability Definitions]
        PAY[payloads/<br/>Payload Library]
        REF[private references<br/>Optional Extension]
        TMP[templates/<br/>Core + Optional]
        SCR[scripts/<br/>19 Automation Scripts]
    end

    subgraph Control["Process Control"]
        TRACK[.task-pids.json<br/>PID Registry]
        TC[task-control.sh<br/>Terminate/Monitor]
        STOP[stop-conditions.md<br/>Stop Triggers]
    end

    subgraph Output["Structured Output"]
        TASK[task.md<br/>State Entry]
        FIND[findings.md<br/>Human Authority]
        SUM[summary.json<br/>Task Summary]
        FJ[findings.json<br/>Structured List]
        EV[evidence-index.json<br/>Evidence Map]
        REP[report.md<br/>Delivery]
    end

    SKILL --> SINGLE
    SKILL --> BATCH
    MEM --> SINGLE
    MEM --> BATCH

    SINGLE --> P0
    BATCH --> P0
    P0 --> P1 --> P2 --> P3 --> P4

    CMD --> P1
    CMD --> P2
    PAY --> P3
    REF -.->|explicit user-gated depth| P3
    REF -.->|tool detail| P1
    TMP --> P0
    TMP --> P4

    P3 --> Control
    Control --> Output

    P4 --> Output
```

---

## Directory Structure

```text
authorized-appsec/
│
├── SKILL.md                      # Main entry point, workflow definition
├── memory-protocol.md            # State management, batch protocol
├── README.md                     # Usage guide, quick reference
│
├── agents/                       # External agent integration configs
│   └── openai.yaml               # OpenAI agent trigger/anti-trigger rules
├── commands/                     # Capability-first definitions
│   ├── capabilities.md           # 11 capabilities, candidate discovery
│   ├── recon.md                  # Recon workflow + OSINT methodology
│   ├── ports.md                  # Web port selection
│   ├── stack-mapping.md          # Tech stack → vulnerability class mapping
│   ├── threat-modeling.md        # STRIDE threat modeling guide
│   ├── source-code-review.md     # Source code review methodology
│   ├── brute-force.md            # Credential testing boundaries
│   ├── modern-auth.md            # OTP, slider, SSO, MFA, token lifecycle
│   └── authenticated-testing.md  # Authenticated coverage branch
│
├── payloads/                     # Vulnerability-specific payloads
│   ├── api-auth.md               # API authentication
│   ├── api-business-logic.md     # Business logic flaws
│   ├── api-cmdi.md               # API command injection
│   ├── api-config.md             # API configuration exposure
│   ├── api-data-exposure.md      # Data leakage, mass assignment
│   ├── api-graphql.md            # GraphQL security
│   ├── api-mobile.md             # Mobile API testing
│   ├── api-nosqli.md             # NoSQL injection
│   ├── api-sqli.md               # API SQL injection
│   ├── api-ssrf.md               # API SSRF
│   ├── api-xxe.md                # API XXE
│   ├── admin-panel.md            # Admin interface testing
│   ├── backup-exposure.md        # Backup/source code exposure
│   ├── cache-poisoning.md        # Web cache poisoning
│   ├── client-side-review.md     # Client-side secret/logic discovery
│   ├── cloud-security.md         # Cloud storage/metadata testing
│   ├── cors.md                   # CORS misconfiguration
│   ├── crlf-injection.md         # CRLF injection
│   ├── csrf.md                   # CSRF tokens, SameSite
│   ├── default-credentials.md     # Default credential testing
│   ├── deserialization.md        # Deserialization attacks
│   ├── dom-xss.md                # DOM-based XSS
│   ├── error-handling.md          # Error handling, information disclosure
│   ├── file-inclusion.md         # LFI/RFI
│   ├── file-read.md              # Arbitrary file read
│   ├── file-upload.md            # File upload bypass
│   ├── host-header.md            # Host header injection
│   ├── http-methods.md           # HTTP method testing
│   ├── http-smuggling.md         # HTTP request smuggling
│   ├── idor.md                   # IDOR/BOLA
│   ├── jwt.md                    # JWT attacks
│   ├── ldap-injection.md         # LDAP injection
│   ├── mfa-bypass.md             # MFA/2FA bypass
│   ├── oauth.md                  # OAuth flows
│   ├── open-redirect.md          # Open redirect
│   ├── password-policy.md         # Password policy, account lockout
│   ├── password-reset.md         # Password reset flaws
│   ├── path-traversal.md         # Path/directory traversal
│   ├── prototype-pollution.md    # Prototype pollution
│   ├── race-condition.md         # Race condition / TOCTOU
│   ├── rate-limiting.md          # Rate limit bypass
│   ├── security-headers.md       # CSP, security headers bypass
│   ├── session-management.md      # Session fixation, timeout, attributes
│   ├── soap-wsdl.md              # SOAP/WSDL web service testing
│   ├── sqli.md                   # SQL injection
│   ├── ssrf.md                   # SSRF
│   ├── ssti.md                   # Server-side template injection
│   ├── subdomain-takeover.md     # Subdomain takeover
│   ├── websocket.md              # WebSocket security
│   ├── xss.md                    # Cross-site scripting
│   └── xxe.md                    # XXE attacks
│
├── templates/                    # Output templates
│   ├── task-template.md          # Single task structure
│   ├── findings-template.md      # Finding format
│   ├── session-template.md       # Session records
│   ├── result-template.md        # Report format
│   ├── fingerprint-template.md   # Phase 0 output
│   ├── discovery-template.md     # Phase 1-2 output
│   ├── vuln-test-template.md     # Phase 3 log
│   ├── chain-template.md         # Phase 4 analysis
│   ├── severity-classification.md # Severity criteria
│   ├── structured-output-requirements.md # JSON schemas
│   ├── coverage-checklist.md     # Coverage gate before reporting
│   ├── batch-template.md         # Batch workflow (NEW)
│   ├── targets-schema.md         # targets.json schema (NEW)
│   ├── stop-conditions.md        # Stop condition definitions
│   ├── process-control.md        # Termination protocol (NEW)
│   ├── retest-template.md        # Retest verification workflow (NEW)
│   ├── rules-of-engagement.md    # Pre-engagement authorization template (NEW)
│   ├── cleanup-template.md       # Cleanup and rollback protocol (NEW)
│   ├── business-scenario-ecommerce.md    # E-commerce flow (OPTIONAL)
│   ├── business-scenario-payment.md      # Payment flow (OPTIONAL)
│   ├── business-scenario-sensitive-reporting.md # Informant/reporting workflows (OPTIONAL)
│   └── business-scenario-user-lifecycle.md # User lifecycle (OPTIONAL)
│
├── scripts/                      # Automation scripts
│   ├── discover-capabilities.sh  # VM tool discovery
│   ├── ensure_structured_outputs.py # JSON sync
│   ├── generate_report.py        # Report generation
│   ├── check-structure.sh        # Self-validation
│   ├── check-task.sh             # Running task health check
│   ├── task-control.sh           # Process termination
│   ├── init_task.py              # Single task directory initialization
│   ├── init_batch.py             # Batch directory initialization
│   ├── aggregate_batch.py        # Batch result aggregation
│   ├── generate_batch_report.py  # Batch report generation
│   ├── import_report.py          # Legacy report import
│   ├── auto_l3_hypotheses.py     # Historical hypothesis generation
│   ├── export_to_l3.py           # L3 knowledge export
│   ├── retrieve_l3.py            # L3 knowledge retrieval
│   ├── capture_evidence.py       # Evidence capture helper
│   ├── exploit_search.py         # Local exploit reference search
│   ├── cleanup.sh                # Test artifact cleanup and rollback
│   ├── smoke-test.sh             # Quick validation smoke test
│   └── build-public-package.sh   # Public release archive builder
│
└── Optional private extensions   # Not part of the public release
    ├── references/               # Private deep methodology, user-gated
    └── l3/                       # Private historical hypotheses
```

---

## Execution Mode Comparison

```mermaid
flowchart LR
    subgraph Single["Single Task Mode"]
        S1[User: Test example.com]
        S2["Create PT-{ID}/"]
        S3[Phase 0-4 Sequential]
        S4[Single Output Set]
    end

    subgraph Batch["Batch Mode"]
        B1[User: Test 3 targets]
        B2[Preflight: Confirm Authorization]
        B3["Create BATCH-{ID}/"]
        B4[targets.json Registry]
        B5[Dispatch T-001, T-002, T-003]
        B6[Execute Per Target]
        B7[Aggregate Results]
        B8[Batch Report]
    end

    S1 --> S2 --> S3 --> S4
    B1 --> B2 --> B3 --> B4 --> B5 --> B6 --> B7 --> B8
```

| Aspect | Single Task | Batch Mode |
|--------|-------------|------------|
| Entry | `SKILL.md` | `templates/batch-template.md` |
| Authorization | Per-task confirm | Unified preflight |
| Output Root | `PT-{ID}/` | `BATCH-{ID}/targets/T-{ID}/` |
| State Tracking | `task.md` | `batch.md` + `targets.json` |
| Process Control | `.task-pids.json` | Per-target `.task-pids.json` |
| Report | Single `report.md` | Batch `report.md` + per-target |

---

## Capability-First Tool Selection

```mermaid
flowchart TB
    subgraph Discovery["Runtime Discovery"]
        DC[discover-capabilities.sh]
        CAP[capabilities.json]
    end

    subgraph Capabilities["7 Capabilities"]
        C1[subdomain-discovery]
        C2[http-probing]
        C3[port-scanning]
        C4[directory-scanning]
        C5[url-extraction]
        C6[fingerprinting]
        C7[vulnerability-scanning]
    end

    subgraph Candidates["Candidate Tools per Capability"]
        C1 --> S1[subfinder, amass, findomain]
        C2 --> S2[httpx, httprobe]
        C3 --> S3[naabu, nmap, masscan]
        C4 --> S4[ffuf, dirsearch, feroxbuster]
        C5 --> S5[gau, katana, waybackurls]
        C6 --> S6[wappalyzer, whatweb]
        C7 --> S7[nuclei, nikto]
    end

    DC --> CAP
    CAP --> Capabilities

    C1 --> |Available?| S1
    C2 --> |Available?| S2
```

**Selection Rules**:
1. Discover tools inside execution VM at runtime
2. Select first available candidate per capability
3. If none available → record limitation, use manual alternative
4. Never hardcode specific tool names

---

## Process Control Architecture

```mermaid
sequenceDiagram
    participant User
    participant MainAgent
    participant TaskControl as task-control.sh
    participant PID as .task-pids.json
    participant Process as Running Tools

    User->>MainAgent: Request stop
    MainAgent->>TaskControl: terminate <task_dir>
    TaskControl->>PID: Read main_pid, tool_pids
    PID-->>TaskControl: {main: 12345, tools: [12346, 12347]}
    TaskControl->>Process: SIGTERM
    Process-->>TaskControl: Graceful shutdown
    alt Still alive after 2s
        TaskControl->>Process: SIGKILL
    end
    TaskControl->>PID: Update status=terminated
    TaskControl->>task.md: Add stop record
    TaskControl-->>MainAgent: Confirmation
    MainAgent-->>User: Task stopped
```

**Termination Flow**:
```text
1. Read .task-pids.json → Get PIDs
2. SIGTERM (graceful) → Wait 2 seconds
3. If alive → SIGKILL (force)
4. Update status in:
   - .task-pids.json (terminated)
   - task.md (stop record)
   - targets.json (batch mode)
```

---

## Stop Condition Decision Tree

```mermaid
flowchart TB
    TRIGGER[Condition Triggered]

    CRITICAL{Critical?}
    HIGH{High?}
    MEDIUM{Medium?}

    STOP[STOP Immediately<br/>Notify User]
    PAUSE[PAUSE + Notify<br/>Wait Decision]
    REQUEST[PAUSE + Request<br/>Authorization]

    CONTINUE[User: Continue]
    MODIFY[User: Modify Scope]
    TERMINATE[User: Stop]

    TRIGGER --> CRITICAL

    CRITICAL --> |Yes| STOP
    CRITICAL --> |No| HIGH

    HIGH --> |Yes| PAUSE
    HIGH --> |No| MEDIUM

    MEDIUM --> |Yes| REQUEST
    MEDIUM --> |No| CONTINUE

    PAUSE --> CONTINUE
    PAUSE --> MODIFY
    PAUSE --> TERMINATE

    REQUEST --> CONTINUE
    REQUEST --> TERMINATE

    TERMINATE --> TC[task-control.sh terminate]
```

**21 Stop Conditions by Severity**:

| Severity | Conditions |
|----------|------------|
| **Critical** (5) | critical_finding, credential_or_token_exposure, mass_data_exposure, service_crash_risk, legal_concern_detected |
| **High** (5) | out_of_scope_target, service_instability, destructive_action_required, lateral_movement_risk, internal_probing_required |
| **Medium** (10) | scope_creep_detected, rate_limit_triggered, waf_block_detected, oob_required, cloud_metadata_required, authenticated_testing_required, persistence_risk, tool_failure_critical, network_unreachable, dns_resolution_failed |
| **Low** (1) | ssl_certificate_invalid (continue with warning) |

---

## Data Flow Architecture

```mermaid
flowchart LR
    subgraph Input["Input"]
        TGT[Target URL/Domain/IP]
        AUTH[Authorization + Scope]
        INT[Intensity Level]
    end

    subgraph Processing["Processing"]
        PHASES[Phase 0-4]
        CAPS[Capability Selection]
        PAYLOADS[Payload Library]
    end

    subgraph Evidence["Evidence Chain"]
        RAW[raw/*.txt]
        SCR[screenshots/*.png]
        SESS[sessions/*.md]
    end

    subgraph Output["Output"]
        MD[*.md Files<br/>Human-readable]
        JSON[*.json Files<br/>Structured]
    end

    TGT --> PHASES
    AUTH --> PHASES
    INT --> PHASES

    CAPS --> PHASES
    PAYLOADS --> PHASES

    PHASES --> RAW
    PHASES --> SCR
    PHASES --> SESS

    RAW --> MD
    RAW --> JSON
    SCR --> EV
    SESS --> MD

    MD --> REP
    JSON --> REP
```

**Output Relationships**:

| File | Authority | Purpose |
|------|-----------|---------|
| `findings.md` | Primary | Human-readable confirmed findings |
| `findings.json` | Projection | Structured list for aggregation |
| `task.md` | Entry | Resume state, next actions |
| `summary.json` | Summary | Task-level metadata |
| `evidence-index.json` | Index | Evidence → Raw file mapping |
| `report.md` | Delivery | Final report for stakeholder |

---

## Template Dependencies

```mermaid
flowchart TB
    subgraph PhaseTemplates["Phase Templates"]
        FP[fingerprint-template.md]
        DS[discovery-template.md]
        VT[vuln-test-template.md]
        CH[chain-template.md]
    end

    subgraph CoreTemplates["Core Templates"]
        TK[task-template.md]
        FN[findings-template.md]
        SS[session-template.md]
        RS[result-template.md]
        STR[structured-output-requirements.md]
        SEV[severity-classification.md]
    end

    subgraph BatchTemplates["Batch Templates (NEW)"]
        BT[batch-template.md]
        TG[targets-schema.md]
        ST[stop-conditions.md]
        PC[process-control.md]
    end

    subgraph ScenarioTemplates["Scenario Templates (OPTIONAL)"]
        EC[business-scenario-ecommerce.md]
        PM[business-scenario-payment.md]
        UL[business-scenario-user-lifecycle.md]
    end

    PhaseTemplates --> CoreTemplates
    BatchTemplates --> PhaseTemplates
    ScenarioTemplates --> FN
    ScenarioTemplates --> VT
```

---

## Self-Check Architecture

```mermaid
flowchart TB
    subgraph Checks["7 Validation Checks"]
        D1[1/7 Directory Structure]
        D2[2/7 Core Documents]
        D3[3/7 Command References]
        D4[4/7 Scripts + Execute Permission]
        D5[5/7 Template Files]
        D6[6/7 Payload Library]
        D7[7/7 Content Consistency]
    end

    subgraph ContentChecks["Content Consistency Checks"]
        C1[OOB Authorization Marking]
        C2[Cloud Metadata Authorization]
        C3[Security Boundary Statement]
        C4[Output Path Convention]
        C5[Language Consistency]
    end

    D7 --> ContentChecks

    subgraph Result["Result"]
        PASS[✓ Structure Check Passed]
        FAIL[✗ Errors: N]
        WARN[! Warnings: N]
    end

    Checks --> |All Pass| PASS
    Checks --> |Errors| FAIL
    Checks --> |Issues| WARN
```

---

## Integration Points

```mermaid
flowchart TB
    subgraph ClaudeCode["Claude Code Integration"]
        AGENT[Main Agent]
        SUBAGENT[Sub Agents<br/>Batch Targets]
        TOOLS[TaskStop<br/>Bash<br/>Read/Write]
    end

    subgraph SkillPackage["Skill Package"]
        SKILL
        MEM
        Resources
    end

    subgraph ExecutionVM["Execution VM"]
        DISC[discover-capabilities.sh]
        TOOLS_AVAIL[Available Tools<br/>httpx, nuclei, etc.]
        CAPJSON[capabilities.json]
    end

    subgraph OutputRoot["Output Root"]
        RESULTS["$AUTHORIZED_APPSEC_RESULTS_ROOT<br/>or ~/authorized-appsec/results/"]
        PTDIR["PT-{ID}/"]
        BATCHDIR["BATCH-{ID}/"]
    end

    AGENT --> SKILL
    AGENT --> MEM

    AGENT --> |Dispatch Batch| SUBAGENT
    SUBAGENT --> PTDIR

    AGENT --> TOOLS
    TOOLS --> |Execute| DISC

    DISC --> TOOLS_AVAIL
    DISC --> CAPJSON

    AGENT --> |Write| OutputRoot
    OutputRoot --> RESULTS
    RESULTS --> PTDIR
    RESULTS --> BATCHDIR
```

---

## Summary

| Component | Count | Purpose |
|-----------|-------|---------|
| Core Documents | 3 | Entry, protocol, usage |
| Commands | 9 | Capability definitions, recon, ports, stack mapping, threat modeling, source review, brute-force, modern-auth, authenticated-testing |
| Payloads | 55 | Vulnerability-specific safe payloads |
| Private References | Not published | Optional local extension; explicitly user-gated when present |
| Core Templates | 23 | Output formatting, batch control, retest, RoE, cleanup, coverage checklist |
| Optional Templates | Current library | Business scenarios |
| Scripts | 19 | Discovery, validation, control, report, batch, L3, init, cleanup, smoke test, release packaging |
| Capabilities | 12 | Runtime tool selection |
| Stop Conditions | Current library | Unified termination triggers |
| Execution Modes | 2 | Single task, batch |

**Key Design Principles**:
1. **Capability-first**: Tools discovered at runtime, not hardcoded
2. **File-based state**: Memory protocol for context management
3. **Tiered validation**: Default safe (payloads/) in normal flow → private deep methodology only on explicit user request
4. **Evidence-driven**: Every finding backed by raw evidence
5. **Process control**: Force termination via PID tracking
6. **Self-validating**: Structure check with content consistency
7. **Layered knowledge**: Safe payloads by default → private deep methodology only when explicitly requested → L3 historical hypotheses
