# Stop Conditions

> **Purpose**: Unified stop conditions for batch and single-task penetration testing.

---

## Stop Condition Definitions

Stop conditions trigger automatic pause and user notification. Testing cannot continue without explicit user decision.

---

## Condition Types

### Scope Boundary Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `out_of_scope_target` | Target matches exclusion or falls outside scope | High | Pause immediately, log in task.md |
| `scope_creep_detected` | Discovery reveals targets outside original scope | Medium | Pause, request scope expansion approval |

### Service Impact Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `service_instability` | Target returning elevated error rates (503, timeouts) | High | Pause, notify user, wait for stability |
| `rate_limit_triggered` | Target enforcing rate limits preventing progress | Medium | Pause, consider intensity reduction |
| `waf_block_detected` | WAF blocking testing requests | Medium | Pause, consider alternative approach |
| `service_crash_risk` | Testing may cause service degradation | Critical | Stop immediately, notify user |

### Finding Severity Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `critical_finding` | Confirmed critical severity vulnerability | Critical | Pause, notify user immediately |
| `credential_or_token_exposure` | Credentials, tokens, or secrets exposed in evidence | Critical | Stop evidence collection, secure data, notify user |
| `mass_data_exposure` | >100 records or credential files accessible | Critical | Stop enumeration, notify user immediately |

### Authorization Extension Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `oob_required` | OOB validation needed for blind vulnerability confirmation | Medium | Pause, request explicit OOB authorization |
| `cloud_metadata_required` | Cloud metadata endpoint probing needed | Medium | Pause, request explicit authorization |
| `internal_probing_required` | Internal network/service probing needed | High | Pause, request explicit authorization |
| `authenticated_testing_required` | Credentials needed for further testing | Medium | Pause, request credential scope approval |

### Operational Risk Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `destructive_action_required` | Validation would cause data modification/deletion | High | Pause, request explicit authorization |
| `persistence_risk` | Testing may leave persistent artifacts | Medium | Pause, request approval |
| `lateral_movement_risk` | Testing may enable lateral movement capability | High | Pause, notify user |
| `legal_concern_detected` | Testing may violate legal boundaries | Critical | Stop immediately, notify user |

### Technical Blocker Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `tool_failure_critical` | Essential tool unavailable or failing | Medium | Pause, consider manual alternative |
| `network_unreachable` | Target network unreachable | Medium | Pause, verify connectivity |
| `ssl_certificate_invalid` | SSL certificate validation failure | Low | Continue with caution, log warning |
| `dns_resolution_failed` | DNS resolution failure for target | Medium | Pause, verify DNS |

### AI / Cloud Native Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `llm_jailbreak_overreach` | LLM testing exceeded single-proof boundary: iterated prompt extraction, bulk RAG enumeration, or multi-tool chain exploitation beyond proof-of-concept | Critical | Stop immediately, notify user, record exact scope of LLM interaction |
| `k8s_admin_compromise` | Unauthenticated K8s API access, etcd read, or cluster-admin equivalent confirmed | Critical | Stop immediately, notify user — full cluster compromise confirmed |
| `origin_ip_disclosed_publicly` | Origin IP discovered via public sources (CT logs, DNS history, space engines) and confirmed accessible | High | Pause, notify user — origin bypasses CDN/WAF protection |
| `vector_db_mass_access` | RAG/vector database query returns >100 records or production PII/credentials | Critical | Stop enumeration, notify user, secure evidence |
| `llm_tool_execution_confirmed` | LLM successfully called unauthorized tool/API (file read, command exec, data query) | High | Pause, record exact tool call and response, notify user |

### Compliance Conditions

| Condition | Trigger | Severity | Action |
|-----------|---------|----------|--------|
| `pipl_data_cross_border` | Testing reveals user data flowing to overseas AI model/API without PIPL compliance (PIPL §38-43) | Critical | Stop immediately, flag for legal review |
| `cnvd_target_in_scope` | Target is classified as critical information infrastructure (CIIP) per China Cybersecurity Law / CIIP Regulation | Critical | Stop, verify authorization includes CIIP testing permission |
| `scope_ip_mismatch` | Source IP differs from authorized IP in engagement letter | High | Pause, verify IP binding with engagement terms |
| `llm_cost_budget_exceeded` | LLM API token cost exceeds budget defined in task.md (default: $10) | Medium | Pause LLM testing, notify user with cost summary, request budget increase or stop |

**llm_cost_budget_exceeded** measurement: capture_evidence.py records token counts per evidence entry. task-control.sh aggregates and compares against budget. Default budget is $10 unless overridden in task.md `## Budget → llm_cost_max_usd: <value>`.

---

## Condition Severity and Response

### Critical Conditions (Stop Immediately)

| Condition | Required Response |
|-----------|-------------------|
| `critical_finding` | Notify user, wait for decision before any further testing |
| `credential_or_token_exposure` | Secure evidence, limit access, notify user |
| `mass_data_exposure` | Stop enumeration, notify user, secure evidence |
| `service_crash_risk` | Stop testing, notify user, document impact |
| `legal_concern_detected` | Stop testing, notify user, document concern |

**Response Protocol**:
```
1. Stop current activity immediately
2. Do not continue to next phase
3. Update task.md / targets.json with stop_triggered
4. Generate immediate notification to user
5. Wait for explicit user decision
```

### High Conditions (Pause and Notify)

| Condition | Required Response |
|-----------|-------------------|
| `out_of_scope_target` | Pause, document scope violation, request decision |
| `service_instability` | Pause, wait for stability, notify user |
| `destructive_action_required` | Pause, request explicit authorization |
| `lateral_movement_risk` | Pause, notify user, request decision |
| `internal_probing_required` | Pause, request explicit authorization |

**Response Protocol**:
```
1. Pause current activity
2. Document condition in task.md / targets.json
3. Notify user with condition details
4. Wait for user decision (continue, modify scope, stop)
```

### Medium Conditions (Pause and Request Authorization)

| Condition | Required Response |
|-----------|-------------------|
| `scope_creep_detected` | Pause, request scope expansion approval |
| `rate_limit_triggered` | Pause, consider intensity reduction or alternative approach |
| `waf_block_detected` | Pause, consider alternative testing method |
| `oob_required` | Pause, request explicit OOB authorization |
| `cloud_metadata_required` | Pause, request explicit authorization |
| `authenticated_testing_required` | Pause, request credential scope approval |
| `persistence_risk` | Pause, request approval |
| `tool_failure_critical` | Pause, consider manual alternative |
| `network_unreachable` | Pause, verify connectivity |
| `dns_resolution_failed` | Pause, verify DNS |

**Response Protocol**:
```
1. Pause current activity
2. Document condition
3. Request specific authorization or alternative approach
4. Wait for user response
```

### Low Conditions (Continue with Caution)

| Condition | Required Response |
|-----------|-------------------|
| `ssl_certificate_invalid` | Continue, log warning, note in report |

**Response Protocol**:
```
1. Log warning in phase file
2. Continue testing
3. Note condition in report
```

---

## Stop Condition Detection

### Automatic Detection

| Condition | Detection Method |
|-----------|------------------|
| `out_of_scope_target` | Pattern match against scope/excluded rules |
| `service_instability` | Monitor HTTP status codes (>10% 503/timeout) |
| `rate_limit_triggered` | HTTP 429 responses, throttling detected |
| `waf_block_detected` | WAF-specific responses, blocked patterns |
| `credential_or_token_exposure` | Pattern match in responses (password, token, key) |
| `mass_data_exposure` | Response contains >100 records or credential patterns |

### Manual Detection

| Condition | Detection Method |
|-----------|------------------|
| `critical_finding` | Analyst confirms critical severity vulnerability |
| `oob_required` | Analyst identifies blind vulnerability needing OOB |
| `cloud_metadata_required` | Analyst identifies cloud metadata probing opportunity |
| `internal_probing_required` | Analyst identifies internal network probing opportunity |
| `destructive_action_required` | Analyst identifies validation causing data change |
| `legal_concern_detected` | Analyst identifies potential legal boundary violation |

---

## User Decision Options

When stop condition triggered, user can choose:

| Decision | Action |
|----------|--------|
| `continue` | Resume testing with original scope/intensity |
| `continue_modified` | Resume with modified parameters (e.g., reduced intensity) |
| `pause` | Keep paused, await later decision |
| `stop` | End testing for this target |
| `expand_scope` | Expand scope to include new target (requires explicit definition) |
| `authorize_capability` | Authorize blocked capability for specific use |

---

## Documentation Format

### In targets.json

```json
{
  "targets": [
    {
      "target_id": "T-001",
      "stop_triggered": "service_instability",
      "stop_details": "Target returning 503 errors on 40% of requests after 2 minutes of testing",
      "stop_at": "2026-05-03T11:00:00Z"
    }
  ],
  "stop_triggered": [
    {
      "target_id": "T-001",
      "condition": "service_instability",
      "details": "503 errors at 40% rate",
      "action_taken": "Paused, user notified",
      "user_decision": null
    }
  ]
}
```

### In task.md

```markdown
## Stop Condition

- triggered_at: 2026-05-03T11:00:00Z
- condition: service_instability
- details: Target returning 503 errors on 40% of requests
- action: Paused, awaiting user decision
- user_decision: [pending]
```

### In batch.md

```markdown
## Stop Conditions

- triggered:
  - T-001: service_instability (503 errors, paused)
  - T-003: out_of_scope_target (matched exclusion, skipped)
- total_paused: 1
- total_skipped: 1
```

---

## Resume After Stop

### Resume Conditions

| Original Condition | Resume Requirements |
|--------------------|---------------------|
| `service_instability` | Service stable, or intensity reduced |
| `rate_limit_triggered` | Rate limit window passed, or approach modified |
| `oob_required` | User authorized OOB with explicit scope |
| `cloud_metadata_required` | User authorized cloud metadata probing |
| `authenticated_testing_required` | Credentials provided with scope definition |
| `out_of_scope_target` | Scope expanded to include target, or target skipped |

### Resume Process

```markdown
Resume after stop:
1. Verify user decision is "continue" or "continue_modified"
2. Update targets.json with user_decision
3. Update task.md with resume parameters
4. Continue from last phase/step
5. Log resume decision in phase file
```

---

## Batch-Level Stop Handling

### Single Target Stop

When one target triggers stop condition:

| Action | Description |
|--------|-------------|
| Pause that target | Update target status to `paused` |
| Continue others | Other targets continue testing |
| Notify user | Report stop condition for specific target |
| Wait for decision | User decides on paused target only |

### Batch-Level Stop

When condition affects entire batch:

| Condition | Batch Action |
|-----------|--------------|
| `legal_concern_detected` | Stop all targets |
| `scope_boundary_violation_batch` | Stop all targets, redefine scope |
| `service_instability_batch` | Pause all targets targeting affected host |

---

## Prevention Guidelines

### Before Testing

```markdown
1. Confirm scope and exclusions explicitly
2. Identify blocked capabilities
3. Define intensity level
4. Set rate expectations
5. Establish stop condition thresholds
```

### During Testing

```markdown
1. Monitor error rates continuously
2. Check scope before each new endpoint
3. Validate findings before marking severity
4. Secure sensitive evidence immediately
5. Document all conditions in task.md
```

---

## Related Templates

| Template | Purpose |
|----------|---------|
| `templates/batch-template.md` | Batch workflow and stop handling |
| `templates/targets-schema.md` | targets.json stop_triggered field |
| `templates/task-template.md` | Single-task stop documentation |