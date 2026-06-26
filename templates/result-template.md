# Authorized AppSec Assessment Report Template

> This template defines the fixed delivery structure for `report.md`.
> 
> **Core Principles**:
> - `report.md` is an aggregation view, not the primary data source
> - `findings.md` is the authority for vulnerability details (human-readable)
> - `findings.json` is the structured projection of vulnerability list (machine-readable)
> - `summary.json` is the structured projection of task-level summary
> 
> **Overall Aggregation Order**:
> 1. `summary.json` → Task overview, boundaries, conclusions, recommendations
> 2. `findings.json` → Vulnerability summary table, statistics
> 3. `findings.md` → Vulnerability details body
> 4. `evidence-index.json` → Evidence index
> 5. Phase files → Fingerprint, environment, high-value path summary
> 
> **Field-level Authority Source**:
> | Field | Authority Source |
> |------|--------|
> | Vulnerability detail description, reproduction steps, remediation | `findings.md` |
> | Vulnerability list, severity, status, evidence references | `findings.json` (consistent with findings.md) |
> | Task boundaries, tech stack, statistics, recommendations | `summary.json` |
> | Evidence paths, summary | `evidence-index.json` |
> 
> **Prohibited**:
> - Do not copy working notes, full raw responses, complete session materials into final report
> - Do include the minimal sanitized PoC needed to reproduce each confirmed finding

---

## Generation Rules

When generating `report.md`, aggregate in this fixed order:

1. Read `summary.json` to generate task overview, boundary statement, task conclusions, next recommendations
2. Read `findings.json` to generate vulnerability summary table and statistics
3. Read `findings.md` to generate vulnerability details body
4. Read `evidence-index.json` to generate evidence index
5. Read `01-fingerprint.md` to generate target fingerprint and environment info
6. When necessary, read `02-discovery.md` and `04-chain.md`, only extract high-value discovery paths or potential impact summary
7. **Fill `templates/coverage-checklist.md` against the task's actual testing, then generate the "Test Coverage & Gaps" section (Section 8) from its `degraded` + `not-covered` rows. A task is not report-ready until the checklist is complete and gaps are reflected here.**

Prohibited:

- Copy complete raw HTTP response full text
- Copy complete payload attempt history
- Copy script source code, complete cookies, tokens, keys
- Write unconfirmed candidates as confirmed vulnerabilities
- Copy batch dictionary scan results verbatim into report body

Required:

- Include a short **PoC** block for each confirmed finding when safe.
- If a live PoC is unsafe, include the blocked PoC boundary and a safe validation outline.
- Keep the complete sanitized request/response or PoC artifact in `raw/` and link it from `evidence-index.json`.

---

## report.md Fixed Structure

> **Language**: The customer report is in Chinese (中文). Section titles, table
> headers, severity labels, and field names are Chinese; internal data fields
> in JSON stay English. Internal `F-XXX` finding IDs are rendered as
> customer-facing `V-XX` (severity-descending), with F-XXX kept as a small
> note for traceability.

> **Evidence**: Each confirmed finding embeds the full request/response
> evidence block (curl + HTTP/JSON) inline, redacted by `redact_response`
> (session keys / tokens / 32+ hex masked to `***REDACTED***`). This is a
> deliberate departure from the older "evidence stays only in raw/" rule — the
> customer report must be self-contained and persuasive. Raw artifacts still
> persist in `raw/` and `evidence-index.json` for audit.

```markdown
# 渗透测试报告

**PT编号** / **目标** / **测试时间** / **测试范围** / **授权状态** / **测试方法**

## 一、漏洞汇总              ← V-XX编号 + 中文等级 + CVSS估分 + 状态
## 二、被测系统资产画像        ← 2.1-2.8 八子节(基本信息/技术栈/部署/认证/组件/模块/数据流/外连)
## 三、漏洞详情              ← V-XX + 完整证据块(脱敏) + 清理状态/影响/修复
## 四、测试过程              ← coverage-checklist 逐项(已覆盖/受限/未覆盖)
## 五、攻击链               ← 04-chain.md 的 AP-XXX 链(F-XXX→V-XX映射)
## 六、安全加固建议           ← 高优先级(14天)/中优先级(30天)/持续改进
## 附录 A: API端点统计       ← 02-discovery.md 端点计数
## 附录 B: WAF行为分析       ← 01-fingerprint.md WAF段
## 附录 C: 测试限制说明       ← summary.json report_meta.test_limitations
## 附录 D: 安全测试标准参考   ← severity-classification.md 定级表
```

---

## 1. Task Overview

Source: `summary.json`

```markdown
## 1. Task Overview

| Item | Content |
|------|------|
| Task ID | {summary.task_id} |
| Target | {summary.target} |
| Target Type | {summary.target_type} |
| Tech Stack | {summary.tech_stack.join(', ')} |
| Current Status | {summary.phase_status} |
| Completed Phase | {summary.current_phase} |

### Task Conclusion

{summary.risk_summary or brief conclusion aggregated from major_findings}
```

---

## 2. Test Boundaries

Source: `summary.json.boundary_summary`

```markdown
## 2. Test Boundaries

> {summary.boundary_summary}
```

If `boundary_summary` is an array, display as short list.

---

## 3. Key Findings Summary

Source: `findings.json`

```markdown
## 3. Key Findings Summary

### 3.1 Vulnerability Summary Table

| Finding ID | Title | Type | Severity | Priority | Status |
|------------|------|------|--------|--------|------|
| {finding.finding_id} | {finding.title} | {finding.category} | {finding.severity} | {finding.priority} | {finding.status} |

### 3.2 Vulnerability Statistics

- Critical: {count}
- High: {count}
- Medium: {count}
- Low: {count}
- Info: {count}
```

For batch tasks, this section can be replaced with:

- `Confirmed Findings`
- `High-value Candidate Targets`
- `Blocked by Protection Targets`

But must still retain statistics and status distinction.

---

## 4. Vulnerability Details

Source: `findings.md`

Rules:

- Directly reuse confirmed vulnerability entries from `findings.md`
- Only retain delivery-required fields: title, affected location, description, key evidence, validation boundary, remediation
- If `findings.md` contains excessive process testing content, compress to summary in `report.md`, do not copy verbatim

Recommended format:

```markdown
## 4. Vulnerability Details

### F-001 — SQL Injection (Numeric, Arithmetic Operation Bypass)

| Item | Content |
|------|------|
| Severity | High |
| Status | confirmed |
| Affected Location | GET /news.asp?classid= |
| Source Phase | phase_3 |

**Vulnerability Description**

{Based on findings.md description body}

**Key Evidence Summary**

- Evidence 1
- Evidence 2
- Evidence 3

**PoC**

```http
GET /api/v1/example?id=%27 HTTP/1.1
Host: example.com
```

Expected observation: {short behavioral difference, status, or error marker}

**Validation Boundary**

{Extracted from findings.json.boundary or findings.md}

**Remediation**

1. ...
2. ...

**Evidence References**: E-001, E-002
```

Do not copy in this section:

- Full payload sequence
- Full raw response HTML
- Step-by-step fuzz history
- Secrets, cookies, bearer tokens, or real user identifiers

These should be retained in `03-vuln-test.md` and `raw/`.

---

## 5. Target Fingerprint & Environment

Primary Source: `01-fingerprint.md`

Optional Supplementary Source: `summary.json`

```markdown
## 5. Target Fingerprint & Environment

### 5.1 Basic Environment

| Item | Value |
|------|-----|
| Web Server | ... |
| Backend Language/Framework | ... |
| Database | ... |
| WAF/CDN | ... |

### 5.2 Attack Surface Summary

- Entry Points:
- Key Parameters:
- Identified Protections:
```

For batch tasks, this section can be changed to:

- `Target Tech Stack Statistics`
- `Protection System Statistics`
- `Confirmed Backend/Entry Distribution`

---

## 6. Evidence Index

Source: `evidence-index.json`

```markdown
## 6. Evidence Index

| Evidence ID | Type | Source Tool | Target | Summary | Raw Path |
|-------------|------|----------|------|------|----------|
| E-001 | http_response | curl | /api/user?id=1 | SQL error echo | raw/http-responses.txt |
| E-002 | screenshot | manual | /api/user?id=1 | Error page screenshot | screenshots/error-001.png |
```

Requirements:

- Only list summary and raw path
- Do not copy raw evidence full text
- Path must be traceable

---

## 7. Remediation Priority & Next Recommendations

Source: `summary.json.next_recommendations`, reference `findings.json` when necessary

Organization:

1. First list `Critical/High` related recommendations
2. Then list `Medium/Low` related recommendations
3. Finally list general governance recommendations

```markdown
## 7. Remediation Priority & Next Recommendations

### P0 / High Priority

1. ...
2. ...

### P1 / Medium Priority

1. ...

### General Recommendations

1. ...
```

---

## 8. Test Coverage & Gaps

Source: `templates/coverage-checklist.md` filled against this task's actual testing.

> This section is what makes untested surface visible. It is generated from the checklist's `degraded` + `not-covered` rows. Do **not** omit it even if coverage is complete — write "all in-scope surfaces covered" explicitly. Silent omission is the failure mode this section exists to prevent.

```markdown
## 8. Test Coverage & Gaps

### Coverage Summary

| Category | covered | degraded | not-covered | out-of-scope |
|----------|---------|----------|-------------|--------------|
| Discovery | {n} | {n} | {n} | {n} |
| Unauthenticated | {n} | {n} | {n} | {n} |
| Authenticated | {n} | {n} | {n} | {n} |
| API-specific | {n} | {n} | {n} | {n} |
| Infrastructure | {n} | {n} | {n} | {n} |

### Gaps (degraded / not-covered, with reason)

| Surface | Status | Reason | Impact on Conclusion |
|---------|--------|--------|----------------------|
| {Horizontal privilege escalation} | degraded | {only 1 account supplied} | {IDOR/BOLA may exist but unverified} |
| {Directory brute-force} | not-covered | {not approved in preflight} | {hidden paths not enumerated} |

### Statement

{One line: what was tested, what was consciously not tested, and the resulting confidence boundary of this report's conclusions.}
```

---

## Appendix (Optional)

Only append following content when necessary:

- High-value discovery path summary (from `02-discovery.md`)
- Vulnerability chain potential impact summary (from `04-chain.md`)
- Testing tool list

Do not put in appendix:

- Full scan path dictionary
- Full candidate backend paths
- Complete raw request/response
- Session keys, cookies, tokens
- Working script source code

---

## Report Generation Checklist

- [ ] `summary.json` exists and fields complete
- [ ] `findings.json` consistent with `findings.md`
- [ ] `evidence-index.json` reference paths traceable
- [ ] `report.md` generated with fixed 7-section structure
- [ ] `boundary_summary` written into report
- [ ] No unconfirmed candidates written as confirmed vulnerabilities
- [ ] No raw sensitive materials copied into final report body
