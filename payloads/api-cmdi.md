# API Command Injection Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify API command injection vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual execution of malicious commands is prohibited
> - Command injection payloads are for understanding attack surface only, **no actual exploitation**
> - Validation proves vulnerability existence via time delay, **no system control obtained**
> - OOB exfiltration requires additional user authorization; not a default validation method
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: API scenarios often involve blind injection. Use time-based validation (`sleep 5`) by default. OOB methods require additional authorization.**

---

## Validation Objectives (Within Security Boundary)

API command injection validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Injection Point Confirmation | ✓ Time delay (`sleep 5`) | - | Reverse shell |
| Existence Confirmation | ✓ Time-based blind only | - | OOB exfiltration (requires auth) |
| Severity Inference | ✓ Based on injection context | - | Execute privilege commands |
| OOB Exfiltration | ❌ Not by default | ✓ Requires explicit authorization | Exfiltrate system data |

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Time-based existence proof | No authorization needed |
| **Tier 2: Authorized Extended** | OOB callback, extended tests | User explicit authorization required |
| **Tier 3: Theory Reference** | Exploitation concepts | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming injection exists via time delay.

---

## Safe Validation Payload

### Time-based Blind Injection (Only Recommended Validation Method)
```bash
# JSON Body
{"target": "127.0.0.1; sleep 5"}
{"ip": "127.0.0.1 && ping -c 5 127.0.0.1"}

# URL parameters
GET /api/ping?host=127.0.0.1;sleep%205
GET /api/export?file=test;sleep%205

# Security boundary: Only observe response time, no other commands
```

### ⚠️ OOB Exfiltration (nslookup/curl/wget actually execute commands, conflicts with total rules)

OOB exfiltration payloads like `nslookup`, `curl`, `wget` essentially trigger command execution,
conflicting with SKILL.md total rule "command execution ❌ do not execute, only provide command".

**Current Stance**: OOB exfiltration **not recommended as default validation step**.

If OOB needed within specific authorization scope:
1. User explicitly authorizes OOB exfiltration
2. Exfiltration target only controlled marker domain (Collaborator/DNSLog)
3. No system data exfiltration
4. Mark "OOB validation executed with user authorization" in report

**Default Validation Method**: Only use time-based blind injection (`sleep 5`), no OOB.

---

## Injection Point Types (For Identifying Attack Surface)

### JSON Body Injection Positions
```json
{"filename": "test"}         -> {"filename": "test; sleep 5"}
{"cmd": "ping 127.0.0.1"}    -> {"cmd": "ping 127.0.0.1; sleep 5"}
{"ip": "127.0.0.1"}          -> {"ip": "127.0.0.1 | sleep 5"}
{"file": "report.pdf"}       -> {"file": "report.pdf; sleep 5"}
```

### REST Parameter Injection Positions
```http
GET /api/ping?host=127.0.0.1              -> ?host=127.0.0.1;sleep%205
GET /api/convert?file=test.pdf            -> ?file=test.pdf;sleep%205
GET /api/tools/ping/127.0.0.1             -> /127.0.0.1;sleep%205
POST /api/export {"format": "csv"}        -> {"format": "csv; sleep 5"}
```

---

## Command Connectors (Technical Principle)

| Connector | Encoding | Description |
|--------|------|------|
| `;` | `%3b` | Sequential execution |
| `&&` | `%26%26` | Execute after if preceding succeeds |
| `||` | `%7c%7c` | Execute after if preceding fails |
| `|` | `%7c` | Pipeline |
| `` `cmd` `` | `%60cmd%60` | Inline execution |
| `$(cmd)` | `%24%28cmd%29` | Inline execution |
| `\n` | `%0a` | Newline execution |

---

## Common API Risk Scenarios

| Scenario | Risk Point | Injection Position |
|------|--------|----------|
| Ping/Traceroute API | System command call | host parameter |
| Export function | Filename concatenation | filename parameter |
| Image processing | ImageMagick command | image path |
| Webhook test | URL concatenation | URL parameter |
| Report generation | Template rendering | template parameter |

---

## Analysis Process

1. Identify API functions that may call system commands
2. Construct time delay payload (`sleep 5`)
3. Observe API response time (>5 seconds confirms injection)
4. **Stop validation, no further exploitation**
5. If OOB exfiltration needed, must obtain user additional authorization first

---

## Output Format

```markdown
## Vulnerability: API Command Injection

### Location
{URL} - {parameter name}

### Injection Type
{time-based blind injection}

### Proof Payload
{"target": "127.0.0.1; sleep 5"}

### Validation Result
- Response time: {X seconds} (>5 seconds confirms injection)
- OOB confirmation: {Only filled when user explicitly authorizes OOB; mark "OOB executed with user authorization"}

### Risk Level
{Critical/High}
```

**Note**: OOB exfiltration field only filled when user explicitly authorizes, default validation only uses time-based blind injection.

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Reverse shell | `bash -i`, `nc -e` strictly prohibited |
| ❌ Execute whoami/id | Only use time delay for proof |
| ❌ File read/write | `cat /etc/passwd`, `ls` prohibited |
| ❌ System modification | Any create/delete/update operations prohibited |
| ❌ Fork bomb | DoS payloads prohibited |
| ❌ OOB without authorization | OOB methods require explicit user authorization before use |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Command execution prohibited"
- `README.md` -> Prohibited execution checklist