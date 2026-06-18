# HTTP Methods Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify HTTP method misconfiguration vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual data modification prohibited
> - HTTP method testing is for understanding attack surface only, **no unauthorized resource modification**
> - Validation proves vulnerability existence (dangerous methods enabled), **no data alteration or deletion**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Testing Guide, PayloadAllTheThings

## Manual Testing

**Note: Test HTTP methods on non-critical endpoints first, maximum 8 method tests per endpoint**

---

## Validation Objectives (Within Security Boundary)

HTTP methods vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| OPTIONS Method | ✓ Identify allowed methods | - | Exploit discovered methods |
| PUT Method | **Not tested by default**(see Dangerous Method Testing Gate below) | ✓ Only testable when user explicitly authorizes create/update/delete testing | Upload web shells |
| DELETE Method | **Not tested by default**(destructive, deletion operation) | ✓ Only testable when user explicitly authorizes create/update/delete testing | Delete actual resources |
| PATCH Method | **Not tested by default** | ✓ Only testable when user explicitly authorizes create/update/delete testing | Modify actual data |
| MOVE / COPY (WebDAV) | **Not tested by default** | ✓ Only testable when user explicitly authorizes create/update/delete testing | moves/copies real resources |
| TRACE/XST | ✓ Test for trace enabled | - | Cookie theft via XST |
| Method Override | ✓ Test override headers (OPTIONS/HEAD-level identification only, no actual create/update/delete sent) | - | Bypass access controls in production |

**Safe Validation Method**: By default only use OPTIONS to identify allowed methods, **Do not actively send PUT/DELETE/PATCH/MOVE/COPY actual requests**. whether these methods are allowed can be inferred from the OPTIONS `Allow` header, no need to send real destructive requests. 

**⚠️ Dangerous method testing gate (PUT/DELETE/PATCH/MOVE/COPY)**:

- **Web applications**:Not tested by defaultthese five methods. Even if OPTIONS shows allowed, do not actively send create/update/delete requests. Only when**explicit user authorization to test create/update/delete operations**then, test only on test endpoints with test data, Clean up afterwards. 
- **OSS / object storage** (Alibaba OSS, AWS S3, etc.):PUT **testable** - write test objects to isolated bucket (for example `pentest-{random}-test.txt`), low-destructive, cleanup-able operation. Delete test objects after testing. DELETE Still requires authorization (avoid deleting bucket objects). 
- **Passive discovery**:if the OPTIONS response shows these methods are allowed, Can be recorded as finding, assign Low/Medium and mark "only observed method allowed, not actively tested". 

---

## OPTIONS Method Testing

### Identify Allowed Methods

```bash
# Check allowed methods via OPTIONS
curl -s -X OPTIONS "https://target.com/api/endpoint" -I | grep -i "allow"

# Check allowed methods via response headers
curl -s -X OPTIONS "https://target.com/" -I

# Common dangerous methods to look for
# PUT, DELETE, PATCH, TRACE, CONNECT
```

### Method Enumeration

```bash
# Test each HTTP method individually
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "https://target.com/api/endpoint" 2>/dev/null)
  echo "[$method] -> $status"
done
```

---

## PUT Method Testing

> **Not tested by default.** The following commands only execute with explicit user authorization to test create/update/delete operations on Web applications, or when the target is OSS/object storage where PUT testing is allowed. Without authorization, infer whether PUT is allowed from OPTIONS only and do not actually send PUT requests.

### Test PUT Functionality

```bash
# Test if PUT is accepted (use harmless content only)
curl -s -o /dev/null -w "%{http_code}" -X PUT "https://target.com/api/test_endpoint" \
  -H "Content-Type: application/json" \
  -d '{"test": "harmless_probe"}'

# Check if PUT creates content (dangerous - requires authorization)
# Only test on non-critical endpoints
curl -s -o /dev/null -w "%{http_code}" -X PUT "https://target.com/api/test_probe_file.txt" \
  -H "Content-Type: text/plain" \
  -d "test_probe_harmless_content"

# Verify creation
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/test_probe_file.txt"

# Clean up: Delete test file if PUT succeeded
curl -s -X DELETE "https://target.com/api/test_probe_file.txt"
```

### ⚠️ PUT File Upload (Requires Authorization)

**Authorization Requirements**:
1. User explicitly authorizes PUT upload testing
2. Only on designated test endpoints
3. Immediately delete any uploaded content
4. Mark "PUT upload tested with user authorization" in report

```bash
# ⚠️ Requires explicit authorization
# Test PUT upload capability on safe endpoint only
curl -s -X PUT "https://target.com/api/upload_test_harmless.txt" \
  -H "Content-Type: text/plain" \
  -d "test_upload_content_harmless_marker"
```

---

## DELETE Method Testing

> **Not tested by default (destructive). ** Deletion may accidentally remove real resources even on test endpoints. execute only with explicit authorization to test create/update/delete, and only use specially created test resources or nonexistent resources (expect 404/405). OSS scenario DELETE still requires authorization. 

### Test DELETE Capability

```bash
# Test if DELETE is accepted (on test resources only)
curl -s -o /dev/null -w "%{http_code}" -X DELETE "https://target.com/api/test_endpoint"

# ⚠️ NEVER delete actual production resources
# Only test DELETE method response code on:
# - Non-existent resources (should return 404 or 405)
# - Test resources created specifically for this purpose

# Test DELETE on non-existent resource (safe)
curl -s -o /dev/null -w "%{http_code}" -X DELETE "https://target.com/api/nonexistent_test_resource_12345"
```

---

## TRACE / XST Testing

### TRACE Method Test

```bash
# Test if TRACE is enabled
curl -s -X TRACE "https://target.com/" -I

# If TRACE returns input: XST vulnerability
curl -s -X TRACE "https://target.com/" -H "X-Test: trace_test_marker"

# Check if custom header is reflected in response
curl -s -X TRACE "https://target.com/" -H "X-Custom-Header: test_value" | grep -i "X-Custom-Header"

# TRACE enables Cross-Site Tracing (XST) - allows cookie theft via XSS
# If enabled: moderate risk (can steal HttpOnly cookies via XSS+XST)
```

### XST Risk Assessment

| Response | Risk | Description |
|----------|------|-------------|
| 200 + reflected | Medium | TRACE enabled, XST possible with XSS |
| 200 + no reflection | Low | TRACE enabled but not exploitable |
| 405 Method Not Allowed | None | TRACE disabled |
| 501 Not Implemented | None | TRACE not supported |

---

## PATCH Method Testing

> **Not tested by default. ** execute only with explicit authorization to test create/update/delete, Test with test data on test endpoints. 

```bash
# Test if PATCH is accepted
curl -s -o /dev/null -w "%{http_code}" -X PATCH "https://target.com/api/test_endpoint" \
  -H "Content-Type: application/json" \
  -d '{"test_field": "patch_test_value"}'

# Test PATCH with If-Match header (ETag-based)
curl -s -o /dev/null -w "%{http_code}" -X PATCH "https://target.com/api/test_endpoint" \
  -H "Content-Type: application/json" \
  -H "If-Match: *" \
  -d '{"test_field": "patch_test_value"}'
```

---

## HTTP Method Override

### X-HTTP-Method-Override

```bash
# Test method override headers
# Some APIs/Middleware accept override via headers
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint" \
  -H "X-HTTP-Method-Override: PUT" \
  -H "Content-Type: application/json" \
  -d '{"test": "override_test"}'

curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint" \
  -H "X-HTTP-Method-Override: DELETE"

curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint" \
  -H "X-HTTP-Method-Override: PATCH" \
  -H "Content-Type: application/json" \
  -d '{"test": "override_test"}'

# X-Method-Override (alternative header)
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint" \
  -H "X-Method-Override: DELETE"

# X-HTTP-Method (another alternative)
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint" \
  -H "X-HTTP-Method: PUT"
```

### Method Override via Query Parameter

```bash
# Some frameworks accept method override via query parameter
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint?_method=DELETE"
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint?_method=PUT"
curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/endpoint?_method=PATCH"
```

---

## HEAD Bypass

### HEAD Method Testing

```bash
# Test if HEAD bypasses authentication or authorization
# Compare HEAD response with GET response

# Authenticated GET
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/protected" -H "Cookie: session=authenticated"

# Compare with HEAD
curl -s -o /dev/null -w "%{http_code}" -X HEAD "https://target.com/api/protected"

# If HEAD returns 200 but GET returns 401: HEAD bypass possible
# Some implementations skip auth for HEAD requests
```

### HEAD for Information Leakage

```bash
# Use HEAD to enumerate resources without downloading body
for path in "admin" "dashboard" "api/users" "api/admin" "config" "internal"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X HEAD "https://target.com/${path}" 2>/dev/null)
  echo "[$status] /${path}"
done
```

---

## Method Tampering

### Case-Based Method Tampering

```bash
# Some servers normalize method case
curl -s -o /dev/null -w "%{http_code}" -X "get" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "Get" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "put" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "Put" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "delete" "https://target.com/api/endpoint"
```

### Arbitrary Method Testing

> The following MOVE/COPY/LOCK WebDAV methods belong to create/update/delete category, **Not tested by default**, requires user authorization. Other exploratory methods (PROPFIND/MKCOL etc. only identify whether support exists)Can be inferred from OPTIONS. 

```bash
# Test with arbitrary/custom methods
curl -s -o /dev/null -w "%{http_code}" -X "JEFF" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "PROPFIND" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "PROPPATCH" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "MKCOL" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "COPY" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "MOVE" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "LOCK" "https://target.com/api/endpoint"
curl -s -o /dev/null -w "%{http_code}" -X "UNLOCK" "https://target.com/api/endpoint"
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A01:2021-Broken Access Control |
| CWE | CWE-650: Trusting HTTP Permission Input on the Server Side |
| CWE | CWE-284: Improper Access Control |

---

## Analysis Process

1. Send OPTIONS request to identify allowed methods
2. Test each potentially dangerous method (PUT, DELETE, PATCH)
3. Test method override headers (X-HTTP-Method-Override, X-Method-Override)
4. Test TRACE/XST for header reflection
5. Test HEAD bypass against authentication
6. Test case sensitivity and method tampering
7. Document methods enabled and their risk level
8. **Stop validation**, report findings without exploiting dangerous methods

---

## Output

```markdown
## Vulnerability: HTTP Method Misconfiguration

### Location
{URL} - {endpoint}

### Allowed Methods
{List of allowed methods from OPTIONS response}

### Dangerous Methods Enabled
{PUT / DELETE / PATCH / TRACE / CONNECT}

### Method Override
{Which override headers work: X-HTTP-Method-Override, X-Method-Override, etc.}

### Validation Result
- OPTIONS response: {methods listed}
- PUT enabled: {yes/no}
- DELETE enabled: {yes/no}
- TRACE enabled: {yes/no}
- Method override works: {yes/no, which headers}
- HEAD bypasses auth: {yes/no}

### Risk Level
{see severity rules}

### Severity Classification

HTTP method abuse severity is based on **whether dangerous method actually works**, and create/update/delete methods are not actively tested by default (PUT/DELETE/PATCH/MOVE/COPY). Dangerous method "allowed" != "exploitable" — escalate only if it actually works and has impact.

| Actual case | Severity | Note |
|---------|------|------|
| OPTIONS only shows dangerous method is allowed, not actively tested | Low | passive observation, capability not confirmed, Mark "not actively tested" |
| After user-authorized testing, confirmed PUT/DELETE/PATCH/MOVE/COPY actually works and affects business resources | Medium/High | Based on impact: can delete data/write webshell = High; can modify test data = Medium |
| OSS PUT test succeeds (unauthorized bucket write) | Medium/High | depends on writable content, webshell execution = High |
| TRACE enabled with reflection (XST possible) | Medium | requires XSS prerequisite to exploit |
| TRACE enabled without reflection | Low | Not exploitable |
| HEAD bypasses auth | Medium | capability confirmed, adjust by reachable data sensitivity |
| Method override header can bypass auth (identification only, no actual privilege escalation) | Low | Mark pending confirmation |

**Boundary coordination**: This file prohibits actively testing create/update/delete methods by default. "Dangerous method actually works = Medium/High" requires **explicit user authorization to test create/update/delete** (Tier 2); record only after confirming effectiveness within the authorized scope. Without authorization, even if OPTIONS shows it is allowed, record Low and mark "not actively tested".
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Upload web shells | PUT only for harmless test content with authorization |
| ❌ Delete production resources | DELETE only on test/non-existent resources |
| ❌ Modify actual data | PATCH only on test resources with authorization |
| ❌ Exploit XST for cookie theft | Only document TRACE enabled, do not exploit |
| ❌ Bypass auth for unauthorized access | Only document auth bypass possibility |
| ❌ Create persistent test files | Delete any test files created during testing |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "PUT/DELETE require authorization"
- `README.md` -> Prohibited execution checklist
