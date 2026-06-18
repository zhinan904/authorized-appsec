# Web Cache Poisoning Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify web cache poisoning vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual cache poisoning is prohibited
> - Cache poisoning payloads are for understanding attack surface only, **no malicious content served to users**
> - Validation proves vulnerability existence (cache key analysis), **no cross-user content injection**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PortSwigger, PayloadsAllTheThings

## Manual Testing

**Note: Do not inject malicious content into shared cache**

---

## Validation Objectives (Within Security Boundary)

Web cache poisoning validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Cache Key Analysis | ✓ Identify unkeyed inputs | - | Inject malicious content |
| Unkeyed Header Reflection | ✓ Test X-Forwarded-Host, X-Original-URL | - | Serve poisoned content to users |
| Parameter Cloaking | ✓ Test cache key confusion | - | Persistent cache poisoning |
| Cache Behavior Detection | ✓ Identify caching headers and behavior | - | CDN-wide cache purge |

**Safe Validation Method**: Analyze cache keys and test for unkeyed input reflection using harmless markers; do not inject content that would be served to other users.

---

## Detection Methods

### Cache Behavior Detection

```bash
# Check if response is cached
curl -s -I https://target.com/page | grep -i "x-cache\|cf-cache\|age:\|cache-control"

# Common cache indicators:
# X-Cache: HIT (Varnish/CDN)
# CF-Cache-Status: HIT (Cloudflare)
# Age: 123 (seconds since cached)
# Cache-Control: public, max-age=3600
```

### Unkeyed Header Analysis

```bash
# Test X-Forwarded-Host (commonly unkeyed)
curl -s -I -H "X-Forwarded-Host: evil.com" https://target.com/page

# Check if response reflects evil.com in:
# - URLs (scripts, links, images)
# - Open Graph tags
# - Canonical URLs
# - CORS headers

# Test X-Original-URL
curl -s -I -H "X-Original-URL: /admin" https://target.com/

# Test X-Rewrite-URL
curl -s -I -H "X-Rewrite-URL: /admin" https://target.com/
```

### Parameter Cloaking

```bash
# Some CDNs ignore certain parameters in cache key
# Test if adding unkeyed param changes response but not cache key

# Step 1: Request with harmless marker
curl -s "https://target.com/page?utm_content=test123"

# Step 2: Request same URL, check if cached
curl -s -I "https://target.com/page"

# Step 3: If utm_content is unkeyed, inject via it
# (HARMLESS test only - do not inject malicious content)
```

### Vary Header Analysis

```bash
# Check Vary header for cache segmentation
curl -s -I https://target.com/page | grep -i "vary"

# Vary: User-Agent -> cache segmented by UA
# Vary: Accept-Encoding -> segmented by encoding
# Vary: Origin -> segmented by CORS origin
# No Vary -> single cache entry for all users
```

### Cache Key Extraction

```bash
# Identify what forms the cache key:
# 1. Request path (almost always keyed)
# 2. Query parameters (usually keyed)
# 3. Host header (usually keyed)
# 4. User-Agent (sometimes keyed)
# 5. Accept-Encoding (sometimes keyed)

# Test: change User-Agent, check if cache miss
curl -s -I -H "User-Agent: TestBot/1.0" https://target.com/page
# If X-Cache: MISS, User-Agent is part of cache key
```

---

## Analysis Process

1. Identify caching layer (CDN, reverse proxy, application)
2. Determine cache key components
3. Test unkeyed headers for reflection
4. Test unkeyed parameters for reflection
5. Analyze Vary header for cache segmentation
6. **Stop validation**, document unkeyed inputs
7. Do not inject malicious content into cache

---

## Severity Classification

cache poisoningto be high severity, must satisfy all three conditions (consistent with the host-header.md cache scenario gate):**1)a shared cache exists in front of the target 2)the poisoned response is cached 3)other users are affected**. downgrade if any condition is unmet. 

| Poisoning Type | Default | Upgrade condition |
|----------------|------|---------|
| XSS via unkeyed header | Low | -> High:Only whenall three conditions are met (shared cache + poisoning is cached + affects others)|
| Redirect via unkeyed header | Low | -> High:same as above, and the cached redirect is served to other users |
| Content injection | Low | -> High:same as above, and poisoned content is served to other users |
| Parameter cloaking | Low | -> Medium:requires specific cache behavior + exploitation is confirmed |
| Unkeyed but no reflection | Info | no reflection, Not exploitable |

**Chain-break point record** (mandatory, consistent with host-header.md):state which closure condition is unmet. common break points are - 
- site connects directly to origin, no shared cache layer (condition 1 breaks) - most common
- poisoning request is accepted but not cached (condition 2 breaks)
- cached but affects only self (condition 3 breaks)

**Key judgment**: unkeyed header exists does not equal cache poisoning — must confirm "poisoned content is actually cached and served to other users" is required for High. Sites without shared cache, even with unkeyed header reflection, only record Low (equivalent to ordinary reflection, not cache poisoning).

---

## Output

```markdown
## Vulnerability: Web Cache Poisoning

### Location
{URL} - Cache: {CDN/proxy type}

### Poisoning Vector
{Unkeyed Header / Parameter Cloaking / Vary Bypass}

### Evidence
- Cache key: {identified components}
- Unkeyed input: {header/parameter}
- Reflection point: {where input appears in response}
- Cache behavior: {HIT/MISS pattern}

### Validation Result
- Cache poisoning confirmed: {yes/no}
- Unkeyed inputs: {list}
- Impact: {XSS / Redirect / Content injection}

### Risk Level
{High} - Enables cross-user content injection via cache
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Inject XSS into cache | Do not serve malicious scripts to other users |
| ❌ Poison redirects | Do not cache malicious redirect targets |
| ❌ Inject persistent content | Do not create long-lived poisoned cache entries |
| ❌ Purge CDN cache | Do not trigger cache purge operations |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> Cache poisoning severity rules
