# Subdomain Takeover Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify subdomain takeover vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual subdomain claiming is prohibited
> - Subdomain takeover payloads are for understanding attack surface only, **no DNS record modification**
> - Validation proves vulnerability existence (dangling CNAME detected), **no actual service registration**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: HackerOne, Bugcrowd, PayloadsAllTheThings

## Manual Testing

**Note: Do NOT register or claim any external service**

---

## Validation Objectives (Within Security Boundary)

Subdomain takeover validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Dangling CNAME Detection | ✓ Identify CNAME pointing to unclaimed service | - | Register the external service |
| Service Fingerprinting | ✓ Identify target service (GitHub, Heroku, AWS) | - | Claim subdomain on that service |
| NXDOMAIN Analysis | ✓ Check if CNAME target resolves | - | Modify DNS records |
| Response Analysis | ✓ Check for "not found" / "unclaimed" page | - | Host malicious content |

**Safe Validation Method**: Identify dangling CNAME records and verify the target service shows "not found" / "unclaimed" status; do NOT register or claim the service.

---

## Detection Methods

### CNAME Analysis

```bash
# Check CNAME records for subdomain
dig CNAME subdomain.example.com +short

# Example outputs:
# dangling: subdomain.example.com -> app.herokuapp.com (app deleted)
# safe: subdomain.example.com -> loadbalancer.aws.com (active)

# Check if CNAME target resolves
dig A app.herokuapp.com +short
# If empty: NXDOMAIN, potential takeover
```

### Service-Specific Fingerprints

```bash
# GitHub Pages
curl -s https://subdomain.example.com | grep -i "There isn't a GitHub Pages site here"
# -> GitHub Pages not claimed

# Heroku
curl -s https://subdomain.example.com | grep -i "No such app"
# -> Heroku app deleted

# AWS S3
curl -s https://subdomain.example.com | grep -i "NoSuchBucket"
# -> S3 bucket deleted

# Azure
curl -s https://subdomain.example.com | grep -i "404 Web Site not found"
# -> Azure resource deleted

# Shopify
curl -s https://subdomain.example.com | grep -i "Sorry, this shop is currently unavailable"
# -> Shopify store closed

# Fastly
curl -s https://subdomain.example.com | grep -i "Fastly error: unknown domain"
# -> Fastly service removed

# Pantheon
curl -s https://subdomain.example.com | grep -i "404 error unknown site!"
# -> Pantheon site deleted

# Tumblr
curl -s https://subdomain.example.com | grep -i "Whatever you were looking for doesn't currently exist"
# -> Tumblr blog deleted

# WordPress.com
curl -s https://subdomain.example.com | grep -i "Do you want to register"
# -> WordPress.com subdomain available
```

### Subdomain Enumeration

```bash
# Discover subdomains (passive)
# Use subfinder, amass, or crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Check each for dangling CNAME
for sub in $(cat subdomains.txt); do
  cname=$(dig CNAME "$sub" +short 2>/dev/null)
  if [[ -n "$cname" ]]; then
    ip=$(dig A "$cname" +short 2>/dev/null)
    if [[ -z "$ip" ]]; then
      echo "POTENTIAL TAKEOVER: $sub -> $cname (NXDOMAIN)"
    fi
  fi
done
```

### HTTP Response Analysis

```bash
# Check for takeover indicators
curl -s -o /dev/null -w "%{http_code}" https://subdomain.example.com

# Common response codes:
# 404 - Service not found (potential takeover)
# 503 - Service unavailable (potential takeover)
# 200 - Active service (safe)
```

---

## Analysis Process

1. Enumerate subdomains for target domain
2. Check CNAME records for each subdomain
3. Identify CNAMEs pointing to external services
4. Verify if external service is active (DNS resolves)
5. Check service-specific "not found" fingerprints
6. **Stop validation**, document dangling CNAMEs
7. Do NOT register or claim any external service

---

## Severity Classification

| Takeover Type | Default Severity | Reason |
|---------------|------------------|--------|
| Active dangling CNAME + service fingerprint | High | Takeover possible with one registration |
| Dangling CNAME, service unclear | Medium | Requires further verification |
| CNAME resolves but returns error | Low | May be temporary outage |
| No CNAME / active service | Info | Not vulnerable |

---

## Output

```markdown
## Vulnerability: Subdomain Takeover

### Location
{subdomain}.{domain} -> {CNAME target}

### Service Type
{GitHub Pages / Heroku / AWS S3 / Azure / Shopify / Other}

### Evidence
- CNAME: {subdomain} -> {target}
- DNS resolution: {NXDOMAIN / resolves}
- Service fingerprint: {"not found" page content}
- HTTP status: {404 / 503 / other}

### Validation Result
- Dangling CNAME: {yes/no}
- Service claimable: {yes/no}
- Service type: {specific service}

### Risk Level
{High} - Dangling CNAME points to unclaimed {service}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Register external service | Do NOT claim GitHub Pages, Heroku, S3, etc. |
| ❌ Modify DNS records | Do NOT change CNAME or other DNS records |
| ❌ Host malicious content | Do NOT serve content via taken-over subdomain |
| ❌ Exploit for phishing | Do NOT use takeover for social engineering |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> Subdomain takeover severity rules
