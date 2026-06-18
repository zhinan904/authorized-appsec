# Authorized AppSec Workflow Guide

> **Version**: 2.8.1 | **Updated**: 2026-06-01
>
> **Capability-first**: This guide is organized by capabilities, not specific tools.
> Tools are discovered inside the Kali Linux VM or equivalent execution VM at runtime.

## Prerequisite

Run capability discovery inside the VM before any recon and write the result into the active task directory:

```bash
./scripts/discover-capabilities.sh <task_dir>/capabilities.json
```

Read the output to understand available tools per capability.

If a capability has no available tools:
- Record limitation in `task.md`
- Use manual alternatives (see `commands/capabilities.md`)
- Do not assume specific tools exist

---

## Input Routing

| Input Type | Workflow |
|------------|----------|
| Full URL | Skip subdomain/port discovery → Start at http-probing |
| Domain | subdomain-discovery → http-probing → continue |
| IP | port-scanning → http-probing → continue |
| IP Range | port-scanning (web ports) → http-probing → user selects |
| Saved Task | Resume from `task.md` |

---

## Phase 0: Boundary + Fingerprint

### Scope Confirmation

Before any network activity, confirm:

| Field | Required |
|-------|----------|
| target | URL, domain, IP, or range |
| authorization | User confirms permission |
| scope | Hosts, paths, excluded systems |
| intensity | passive / gentle / standard |
| automation | Which capabilities allowed |
| credentials | Session context if applicable |

### HTTP Fingerprint (http-probing)

**Capability**: `http-probing`

**Goal**: Get status, title, tech stack, security headers in one request.

**Discovery**: Check `capabilities.json` for `http-probing.candidates`.

**Execution** (adapt to discovered tool):

```bash
# If httpx available
httpx -u <target> -tech-detect -title -status-code -web-server -json -o fingerprint.json

# If httprobe available (limited output)
httprobe -p 80,443,8080,8443 < hosts.txt

# If no tool: manual curl
curl -sI <target> | grep -E "Server|X-|Content-Type"
curl -s <target> | grep -E "<title>|<script|<link"
```

**Output Fields**:

| Field | Purpose |
|-------|---------|
| status_code | Alive check |
| title | Context clue |
| tech_detect | Attack surface hint |
| web_server | Version vulnerabilities |
| content_length | Change detection |

### SPA Detection → Headless Browser Trigger

When fingerprinting reveals SPA indicators, standard curl-based recon degrades. Trigger headless-browser capability instead.

**SPA Detection Signals**:

| Signal | Pattern | Detection Method |
|--------|---------|------------------|
| React | `__NEXT_DATA__`, `_reactRootContainer`, `data-reactroot` | HTML source grep |
| Vue | `__vue__`, `data-v-`, `nuxt` | HTML source grep |
| Angular | `ng-version`, `ng-app`, `_nghost` | HTML source grep |
| Svelte | `svelte`, `__svelte` | HTML source grep |
| Empty body + JS bundle | `<div id="root"></div>` + `<script src="*.js">` | Body length < 200 + script tag |
| CSR-only rendering | All content in JS, no SSR text | Compare curl output vs browser view |

**Trigger Rules**:

| Condition | Action | Fallback |
|-----------|--------|----------|
| 2+ SPA signals detected | Use headless-browser capability | Check `capabilities.json` for `headless-browser.candidates` |
| Headless browser available | Render page, extract DOM, run JS | Capture rendered HTML + API calls |
| No headless browser | Degrade: curl + JS source map parsing (covers ~30% of SPAs — webpack without obfuscation, public source maps) | See degraded mode boundary below |
| SPA + API endpoints found | Add API endpoints to testing queue | Log in `01-fingerprint.md` as `spa_api_endpoints` |

**Degraded Mode Boundary**: Degraded mode (curl + source map parsing) can extract API routes from ~30% of SPAs — those where webpack chunks are unobfuscated and `.map` files are publicly served. For the remaining ~70% (minified/obfuscated bundles, no source maps, code-split bundles with dynamic imports, WASM-heavy apps), degraded mode produces incomplete or zero results. When the first degraded pass yields < 5 API endpoints or fails to extract meaningful routes, **do not iterate** — instead record in `task.md`:

```yaml
headless_required: true
status: blocked
blocked_reason: "SPA with [framework] detected; degraded mode insufficient (no source maps / obfuscated bundles); headless-browser capability required for meaningful recon"
```

This prevents two failure modes: (a) silently returning zero endpoints and skipping the target, and (b) grinding through degraded mode producing incomplete results that miss the majority of the attack surface.

**Degraded Mode (no browser)**:

```bash
# Extract API routes from JS bundles
curl -s <url> | grep -oE 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
  curl -s <url>/$js | grep -oE '"/(api|v[0-9])/[^"]+"'
done

# Parse source maps if available
curl -s <url>/main.js.map | python3 -c "import sys,json; [print(s.get('src','')) for s in json.load(sys.stdin).get('sources',[])]"
```

**Output**: Record SPA detection in `01-fingerprint.md` under `## SPA Detection` with:
- Detected framework(s)
- Whether headless browser was available
- Extracted API endpoints (if any)
- Recommendation for Phase 2/3 testing approach

### Fingerprint Analysis (fingerprinting)

**Capability**: `fingerprinting`

**Goal**: Deep framework identification.

**Execution**:

```bash
# If Ehole available
Ehole -u <target> -o fingerprint.json

# If wappalyzer CLI available
wappalyzer <target>

# If no tool: manual pattern matching
curl -s <target> | grep -oE "wp-content|react|angular|vue|laravel|django|spring"
curl -sI <target> | grep -E "X-Powered-By|Set-Cookie"
```

Write results to `01-fingerprint.md` with attack-surface hypothesis.

---

## Phase 1-2: Attack Surface Discovery

### Subdomain Discovery (domain input)

**Capability**: `subdomain-discovery`

**Allowed**: Only when subdomain discovery is in scope.

**Execution**:

```bash
# If subfinder available
subfinder -d <domain> -silent -o subs.txt

# If amass available
amass enum -passive -d <domain> -o subs.txt

# If findomain available
findomain -t <domain> -o subs.txt

# If no tool: passive DNS via certificate logs
# Use online CT logs API or manual dig
```

**Intensity Mapping**:

| Intensity | Tool Flags |
|-----------|------------|
| passive | subfinder: default, amass: `-passive` |
| gentle | `-rl 50` rate limit |
| standard | `-all` all sources, `-recursive` |

**Output**: List of FQDNs → Feed to http-probing.

### Port Scanning

**Capability**: `port-scanning`

**Allowed**: Only when port scanning is approved.

**Web Ports Focus**: See `commands/ports.md` for common web ports.

**Execution**:

```bash
# If naabu available
naabu -iL hosts.txt -top-ports 100 -rate 100 -json -o ports.json

# If nmap available
nmap -iL hosts.txt -p 80,443,8080,8443,3000,5000,8000,9000 -T3 -oG ports.gnmap

# If rustscan available
rustscan -a hosts.txt -p 80,443,8080,8443 --ulimit 5000

# If no tool: nc manual probe
for port in 80 443 8080 8443; do
  nc -zv <host> $port 2>&1 | grep succeeded
done
```

**Intensity Mapping**:

| Intensity | Tool Flags |
|-----------|------------|
| passive | naabu: `-passive` (no direct probe) |
| gentle | naabu: `-rate 50 -c 5`, nmap: `-T2` |
| standard | `-top-ports 100`, nmap: `-T3` |

### URL/JS Extraction

**Capability**: `url-extraction`

**Goal**: Find endpoints, API paths, hidden routes.

**Execution**:

```bash
# If URLFinder available
URLFinder -u <url> -s all -m 3 -o urls.json

# If katana available
katana -u <url> -d 3 -jc -o urls.json

# If gau available
gau <domain> --threads 10 --o urls.txt

# If no tool: grep from source
curl -s <url> | grep -oE 'href="[^"]+"|src="[^"]+"'
curl -s <url> | grep -oE '/api/[^"]+|/v[0-9]/[^"]+'
```

**Intensity Mapping**:

| Intensity | Depth |
|-----------|-------|
| gentle | 1-2 levels |
| standard | 3 levels |

### Directory Scanning

**Capability**: `directory-scanning`

**Allowed**: Only when approved. Requires wordlist.

**Wordlist Discovery**:

```bash
# Find wordlists in VM
find /usr/share -name "*.txt" -path "*wordlist*" 2>/dev/null | head -10
find /opt -name "*.txt" -path "*wordlist*" 2>/dev/null | head -10
```

**Execution**:

```bash
# If spray available
spray -u <url> -d <wordlist> --thread 5 --rate-limit 10 -f dirs.json

# If ffuf available
ffuf -u <url>/FUZZ -w <wordlist> -t 10 -rate 50 -o dirs.json

# If dirsearch available
dirsearch -u <url> -w <wordlist> -t 10 -e php,html,js -o dirs.txt

# If no tool: curl iteration (slow, small list only)
for word in admin login api test config backup; do
  curl -s -o /dev/null -w "%{http_code}" <url>/$word
done
```

**Intensity Mapping**:

| Intensity | Threads | Rate |
|-----------|---------|------|
| gentle | 5 | 10 req/s |
| standard | 10-20 | 50 req/s |

### Active Parameter Discovery

**Capability**: `parameter-fuzzing` (reuses directory-scanning tools — ffuf/`FUZZ` keyword)

**Goal**: find **hidden parameters** on known endpoints that passive JS extraction missed. This is distinct from endpoint discovery — here the endpoint is known and we fuzz its parameter *names*. Many BOLA / injection / mass-assignment findings depend on a parameter the front end never exposes.

**When to run**: in Phase 1-2, after the Endpoints Catalog is populated. Prioritize endpoints that accept input (POST bodies, query strings, mutation-style API paths). Do not fuzz every endpoint — pick the high-value ones identified in the Test Queue.

**Allowed**: same gate as directory scanning (approved in preflight). Non-destructive: GET/HEAD probing only, no data mutation.

**Execution**:

```bash
# If ffuf available — fuzz parameter names on a known endpoint
ffuf -u '<url>/endpoint?FUZZ=test' -w <param_wordlist> -t 10 -rate 50 -mc 200,302,500 -fs <baseline_size> -o params.json

# POST body parameter fuzz
ffuf -u '<url>/endpoint' -X POST -d 'FUZZ=test' -w <param_wordlist> -t 10 -rate 50 -o post_params.json

# Arjun (if available) — purpose-built for hidden params
arjun -u '<url>/endpoint' -o params.json

# If no tool: small manual probe of common hidden params
for p in id admin debug test source backup callback url redirect next format json xml; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "<url>/endpoint?$p=test")
  echo "$p: $code"
done
```

**Baseline handling**: filter out responses matching the baseline size/status (`-fs`, `-fc`) — a parameter that changes nothing is not interesting. Reflective parameters (response echoes the value) and status deltas (200 vs default 400/404) are the signal.

**Wordlist sources**:

```bash
# Common param wordlists in VM
find /usr/share -iname "*param*wordlist*" 2>/dev/null
find /usr/share/seclists -iname "*params*" 2>/dev/null
# SecLists: Discovery/Web-Content/burp-parameter-names.txt
```

**Intensity Mapping**:

| Intensity | Threads | Rate | Scope |
|-----------|---------|------|-------|
| gentle | 5 | 10 req/s | top-N high-value endpoints only |
| standard | 10 | 50 req/s | all input-accepting endpoints |

**Output**: confirmed hidden parameters go into `02-discovery.md` under "Parameters Identified" with a new marker (`source: active-fuzz`) to distinguish them from passively extracted ones. Each newly found parameter feeds the Test Queue for Phase 3.

**Boundary**: GET/HEAD probing only. Do not use discovered parameters to create/update/delete data during discovery — that is Phase 3 validation and follows its own action-policy gates.

---

## Phase 3: Vulnerability Validation

### Targeted Vulnerability Scan

**Capability**: `vulnerability-scanning`

**Default: opt-in only.** This whole section applies **only when the user has explicitly requested nuclei/scanner-based scanning** in preflight or task conversation. Without that explicit request, skip every block below and go straight to **Manual Payload Testing**. Do not run nuclei/nikto/wpscan based on a fingerprint tag, L3 hypothesis, discovery result, or "scan for vulnerabilities" phrasing — those authorize the manual workflow, not template scanning. Record the explicit request in `task.md`.

**Goal**: Scan for known CVEs, misconfigurations based on fingerprint.

**Tag Selection**: Use fingerprint results to narrow scan scope.

Only use a tag when the current task has direct evidence for that technology. Path naming, L3 recall, or historical user examples are insufficient by themselves.

| Fingerprint | Nuclei Tags |
|-------------|-------------|
| Nacos | `nacos` |
| Spring | `spring` |
| Apache Shiro | `shiro` |
| WebLogic | `weblogic` |
| Fastjson | `fastjson` |
| ThinkPHP | `thinkphp` |
| WordPress | `wordpress` |

**Execution** (only after explicit approval recorded in `task.md`):

```bash
# If nuclei available AND explicitly approved
nuclei -u <url> -tags <tag> -severity critical,high,medium -o vulns.txt

# Generic exposure scan (explicitly approved only)
nuclei -u <url> -tags exposure,misconfig -severity medium,high,critical -o exposures.txt

# If nikto available AND explicitly approved
nikto -h <url> -o nikto.txt

# Default path — no scanner approval needed
# Use payloads/*.md for specific vulnerability classes (see Manual Payload Testing)
```

**Intensity Mapping**:

| Intensity | Flags |
|-----------|-------|
| gentle | `-rate-limit 10 -bulk-size 5` |
| standard | `-rate-limit 50 -bulk-size 20` |

### Manual Payload Testing

When no scanner available, use skill-provided payload guides:

| Vulnerability Class | Payload Guide |
|--------------------|---------------|
| SQL Injection | `payloads/sqli.md`, `payloads/api-sqli.md` |
| NoSQL Injection | `payloads/api-nosqli.md` |
| SSRF | `payloads/ssrf.md`, `payloads/api-ssrf.md` |
| XSS | `payloads/xss.md` |
| XXE | `payloads/xxe.md`, `payloads/api-xxe.md` |
| CSRF | `payloads/csrf.md` |
| JWT | `payloads/jwt.md` |
| File Inclusion | `payloads/file-inclusion.md` |
| File Read | `payloads/file-read.md` |
| File Upload | `payloads/file-upload.md` |
| API Auth Bypass | `payloads/api-auth.md` |
| API Business Logic | `payloads/api-business-logic.md` |
| Command Injection | `payloads/api-cmdi.md` |
| Deserialization | `payloads/deserialization.md` |
| GraphQL | `payloads/api-graphql.md` |
| Config Exposure | `payloads/api-config.md` |
| Data Exposure | `payloads/api-data-exposure.md` |
| Open Redirect | `payloads/open-redirect.md` |
| SSTI | `payloads/ssti.md` |
| OAuth/OIDC | `payloads/oauth.md` |
| Password Reset | `payloads/password-reset.md` |
| LDAP Injection | `payloads/ldap-injection.md` |
| Host Header | `payloads/host-header.md` |
| Rate Limiting | `payloads/rate-limiting.md` |
| IDOR | `payloads/idor.md` |
| WebSocket | `payloads/websocket.md` |
| MFA Bypass | `payloads/mfa-bypass.md` |
| CORS | `payloads/cors.md` |
| HTTP Smuggling | `payloads/http-smuggling.md` |
| CRLF Injection | `payloads/crlf-injection.md` |
| Cache Poisoning | `payloads/cache-poisoning.md` |
| Race Condition | `payloads/race-condition.md` |
| Prototype Pollution | `payloads/prototype-pollution.md` |
| Subdomain Takeover | `payloads/subdomain-takeover.md` |
| DOM XSS | `payloads/dom-xss.md` |
| Default Credentials | `payloads/default-credentials.md` |
| Error Handling / Info Disclosure | `payloads/error-handling.md` |
| Security Headers / CSP Bypass | `payloads/security-headers.md` |
| Path Traversal | `payloads/path-traversal.md` |
| Cloud Security | `payloads/cloud-security.md` |
| Session Management | `payloads/session-management.md` |
| Admin Panel | `payloads/admin-panel.md` |
| Client-Side Review | `payloads/client-side-review.md` |
| Backup / Source Exposure | `payloads/backup-exposure.md` |
| HTTP Methods | `payloads/http-methods.md` |
| SOAP / WSDL | `payloads/soap-wsdl.md` |
| Mobile API | `payloads/api-mobile.md` |
| Password Policy | `payloads/password-policy.md` |

Read the relevant payload file before testing.

---

## Workflow Composition

### URL Workflow

```
http-probing → fingerprinting → url-extraction → directory-scanning → manual payload validation
```

1. http-probing: Get basic fingerprint
2. fingerprinting: Deep tech identification
3. url-extraction: Find endpoints
4. directory-scanning: Find hidden paths (if approved)
5. manual payload validation: Validate prioritized findings using the relevant `payloads/*.md`
6. scanner-based validation: Run `vulnerability-scanning` only when the user explicitly approves nuclei/nikto/wpscan-style scanning

### Domain Workflow

```
subdomain-discovery → http-probing → port-scanning → fingerprinting → manual payload validation
```

### IP Range Workflow

```
port-scanning (web ports) → http-probing → fingerprinting → url-extraction → manual payload validation
```

---

## Rate Control Guidelines

All tools should respect intensity settings:

| Intensity | HTTP Rate | Port Rate | Threads |
|-----------|-----------|-----------|---------|
| passive | N/A (no direct probe) | passive mode | 1 |
| gentle | 10-30 req/s | 50-100 ports/min | 5 |
| standard | 50-100 req/s | 200-500 ports/min | 10-20 |

Apply rate flags based on discovered tool's capabilities.

---

## Error Handling

When a tool fails:

1. Check if tool exists: `command -v <tool>`
2. Check tool output for errors
3. Try next candidate from `capabilities.json`
4. If all candidates fail: record in `task.md`, use manual alternative

Record in `task.md`:

```md
## Tool Failures

- port-scanning: naabu crashed, nmap unavailable → used nc manual probe
```

---

## Output Requirements

All recon output should be:

1. Written to `raw/` directory
2. Summarized in phase files (`01-fingerprint.md`, `02-discovery.md`)
3. Confirmed findings go to `findings.md` only after Phase 3 validation

Do not write scanner hits directly to `findings.md`. Validate first.

---

## Passive Reconnaissance (OSINT)

Passive reconnaissance gathers intelligence without directly interacting with the target. Use before active probing to inform attack surface hypotheses.

### When to Use

| Scenario | Recommended |
|----------|-------------|
| Before any active probing | Yes |
| Domain input with subdomain scope | Yes |
| Understanding attack surface before fingerprint | Yes |
| When active probing is restricted | Primary method |

### DNS and Certificate Intelligence

| Source | Purpose | Method |
|--------|---------|--------|
| Certificate Transparency (crt.sh) | Subdomain discovery, internal hostnames | `curl -s "https://crt.sh/?q=%25.example.com&output=json"` |
| DNS TXT records | SPF, domain verification, infrastructure hints | `dig example.com TXT +short` |
| DNS CNAME/A records | Subdomain resolution, service identification | `dig example.com CNAME +short` |
| Reverse DNS | IP-to-hostname mapping | `dig -x 192.0.2.1 +short` |
| WHOIS | Registrant info, nameservers, dates | `whois example.com` |

### Web Archive and URL History

| Source | Purpose | Method |
|--------|---------|--------|
| Wayback Machine | Historical URLs, endpoints, parameters | `curl -s "https://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&fl=original"` |
| URLFinder / gau | Historical URL collection | Use `url-extraction` capability |
| robots.txt / sitemap.xml | Disallowed paths, site structure | `curl -s https://example.com/robots.txt` |
| .well-known/security.txt | Security contact, policy | `curl -s https://example.com/.well-known/security.txt` |

### Metadata and Source Code

| Source | Purpose | Method |
|--------|---------|--------|
| GitHub/GitLab search | Exposed secrets, internal paths, config files | Search for `example.com`, API keys, passwords |
| Google Dorking | Indexed sensitive content | `site:example.com intitle:"index of"` |
| Shodan / Censys (if available) | Open ports, services, banners | Query target domain/IP |
| DNSdumpster (if available) | DNS mapping, subdomain visualization | Web-based lookup |
| Wappalyzer (online) | Technology identification without probing | Browser extension or API |

### Cloud and Infrastructure

| Source | Purpose | Method |
|--------|---------|--------|
| SPF records | Email infrastructure, cloud services | `dig example.com TXT +short` (look for include:) |
| MX records | Email provider identification | `dig example.com MX +short` |
| NS records | DNS provider, hosting hints | `dig example.com NS +short` |
| S3 bucket enumeration | Exposed storage | Check `https://s3.amazonaws.com/example-bucket` |

### OSINT Output Handling

Record all passive reconnaissance findings in `02-discovery.md`:

```markdown
## Passive Reconnaissance

### DNS Intelligence
- crt.sh: Found 15 subdomains, 3 new hosts identified
- TXT records: SPF includes _spf.google.com (G Suite), domain verification tags
- CNAME: api.example.com -> lb.example.cloud

### Web Archive
- Wayback Machine: 200+ historical URLs, /api/v1/ prefix identified
- robots.txt: Disallows /admin/, /internal/, /staging/

### Source Code Intelligence
- GitHub: Public repo found, .env file committed (potential secret exposure)
- Google Dork: site:example.com filetype:pdf identifies document directory
```

### OSINT to Active Testing Transition

| OSINT Finding | Leads to Active Test |
|---------------|---------------------|
| Discovered subdomain | Add to http-probing scope (with approval) |
| Exposed .env in GitHub | Test for credential reuse |
| /admin/ in robots.txt | Fingerprint admin interface (with scope check) |
| API path in Wayback | Add to endpoint testing queue |
| Cloud service in SPF | Check for cloud metadata endpoints (with authorization) |
