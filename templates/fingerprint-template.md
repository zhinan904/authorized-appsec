# Fingerprint Report Template

> Phase 0 output template for `01-fingerprint.md`

---

## Template

```markdown
# Fingerprint - {target}

**Task ID**: {task_id}
**Started At**: {timestamp}
**Intensity**: {passive/gentle/standard}

---

## Scope Confirmation

| Field | Value |
|-------|-------|
| Target | {url/domain/ip} |
| Authorization | {confirmed_by_user/...} |
| Scope Boundary | {hosts, paths, exclusions} |
| Allowed Automation | {capabilities permitted} |

---

## HTTP Fingerprint

| Field | Value |
|-------|-------|
| Status Code | {200/301/403/...} |
| Title | {page title} |
| Web Server | {nginx/apache/iis/...} |
| Content-Type | {text/html/application/json/...} |
| Response Length | {bytes} |

### Headers

```
Server: {value}
X-Frame-Options: {value}
X-Content-Type-Options: {value}
Content-Security-Policy: {value}
Strict-Transport-Security: {value}
Set-Cookie: {cookie_name}; {attributes}
```

### Security Headers Summary

| Header | Present | Value |
|--------|---------|-------|
| X-Frame-Options | {yes/no} | {DENY/SAMEORIGIN/...} |
| X-Content-Type-Options | {yes/no} | {nosniff/...} |
| CSP | {yes/no} | {policy or none} |
| HSTS | {yes/no} | {max-age=...} |

---

## Tech Stack

| Component | Value | Confidence |
|-----------|-------|------------|
| Frontend Framework | {react/vue/angular/...} | {high/medium/low} |
| Backend Language | {php/java/python/node/...} | {high/medium/low} |
| Backend Framework | {laravel/spring/django/express/...} | {high/medium/low} |
| Database Hint | {mysql/postgres/mongodb/...} | {low} |
| CMS | {wordpress/drupal/...} | {high/medium} |

**Evidence**: {header clues, HTML patterns, script paths, cookies}

---

## WAF/CDN Detection

| Indicator | Value |
|-----------|-------|
| WAF Hint | {cloudflare/aws/akamai/none/unknown} |
| CDN Hint | {yes/no/unknown} |
| Blocked Patterns | {patterns that triggered block} |

---

## Visible Attack Surface

### Entry Points

| Type | Location | Method |
|------|----------|--------|
| Forms | {path} | {GET/POST} |
| API Endpoints | {/api/v1/...} | {method} |
| File Upload | {path} | {POST multipart} |
| Search/Filter | {parameter} | {GET/POST} |

### Parameters Observed

- {param1}: {type, in form/query/path}
- {param2}: {type, in cookie/header}

### Authentication

| Type | Location | Notes |
|------|----------|-------|
| Login Form | {/login} | {username/password fields} |
| API Auth | {header/cookie} | {Bearer/session} |
| OAuth | {/oauth/...} | {provider} |

---

## Initial Attack Surface Hypothesis

| Priority | Vulnerability Class | Reason | Confidence |
|----------|--------------------|--------|------------|
| P0 | {sqli/xss/auth/...} | {reasoning} | {high/medium/low} |
| P1 | {vuln class} | {reasoning} | {medium} |
| P2 | {vuln class} | {reasoning} | {low} |

---

## L3 Hypothesis Trigger

Run after recording the current-task fingerprint:

```bash
python3 scripts/auto_l3_hypotheses.py {task_dir}
```

| Field | Value |
|-------|-------|
| Trigger Status | {matched/not_matched/not_run} |
| Match Signals | {signals from current-task evidence only} |
| Queued Categories | {categories to validate, if any} |
| Reporting Boundary | L3 hypotheses are not findings; report only after Phase 3 current-task validation |

---

## Blocked/Deferred Items

- {item}: {reason (missing tool, auth required, out of scope)}

---

## Next Actions

1. Proceed to Phase 1 attack-surface mapping
2. Focus on: {priority targets}
3. Tools needed: {capabilities to discover}
```

---

## Usage

1. Create `01-fingerprint.md` after Phase 0 completion
2. Fill all sections from http-probing and manual analysis
3. Keep security header analysis for defensive findings
4. Attack surface hypothesis guides Phase 1 queue
5. Update `task.md` with tech_stack, waf, and finding_counts

---

## Minimal / Empty Response Handling

When the target returns Content-Length: 0 or a response with no visible content
(no forms, no links, no JavaScript-rendered DOM), the standard fingerprint
template will have many empty fields. **Do not skip Phase 0** — adapt it.

### Triage the root cause

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| 200 OK, Content-Length: 0, PHP header present | PHP app with empty output (suppressed errors, routed to void controller) | Probe common PHP paths (/index.php, /admin/, /login) with GET and POST |
| 200 OK, body contains only `<!-- comment -->` | CMS placeholder / stub page | The site uses a CMS with routed paths; directory brute-force is essential |
| 200 OK, Content-Length: 0, no PHP header | Static server serving empty index | Check DirectoryIndex config; try /index.html, /index.htm |
| 302 redirect, Location: ../ | CMS auth gate (admin directories) | The directory exists but redirects unauthenticated users |
| 403 Forbidden with body | Apache rejecting directory listing | Individual files inside the directory may still be accessible — probe them directly |
| 404 | Path doesn't exist | Move on quickly; don't retry the same path |

### When the homepage is empty

1. **Always probe `/index.php` explicitly** — the root `/` may use a different handler.
2. **Always run directory brute-force early** — gobuster/ffuf can find content even when the root is blank.
3. **Check headers for CMS/PHP clues** — `X-Powered-By`, `Set-Cookie`, `Server` reveal the tech stack even when the body is empty.
4. **Probe common CMS paths directly** — `/admin/`, `/user/`, `/wp-admin/`, `/e/admin/` (EmpireCMS) before waiting for brute-force results.
5. **Test alternate HTTP methods** — POST to `/index.php` may return different output than GET.
6. **Check response for TRACE** — a TRACE-enabled server leaks internal proxy/header info.

### Attack surface hypothesis for empty targets

When the visible attack surface is zero, prioritize:

| Priority | Hypothesis | Action |
|----------|-----------|--------|
| P0 | Hidden admin/login panels | Brute-force directories; probe CMS-specific admin paths |
| P0 | PHP error suppression | Trigger errors with `?[]=1`, malformed params, type juggling |
| P1 | Directory listing somewhere | Scan for open directories that expose file structure |
| P1 | Backup/config files accessible | Probe `.env`, `.git/HEAD`, `config.php.bak`, `*.sql` |
| P2 | Default CMS install with sample content | Access CMS-specific paths even if root is empty |

### Recording

When the root response is empty, add a note to the fingerprint:
```markdown
## Incident Note
Root response is Content-Length: 0. PHP processing confirmed via X-Powered-By header.
Expanded directory brute-force is the primary discovery mechanism for this target.
```
