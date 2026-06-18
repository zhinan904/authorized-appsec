# Error Handling / Information Disclosure Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify error handling and information disclosure vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual sensitive data extraction prohibited
> - Error provocation payloads are for understanding attack surface only, **no system destabilization**
> - Validation proves vulnerability existence (error leaks sensitive info), **no exploitation of disclosed data**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Testing Guide, PayloadAllTheThings

## Manual Testing

**Note: Craft up to 8 error-provoking requests per endpoint**

---

## Validation Objectives (Within Security Boundary)

Error handling and information disclosure vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Forced Error Responses | ✓ Trigger errors with invalid input | - | Deliberate service disruption |
| Stack Trace Detection | ✓ Observe stack trace in response | - | Use trace for targeted exploitation |
| Debug Mode Detection | ✓ Identify debug mode enabled | - | Access debug console features |
| Verbose Database Errors | ✓ Confirm SQL error leakage | - | Use error to craft injection |
| Path Disclosure | ✓ Confirm path disclosure in error | - | Access files via disclosed paths |
| Version Disclosure | ✓ Identify version from error | - | Target known CVE exploits |

**Safe Validation Method**: Send malformed requests, observe error response content; document what information is disclosed without exploiting it.

---

## Forced Error Techniques

### Invalid Input Values

```bash
# String in numeric parameter
curl -s "https://target.com/api/user?id=abc" | grep -i "error\|exception\|trace"

# Negative IDs
curl -s "https://target.com/api/user?id=-1" | grep -i "error\|exception\|stack"

# Extremely long input
curl -s "https://target.com/api/user" -d '{"name":"AAAA...5000...AAAA"}' | grep -i "error\|exception"

# Null bytes
curl -s "https://target.com/api/user?id=%00" | grep -i "error\|exception"

# Special characters
curl -s "https://target.com/api/user?name=test%27%22%60%3C%3E" | grep -i "error\|exception"

# Empty parameter values
curl -s "https://target.com/api/user?id=" | grep -i "error\|debug"
```

### Unexpected Type Injection

```bash
# Array instead of string
curl -s "https://target.com/api/user" -H "Content-Type: application/json" \
  -d '{"id": [1,2,3]}' | grep -i "error\|exception\|trace"

# Object instead of string
curl -s "https://target.com/api/user" -H "Content-Type: application/json" \
  -d '{"id": {"$gt": ""}}' | grep -i "error\|exception"

# Boolean where string expected
curl -s "https://target.com/api/user?name=true" | grep -i "error\|exception"

# Float where integer expected
curl -s "https://target.com/api/user?id=1.5" | grep -i "error\|exception"
```

### Boundary Value Testing

```bash
# Integer overflow
curl -s "https://target.com/api/user?id=999999999999999999" | grep -i "error\|exception"

# Maximum length input
curl -s "https://target.com/api/user" -d "name=$(python3 -c 'print("A"*100000)')" | grep -i "error"

# Date boundary values
curl -s "https://target.com/api/event?date=9999-12-31" | grep -i "error\|exception\|trace"

# Zero value
curl -s "https://target.com/api/user?id=0" | grep -i "error\|exception"
```

---

## Stack Trace Provocation

### Common Error-Triggering Parameters

```bash
# Single quote (SQL error)
curl -s "https://target.com/api/search?q='" | grep -i "sql\|syntax\|mysql\|postgres\|oracle"

# Double quote
curl -s "https://target.com/api/search?q=%22" | grep -i "exception\|trace\|stack"

# Backslash
curl -s "https://target.com/api/search?q=%5C" | grep -i "error\|exception"

# Format string
curl -s "https://target.com/api/search?q=%s%s%s%s" | grep -i "error\|exception\|trace"

# JSON injection
curl -s "https://target.com/api/user" -H "Content-Type: application/json" \
  -d '{invalid json' | grep -i "error\|exception\|parse"
```

### HTTP Methods and Headers

```bash
# Wrong HTTP method
curl -s -X PATCH "https://target.com/api/user" | grep -i "error\|trace\|stack"

# Invalid Content-Type
curl -s "https://target.com/api/user" -H "Content-Type: text/xml" -d '{"id":1}' | grep -i "error\|exception"

# Missing required headers
curl -s "https://target.com/api/user" -H "Content-Type:" | grep -i "error\|exception\|trace"

# Oversized headers
curl -s "https://target.com/api/user" -H "X-Long-Header: $(head -c 10000 /dev/zero | tr '\0' 'A')" | grep -i "error"
```

---

## Debug Mode Detection

### Common Debug Indicators

```bash
# Check for debug parameters
curl -s "https://target.com/api/user?id=1&debug=true" | grep -i "debug\|trace\|profiler"
curl -s "https://target.com/api/user?id=1&debug=1" | grep -i "debug\|trace\|profiler"
curl -s "https://target.com/api/user?id=1&XDEBUG_SESSION_START=test" | grep -i "debug\|step"

# Check for common debug endpoints
for path in _debugbar debug profiler _profiler trace error-telescope _ignition telescope requests sparkle adminer phpinfo server-info server-status; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] /$path -> $status"
  fi
done

# Laravel debug mode indicators
curl -s "https://target.com/_ignition/health-check" | grep -i "ignition\|laravel\|debug"

# Django debug mode indicators
curl -s "https://target.com/nonexistent_page_404_test" | grep -i "django\|debug\|settings\|traceback"

# Spring Boot actuator debug
curl -s "https://target.com/actuator/env" | grep -i "java\|spring\|version"
```

---

## Verbose Database Errors

### Database Error Pattern Matching

```bash
# MySQL error patterns
curl -s "https://target.com/api/search?q='" | grep -i "mysql\|MariaDB\|syntax error\|sql_state\|errno"

# PostgreSQL error patterns
curl -s "https://target.com/api/search?q='" | grep -i "postgresql\|psql\|syntax error\|query\|relation"

# MSSQL error patterns
curl -s "https://target.com/api/search?q='" | grep -i "Microsoft SQL\|ODBC\|sqlserver\|unclosed quotation"

# Oracle error patterns
curl -s "https://target.com/api/search?q='" | grep -i "oracle\|ORA-\|PLS-\|TNS-"

# SQLite error patterns
curl -s "https://target.com/api/search?q='" | grep -i "sqlite\|SQLITE_ERROR\|no such table"

# MongoDB error patterns
curl -s "https://target.com/api/search" -H "Content-Type: application/json" \
  -d '{"$where": "1==1"}' | grep -i "mongo\|bson\|mongoose"
```

---

## Path Disclosure

### Error-Induced Path Leakage

```bash
# Force errors that reveal file paths
curl -s "https://target.com/api/search?q=%27%22%60" | grep -iE "(/[a-zA-Z0-9_./-]+\.(py|php|rb|java|cs|go|js))|C:\\|[A-Z]:\\" 

# Check for path leakage in stack traces
curl -s "https://target.com/api/error_trigger" | grep -iE "at [a-zA-Z]+\(|File \"/|in /|/var/www|/home/|/opt/|/usr/"

# ASP.NET path disclosure
curl -s "https://target.com/api/error_trigger" | grep -iE "C:\\|\\\\inetpub|\\\\wwwroot|aspx\|asp\|web.config"

# PHP path disclosure (invalid content-type)
curl -s "https://target.com/api/user" -H "Content-Type: text/xml" -d '<invalid' | grep -iE "Fatal error|Warning.*(/var/www|/home/|/usr/)"
```

### Common Path Disclosure Patterns

| Pattern | Language/Framework | Indicator |
|---------|-------------------|-----------|
| `/var/www/html/` | PHP/Apache | Linux web root |
| `C:\inetpub\wwwroot\` | ASP.NET/IIS | Windows web root |
| `/app/` | Docker/Spring | Container path |
| `/src/` | Node.js/Python | Source path |
| `/opt/tomcat/` | Java/Tomcat | Tomcat path |
| `/home/user/` | Various | Home directory |

---

## Version Disclosure Through Errors

### Server Header Analysis

```bash
# Server header version disclosure
curl -sI "https://target.com" | grep -iE "server:|x-powered-by:|x-aspnet-version:"

# Common version-revealing headers
curl -sI "https://target.com" | grep -iE "x-runtime|x-version|x-api-version|x-application-version"
```

### Error Page Version Fingerprinting

```bash
# Default error pages often reveal versions
curl -s "https://target.com/nonexistent_aspx_path" | grep -iE "ASP.NET|IIS|version|\.NET Framework"
curl -s "https://target.com/500" | grep -iE "nginx|apache|tomcat|version"
curl -s "https://target.com/404" | grep -iE "version|powered by|framework"

# PHP version disclosure via X-Powered-By
curl -sI "https://target.com" | grep -i "x-powered-by"

# Spring Boot version via actuator
curl -s "https://target.com/actuator/info" | grep -i "version\|build"
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A05:2021-Security Misconfiguration |
| CWE | CWE-209: Generation of Error Message Containing Sensitive Information |
| CWE | CWE-215: Insertion of Sensitive Information Into Debugging Code |
| CWE | CWE-497: Exposure of System Data to an Unauthorized Control Sphere |

---

## Analysis Process

1. Send well-formed request to establish baseline response
2. Send malformed requests (invalid types, boundary values, special characters)
3. Compare error responses against baseline for information disclosure
4. Check for stack traces, debug modes, database errors, paths, versions
5. Classify each disclosure by type (stack trace, path, version, database)
6. Document findings with minimal disruptive payloads only
7. **Stop validation**, report findings without exploiting disclosed information

---

## Output

```markdown
## Vulnerability: Information Disclosure via Error Handling

### Location
{URL} - {parameter}

### Disclosure Type
{Stack Trace / Debug Mode / Database Error / Path Disclosure / Version Disclosure}

### Evidence
- Error response contains: {stack trace / file path / database version / etc.}
- Disclosed information: {specific data leaked}
- Trigger payload: {malformed input used}

### Validation Result
- Stack trace leaking: {yes/no}
- Database error leaking: {yes/no}
- Path disclosure: {yes/no}
- Version disclosure: {yes/no}
- Debug mode active: {yes/no}

### Risk Level
{see severity rules}

### Severity Classification

Error disclosure impact depends on**the sensitivity of disclosed content**. stack traces/paths/versions are only auxiliary attack clues (Low); disclosurekeys/credentials/SQL/PII has direct impact. 

| Disclosed content | Severity | Note |
|---------|------|------|
| keys/credentials/database connection strings/PII | **High** | directly exploitable sensitive data |
| SQL statements/table structure/internal API details | Medium | assists injection/attack surface expansion |
| full stack trace/framework version/source code path | Low | auxiliary information, indirect use |
| server version/banner/technology stack | Info/Low | fingerprint information, low value |
| debug mode enabled without sensitive disclosure | Low | risk signal, Pending confirmation |

**Key judgment**: Medium or higher requires confirming that the error response disclosed **actionable sensitive information** (credentials/SQL/PII/internal structure). Version-only disclosure or generic error page only, record Info/Low. This follows the "missing/disclosure itself does not equal harm" gating principle.

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Service disruption | Do not send payloads designed to crash the service |
| ❌ Exploit disclosed paths | Do not use disclosed file paths to access files |
| ❌ Use database errors for injection | Error info is evidence only, not injection vectors |
| ❌ Access debug consoles | Only document existence, do not use debugger features |
| ❌ Target CVEs via version info | Version disclosure is a finding, not an attack vector |
| ❌ Extract sensitive data from errors | Document type only, do not exfiltrate actual data |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Do not enable harm"
- `README.md` -> Prohibited execution checklist