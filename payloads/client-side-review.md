# Client-Side Secret & Logic Discovery Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify client-side secret exposure and business logic disclosure vulnerability risk characteristics.
>
> - All testing is **limited to discovery**, actual use of discovered secrets is prohibited
> - Client-side secret scanning is for understanding exposure only, **no credential exploitation**
> - Validation proves vulnerability existence (secret found in source), **no unauthorized API access**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Testing Guide, PayloadAllTheThings

## Manual Testing

**Note: Systematically review all JavaScript and client-side storage**

---

## Validation Objectives (Within Security Boundary)

Client-side secret and logic discovery vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| JavaScript Secret Scanning | ✓ Find exposed keys/tokens | - | Use keys for unauthorized access |
| localStorage/sessionStorage | ✓ Check for stored secrets | - | Modify other users' storage |
| Service Worker Analysis | ✓ Review SW scripts for secrets | - | Register malicious SW |
| Client-Side Business Logic | ✓ Review client-side auth logic | - | Bypass payment/authorization |
| Hardcoded Credentials | ✓ Find embedded credentials | - | Access systems with found creds |
| Debug Parameters | ✓ Identify debug switches | - | Enable debug in production |

**Safe Validation Method**: Find and document exposed secrets without using them. Report the finding with type and location of exposed secret.

---

## JavaScript Secret Scanning

### API Key and Token Patterns

```bash
# Download all JavaScript files
curl -s "https://target.com" | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//' > js_files.txt

# Scan for API keys, tokens, passwords in JS
while read -r js_file; do
  curl -s "https://target.com${js_file}" | grep -iE \
    "api[_-]?key|apikey|api[_-]?secret|token|password|secret|auth|credential|private[_-]?key" | \
    head -20
done < js_files.txt
```

### Common Secret Patterns

```bash
# Search for common secret formats in JavaScript
curl -s "https://target.com/app.js" | grep -oE \
  '(AWS_ACCESS_KEY|AKIA)[0-9A-Z]{16}|[0-9a-f]{32,64}|eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+|sk[_-]?live[_-]?[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+| -----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'

# AWS Access Key pattern: AKIA followed by 16 uppercase alphanumeric
curl -s "https://target.com/app.js" | grep -oE 'AKIA[0-9A-Z]{16}'

# AWS Secret Key pattern (40 chars base64)
curl -s "https://target.com/app.js" | grep -oE '[A-Za-z0-9/+=]{40}'

# Stripe key pattern
curl -s "https://target.com/app.js" | grep -oE '(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}'

# Google API key pattern
curl -s "https://target.com/app.js" | grep -oE 'AIza[0-9A-Za-z_-]{35}'

# GitHub token pattern
curl -s "https://target.com/app.js" | grep -oE 'ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}'

# Slack token pattern
curl -s "https://target.com/app.js" | grep -oE 'xox[baprs]-[0-9a-zA-Z-]+'

# JWT pattern
curl -s "https://target.com/app.js" | grep -oE 'eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+'

# Private key pattern
curl -s "https://target.com/app.js" | grep -oE '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'
```

### Source Map Exposure

```bash
# Check for JavaScript source maps
curl -s -o /dev/null -w "%{http_code}" "https://target.com/app.js.map"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/main.js.map"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/vendor.js.map"

# Check for source map reference in JS
curl -s "https://target.com/app.js" | grep -oE '//# sourceMappingURL=[^ ]+'
```

---

## localStorage / sessionStorage Testing

### Browser Console Commands

```javascript
// Check localStorage
Object.entries(localStorage).forEach(([key, value]) => {
  if (/token|key|secret|password|auth|session|jwt/i.test(key)) {
    console.log(`[localStorage] ${key}: ${value.substring(0, 50)}...`);
  }
});

// Check sessionStorage
Object.entries(sessionStorage).forEach(([key, value]) => {
  if (/token|key|secret|password|auth|session|jwt/i.test(key)) {
    console.log(`[sessionStorage] ${key}: ${value.substring(0, 50)}...`);
  }
});

// Check all cookies
document.cookie.split(';').forEach(c => {
  console.log(`[cookie] ${c.trim()}`);
});

// Check IndexedDB (if applicable)
indexedDB.databases().then(dbs => {
  dbs.forEach(db => console.log(`[IndexedDB] ${db.name}`));
});
```

### localStorage Risk Assessment

| Storage Type | Risk | Example |
|-------------|------|---------|
| JWT token in localStorage | High | `localStorage.setItem('token', 'eyJ...')` |
| API key in localStorage | High | `localStorage.setItem('apiKey', 'sk_live_...')` |
| User data in localStorage | Medium | `localStorage.setItem('user', JSON.stringify(userData))` |
| Session in sessionStorage | Medium | `sessionStorage.setItem('session', '...')` |
| CSRF token in localStorage | Low | `localStorage.setItem('csrf', '...')` |
| Preferences in localStorage | Info | `localStorage.setItem('theme', 'dark')` |

---

## Service Worker Analysis

```bash
# Check for registered service workers
curl -s "https://target.com/" | grep -oE 'navigator\.serviceWorker\.register\(["\x27][^"\x27]+'

# Common service worker paths
for path in sw.js service-worker.js worker.js sw.js; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] /$path -> $status"
  fi
done

# Analyze service worker content
curl -s "https://target.com/sw.js" | grep -iE "fetch|cache|token|key|secret|password|auth"
```

---

## Client-Side Business Logic Review

### Authentication Logic in JavaScript

```bash
# Look for client-side auth validation
curl -s "https://target.com/app.js" | grep -iE "isAuthenticated|isLoggedIn|checkAuth|validateAuth|authCheck|role|permission|isAdmin"

# Look for authorization checks
curl -s "https://target.com/app.js" | grep -iE "hasPermission|canAccess|checkRole|isAllowed|userRole|adminRole"

# Look for client-side route guards
curl -s "https://target.com/app.js" | grep -iE "beforeEach|routeGuard|canActivate|RequireAuth|ProtectedRoute"
```

### Payment/Pricing Logic

```bash
# Look for client-side pricing logic
curl -s "https://target.com/app.js" | grep -iE "price|total|amount|discount|coupon|checkout|payment"

# Look for client-side validation that should be server-side
curl -s "https://target.com/app.js" | grep -iE "validate|sanitize|checkInput|verifyInput"
```

### Feature Flags and Debug Logic

```bash
# Look for feature flags
curl -s "https://target.com/app.js" | grep -iE "featureFlag|feature_flag|enableFeature|debug|devMode|isDev|isDebug|SHOW_DEBUG|ENABLE_DEBUG"

# Look for hidden endpoints
curl -s "https://target.com/app.js" | grep -oE '"/api/[^"]+"' | sort -u

# Look for hidden routes
curl -s "https://target.com/app.js" | grep -oE '"/(admin|debug|internal|staging|test)[^"]*"' | sort -u
```

---

## Hardcoded Credentials Detection

```bash
# Search for hardcoded credentials patterns
curl -s "https://target.com/app.js" | grep -iE "username.*=.*['\"].*['\"]|password.*=.*['\"].*['\"]|apikey.*=.*['\"].*['\"]|secret.*=.*['\"].*['\"]"

# Search for database connection strings
curl -s "https://target.com/app.js" | grep -iE "mongodb://|mysql://|postgres://|redis://|amqp://"

# Search for cloud provider connection strings
curl -s "https://target.com/app.js" | grep -iE "DefaultEndpointsProtocol|AccountName|AccountKey|aws_access_key|aws_secret"

# Search for OAuth/API secrets
curl -s "https://target.com/app.js" | grep -iE "client_secret|oauth_secret|app_secret|app_key"
```

---

## Exposed Debug Parameters

```bash
# Test common debug parameters
for param in "debug=true" "debug=1" "debug=yes" "test=true" "dev=true" "stage=true" "trace=true"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/?${param}" 2>/dev/null)
  echo "[$status] ?${param}"
done

# Check for debug response headers
curl -sI "https://target.com/?debug=true" | grep -iE "debug|trace|x-debug|server-timing"

# Check for verbose error responses with debug parameters
diff <(curl -s "https://target.com/api/users") <(curl -s "https://target.com/api/users?debug=true")
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A05:2021-Security Misconfiguration |
| OWASP Web | A07:2021-Identification and Authentication Failures |
| CWE | CWE-798: Use of Hard-coded Credentials |
| CWE | CWE-922: Insecure Storage of Sensitive Information |

---

## Analysis Process

1. Collect all JavaScript source files from target pages
2. Scan JavaScript for API keys, tokens, secrets, credentials
3. Check localStorage/sessionStorage for stored sensitive data
4. Analyze service workers for sensitive logic or data
5. Review client-side authentication and authorization logic
6. Search for hidden endpoints and feature flags
7. Test debug parameters and verbose error modes
8. Document all findings with type, location, and severity
9. **Stop validation**, report findings without using discovered secrets

---

## Output

```markdown
## Vulnerability: Client-Side Secret Exposure

### Location
{URL} - {JavaScript file / localStorage key}

### Secret Type
{API Key / Token / Password / Private Key / Connection String}

### Evidence
- Secret found in: {source file / localStorage / sessionStorage}
- Pattern matched: {key pattern / regex}
- Value (redacted): {first 8 chars}...

### Validation Result
- Secret type: {AWS key / Stripe key / JWT / database connection string / etc.}
- Exposure method: {hardcoded in JS / localStorage / source map / SW}
- Severity: {based on key type and exposure}

### Risk Level
{Critical/High/Medium} - {secret type} exposed in {location}, could enable {attack type}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Use discovered API keys | Only document existence, do not authenticate |
| ❌ Access systems with found creds | Credentials are evidence of exposure, not access |
| ❌ Register malicious service workers | Only analyze existing SW scripts |
| ❌ Modify client-side storage | Only observe stored data |
| ❌ Exploit client-side logic bypasses | Only document bypass possibilities |
| ❌ Report full secret values | Redact secret values in reports |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Do not exploit discovered secrets"
- `README.md` -> Prohibited execution checklist