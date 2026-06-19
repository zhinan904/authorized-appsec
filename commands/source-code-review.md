# Source Code Review Methodology

> **Version**: 2.21.0 | **Updated**: 2026-06-18
>
> **Purpose**: Structured source code review methodology for authorized application security assessment. Applies when source code is provided within scope.

---

## Overview

Source code review complements black-box testing by revealing vulnerabilities that may not be observable from external testing. This guide covers:

1. When source code review applies in scope
2. JavaScript source review methodology
3. Secret/credential scanning procedures
4. Hardcoded key detection patterns
5. Dependency vulnerability identification
6. SAST tool integration
7. Review checklist

**Reference**: Use `payloads/client-side-review.md` for client-side JavaScript scanning procedures.

---

## When Source Code Review Applies

### Scope Conditions

Source code review is applicable when:

| Condition | Approach |
|-----------|----------|
| Source code provided in scope | Full review possible |
| JavaScript source accessible | Client-side review (see `payloads/client-side-review.md`) |
| Source map files available | Reconstruct original source for review |
| Public repository discovered | Review within scope boundaries only |
| Configuration files exposed | Targeted review (see `payloads/backup-exposure.md`) |
| Decompiled application | Targeted review of decompiled source |

### Scope Boundaries

- **In scope**: Code explicitly provided by client, client-side JavaScript, source code from exposed repositories within scope
- **Out of scope**: Source code from third-party libraries not in scope, public repositories outside scope, decompiled source from proprietary software not authorized
- **Always verify scope** before reviewing any source code

---

## JavaScript Source Review Methodology

### Overview

JavaScript source review focuses on two categories:

1. **Client-side JavaScript**: Runs in the browser, always accessible (see `payloads/client-side-review.md`)
2. **Server-side JavaScript (Node.js)**: Accessible only when source code is provided in scope

### Client-Side JavaScript Review

Refer to `payloads/client-side-review.md` for detailed procedures covering:

- API key and token pattern scanning
- localStorage/sessionStorage secret analysis
- Service worker analysis
- Client-side business logic review
- Hardcoded credentials detection
- Exposed debug parameters

### Server-Side JavaScript Review (When In Scope)

```bash
# Pattern-based review for Node.js source code

# 1. Find all JavaScript/TypeScript files
find . -name "*.js" -o -name "*.ts" -o -name "*.mjs" | head -50

# 2. Search for SQL queries (injection risk)
grep -rn "query\|execute\|raw\s*(" --include="*.js" --include="*.ts" . | grep -v node_modules

# 3. Search for exec/spawn (command injection risk)
grep -rn "exec\|spawn\|execSync\|execFile" --include="*.js" --include="*.ts" . | grep -v node_modules

# 4. Search for file system operations (path traversal risk)
grep -rn "readFile\|writeFile\|createReadStream\|fs\." --include="*.js" --include="*.ts" . | grep -v node_modules

# 5. Search for eval and dynamic code execution (code injection risk)
grep -rn "eval\|Function(\|new Function\|vm\.run" --include="*.js" --include="*.ts" . | grep -v node_modules
```

---

## Secret and Credential Scanning

### Scanning Methodology

```bash
# Use git-secrets or truffleHog if available
# Otherwise, use grep-based patterns

# 1. AWS keys
grep -rn "AKIA[0-9A-Z]\{16\}" . --include="*.js" --include="*.ts" --include="*.py" --include="*.yml" --include="*.env" --include="*.json"

# 2. AWS secret keys (40-char base64)
grep -rn -E "[A-Za-z0-9/+=]{40}" . --include="*.env" --include="*.yml" --include="*.json" | grep -i "secret\|key\|aws"

# 3. Database connection strings
grep -rn "mongodb://\|mysql://\|postgres://\|postgresql://\|redis://\|amqp://" . --include="*.js" --include="*.ts" --include="*.py" --include="*.yml" --include="*.env"

# 4. Private keys
grep -rn "BEGIN (RSA |EC |DSA )\?PRIVATE KEY" . --include="*.pem" --include="*.key" --include="*.js" --include="*.yml"

# 5. JWT secrets
grep -rn "jwt.secret\|JWT_SECRET\|jwt_secret\|token.secret\|TOKEN_SECRET" . --include="*.js" --include="*.ts" --include="*.env" --include="*.yml"

# 6. API keys (generic)
grep -rn -i "api_key\|apikey\|api_secret\|api_secret_key\|APP_KEY\|APP_SECRET" . --include="*.js" --include="*.ts" --include="*.env" --include="*.yml" --include="*.json"

# 7. OAuth secrets
grep -rn -i "client_secret\|oauth_secret\|OAUTH_CLIENT_SECRET" . --include="*.js" --include="*.ts" --include="*.env" --include="*.yml"

# 8. Encryption keys
grep -rn -i "encryption_key\|ENCRYPTION_KEY\|encrypt_key\|AES_KEY\|aes-256" . --include="*.js" --include="*.ts" --include="*.env" --include="*.yml"

# 9. Passwords
grep -rn -E "(password|passwd|pwd)\s*[:=]\s*['\'][^'\"]{3,}['\"]" . --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.go"

# 2. Hardcoded API keys
grep -rn -E "(api_key|apikey|api-key|API_KEY)\s*[:=]\s*['\"][^'\"]{10,}['\"]" . --include="*.js" --include="*.ts" --include="*.py" --include="*.java"

# 3. Hardcoded encryption keys
grep -rn -E "(encryption_key|ENCRYPTION_KEY|cipher_key)\s*[:=]\s*['\"][^'\"]{10,}['\"]" . --include="*.js" --include="*.ts" --include="*.py"

# 4. Hardcoded salt values
grep -rn -E "(salt|SALT)\s*[:=]\s*['\"][^'\"]{5,}['\"]" . --include="*.js" --include="*.ts" --include="*.py"

# 5. Hardcoded IV (initialization vector)
grep -rn -E "(iv|IV|initialization_vector)\s*[:=]\s*['\"][^'\"]{10,}['\"]" . --include="*.js" --include="*.ts" --include="*.py"
```

### Language-Specific Patterns

#### Python (Django/Flask)

```python
# Patterns to search for:
SECRET_KEY = '...'                    # Django secret key
DEBUG = True                           # Debug mode
DATABASES = {'default': {...}}         # Database config with password
ALLOWED_HOSTS = ['*']                  # Wildcard hosts
CORS_ORIGIN_ALLOW_ALL = True           # CORS allow all
```

#### Node.js (Express/NestJS)

```javascript
// Patterns to search for:
const secret = '...'                  // Hardcoded secret
app.use(session({ secret: '...' }))    // Session secret
jwt.sign({...}, '...')                 // JWT secret
database.connect('mongodb://...')      // Database connection string
process.env.SECRET || 'hardcoded'      // Fallback to hardcoded value
```

#### Java (Spring Boot)

```java
// Patterns to search for:
@Value("${secret:hardcoded}")          // Default hardcoded value
spring.datasource.password=...         # Database password in config
server.ssl.key-store-password=...       # SSL key password
```

#### PHP (Laravel)

```php
// Patterns to search for:
'password' => env('DB_PASSWORD', '...')  // Fallback password
'app.key' => 'base64:...'                // App key
'debug' => true,                          // Debug mode
```

---

## Dependency Vulnerability Identification

### Known Vulnerable Dependencies

```bash
# 1. Check package.json for known vulnerable dependencies
cat package.json | jq '.dependencies, .devDependencies'

# 2. Check requirements.txt for Python dependencies
cat requirements.txt

# 3. Check pom.xml for Java dependencies
grep -E "<groupId>|<artifactId>|<version>" pom.xml

# 4. Run npm audit (if available and within scope)
npm audit --json

# 5. Run pip audit (if available and within scope)
pip-audit -r requirements.txt

# 6. Check for outdated dependencies
npm outdated --json 2>/dev/null
pip list --outdated 2>/dev/null
```

### Critical Dependency Patterns

| Dependency Type | Risk | Detection |
|----------------|------|-----------|
| lodash < 4.17.21 | Prototype pollution | `package.json` version check |
| express < 4.17.3 | Open redirect | `package.json` version check |
| jquery < 3.5.0 | XSS | `package.json` or CDN link check |
| django < 2.2.0 | Multiple CVEs | `requirements.txt` version check |
| flask < 1.0 | Debug mode risks | `requirements.txt` version check |
| spring < 5.3.0 | Multiple CVEs | `pom.xml` version check |
| log4j < 2.17.0 | RCE (Log4Shell) | `pom.xml` or `build.gradle` check |
| commons-text < 1.10.0 | RCE (Text4Shell) | `pom.xml` version check |
| moment < 2.29.2 | ReDoS | `package.json` version check |

---

## SAST Tool Integration

### Automated Scanning

When source code is provided in scope, use SAST tools if available:

```bash
# 1. Check for available SAST tools
command -v semgrep && echo "semgrep available"
command -v bandit && echo "bandit available"
command -v eslint && echo "eslint available"
command -v brakeman && echo "brakeman available"

# 2. Run semgrep (multi-language)
semgrep --config=auto --json . > semgrep_results.json

# 3. Run bandit (Python)
bandit -r . -f json -o bandit_results.json

# 4. Run eslint with security plugin (JavaScript)
npx eslint --plugin security . --format json > eslint_results.json

# 5. Run brakeman (Ruby on Rails)
brakeman -o brakeman_results.json .
```

### SAST Results Integration

1. Run SAST tool against provided source code
2. Parse results for security-relevant findings
3. Correlate SAST findings with black-box test results
4. Prioritize findings by exploitability (reachable vs unreachable code)
5. Document findings in `findings-template.md` format

### Manual Review Priority

When SAST tools are not available:

| Priority | Code Pattern | Vulnerability | Search Command |
|----------|-------------|---------------|----------------|
| P0 | `eval()`, `exec()` | Code injection | `grep -rn "eval\|exec\|Function"` |
| P0 | SQL string concatenation | SQL injection | `grep -rn "query.*+\|execute.*+"` |
| P0 | `spawn()`, `exec()` with input | Command injection | `grep -rn "spawn\|exec\|system"` |
| P1 | File path with input | Path traversal | `grep -rn "readFile\|writeFile.*+"` |
| P1 | Hardcoded secrets | Credential exposure | See secret scanning section |
| P1 | `innerHTML`, `v-html` | XSS | `grep -rn "innerHTML\|v-html\|dangerouslySetInnerHTML"` |
| P2 | Missing auth checks | Auth bypass | `grep -rn "router\|middleware\|beforeEach"` |
| P2 | Weak crypto | Crypto weakness | `grep -rn "md5\|sha1\|DES\|RC4\|ECB"` |
| P3 | Debug mode | Info disclosure | `grep -rn "DEBUG\|debug.*true\|app.debug"` |
| P3 | CSRF token missing | CSRF | `grep -rn "csrf\|csrfMiddleware\|_csrf"` |

---

## Review Checklist

### Pre-Review

- [ ] Source code scope confirmed and authorized
- [ ] Target files identified (application code, not third-party libraries)
- [ ] SAST tools checked for availability
- [ ] Review priority areas identified from fingerprint

### Secret Scanning

- [ ] Scan for hardcoded credentials in source code
- [ ] Scan for API keys and tokens
- [ ] Scan for database connection strings
- [ ] Scan for private keys and certificates
- [ ] Check `.env`, `config/`, `settings/` files for secrets
- [ ] Verify no secrets in version control history (if repository access)

### JavaScript Review (see also `payloads/client-side-review.md`)

- [ ] Client-side API keys and tokens
- [ ] localStorage/sessionStorage usage
- [ ] Client-side authentication logic
- [ ] Client-side authorization checks
- [ ] Service worker registration and logic
- [ ] Source map availability
- [ ] Hidden endpoints in JavaScript

### Input Validation

- [ ] SQL query construction (parameterized vs concatenated)
- [ ] Command execution with user input
- [ ] File path operations with user input
- [ ] Dynamic code evaluation (`eval`, `Function`)
- [ ] Deserialization of user input
- [ ] Template rendering with user input

### Authentication & Authorization

- [ ] Authentication mechanism review
- [ ] Session management implementation
- [ ] Authorization check patterns
- [ ] Role-based access control implementation
- [ ] Password storage and validation
- [ ] Token generation and validation

### Cryptography

- [ ] Weak hashing algorithms (MD5, SHA1)
- [ ] Weak encryption algorithms (DES, RC4, ECB mode)
- [ ] Hardcoded cryptographic keys
- [ ] Insecure random number generation
- [ ] SSL/TLS configuration

### Configuration

- [ ] Debug mode settings
- [ ] CORS configuration
- [ ] Security headers configuration
- [ ] Rate limiting implementation
- [ ] Error handling and information disclosure
- [ ] Logging of sensitive data

---

## Output Format

Document source code review findings using the following format:

```markdown
## Source Code Review Finding

### File
{file path}:{line number}

### Vulnerability Type
{SQL Injection / Hardcoded Secret / Insecure Crypto / etc.}

### Severity
{Critical / High / Medium / Low}

### Code Snippet
{relevant code snippet}

### Description
{What the vulnerability is and how it could be exploited}

### Recommendation
{How to fix the vulnerability}
```

---

## References

- `payloads/client-side-review.md` - Client-side JavaScript scanning procedures
- `payloads/backup-exposure.md` - Backup and source code exposure testing
- `payloads/error-handling.md` - Error handling and information disclosure
- `commands/stack-mapping.md` - Technology to vulnerability mapping
- `templates/findings-template.md` - Findings documentation format
