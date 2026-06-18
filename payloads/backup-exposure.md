# Backup & Source Code Exposure Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify backup and source code exposure vulnerability risk characteristics.
>
> - All testing is **limited to proving existence** of exposed files, no content exploitation
> - Backup file discovery is for understanding exposure only, **no credential or config extraction**
> - Validation proves file is accessible, **no downloading of sensitive content**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings, SecLists

## Manual Testing

**Note: Check for backup/source file patterns, confirm accessibility only**

---

## Validation Objectives (Within Security Boundary)

Backup and source code exposure vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| .git Directory Exposure | ✓ Check if .git accessible | - | Download full repository |
| .env File Exposure | ✓ Check if .env accessible | - | Extract database credentials |
| Backup File Detection | ✓ Detect .bak/.old/.zip files | - | Download and extract sensitive content |
| Configuration File Access | ✓ Check config file accessibility | - | Read database credentials |
| Directory Listing | ✓ Confirm listing enabled | - | Enumerate all files |
| Source Code Disclosure | ✓ Check for source exposure | - | Read application source |

**Safe Validation Method**: Check HTTP status code and headers to confirm file existence. Do not download or read sensitive file contents.

---

## .git Directory Exposure

### Git Directory Detection

```bash
# Check for .git directory exposure
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.git/HEAD"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.git/config"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.git/HEAD"

# If 200: .git directory is exposed
# HEAD file content indicates repository exists
curl -s "https://target.com/.git/HEAD"

# Check for .gitignore (confirms git usage)
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.gitignore"
```

### Git Repository Reconstruction (Proof Only)

```bash
# ⚠️ Do NOT download full repository - only confirm exposure

# Check ref structure
curl -s "https://target.com/.git/refs/heads/main"
curl -s "https://target.com/.git/refs/heads/master"

# Check objects (confirms repository data exists)
curl -s "https://target.com/.git/objects/pack/" | head -20

# Check commit log (proves data exists)
curl -s "https://target.com/.git/logs/HEAD" | head -5

# Document: .git directory exposed, repository data accessible
# Do NOT: dmitry or git-dumper to clone entire repository
```

---

## .svn Directory Exposure

```bash
# Check for .svn directory
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.svn/entries"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.svn/wc.db"

# If 200: SVN directory is exposed
curl -s "https://target.com/.svn/entries" | head -10
```

---

## .env File Exposure

```bash
# Check for .env files
for env_file in ".env" ".env.local" ".env.production" ".env.staging" ".env.development" ".env.test"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${env_file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[!] FOUND: /${env_file} -> ${status}"
  fi
done

# ⚠️ Do NOT read .env content - only confirm existence
# If exposed, report as Critical: "Database credentials, API keys, and secrets may be exposed"

# Check response size to confirm it's a real .env file (not 404 page)
curl -sI "https://target.com/.env" | grep -i "content-length\|content-type"
```

---

## Backup File Patterns

### Common Backup Extensions

```bash
# Check backup patterns for common files
for file in "index.php" "config.php" "web.config" "application.yml" "database.yml" ".htaccess" "wp-config.php"; do
  for ext in ".bak" ".old" ".orig" ".copy" ".tmp" ".save" ".swp" ".swo" "~" ".zip" ".tar" ".tar.gz" ".rar" ".7z" ".sql" ".db" ".bak2"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}${ext}" 2>/dev/null)
    if [ "$status" == "200" ]; then
      echo "[+] /${file}${ext} -> ${status}"
    fi
  done
done
```

### Filename Variations

```bash
# Check common backup filename patterns
for backup in "backup.sql" "backup.zip" "backup.tar.gz" "db.sql" "database.sql" "dump.sql" "site.zip" "www.zip" "web.zip" "backup.tar" "db.backup" "wwwroot.zip"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${backup}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${backup} -> ${status}"
  fi
done

# Check root-level backup patterns
for path in "/" "/backup/" "/backups/" "/db/" "/database/" "/sql/" "/dumps/" "/old/" "/archive/" "/temp/" "/tmp/"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] ${path} -> ${status}"
  fi
done
```

---

## Configuration File Access

### Framework Configuration Files

```bash
# Web.config (ASP.NET)
curl -s -o /dev/null -w "%{http_code}" "https://target.com/web.config"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/Web.config"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/Web.Config"

# Spring Boot / Java
for file in "application.yml" "application.properties" "application-dev.yml" "application-prod.yml" "bootstrap.yml"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done

# Django / Python
for file in "settings.py" "settings.py.bak" "local_settings.py" ".env"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done

# Laravel / PHP
for file in ".env" ".env.bak" ".env.local" "config.php" "database.php" ".htaccess" "wp-config.php" "wp-config.php.bak"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done

# Ruby on Rails
for file in "config/database.yml" "config/secrets.yml" "config/credentials.yml.enc"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done
```

### .htaccess Exposure

```bash
# Check for .htaccess exposure
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.htaccess"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.htpasswd"

# Check .htaccess in subdirectories
for dir in "admin" "api" "uploads" "images" "static"; do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/${dir}/.htaccess"
done
```

---

## Directory Listing

```bash
# Check for directory listing
for dir in "/" "/admin/" "/backup/" "/config/" "/data/" "/uploads/" "/static/" "/files/" "/images/" "/docs/" "/temp/" "/logs/"; do
  response=$(curl -s "https://target.com${dir}" 2>/dev/null)
  if echo "$response" | grep -qiE "Index of|directory listing|parent directory|<title>.*index"; then
    echo "[!] Directory listing enabled: ${dir}"
  fi
done

# Check for directory listing indicators
curl -s "https://target.com/uploads/" | grep -iE "Index of|parent directory|<a href=\".*\/\">"
```

---

## Source Code Disclosure

### Source Code Exposure Patterns

```bash
# PHP source exposure via double extension
curl -s -o /dev/null -w "%{http_code}" "https://target.com/index.php.bak"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/index.php~"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/index.phps"

# ASP.NET source via backup extensions
curl -s -o /dev/null -w "%{http_code}" "https://target.com/default.aspx.cs"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/default.aspx.bak"

# Java source files
curl -s -o /dev/null -w "%{http_code}" "https://target.com/WEB-INF/web.xml"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/META-INF/MANIFEST.MF"

# Check for source map files
curl -s -o /dev/null -w "%{http_code}" "https://target.com/static/js/main.js.map"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/assets/app.js.map"
```

### Sensitive File Patterns

```bash
# Common sensitive files
for file in "robots.txt" "sitemap.xml" "crossdomain.xml" "clientaccesspolicy.xml" ".well-known/security.txt" "CONTRIBUTING.md" "README.md" "CHANGELOG.md" "HISTORY.md"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done

# Docker files
for file in "Dockerfile" "docker-compose.yml" "docker-compose.yaml" ".dockerignore"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done

# CI/CD files
for file in ".gitlab-ci.yml" "Jenkinsfile" ".travis.yml" "bitbucket-pipelines.yml" ".github/workflows/deploy.yml"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${file}" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] /${file} -> ${status}"
  fi
done
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A01:2021-Broken Access Control |
| OWASP Web | A05:2021-Security Misconfiguration |
| CWE | CWE-538: File and Directory Information Exposure |
| CWE | CWE-540: Inclusion of Sensitive Information in Source Code |
| CWE | CWE-552: Files or Directories Accessible to External Parties |

---

## Analysis Process

1. Check for .git/.svn directory exposure (most critical)
2. Enumerate .env files and configuration files
3. Test backup file patterns for common files
4. Scan for source code disclosure patterns (double extensions, source maps)
5. Test for directory listing on common directories
6. Check for sensitive metadata files (robots.txt, sitemap.xml)
7. Verify file accessibility via HTTP status codes only
8. **Stop validation**, report file existence without reading sensitive content

---

## Output

```markdown
## Vulnerability: Backup / Source Code Exposure

### Location
{URL} - {file path}

### Type
{.git Directory / .env File / Backup File / Config File / Directory Listing / Source Code}

### Evidence
- File accessible: {path} -> {status code}
- Content type: {from response headers}
- Content length: {from response headers}

### Validation Result
- .git directory exposed: {yes/no}
- .env file exposed: {yes/no}
- Backup file found: {yes/no, path}
- Config file exposed: {yes/no, path}
- Directory listing: {yes/no}
- Source code disclosure: {yes/no}

### Risk Level
{see severity rules}

### Severity Classification

Backup/sensitive file exposure impact depends on**file content sensitivity**. directly exploitable (keys/credentials/source code)is required for high severity; ordinary backups/directory listings are only information disclosure. 

| Exposed file type | Severity | Note |
|------------|------|------|
| `.env` / configuration file contains keys/database credentials/API keys | **High** | credentials are directly exploitable |
| source code archive / `.git` / `.svn` / database backup | **High** | source code can be used to find vulnerabilities, database contains user data |
| `web.config` / `wp-config` contains connection strings | **High** | same as above, credentials are exploitable |
| Directory listing (Directory listing)| Medium | exposes file structure, assists discovery |
| ordinary backups/logs/temporary files (without sensitive content)| Low | information disclosure without direct impact |
| empty files/example files/harmless static resources | Info/Low | no value |

**Key judgment**: Reporting High requires confirming the disclosed file **contains exploitable sensitive content** (credentials/source code/user data). File is reachable but content is harmless, record Low. Boundary note: finding a reachable `.env` is High (no need to prove by reading content — reachability means attackers can read it), but actually reading content is Tier 2.

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Download full .git repository | Only confirm .git directory is accessible |
| ❌ Read .env content | Only confirm file exists, do not extract credentials |
| ❌ Extract backup content | Only confirm file is downloadable |
| ❌ Read source code | Only confirm source code is accessible |
| ❌ Read database configs | Only confirm config file exposure, do not extract credentials |
| ❌ List all files via directory listing | Only confirm listing is enabled |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Do not read sensitive file content"
- `README.md` -> Prohibited execution checklist