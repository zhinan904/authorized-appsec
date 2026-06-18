# File Upload Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify file upload vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual execution prohibited
> - Webshell/command execution code for understanding attack surface only, **not as actual exploitation tool**
> - Actual validation only proves vulnerability existence, **no malicious operations**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Objectives (Within Security Boundary)

File upload vulnerability validation core objective is **proving existence**, not obtaining execution capability:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Extension Bypass | ✓ Construct request to prove bypass | - | Upload actual webshell |
| Content-Type Bypass | ✓ Modify header to prove bypass | - | Upload executable file |
| File Header Bypass | ✓ Construct polyglot to prove bypass | - | Upload and access for execution |
| Path Controllable | ✓ Prove path controllable via response | - | Use path to write file |
| Upload & Execute | ❌ Not by default | ✓ Requires explicit authorization | Malicious payload execution |

---

## File Extension Bypass (Proof Method)

### PHP Extension Bypass Test
```bash
# Test request - prove extension filter bypassable
# Upload test.jpg.php or test.php%00.jpg
# Observe: Successfully saved? Save path? Accessible?
curl -X POST -F "file=@test.txt;filename=test.php.jpg" {URL}

# Security boundary: Only send request, observe response, no access to upload result
```

### Bypass Method List (For Constructing Test Requests)

| Bypass Type | Payload Example | Description |
|----------|-------------|------|
| Case | shell.pHp, shell.PHP5 | PHP case bypass |
| Double | shell.phphpp | After filter becomes shell.php |
| Space/Dot | shell.php. shell.php | Windows feature |
| NTFS Stream | shell.php::$DATA | Windows NTFS ADS |
| Null Byte | shell.php%00.jpg | PHP<5.3.4 |
| Alternative Extension | shell.phtml, shell.php5 | PHP alternative extension |
| Parse Vulnerability | shell.php.xxx | Apache/Nginx parsing |

### JSP Extension
| Bypass Type | Payload Example |
|----------|-------------|
| Alternative Extension | shell.jsp, shell.jspx, shell.jspf |
| Null Byte | shell.jsp%00 |
| Mixed | shell.txt.jsp |

### ASP/ASPX Extension
| Bypass Type | Payload Example |
|----------|-------------|
| Alternative Extension | shell.asp, shell.aspx, shell.asa, shell.cer |
| Semicolon | shell.asp;shell.jpg |
| NTFS Stream | shell.asp::$DATA |

---

## Content-Type Bypass Test

```bash
# Test request - prove Content-Type validation bypassable
curl -X POST \
  -H "Content-Type: multipart/form-data" \
  -F "file=@test.php;type=image/jpeg" \
  {URL}

# Security boundary: Only send request observe response, no execution of uploaded file
```

**Content-Types to Try**:
- `image/jpeg` / `image/png` / `image/gif`
- `text/plain` / `application/octet-stream`

---

## Magic Bytes (File Header) Bypass Test

```bash
# Construct test file with file header - prove file content detection bypassable
echo -e '\x89PNG\r\n\x1a\n<?php echo "test"; ?>' > test.png

# Security boundary: File content contains no actual execution code, only harmless echo
curl -X POST -F "file=@test.png;filename=test.php" {URL}
```

**Common File Headers**:
- PNG: `\x89PNG\r\n\x1a\n`
- JPEG: `\xff\xd8\xff`
- GIF: `GIF89a`
- BMP: `BM`

---

## Config File Upload Test (Proof Method)

### .htaccess (Apache)
```bash
# Test request - prove config file uploadable
curl -X POST -F "file=@.htaccess" {URL}

# .htaccess content (harmless validation)
AddType application/x-httpd-php .test

# Security boundary: .test extension has no actual harm, only proves config file uploadable
```

### web.config (IIS)
```xml
<!-- Test content - prove config file uploadable -->
<configuration>
  <system.webServer>
    <handlers>
      <add name="test" path="*.test" verb="*" />
    </handlers>
  </system.webServer>
</configuration>
```

---

## Analysis Process

1. Upload point identification (form/API)
2. Normal file upload test (establish baseline)
3. Extension restriction detection (blacklist/whitelist)
4. Content-Type restriction detection
5. File content restriction detection (file header)
6. Save path analysis
7. Construct bypass payload (prove bypassable)
8. Confirm save path controllable

---

## Output Format

```markdown
## Vulnerability: File Upload Bypass

### Location
{URL}

### Bypass Type
{extension/Content-Type/file header/config file}

### Proof Payload
```http
POST {URL}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="{bypass filename}"
Content-Type: {bypass Content-Type}

{file content}
------WebKitFormBoundary--
```

### Save Path
{server returned save path}

### Risk Level
{see severity rules}

### Severity Classification

File upload harm depends on **whether the uploaded file can be parsed/executed or overwrite critical files**. Upload succeeding is only the first step — many upload points store files to object storage, CDN, or rename them, never executing. **Severity is based on actual post-upload reachability.**

| Actual case | Severity | Note |
|---------|------|------|
| after user authorization confirmed uploaded script is parsed and executed by server (webshell accessible and executes commands)| **High** | upload -> RCE chain closure (RCE live verification requires authorization) |
| Upload succeeds and file is directly accessible (same-origin URL reachable), but execution not verified (default testing scope)| **Medium** | upload is reachable, executioncapability not confirmed |
| Upload succeeds but file unreachable (Path inaccessible / stored in isolation / renamed unknown)| Low | Upload point exists but not exploitable |
| Can overwrite existing server files (e.g. .htaccess / configuration file)| **High** | Overwriting configuration can cause configuration injection/RCE |
| Only upload request accepted (response 200)but cannot confirm actual storage | Low | Pending confirmation |

**Boundary coordination**: Verifying whether an uploaded file executes (accessing the webshell) is a destructive operation and requires user authorization. Default testing only sends the upload request and observes the response; do not access the execution result — therefore the default scope is at most Medium. "Execution confirmed = High" requires user authorization to verify. Do not report Critical based on "upload 200" alone.
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Upload actual webshell | Only construct proof request |
| ❌ Access uploaded executable file | Only observe response |
| ❌ Execute command validation | Only prove vulnerability existence |
| ❌ Persistence implant | No persistence operations |
| ❌ Reverse shell | Strictly prohibited |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "1-click prohibited"
- `README.md` -> Prohibited execution checklist