# Deserialization Vulnerability Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized penetration testing reference** only, helping identify deserialization vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual RCE execution is prohibited
> - Deserialization payloads are for understanding attack surface only, **no system control obtained**
> - Validation proves vulnerability existence (deserialization occurs), **no malicious payload execution**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Java, PHP, Python, .NET deserialization have different detection methods**

---

## Validation Objectives (Within Security Boundary)

Deserialization vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Deserialization Detection | ✓ Send serialized test object | - | RCE payload execution |
| Framework Identification | ✓ Identify serialization format | - | Exploit known gadget chain |
| Class/Type Control | ✓ Test if class is controllable | - | Load malicious class |
| Safe Gadget Test | ✓ Use harmless payload (DNS ping) | ✓ Time delay proof | Reverse shell/RCE |
| Gadget Chain Exploitation | ❌ Not by default | ✓ Requires explicit authorization | Malicious code execution |

**Safe Validation Method**: Prove deserialization occurs using harmless markers (DNS ping, time delay); do not execute RCE payloads without authorization.

---

## Serialization Format Detection

### Java Serialization

```bash
# Java serialized object starts with magic bytes: 0xac 0xed
# Check raw bytes or base64 decoded content

echo "<base64_payload>" | base64 -d | xxd | head -1
# If starts with ac ed -> Java serialization

# Content-Type indicators
Content-Type: application/x-java-serialized-object
X-Serialization: java
```

### PHP Serialization

```bash
# PHP serialized format: O:..."className":... or s:..."string"
# Check for patterns

curl -s <url> | grep -E 'O:\d+:|s:\d+:|a:\d+:'

# Cookie/session data often PHP serialized
# Example: O:8:"UserClass":1:{s:4:"name";s:4:"test";}
```

### Python Pickle

```bash
# Python pickle specific markers
# Check base64 decoded content

echo "<base64_payload>" | base64 -d | xxd | head -5
# Pickle protocol markers present

# Content-Type indicator
Content-Type: application/python-pickle
```

### .NET / JSON.NET

```bash
# .NET serialized types often include full class name
# Check for patterns like:

${type:...}
$type$assembly
__type
```

---

## Java Deserialization

### Safe Detection Payload

```bash
# DNS ping payload (harmless, proves deserialization)
# Using ysoserial (if available)
java -jar ysoserial.jar URLDNS "http://YOUR_COLLABORATOR/dns-test" | base64

# Send in request
curl -X POST <url> -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser

# If DNS callback received -> deserialization occurs
```

### Common Frameworks with Vulnerabilities

| Framework | Gadget Chain | Detection |
|-----------|--------------|-----------|
| Apache Commons Collections | CommonsCollections1-7 | Version check |
| Spring | SpringPartiallyComparableAdvisorHolder | Dependency analysis |
| Fastjson | Fastjson1-2 | JSON with @type |
| Jackson | JacksonPolymorphic | enableDefaultTyping check |
| WebLogic | WebLogicT3 | T3 protocol detection |

### Fastjson Detection

```json
// Send harmless JSON with @type to check if processed
{"@type":"java.net.URL","val":"http://YOUR_COLLABORATOR/fastjson-test"}

// If DNS callback received -> Fastjson deserialization occurs
```

---

## PHP Deserialization

### Safe Detection Payload

```php
// PHP serialization test object (harmless)
O:8:"stdClass":1:{s:4:"test";s:4:"mark";}

// Send in cookie or parameter
Cookie: session=O:8:"stdClass":1:{s:4:"test";s:4:"mark";}
```

### Object Injection Test

```php
// Test if object instantiation is controllable (harmless class)
O:9:"Exception":1:{s:7:"message";s:4:"test";}

// If accepted and error shows -> object injection possible
```

### Magic Method Detection

```php
// PHP classes with magic methods (__wakeup, __destruct) are exploitable
// Check class definition if accessible

// Test payload structure
O:8:"UserClass":2:{s:4:"name";s:4:"test";s:6:"admin";b:1;}
```

---

## Python Pickle

### Safe Detection Payload

```python
# Python pickle harmless payload
import pickle
import base64

class TestObj:
    def __reduce__(self):
        return (str, ("pickle-test-mark",))

payload = pickle.dumps(TestObj())
print(base64.b64encode(payload).decode())

# Send and observe if "pickle-test-mark" appears anywhere
```

### ⚠️ Time Delay Test (Requires Authorization)

```python
# Only with authorization - proves code execution capability
import pickle
import base64
import time

class SleepTest:
    def __reduce__(self):
        return (time.sleep, (5,))

payload = pickle.dumps(SleepTest())
# If response delayed 5s -> pickle code execution confirmed
```

---

## .NET Deserialization

### JSON.NET Detection

```json
// Test if $type handled
{
  "$type": "System.Uri",
  "value": "http://YOUR_COLLABORATOR/net-test"
}

// If DNS callback -> polymorphic deserialization enabled
```

### ViewState Detection (ASP.NET)

```bash
# Check for ViewState parameter
curl -s <url> | grep -E "VIEWSTATE|__VIEWSTATE"

# ViewState is often serialized; check MAC validation
# If no MAC -> ViewState deserialization vulnerable
```

---

## Analysis Process

1. Identify serialization format from content-type, magic bytes, or patterns
2. Identify framework/library used (from fingerprint or dependency hints)
3. Send harmless detection payload (DNS ping, test object)
4. Observe response/callback to confirm deserialization occurs
5. **Stop validation**, confirm vulnerability exists
6. If gadget chain exploitation needed, obtain explicit authorization first

---

## Output

```markdown
## Vulnerability: Unsafe Deserialization

### Location
{URL} - {parameter/endpoint}

### Serialization Type
{Java/PHP/Python/.NET}

### Framework/Library
{Apache Commons Collections / Fastjson / Jackson / PHP unserialize}

### Evidence
- Serialized format detected: {magic bytes/pattern}
- DNS callback: {received/not received}
- Test payload accepted: {yes/no}

### Risk Level
{see severity rules}

### Severity Classification

Deserialization findings must distinguish "**a deserialization point exists**" from "**deserialization leads to confirmed RCE**". The two often diverge: input may reach a deserializer, but no usable gadget chain exists, a blacklist blocks the gadget, or the impact cannot be proven. **High severity requires confirmed RCE; otherwise record Low.**

| Actual case | Severity | Note |
|---------|------|------|
| Explicit user authorization for RCE verification, and code execution is confirmed | **High** | Gadget chain is closed; RCE is real |
| Deserialization point confirmed, but no usable gadget / gadget blocked / RCE not verified | **Low** | Design flaw, but current exploitability is unproven. Do not report High based on "a gadget may exist" |
| Only deserialization behavior observed, controllable input uncertain | Low | Pending confirmation |

**Boundary coordination**: This file's Prohibited Operations prohibits RCE execution by default. Therefore within default testing scope, deserialization issues are always Low — do not report High even if a gadget is suspected. "Confirmed RCE = High" requires **explicit user authorization to execute RCE verification** (Tier 2 authorized operation); record High only after RCE succeeds within the authorized scope, and record the gadget and verification method used. Do not increase severity based on speculative RCE possibility without authorization.
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ RCE execution | Do not execute reverse shell, command, or malicious code |
| ❌ File read/write | Do not use gadget chain for file operations without authorization |
| ❌ Privilege escalation | Do not execute payloads for system-level access |
| ❌ Gadget chain exploitation | Requires explicit authorization before use |
| ❌ DoS payloads | No fork bomb, memory exhaustion, or crash payloads |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "File upload, RCE, reverse shell | Do not execute"
