# WebSocket Security Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify WebSocket security vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual malicious operations are prohibited
> - WebSocket payloads are for understanding attack surface only, **do not enable harm**
> - Validation proves vulnerability existence, **no message flooding or DoS**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP WebSocket Security, HackTricks

## Manual Testing

**Note: WebSocket connections require different testing approach than HTTP**

---

## Validation Objectives (Within Security Boundary)

WebSocket security vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Cross-Origin WebSocket | ✓ Test origin header | - | Execute malicious messages |
| Authentication Check | ✓ Verify auth mechanism | - | Access other users' WebSocket |
| Message Injection | ✓ Test message format | - | Inject harmful commands |
| Input Validation | ✓ Send test payloads | - | Trigger actual exploitation |
| Rate Limiting | ✓ Observe rate behavior | ✓ Send sustained messages | DoS attack |

**Safe Validation Method**: Connect and verify authentication/authorization exists; send harmless test messages to prove input handling.

---

## Validation Tier Classification

This payload file uses a **tiered validation approach**:

| Tier | Description | Authorization |
|------|-------------|---------------|
| **Tier 1: Safe Validation** | Origin test, auth verification, harmless message probe | No authorization needed |
| **Tier 2: Authorized Extended** | Sustained rate test, message exploitation | User explicit authorization required |
| **Tier 3: Theory Reference** | DoS concepts, malicious message scenarios | For understanding only, do not execute |

**Default execution**: Only Tier 1 methods.
**Stop condition**: After confirming authentication/authorization status or input handling flaw.

---

## WebSocket Endpoint Discovery

### Common WebSocket Endpoints

```text
/ws
/socket
/chat
/realtime
/live
/stream
/ws/<channel>
/socket.io (Socket.IO library)
/cable (Action Cable - Rails)
/graphql (GraphQL subscriptions)
```

### WebSocket Detection

```bash
# Check for WebSocket upgrade in HTTP response
curl -i "https://example.com/ws"
# Look for: Upgrade: websocket, Connection: Upgrade

# Use tools
httpx -u https://example.com -ws
nuclei -u https://example.com -tags websocket
```

---

## Cross-Origin WebSocket Connection

### Origin Header Test

**Tier 1: Safe Validation**

```javascript
// Connect from different origin
const ws = new WebSocket('wss://api.example.com/ws');

// Or specify custom origin via header manipulation
// Some servers validate origin, some don't

// Test: Connect from arbitrary origin
// curl/httpx cannot easily test WebSocket
// Use browser console or specialized tools
```

```bash
# Using wscat (if available)
wscat -c "wss://api.example.com/ws" \
      -H "Origin: https://evil.com"

# Vulnerable: Connection established with arbitrary origin
# Protected: Connection rejected or closed
```

**Analysis**:
- If server accepts any origin -> Cross-Origin WebSocket possible
- Attacker can connect from evil.com and send/receive messages
- Can lead to CSRF-like attacks via WebSocket

---

## WebSocket Authentication

### Missing Authentication

**Tier 1: Safe Validation**

```javascript
// Connect without any credentials
const ws = new WebSocket('wss://api.example.com/ws');

ws.onopen = () => {
  console.log('Connected without auth');
  ws.send('test');
};

ws.onmessage = (event) => {
  console.log('Received:', event.data);
};

// Vulnerable: Connection works, receives messages
// Protected: Connection rejected or no sensitive data returned
```

### Token in URL Path

```javascript
// WebSocket with token in path
const ws = new WebSocket('wss://api.example.com/ws/<token>');

// Test: Try without token or with invalid token
const ws2 = new WebSocket('wss://api.example.com/ws/invalid_token');
```

### Token in Query Parameter

```javascript
// WebSocket with token in query
const ws = new WebSocket('wss://api.example.com/ws?token=<valid_token>');

// Test: Try without token
const ws2 = new WebSocket('wss://api.example.com/ws?token=invalid');
```

### Token in Message (After Connection)

```javascript
// Authenticate via message after connection
const ws = new WebSocket('wss://api.example.com/ws');

ws.onopen = () => {
  // Try sending messages before auth
  ws.send(JSON.stringify({action: "get_data"}));
  
  // Vulnerable: Server responds without auth message
  // Protected: Server rejects or ignores
};
```

---

## WebSocket Message Injection

### JSON Message Injection

**Tier 1: Safe Validation**

```javascript
// Test message handling with harmless payload
const ws = new WebSocket('wss://api.example.com/ws');

ws.onopen = () => {
  // Try different message formats
  ws.send(JSON.stringify({type: "ping"}));
  ws.send(JSON.stringify({type: "test", data: "safe_value"}));
  
  // Try type confusion
  ws.send(JSON.stringify({type: ["ping"]}));  // Array instead of string
  ws.send(JSON.stringify({type: 123}));       // Number instead of string
};
```

### Message Parameter Tampering (Requires Authorization)

**Tier 2: Authorized Extended**

```javascript
// Test parameter tampering - requires authorization
// Example: Chat system, try sending to other user_id
ws.send(JSON.stringify({
  action: "send_message",
  user_id: "other_user_id",  // IDOR via WebSocket
  message: "test"
}));

// Example: Gaming, try modifying score
ws.send(JSON.stringify({
  action: "update_score",
  score: 999999
}));
```

---

## WebSocket Input Validation

### XSS via WebSocket Message

**Tier 1: Safe Validation (Server Response Check)**

```javascript
// Send XSS payload, check if server echoes it
ws.send(JSON.stringify({message: "<script>alert(1)</script>"}));

ws.onmessage = (event) => {
  // Check if response contains unescaped payload
  console.log(event.data);
  
  // Vulnerable: Response contains raw <script> tag
  // Protected: Response has escaped &lt;script&gt;
};
```

### SQL Injection via WebSocket

```javascript
// Send SQLi payload via WebSocket
ws.send(JSON.stringify({search: "test' OR '1'='1"}));

ws.onmessage = (event) => {
  // Check for SQL error in response
  console.log(event.data);
  
  // Vulnerable: SQL syntax error returned
  // Protected: No error or sanitized response
};
```

---

## WebSocket Rate Limiting

### Rate Limit Test (Requires Authorization)

**Tier 2: Authorized Extended**

```javascript
// Send many messages quickly - requires authorization
// Purpose: Check if rate limiting exists

for (let i = 0; i < 100; i++) {
  ws.send(JSON.stringify({type: "ping"}));
}

// Vulnerable: All 100 accepted, no rate limit
// Protected: Connection throttled or closed
```

**Note**: Sustained message flooding -> DoS risk, requires authorization.

---

## WebSocket Hijacking

### Session Hijacking (Theory Reference)

```javascript
// If WebSocket uses cookie-based auth and no origin check
// Attacker can connect from evil.com using victim's cookies
// This is CSRF-equivalent for WebSocket

// Theory reference only - do not execute
// 1. Victim visits evil.com
// 2. evil.com opens WebSocket to target
// 3. Browser sends cookies with WebSocket upgrade request
// 4. evil.com can send/receive messages on behalf of victim
```

---

## WebSocket vs HTTP Comparison

| Aspect | HTTP | WebSocket |
|--------|------|-----------|
| Connection | Request-response | Persistent bidirectional |
| Authentication | Headers, cookies | Headers + first message |
| CSRF Protection | SameSite, tokens | Origin header check |
| Rate Limiting | Per-request | Per-connection or per-message |
| Testing Tool | curl, httpx | wscat, browser console |

---

## Analysis Process

### Tier 1: Default Validation

1. Identify WebSocket endpoints (URL patterns, HTTP upgrade)
2. Test cross-origin connection (arbitrary origin)
3. Test authentication requirement (connect without credentials)
4. Send harmless test messages, observe response handling
5. Check input validation (XSS/SQLi payloads in messages)
6. **Stop validation**, document authentication/authorization status

### Tier 2: Authorized Extended (Requires Authorization)

7. Message parameter tampering (IDOR via WebSocket)
8. Rate limit testing (sustained messages)
9. Exploit confirmed vulnerabilities

---

## Severity Classification

WebSocket vulnerability severity is based on **actual sensitivity exposed by unauthenticated/unvalidated endpoints** — not on "missing itself".

| WebSocket Vulnerability | Default | Upgrade condition |
|-------------------------|------|---------|
| Missing authentication | Medium | -> High: Only when unauthenticated endpoint can trigger sensitive operations/privilege escalation/read-write sensitive data. Public data = Medium, no-value data = Low |
| Missing origin validation | Medium | -> High: Only when cross-origin can trigger sensitive operations (modify data/execute commands). Connection-only with no sensitive action = Medium |
| XSS in message handling | Medium | -> High: Stored type and execution confirmed (same dom-xss caliber, requires authorization to verify execution)|
| SQLi via message | Medium | -> High: Requires confirming injection can extract data/bypass (same sqli caliber, injection point only = Medium)|
| IDOR via message | Medium | -> High: Can access others' sensitive resources (same idor caliber)|
| Missing rate limiting | Low | -> Medium: Brute-force/DoS feasible and achieved (same rate-limiting caliber)|

**Key judgment**: WebSocket "missing authentication/missing origin" is a configuration flaw, but exploitation value depends on the functionality exposed by the endpoint. Reporting High requires confirming the flaw can be exploited to achieve specific harm (sensitive data/privilege escalation/execution). Proof only of unauthenticated connection records Medium or below.

---

## Tools

| Tool | Usage |
|------|-------|
| wscat | CLI WebSocket client |
| websocat | CLI WebSocket client (more features) |
| Burp Suite | WebSocket interception and replay |
| browser console | Quick manual testing |
| httpx | WebSocket endpoint detection |
| nuclei | WebSocket vulnerability templates |

---

## Output

```markdown
## Vulnerability: WebSocket Security Issue

### Location
wss://api.example.com/ws

### Vulnerability Type
{Missing Authentication / Missing Origin Validation / XSS via Message}

### Proof Payload
Origin: https://evil.com (connection accepted)

### Validation Result
- Origin check: Not enforced
- Authentication: Not required
- Response: Contains sensitive data without auth

### Risk Level
{High} - Cross-origin WebSocket attack possible
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Message flooding | Do not send sustained messages without authorization |
| ❌ DoS attack | Do not cause service disruption |
| ❌ Malicious commands | Do not execute harmful actions via WebSocket |
| ❌ Access other users' connection | Do not hijack sessions |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Prove existence, do not enable harm"
- `templates/severity-classification.md` -> WebSocket severity rules