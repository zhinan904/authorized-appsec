# Modern Authentication Workflows

> Load this file when the target uses OTP, slider CAPTCHA, SMS, QR-code scan, SSO, PKCE, or MFA flows that require session acquisition before testing.

---

## Purpose

Standard HTTP Basic/Bearer + cookie sessions are insufficient for 2025+ targets. This reference covers session acquisition workflows for modern Chinese and international authentication patterns so that the operator can obtain a valid session before Phase 3 validation begins.

---

## Workflow Decision Tree

```
Target login page
  │
  ├── HTML form (username/password)?
  │   ├── Standard POST → proceed with sessions/anonymous→user
  │   ├── + CAPTCHA (slider/rotate/select)?
  │   │   └── See §1: CAPTCHA Handling
  │   ├── + SMS/Email OTP?
  │   │   └── See §2: OTP Flows
  │   └── + MFA (TOTP/app push)?
  │       └── See §3: MFA Flows
  │
  ├── QR Code / Scan login?
  │   ├── WeChat Work?
  │   ├── DingTalk?
  │   ├── Feishu?
  │   └── See §4: Scan Login Flows
  │
  ├── SSO redirect?
  │   ├── SAML?
  │   ├── OIDC + PKCE?
  │   ├── OAuth2 implicit/authorization code?
  │   └── See §5: SSO Flows
  │
  └── API key / JWT in localStorage?
      └── Extract from browser DevTools
```

---

## 1. CAPTCHA Handling

### Slider CAPTCHA

**Common Chinese providers**: GeeTest, NetEase YiDun, Tencent Captcha, Alibaba Captcha

```bash
# Strategy 1: Manual solve + token extraction
# 1. Open browser DevTools → Network tab
# 2. Solve the slider manually
# 3. Capture the validate callback request
# 4. Extract the captcha_token from the response

# Strategy 2: Playwright/Puppeteer automation (if installed)
# Use headless browser to handle slider

# Strategy 3: API direct call (bypass frontend)
# Some APIs accept requests without captcha_token
# Test: send login request without captcha field
curl -X POST https://{target}/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}'
# If 200 → captcha enforcement is frontend-only (finding)
```

### CAPTCHA bypass patterns

| Technique | When | Method |
|---|---|---|
| Omit captcha field | Frontend-only enforcement | POST without captcha_token parameter |
| Reuse token | Token not bound to session | Capture one token, replay with different credentials |
| Enumerate token | Predictable token format | Analyze token structure (timestamp+random?) |
| API bypass | Different endpoints for web vs API | Test mobile API endpoints that may skip captcha |
| Expired token reuse | Server doesn't validate expiry | Use an old but valid captcha_token |

---

## 2. OTP Flows (SMS / Email)

### Session acquisition

```bash
# 1. Request OTP
curl -X POST https://{target}/api/sms/send \
  -H "Content-Type: application/json" \
  -d '{"phone":"<authorized_test_phone>"}'

# 2. Enter OTP manually (provided by authorized test user)
curl -X POST https://{target}/api/login/sms \
  -H "Content-Type: application/json" \
  -d '{"phone":"<authorized_test_phone>","code":"123456"}'

# 3. Capture token from response
# Response: {"token": "eyJ...", "refresh_token": "eyJ..."}
```

### OTP vulnerability checks (Phase 3)

| Check | Method | Expected (secure) |
|---|---|---|
| OTP brute force | Try 000000-999999 with automation | Rate limited after 3-5 attempts |
| OTP reuse | Submit same OTP twice | Second attempt rejected |
| OTP no expiry | Wait 30 min, use same OTP | Expired |
| OTP in response | Check SMS send API response | OTP not in response body |
| OTP for other user | Request OTP for user B with user A session | Cannot request for others |
| OTP enumeration | Different response for valid/invalid phone | Same response for all |
| OTP bypass | Send empty code or "000000" | Rejected |

---

## 3. MFA Flows

### TOTP (Google Authenticator / Microsoft Authenticator)

```bash
# If authorized test account has TOTP configured:
# Use pyotp to generate valid codes
pip install pyotp

python3 -c "
import pyotp
totp = pyotp.TOTP('<base32_secret>')  # Provided by authorized user
print(totp.now())
"
```

### MFA bypass checks

| Check | Method | Expected (secure) |
|---|---|---|
| MFA skip | Add `?mfa_bypass=true` or omit mfa_code | MFA enforced |
| Backup code reuse | Use same backup code twice | Rejected |
| MFA disable without re-auth | Navigate to /settings/security/mfa/disable | Requires current password |
| Rate limit on MFA code | Brute force 6-digit codes | Rate limited after 3-5 attempts |
| MFA not enforced on all paths | Access sensitive API without completing MFA | All sensitive paths require MFA |
| Session before MFA | Check if session token is valid before MFA complete | Token invalid until MFA done |

---

## 4. Scan Login (QR Code)

### WeChat Work

```bash
# Flow:
# 1. GET /api/qr/connect → returns QR code URL + state token
# 2. User scans with WeChat Work app
# 3. Browser polls: GET /api/qr/status?state={state}
# 4. Status changes: waiting → scanned → confirmed
# 5. On confirmed: GET /api/qr/callback?code={auth_code}&state={state}
# 6. Server exchanges auth_code for access_token + user info

# Manual acquisition:
# 1. Open login page in browser
# 2. Scan QR code with authorized WeChat Work account
# 3. Open DevTools → Application → Cookies/LocalStorage
# 4. Copy access_token / session cookie

# Automated (if headless browser available):
# 1. Open QR code page
# 2. Extract QR code URL
# 3. Authorized user scans (manual step)
# 4. Poll for confirmation
# 5. Extract token from callback response
```

### DingTalk

```bash
# Similar flow, different OAuth endpoints:
# Authorization URL:
https://login.dingtalk.com/oauth2/auth?redirect_uri={callback}&response_type=code&client_id={appkey}&scope=openid&state={state}&prompt=consent

# Token exchange:
POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken
{"clientSecret": "{appsecret}", "code": "{authcode}", ...}
```

### Feishu

```bash
# Authorization URL:
https://open.feishu.cn/open-apis/authen/v1/authorize?app_id={app_id}&redirect_uri={callback}&state={state}

# Token exchange:
POST https://open.feishu.cn/open-apis/authen/v1/oidc/access_token
Authorization: Bearer {app_access_token}
{"grant_type": "authorization_code", "code": "{code}"}
```

---

## 5. SSO Flows

### OIDC + PKCE (most common modern SSO)

```bash
# PKCE flow observation (passive, no interception):
# 1. Record the authorization URL from browser redirect
# 2. Note: code_challenge, code_challenge_method, state parameters

# Session acquisition (authorized):
# 1. User logs in normally through SSO
# 2. Capture authorization code from redirect callback
# 3. Exchange code for tokens

# Security checks:
# - Is code_verifier validated? (remove it → should fail)
# - Is state parameter validated? (change it → should fail)
# - Is redirect_uri validated exactly? (change to attacker.com → should fail)
# - Token storage: localStorage vs httpOnly cookie?
# - ID token validation: aud, iss, exp checked?
```

### SAML

```bash
# SAML security checks:
# 1. Signature wrapping attack — inject unsigned assertion
# 2. XML signature exclusion — remove Signature element
# 3. Comment injection in NameID
# 4. Replay assertion after expiry
# 5. Destination URL mismatch

# Test with SAML Raider (Burp extension) or manually:
# Capture SAML request (base64 + URL-encoded)
# Decode: base64 -d <<< "PHNhbWxwOlJlc3BvbnNl..."
# Modify assertion
# Re-encode and forward
```

---

## 6. Token Lifecycle Management

### Token types and handling

| Token Type | Storage | Refresh | Expiry |
|---|---|---|---|
| Session cookie | httpOnly cookie | Server-side sliding | 30 min inactive |
| JWT access token | localStorage / cookie | Short-lived (5-15 min) | exp claim |
| JWT refresh token | httpOnly cookie | Long-lived (7-30 days) | Separate endpoint |
| API key | Header / query param | No expiry (manual rotation) | Manual |
| OAuth token | Authorization header | refresh_token grant | expires_in |

### Long-task token continuity

```bash
# Problem: Phase 3 takes >30 min, token expires mid-test
# Solution: Auto-refresh hook

# For JWT with refresh token:
while true; do
  # Check token expiry
  exp=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp')
  now=$(date +%s)
  if [ $((exp - now)) -lt 300 ]; then  # Less than 5 min remaining
    # Refresh
    response=$(curl -s -X POST https://{target}/api/auth/refresh \
      -H "Authorization: Bearer $REFRESH_TOKEN")
    ACCESS_TOKEN=$(echo "$response" | jq -r '.access_token')
    REFRESH_TOKEN=$(echo "$response" | jq -r '.refresh_token // .refresh_token')
    echo "Token refreshed at $(date)"
  fi
  sleep 60
done &
REFRESH_PID=$!

# ... run Phase 3 tests ...

kill $REFRESH_PID 2>/dev/null
```

### Session recording for reports

```bash
# Record full auth flow for evidence
mkdir -p raw/sessions/

# Capture auth request/response
curl -v -X POST https://{target}/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<user>","password":"<pass>"}' \
  > raw/sessions/login-$(date +%Y%m%d-%H%M%S).txt 2>&1

# Redact sensitive values before storing
sed -i 's/"token": "eyJ[^"]*"/"token": "[REDACTED]"/g' raw/sessions/*.txt
sed -i 's/"password": "[^"]*"/"password": "[REDACTED]"/g' raw/sessions/*.txt
```

---

## Integration with sessions/ Directory

After session acquisition, write to `sessions/`:

```markdown
# sessions/user.md

## Source
- auth_method: sms_otp
- phone: 138****1234 (last 4 digits only)
- obtained_at: 2026-06-02T14:30:00+08:00

## Scope
- role: standard_user
- tenant: acme_corp
- permissions: read, write_own

## Status
- valid: true
- expires_at: 2026-06-02T15:00:00+08:00 (estimated)
- refresh_available: true

## Token (redacted)
- access_token: eyJ...[REDACTED]...xYz
- refresh_token: stored in environment variable, not in file

## Notes
- Token refreshes automatically via background hook
- OTP was received on authorized test phone
- MFA bypass not attempted (out of scope)
```
