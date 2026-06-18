# Password Policy & Account Lockout Testing Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify password policy and account lockout vulnerability risk characteristics.
>
> - All testing is **limited to proving policy weaknesses**, no unauthorized account access
> - Account lockout testing uses your own test accounts, **no lockout of other users' accounts**
> - Password complexity testing is for understanding policy gaps, **no brute-force attacks**
> - Validation proves vulnerability existence (weak policy confirmed), **no credential compromise**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: OWASP Authentication Testing, NIST SP 800-63B

## Manual Testing

**Note: Use your own test accounts only. Maximum 3-5 attempts per lockout test.**

---

## Validation Objectives (Within Security Boundary)

Password policy and account lockout vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Password Complexity | ✓ Test minimum requirements | - | Brute-force other users' passwords |
| Password History | ✓ Check if previous passwords rejected | - | Access other users' password history |
| Account Lockout | ✓ Test lockout on own account | - | Lockout other users' accounts |
| Lockout Duration | ✓ Measure lockout reset time | - | Prolong lockout denial |
| Password Reset Flow | ✓ Test reset mechanism security | - | Reset other users' passwords |
| Username Enumeration | ✓ Check login/forgot responses | - | Enumerate all valid usernames |

**Safe Validation Method**: Use your own test accounts for all lockout and password testing. Document policy weaknesses without exploiting them.

---

## Password Complexity Testing

### Minimum Requirements Check

```bash
# Test password policy requirements by attempting weak passwords
# Use your own test account only

# Test minimum length
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "test_user_policy", "password": "1"}'

curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "test_user_policy", "password": "1234567"}'

# Test numeric-only password
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "test_user_policy", "password": "12345678"}'

# Test lowercase-only password
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "test_user_policy", "password": "abcdefgh"}'

# Test common password
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "test_user_policy", "password": "Password1"}'

# Test very weak pattern
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "test_user_policy", "password": "aaaaaaaa"}'
```

### Password Policy Assessment

| Requirement | Secure | Weak | Critical |
|------------|--------|------|----------|
| Minimum length | >= 12 chars | 8-11 chars | < 8 chars |
| Upper case required | Yes | No | No |
| Lower case required | Yes | No | No |
| Number required | Yes | No | No |
| Special char required | Yes | No | No |
| Common password check | Yes | No | No |
| No sequential chars | Yes | No | No |
| No repeated chars | Yes | No | No |

### Top Common Passwords Check

```bash
# Test if common passwords are accepted (max 5 attempts)
# These are the most common passwords globally
for password in "123456" "password" "12345678" "qwerty" "abc123"; do
  response=$(curl -s -X POST "https://target.com/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"test_user_$$\", \"password\": \"$password\"}")
  echo "Password '$password': $response"
done

# If common passwords are accepted: weak password policy (finding)
```

---

## Password History Enforcement

```bash
# Test if previous passwords can be reused (use your own account)

# Step 1: Change password to a new value
curl -s -X POST "https://target.com/api/auth/change-password" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password": "OldPass123!", "new_password": "NewPass456!"}'

# Step 2: Try to change back to previous password
curl -s -X POST "https://target.com/api/auth/change-password" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password": "NewPass456!", "new_password": "OldPass123!"}'

# If previous password accepted: password history not enforced (finding)
```

---

## Account Lockout Testing

### Lockout Threshold Testing (Own Account Only)

```bash
# ⚠️ Use YOUR OWN test account only
# Test lockout threshold with wrong passwords

lockout_count=0
for i in $(seq 1 10); do
  response=$(curl -s -X POST "https://target.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "YOUR_TEST_ACCOUNT", "password": "wrong_password_'$i'"}')
  
  # Parse response for lockout indicator
  status=$(echo "$response" | grep -o "locked\|too many\|attempt\|429\|403\|401")
  
  if echo "$status" | grep -qi "locked\|too many\|429\|403"; then
    echo "[!] Account locked after $i attempts"
    break
  else
    echo "[$i] Login failed: $status"
  fi
  lockout_count=$i
  sleep 1
done

echo "Lockout threshold: approximately $lockout_count attempts"
```

### Lockout Duration Testing

```bash
# After account lockout, measure time to auto-unlock

# Step 1: Trigger lockout (use own account)
for i in $(seq 1 6); do
  curl -s -X POST "https://target.com/api/auth/login" \
    -d "username=YOUR_TEST_ACCOUNT&password=wrong_$i" > /dev/null
done

# Step 2: Try login every 30 seconds until unlocked
start_time=$(date +%s)
while true; do
  response=$(curl -s -X POST "https://target.com/api/auth/login" \
    -d "username=YOUR_TEST_ACCOUNT&password=YOUR_CORRECT_PASSWORD")
  
  if echo "$response" | grep -qi "success\|token\|200"; then
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "Account unlocked after ${duration} seconds"
    break
  fi
  
  sleep 30
  # Timeout after 30 minutes
  current_time=$(date +%s)
  if (( current_time - start_time > 1800 )); then
    echo "Timeout: account still locked after 30 minutes"
    break
  fi
done
```

### Lockout Bypass Testing

```bash
# Test if lockout can be bypassed
# Use YOUR OWN test account only

# Test 1: Different IP address
curl -s -X POST "https://target.com/api/auth/login" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -d "username=YOUR_TEST_ACCOUNT&password=wrong_bypass_1"

# Test 2: Different User-Agent
curl -s -X POST "https://target.com/api/auth/login" \
  -H "User-Agent: DifferentBrowser/1.0" \
  -d "username=YOUR_TEST_ACCOUNT&password=wrong_bypass_2"

# Test 3: Case variation in username
curl -s -X POST "https://target.com/api/auth/login" \
  -d "username=YOUR_TEST_ACCOUNT&password=wrong_bypass_3"

curl -s -X POST "https://target.com/api/auth/login" \
  -d "username=your_test_account&password=wrong_bypass_4"
```

---

## Password Reset Flow Testing

### Reset Token Security

```bash
# Test password reset flow
# Step 1: Request password reset
curl -s -X POST "https://target.com/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email": "your_test@email.com"}'

# Step 2: Check reset token format from email/link
# Analyze token for:
# - Length (short = brute-forceable)
# - Entropy (predictable = insecure)
# - Expiration (long-lived = risky)

# Test reset token expiration
# Request reset, wait, then try token at intervals
# 1 minute, 5 minutes, 15 minutes, 1 hour, 24 hours
```

### Reset Flow Weaknesses

```bash
# Test for password reset vulnerabilities

# Step 1: Check if reset token is returned in response
curl -s -X POST "https://target.com/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email": "your_test@email.com"}' | grep -i "token\|reset"

# Step 2: Check if reset token works multiple times
curl -s -X POST "https://target.com/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "password": "NewPassword123!"}'

# Try same token again
curl -s -X POST "https://target.com/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{"token": "RESET_TOKEN", "password": "NewPassword456!"}'

# Step 3: Check if old password works after reset (it shouldn't)
curl -s -X POST "https://target.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "your_test@email.com", "password": "OldPassword123!"}'
```

### Reset Token Predictability

```bash
# Test token predictability
# Request multiple reset tokens and compare

for i in $(seq 1 3); do
  response=$(curl -s -X POST "https://target.com/api/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d '{"email": "your_test+'$i'@email.com"}')
  echo "Token $i: $response"
  sleep 2
done

# Analyze patterns in tokens:
# - Sequential numbers
# - Timestamps
# - Similar structure
# - Predictable encoding
```

---

## Username Enumeration

### Login-Based Enumeration

```bash
# Compare login responses for existing vs non-existing users

# Existing user with wrong password
curl -s -X POST "https://target.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "existing_user", "password": "wrong_password"}'

# Non-existing user with wrong password
curl -s -X POST "https://target.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "nonexistent_user_12345", "password": "wrong_password"}'

# Compare differences in:
# - Response message ("Invalid username" vs "Invalid password")
# - Response time (existing user may take longer for password check)
# - Status code differences
# - Response body differences
```

### Forgot Password-Based Enumeration

```bash
# Compare forgot password responses

# Existing user
curl -s -X POST "https://target.com/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email": "existing@email.com"}'

# Non-existing user
curl -s -X POST "https://target.com/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email": "nonexistent12345@email.com"}'

# Compare responses:
# - "Reset email sent" vs "No account found"
# - Different response times
# - Different status codes
# - Email reveals: "Email sent to j***@email.com" (partial disclosure)
```

### Registration-Based Enumeration

```bash
# Compare registration responses

# Existing username
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "existing_user", "password": "TestPassword123!", "email": "test@email.com"}'

# Non-existing username
curl -s -X POST "https://target.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username": "nonexistent12345xyz", "password": "TestPassword123!", "email": "test2@email.com"}'

# Compare:
# - "Username already taken" vs "Registration successful"
# - Different response for username vs email conflict
```

### Timing-Based Enumeration

```bash
# Measure response time differences
# Existing users typically take longer (password hash comparison)

time curl -s -X POST "https://target.com/api/auth/login" \
  -d "username=existing_user&password=wrong" > /dev/null

time curl -s -X POST "https://target.com/api/auth/login" \
  -d "username=nonexistent_xyz_12345&password=wrong" > /dev/null

# If existing user takes significantly longer: timing attack possible
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A07:2021-Identification and Authentication Failures |
| CWE | CWE-521: Weak Password Requirements |
| CWE | CWE-262: Not Using Password Aging Mechanism |
| CWE | CWE-307: Improper Restriction of Excessive Authentication Attempts |

---

## Analysis Process

1. Test password complexity requirements with weak passwords
2. Attempt registration with common passwords
3. Check password history enforcement on your own account
4. Test account lockout threshold (own account only)
5. Measure lockout duration and bypass possibilities
6. Analyze password reset flow for weaknesses
7. Test username enumeration via login, forgot password, registration
8. Compare response timing for existing vs non-existing users
9. **Stop validation**, report policy weaknesses without exploitation

---

## Output

```markdown
## Vulnerability: Weak Password Policy / Account Lockout

### Location
{URL} - {authentication endpoint}

### Type
{Weak Complexity / No Lockout / Lockout Bypass / Enumeration / Reset Weakness}

### Evidence
- Password policy: {min length, complexity requirements, common password check}
- Lockout threshold: {X attempts / no lockout}
- Lockout duration: {X minutes / permanent / none}
- Password history: {enforced / not enforced}
- Username enumeration: {login / forgot / registration / timing}

### Validation Result
- Weak password accepted: {yes/no, which passwords}
- Account lockout exists: {yes/no, threshold}
- Lockout bypass possible: {yes/no, method}
- Username enumeration: {yes/no, method}
- Password reset weakness: {token reuse/predictable/no expiration}

### Risk Level
{Medium/High} - {specific weakness} enables {attack type}
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Lockout other users' accounts | Only test with your own accounts |
| ❌ Brute-force passwords | Max 3-5 attempts per test account |
| ❌ Reset other users' passwords | Only test with own test email |
| ❌ Enumerate all valid usernames | Only test with a few known/unknown pairs |
| ❌ Use discovered credentials | Credentials are evidence only, not for access |
| ❌ Prolong account lockout | Always allow lockout to reset naturally |

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Own accounts only"
- `README.md` -> Prohibited execution checklist