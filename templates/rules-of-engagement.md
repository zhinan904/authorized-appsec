# Rules of Engagement Template

> **Purpose**: Pre-engagement authorization and scope documentation. Complete this before any active testing.

---

## Document Information

| Field | Value |
|-------|-------|
| Engagement ID | PT-{YYYYMMDD}-{SEQ} |
| Client | [Client name] |
| Prepared By | [Tester name] |
| Date | YYYY-MM-DD |
| Version | 1.0 |

---

## 1. Authorization

| Field | Value |
|-------|-------|
| Authorization Type | [ ] Written contract [ ] Email confirmation [ ] Verbal (documented) |
| Authorized By | [Name, title, contact] |
| Authorization Date | YYYY-MM-DD |
| Authorization Scope | [Reference scope document or describe below] |
| Authorization Evidence | [Link to signed document or email thread] |

**Critical**: Do not begin any active probing until authorization is confirmed and documented.

---

## 2. Scope Definition

### 2.1 In-Scope Targets

| Target ID | Target | Type | Notes |
|-----------|--------|------|-------|
| T-001 | https://example.com | URL | Primary web application |
| T-002 | https://api.example.com | URL | API backend |
| T-003 | 192.168.1.0/24 | IP range | Internal network (requires VPN) |

### 2.2 Out-of-Scope (Excluded)

| Target | Reason |
|--------|--------|
| staging.example.com | Not included in authorization |
| 192.168.2.0/24 | Production database network, excluded by client |
| Third-party services | CDN, payment processor, email provider |

### 2.3 Scope Boundaries

- [ ] Subdomain discovery is authorized (if domain in scope)
- [ ] Port scanning is authorized (if IP/host in scope)
- [ ] Directory/content discovery is authorized
- [ ] API endpoint exploration beyond documented endpoints is authorized
- [ ] Testing with authenticated sessions is authorized

---

## 3. Testing Parameters

### 3.1 Intensity Level

| Level | Description | Selected |
|-------|-------------|----------|
| Passive | No active probing, only analyze provided artifacts | [ ] |
| Gentle | Low request rate, minimal impact, avoid automated scanning | [ ] |
| Standard | Normal testing pace, targeted automated scanning with rate limiting | [ ] |

**Selected Intensity**: [ passive / gentle / standard ]

### 3.2 Allowed Capabilities

| Capability | Allowed | Restrictions |
|-------------|---------|--------------|
| Subdomain discovery | [ ] | [Specify: passive only, rate limit, etc.] |
| HTTP probing | [ ] | [Specify: rate, timeout] |
| Port scanning | [ ] | [Specify: top-N, full scan, rate] |
| Directory scanning | [ ] | [Specify: wordlist size, rate] |
| URL/JS extraction | [ ] | [Specify: depth] |
| Fingerprinting | [ ] | None |
| Vulnerability scanning | [ ] | [Specify: templates, severity] |

### 3.3 Testing Windows

| Parameter | Value |
|-----------|-------|
| Start Date | YYYY-MM-DD |
| End Date | YYYY-MM-DD |
| Preferred Hours | [e.g., 22:00-06:00 UTC, business hours only, any time] |
| Time Zone | [UTC / client local] |
| Blackout Periods | [e.g., product launch on YYYY-MM-DD, no testing] |

---

## 4. Credential and Session Scope

### 4.1 Test Accounts

| Role | Username | Source | Restrictions |
|------|----------|--------|--------------|
| Anonymous | N/A | N/A | No credentials needed |
| Standard User | [Provided by client] | Client-provided | Read-only, no data modification |
| Admin User | [Not provided] | — | Not in scope for this engagement |

### 4.2 Session Rules

- [ ] Sessions provided by client may be used
- [ ] Tester may create accounts for testing
- [ ] Tester must not modify or delete production data
- [ ] All test data must be cleaned up after engagement
- [ ] Session tokens must not be shared between test accounts

---

## 5. Communication and Reporting

### 5.1 Communication Protocol

| Event | Method | Recipient | SLA |
|-------|--------|-----------|-----|
| Critical finding discovered | [Email/Phone/Slack] | [Contact] | Within 1 hour |
| Service disruption observed | [Email/Phone] | [Contact] | Immediate |
| Status update | [Email] | [Contact] | Daily / Weekly |
| Final report delivery | [Email/Secure Portal] | [Contact] | Within N days of completion |

### 5.2 Reporting Schedule

| Milestone | Deliverable | Due Date |
|-----------|-------------|----------|
| Interim report | [Interim findings summary] | YYYY-MM-DD |
| Final report | [Complete report with all findings] | YYYY-MM-DD |
| Retest report | [Verification of remediated findings] | YYYY-MM-DD |

---

## 6. Restrictions and Constraints

### 6.1 Prohibited Actions

- Do not modify, delete, or corrupt production data
- Do not install persistent backdoors or implants
- Do not access data beyond what is necessary for proof of vulnerability
- Do not perform denial-of-service attacks
- Do not exfiltrate data beyond minimal proof-of-concept
- Do not test third-party systems not explicitly in scope
- Do not share findings or client data with unauthorized parties

### 6.2 Data Handling

- [ ] All evidence encrypted at rest
- [ ] Evidence destroyed after engagement per retention policy
- [ ] No credentials stored in plain text in reports or deliverables
- [ ] Screenshots sanitized of non-essential personal data

### 6.3 Legal Considerations

- [ ] Mutual NDA signed
- [ ] Liability insurance coverage confirmed
- [ ] Data protection regulations applicable (GDPR, CCPA, etc.)
- [ ] Incident response procedure agreed upon

---

## 7. Approval

| Role | Name | Signature/Confirmation | Date |
|------|------|----------------------|------|
| Client Sponsor | | | |
| Client Technical Contact | | | |
| Testing Lead | | | |
| Testing Company | | | |

---

## 8. Engagement Checklist

Before starting testing, confirm:

- [ ] Written authorization received
- [ ] Scope boundaries understood and documented
- [ ] Testing window confirmed with client
- [ ] Test accounts received (if applicable)
- [ ] Communication protocol established
- [ ] Emergency contact procedure verified
- [ ] Stop conditions understood (see `templates/stop-conditions.md`)
- [ ] Data handling requirements acknowledged
- [ ] Legal requirements satisfied (NDA, liability, etc.)