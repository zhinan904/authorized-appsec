# Default Credential Testing Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized penetration testing reference** only, helping identify default credential vulnerability risk characteristics.
>
> - All testing is **limited to proving existence of default credentials**, no further exploitation
> - Maximum 3-5 login attempts per default credential set, **no brute force**
> - Validation proves default credentials exist (login succeeded), **no data access beyond proof**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: DefaultCreds-Cheat-Sheet, SecLists

## Manual Testing

**Note: Test maximum 3-5 default credential combinations per service, stop immediately upon successful login**

---

## Validation Objectives (Within Security Boundary)

Default credential vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| Default Username/Password | ✓ Test 3-5 common combinations | - | Mass brute force |
| Admin Panel Access | ✓ Verify login succeeds with default creds | - | Access sensitive data beyond proof |
| Database Default Creds | ✓ Test local/remote default connection | ✓ Requires explicit authorization | Data extraction |
| Management Console | ✓ Verify default login works | - | Configuration changes |
| Service Account Creds | ✓ Test hardcoded service credentials | - | Lateral movement |

**Safe Validation Method**: Attempt login with known default credentials, confirm access by verifying authenticated response, immediately log out. Do not browse, extract, or modify data.

---

## Common Default Credentials by Platform

### Web Servers & Reverse Proxies

```text
# Apache Tomcat
admin:admin          # /manager/html
admin:tomcat
tomcat:tomcat
role1:role1

# Nginx (no default login, but check /nginx_status for exposure)

# Apache HTTPD (no default login)

# IIS
administrator:password
administrator:Password1
```

### Databases

```text
# MySQL
root:                # empty password
root:root
root:mysql
root:password

# PostgreSQL
postgres:postgres
postgres:password

# MongoDB
admin:admin          # admin database
# Often no auth by default (check --noauth)

# Redis
# No username, check for no auth: CONFIG GET requirepass

# Elasticsearch
# Often no auth by default
elastic:changeme     # X-Pack default
```

### Management Panels

```text
# phpMyAdmin
root:                # empty password (common)
root:root
pma:pma

# Adminer
root:                # try empty password

# cPanel
admin:password

# WebLogic
admin:admin          # /console
weblogic:weblogic
weblogic:welcome1

# Jenkins
admin:admin          # initial setup, check /script
admin:password

# JBoss
admin:admin          # /jmx-console

# GlassFish
admin:adminadmin     # /asadmin (port 4848)

# Solr
admin:admin          # :8983/solr/admin

# Grafana
admin:admin          # :3000 (forced password change on first login)

# Kibana
kibana:kibana       # :5601

# RabbitMQ
guest:guest          # :15672 (only localhost by default)

# Zeus/ZVA
admin:admin
```

### Network Devices

```text
# Cisco
admin:admin
cisco:cisco
enable:password      # enable mode

# Fortinet
admin:              # empty password
admin:password

# Juniper
root:                # empty password (initial setup)
super:juniper123

# MikroTik
admin:              # empty password

# Ubiquiti
ubnt:ubnt
admin:password
```

### CMS & Frameworks

```text
# WordPress
admin:admin
admin:password
admin:admin123

# Drupal
admin:admin
admin:drupal
admin:password

# Joomla
admin:admin

# Django
admin:admin          # /admin

# Flask-Admin
admin:admin

# Strapi
admin:admin@strapi.io  # :1337/admin (initial setup)
admin:admin
```

### Cloud & Container

```text
# Kubernetes Dashboard
# Check for service account token (often default-mounted)

# Docker Registry
# Often no auth: try GET /v2/_catalog

# Portainer
admin:portainer4tim  # initial setup password

# Rancher
admin:admin          # :8080
```

---

## Testing Methodology

### Step 1: Identify Service and Version

```bash
# Fingerprint the service first
httpx -u <target> -tech-detect -title -status-code -server

# Check common admin paths
for path in admin administrator login dashboard console manager cpanel wp-admin phpmyadmin grafana jenkins; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/$path" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] /$path -> $status"
  fi
done
```

### Step 2: Test Default Credentials (Max 3-5 Per Service)

```bash
# HTTP Basic Auth
curl -s -o /dev/null -w "%{http_code}" -u admin:admin https://<target>/admin/

# Form-based login
curl -s -X POST "https://<target>/login" \
  -d "username=admin&password=admin" \
  -c cookies.txt -L
# Check if authenticated by accessing protected page
curl -s -b cookies.txt "https://<target>/dashboard" | grep -i "welcome\|dashboard\|logout"

# API endpoint
curl -s -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  "https://<target>/api/v1/users"
```

### Step 3: Verify Access

```bash
# After successful login, verify authenticated state only
# DO NOT browse, enumerate, or extract data

# Check authenticated response
curl -s -b cookies.txt "https://<target>/api/v1/me" | head -20

# Log out immediately
curl -s -X POST "https://<target>/logout" -b cookies.txt
```

### Special Case: Redis / No-SQL Default Auth

```bash
# Redis - check if auth is required
redis-cli -h <target> ping
# If PONG: no auth required (Critical finding)

# MongoDB - check if auth is required
mongo --host <target> --eval "db.adminCommand('listDatabases')"
# If returns databases: no auth required (Critical finding)

# Elasticsearch - check if auth is required
curl -s "http://<target>:9200/_cat/indices"
# If returns indices: no auth required (Critical finding)
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP API | API1:2023-Broken Object Level Authorization |
| OWASP Web | A07:2021-Identification and Authentication Failures |
| CWE | CWE-521: Weak Password Requirements |
| CWE | CWE-798: Use of Hard-coded Credentials |
| CWE | CWE-259: Use of Hard-coded Password in Dictionary |

---

## Analysis Process

1. Identify service type and version from fingerprint
2. Look up known default credentials for that service
3. Test maximum 3-5 combinations
4. Verify authenticated response (welcome message, dashboard access, API data)
5. Log out immediately
6. Record finding with evidence of successful authentication
7. Report: "Default credentials for [service] at [endpoint]: [username]:[password]"

## Output

- Identified service and version
- Tested credential combinations (list attempts, not actual passwords in report)
- Evidence of successful authentication (authenticated response, dashboard screenshot)
- Immediate logout confirmation
- Severity assessment (typically Critical or High)

## Severity Classification

Default credentials severity is based on **whether credentials can actually log in** — a list existing != exploitable. Default Low, logging into a real account is required for High.

| Actual case | Severity | Note |
|---------|------|------|
| Default credentials can log in to a real account/admin panel | High | Credentials are exploitable, account takeover |
| Default credentials can log in but only to a test account | Medium | Limited impact |
| suspected default credentials found but login not verified | Low | Pending confirmation |
| only discovery oflogin interface (no credential testing) | Info | Informational |

**Key judgment**:Reporting High requires confirming**default credentials actually log in and belong to a real account**; test account only is downgraded to Medium. default credential login testing is Tier 2 and requires authorization. 

---

## Prohibited

- ⚠️ No brute force or credential stuffing (max 3-5 attempts)
- ⚠️ No data browsing or extraction beyond proof of access
- ⚠️ No configuration changes
- ⚠️ No lateral movement using discovered credentials
- ⚠️ Only prove existence, report and stop