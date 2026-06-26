#!/usr/bin/env python3
"""Scope-checked HTTP request wrapper with mandatory request logging.

This wrapper is intentionally small and dependency-free. It sends one bounded
HTTP request, saves sanitized raw evidence, and appends an auditable request row
to 02-discovery.md or 03-vuln-test.md.
"""
import argparse
import json
import re
import ssl
import sys
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from urllib.parse import urlparse


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CONDITIONALLY_SAFE_METHODS = {"POST"}
MAX_BODY_BYTES = 512 * 1024
HOST_HEADER_NAMES = {"host"}


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def append_text(path: Path, content: str):
    with path.open("a", encoding="utf-8") as fh:
        fh.write(content)


def normalize_host(value: str) -> str:
    value = (value or "").strip().strip("`").lower()
    if not value or value in {"-", "n/a", "none", "unknown", "pending"}:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return host.strip("[]").lower()


def parse_authority(value: str) -> tuple[str, int | None]:
    value = (value or "").split(",", 1)[0].strip().strip("`")
    if not value:
        return "", None
    parsed = urlparse(value if "://" in value else f"//{value}")
    try:
        port = parsed.port
    except ValueError:
        raise SystemExit(f"invalid host header port: {value}")
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return normalize_host(host), port


def split_csvish(value: str) -> list[str]:
    items = []
    for raw in re.split(r"[,;\s]+", value or ""):
        raw = raw.strip().strip("`")
        if raw:
            items.append(raw)
    return items


def parse_task_meta(task_dir: Path) -> dict:
    meta = {}
    for line in read_text(task_dir / "task.md").splitlines():
        stripped = line.strip()
        if not stripped.startswith("- ") or ":" not in stripped:
            continue
        key, value = stripped[2:].split(":", 1)
        meta[key.strip()] = value.strip()
    return meta


def target_default_port(target: str) -> int | None:
    parsed = urlparse(target if "://" in target else f"//{target}")
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def parse_preflight(task_dir: Path) -> dict:
    meta = parse_task_meta(task_dir)
    target = meta.get("target", "")
    target_host = normalize_host(meta.get("target", ""))
    allowlist = []
    for item in split_csvish(meta.get("scope_allowlist", "")):
        host = normalize_host(item)
        if host and host not in allowlist:
            allowlist.append(host)
    if target_host and target_host not in allowlist:
        allowlist.insert(0, target_host)

    approved_ports = []
    raw_ports = meta.get("approved_ports", "")
    if not str(raw_ports).strip() or str(raw_ports).strip().lower() == "default-for-target":
        port = target_default_port(target)
        if port:
            approved_ports.append(port)
    else:
        for item in split_csvish(raw_ports):
            if re.fullmatch(r"\d{1,5}", item):
                approved_ports.append(int(item))

    complete = str(meta.get("preflight_complete", "")).strip().lower() in {"true", "yes", "complete", "completed", "pass", "passed"}
    missing = []
    if not complete:
        missing.append("preflight_complete=true")
    for key in ("authorization", "scope", "intensity", "automation", "credentials"):
        value = str(meta.get(key, "")).strip().lower()
        if not value or value in {"pending", "unknown", "unset", "todo", "tbd"}:
            missing.append(key)
    if not allowlist:
        missing.append("scope_allowlist")

    return {"meta": meta, "allowlist": allowlist, "approved_ports": approved_ports, "complete": not missing, "missing": missing}


def redact_sensitive(text: str) -> str:
    text = text or ""
    replacements = [
        (r"(?im)^(Authorization:\s*(?:Bearer|Basic)\s+).+$", r"\1<REDACTED>"),
        (r"(?im)^(Cookie:\s*).+$", r"\1<REDACTED>"),
        (r"(?im)^(Set-Cookie:\s*).+$", r"\1<REDACTED>"),
        (r"(?i)(^|[?&\s;])((?:token|access_token|jwt|password|passwd|secret|openid|unionid|userid|loginid|key)=)[^&\s`'\"<>),|]+", r"\1\2<REDACTED>"),
        (r'(?i)("(?:token|access_token|jwt|password|passwd|secret|openId|unionId|userId|loginId|key)"\s*:\s*")[^"]*"', r'\1<REDACTED>"'),
    ]
    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text)
    return text


def parse_header(raw: str) -> tuple[str, str]:
    if ":" not in raw:
        raise SystemExit(f"invalid header, expected Name: Value: {raw}")
    key, value = raw.split(":", 1)
    key = key.strip()
    if not key:
        raise SystemExit(f"invalid header name: {raw}")
    return key, value.strip()


def parse_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit("only http:// and https:// URLs are supported")
    if not parsed.hostname:
        raise SystemExit("URL must include a host")
    if parsed.username or parsed.password:
        raise SystemExit("URL userinfo is not supported; pass credentials with --header after explicit authorization")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise SystemExit(f"invalid URL port: {exc}")
    return parsed, path, port


def assert_scope(preflight: dict, parsed, port: int):
    host = normalize_host(parsed.hostname or "")
    allowlist = set(preflight["allowlist"])
    if not preflight["complete"]:
        raise SystemExit("preflight incomplete: " + ", ".join(preflight["missing"]))
    if host not in allowlist:
        raise SystemExit(f"scope violation blocked: host '{host}' not in scope_allowlist {sorted(allowlist)}")
    if preflight["approved_ports"] and port not in preflight["approved_ports"]:
        raise SystemExit(f"scope violation blocked: port '{port}' not in approved_ports {preflight['approved_ports']}")


def assert_headers_in_scope(preflight: dict, headers: dict):
    allowlist = set(preflight["allowlist"])
    for key, value in headers.items():
        if key.lower() not in HOST_HEADER_NAMES:
            continue
        host, port = parse_authority(value)
        if not host:
            raise SystemExit(f"invalid scoped host header: {key}: {value}")
        if host not in allowlist:
            raise SystemExit(f"scope violation blocked: header '{key}' host '{host}' not in scope_allowlist {sorted(allowlist)}")
        if preflight["approved_ports"] and port is not None and port not in preflight["approved_ports"]:
            raise SystemExit(f"scope violation blocked: header '{key}' port '{port}' not in approved_ports {preflight['approved_ports']}")


def ensure_method_allowed(method: str, allow_unsafe: bool, idempotent_post: bool):
    method = method.upper()
    if method in SAFE_METHODS:
        return
    if method in CONDITIONALLY_SAFE_METHODS and idempotent_post:
        return
    if allow_unsafe:
        return
    raise SystemExit(
        f"method '{method}' blocked by default. Use safe methods, or pass --idempotent-post for read-only POST validation."
    )


def request_once(parsed, path: str, method: str, headers: dict, body: bytes | None, timeout: float, insecure: bool):
    conn_cls = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    kwargs = {"timeout": timeout}
    if parsed.scheme == "https" and insecure:
        kwargs["context"] = ssl._create_unverified_context()
    conn = conn_cls(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), **kwargs)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw_body = response.read(MAX_BODY_BYTES + 1)
        truncated = len(raw_body) > MAX_BODY_BYTES
        raw_body = raw_body[:MAX_BODY_BYTES]
        return {
            "status": response.status,
            "reason": response.reason,
            "headers": response.getheaders(),
            "body": raw_body,
            "truncated": truncated,
        }
    finally:
        conn.close()


def next_raw_path(task_dir: Path, phase: str) -> Path:
    raw_dir = task_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = "discovery" if phase in {"1", "2", "phase_1", "phase_2", "discovery"} else "vuln"
    idx = 1
    while True:
        candidate = raw_dir / f"guarded-{prefix}-{stamp}-{idx:03d}.txt"
        if not candidate.exists():
            return candidate
        idx += 1


def write_raw(raw_path: Path, parsed, path: str, method: str, headers: dict, body: bytes | None, result: dict):
    lines = [
        f"# Guarded Request Evidence",
        f"timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"request: {method} {parsed.scheme}://{parsed.hostname}{':' + str(parsed.port) if parsed.port else ''}{path}",
        "",
        "## Request Headers",
    ]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    if body is not None:
        lines.extend([
            "",
            "## Request Body",
            body.decode("utf-8", errors="replace"),
        ])
    lines.extend([
        "",
        "## Response",
        f"status: {result['status']} {result['reason']}",
        "",
        "## Response Headers",
    ])
    for key, value in result["headers"]:
        lines.append(f"{key}: {value}")
    body_text = result["body"].decode("utf-8", errors="replace")
    lines.extend([
        "",
        "## Body",
        body_text,
    ])
    if result["truncated"]:
        lines.append("\n[truncated]")
    write_text(raw_path, redact_sensitive("\n".join(lines).rstrip() + "\n"))


def md_escape(value: str) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def log_value(value: str) -> str:
    return md_escape(redact_sensitive(value))


def count_existing_rows(text: str) -> int:
    count = 0
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.strip().startswith("|") else []
        if len(cells) >= 4 and any(c.upper() in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} for c in cells):
            count += 1
    return count


def ensure_discovery_file(task_dir: Path, target: str):
    path = task_dir / "02-discovery.md"
    if path.exists() and "## Request Log" in read_text(path):
        return
    if not path.exists():
        write_text(
            path,
            f"# Attack Surface Discovery - {target}\n\n"
            f"**Updated At**: {datetime.now(timezone.utc).isoformat()}\n\n"
            "## Request Log (mandatory - every request made this phase)\n\n"
            "| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |\n"
            "|---|--------|------------------|------|--------|-----------|------|-------|\n",
        )
    else:
        append_text(
            path,
            "\n\n## Request Log (mandatory - every request made this phase)\n\n"
            "| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |\n"
            "|---|--------|------------------|------|--------|-----------|------|-------|\n",
        )


def ensure_vuln_file(task_dir: Path, target: str):
    path = task_dir / "03-vuln-test.md"
    if path.exists() and "## Guarded Request Log" in read_text(path):
        return
    if not path.exists():
        write_text(
            path,
            f"# Vulnerability Validation - {target}\n\n"
            f"**Updated At**: {datetime.now(timezone.utc).isoformat()}\n\n"
            "## Guarded Request Log (mandatory - every validation request)\n\n"
            "| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |\n"
            "|---|--------|------------------|------|--------|-----------|------|-------|\n",
        )
    else:
        append_text(
            path,
            "\n\n## Guarded Request Log (mandatory - every validation request)\n\n"
            "| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |\n"
            "|---|--------|------------------|------|--------|-----------|------|-------|\n",
        )


def log_authority(parsed) -> str:
    return parsed.netloc or parsed.hostname or ""


def append_log(task_dir: Path, phase: str, parsed, path: str, method: str, status: int, raw_ref: str, note: str):
    is_discovery = phase in {"1", "2", "phase_1", "phase_2", "discovery"}
    log_path = task_dir / ("02-discovery.md" if is_discovery else "03-vuln-test.md")
    target = parsed.hostname or "target"
    if is_discovery:
        ensure_discovery_file(task_dir, target)
    else:
        ensure_vuln_file(task_dir, target)
    current = read_text(log_path)
    idx = count_existing_rows(current) + 1
    row = (
        f"| {idx} | {method} | {log_value(log_authority(parsed))} | {log_value(path)} | "
        f"{status} | yes | request_guard | {log_value(raw_ref + ('; ' + note if note else ''))} |\n"
    )
    append_text(log_path, row)


def effective_request_host(parsed, headers: dict) -> str:
    for key, value in headers.items():
        if key.lower() in HOST_HEADER_NAMES:
            return value
    if parsed.port:
        return f"{parsed.hostname}:{parsed.port}"
    return parsed.hostname or ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send one scope-checked HTTP request and append the mandatory request log")
    parser.add_argument("task_dir", help="Authorized AppSec task directory")
    parser.add_argument("url", help="In-scope URL to request")
    parser.add_argument("--phase", choices=["1", "2", "3", "phase_1", "phase_2", "phase_3", "discovery", "vuln"], required=True)
    parser.add_argument("--method", default="GET", help="HTTP method, default GET")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: Value' form; may repeat")
    parser.add_argument("--body", default=None, help="Request body for bounded validation")
    parser.add_argument("--body-file", default=None, help="Read request body from file")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--idempotent-post", action="store_true", help="Allow POST only when it is documented as read-only/idempotent")
    parser.add_argument("--allow-unsafe-method", action="store_true", help="Override method guard; requires --note")
    parser.add_argument("--note", default="", help="Short note for the request log")
    parser.add_argument("--json-output", action="store_true", help="Print machine-readable result JSON")
    args = parser.parse_args(argv)

    task_dir = Path(args.task_dir).resolve()
    if not task_dir.exists():
        raise SystemExit(f"task directory not found: {task_dir}")
    method = args.method.upper()
    ensure_method_allowed(method, args.allow_unsafe_method, args.idempotent_post)
    if args.allow_unsafe_method and not args.note.strip():
        raise SystemExit("--allow-unsafe-method requires --note documenting authorization and safety boundary")

    parsed, request_path, port = parse_url(args.url)
    preflight = parse_preflight(task_dir)
    assert_scope(preflight, parsed, port)

    headers = {}
    for raw in args.header:
        key, value = parse_header(raw)
        headers[key] = value
    assert_headers_in_scope(preflight, headers)

    body = None
    if args.body_file:
        body = Path(args.body_file).read_bytes()
    elif args.body is not None:
        body = args.body.encode("utf-8")
    if body is not None and len(body) > MAX_BODY_BYTES:
        raise SystemExit(f"request body too large: {len(body)} bytes > {MAX_BODY_BYTES}")

    result = request_once(parsed, request_path, method, headers, body, args.timeout, args.insecure)
    raw_path = next_raw_path(task_dir, args.phase)
    write_raw(raw_path, parsed, request_path, method, headers, body, result)
    raw_ref = str(raw_path.relative_to(task_dir))
    parsed_for_log = parsed._replace(netloc=effective_request_host(parsed, headers))
    append_log(task_dir, args.phase, parsed_for_log, request_path, method, result["status"], raw_ref, args.note)

    output = {"status": result["status"], "raw_ref": raw_ref, "host": normalize_host(parsed.hostname or ""), "path": request_path}
    if args.json_output:
        print(json.dumps(output, ensure_ascii=False))
    else:
        print(f"request-logged: {result['status']} {raw_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
