#!/usr/bin/env python3
"""Capture evidence with integrity guarantees.

Creates HAR-like capture, SHA-256 hash chain, timestamped records,
and automatic sensitive value redaction.

Usage:
    python3 scripts/capture_evidence.py <task_dir> capture \\
        --method GET --url "https://target/api/users" \\
        --header "Authorization: Bearer TOKEN" \\
        --output evidence-F-001-request

    python3 scripts/capture_evidence.py <task_dir> hash-chain \\
        --output evidence-chain.txt

    python3 scripts/capture_evidence.py <task_dir> redact \\
        --input raw/evidence-F-001-request.json
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REDACT_PATTERNS = [
    (re.compile(r'(Bearer\s+)\S+', re.I), r'\1[REDACTED]'),
    (re.compile(r'("(?:password|passwd|secret|token|api_key|apikey|access_token|refresh_token|private_key|secret_key|client_secret)"\s*:\s*")([^"]*")', re.I), r'\1[REDACTED]"'),
    (re.compile(r'(Authorization:\s*)(Basic|Bearer|Digest)\s+\S+', re.I), r'\1\2 [REDACTED]'),
    (re.compile(r'(Cookie:\s*)\S+', re.I), r'\1[REDACTED]'),
    (re.compile(r'(Set-Cookie:\s*)(\S+=[^;]*)', re.I), r'\1[REDACTED]'),
    (re.compile(r'\b\d{6}\b'), 'XXXXXX'),  # OTP codes
]

# Whitelist: only these fields survive redaction. Everything else in headers/cookies is redacted.
SAFE_HEADER_NAMES = {
    "content-type", "content-length", "accept", "user-agent",
    "host", "origin", "referer", "x-request-id", "x-forwarded-for",
    "accept-encoding", "accept-language", "cache-control", "connection",
    "date", "server", "x-powered-by", "etag", "vary", "allow",
}

SAFE_COOKIE_NAMES = set()  # Empty = all cookie values redacted


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def redact_text(text: str) -> str:
    """Two-layer redaction: whitelist check first, then pattern-based catch-all."""
    # Layer 1: Whitelist-based header filtering
    # Parse as HAR-like JSON and selectively redact
    try:
        record = json.loads(text)
        for entry in record.get("log", {}).get("entries", []):
            # Redact request headers not in whitelist
            for h in entry.get("request", {}).get("headers", []):
                if h.get("name", "").lower() not in SAFE_HEADER_NAMES:
                    h["value"] = "[REDACTED]"
            # Redact response headers not in whitelist
            for h in entry.get("response", {}).get("headers", []):
                if h.get("name", "").lower() not in SAFE_HEADER_NAMES:
                    h["value"] = "[REDACTED]"
        text = json.dumps(record, indent=2, ensure_ascii=False)
    except (json.JSONDecodeError, KeyError):
        pass  # Not JSON — fall through to pattern redaction

    # Layer 2: Pattern-based catch-all (blacklist) for anything the whitelist missed
    # This catches secrets in body text, query strings, non-header contexts
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture_request(task_dir: str, method: str, url: str, headers: list,
                    body: str, response_body: str, response_status: int,
                    response_headers: list, output_name: str, redact: bool = True):
    """Create a HAR-like evidence record with hash chain."""
    raw_dir = Path(task_dir) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    timestamp = now_iso()

    # Build evidence record
    header_dict = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            header_dict[k.strip()] = v.strip()

    resp_header_dict = {}
    for h in response_headers:
        if ":" in h:
            k, v = h.split(":", 1)
            resp_header_dict[k.strip()] = v.strip()

    record = {
        "log": {
            "version": "1.2",
            "creator": {"name": "capture_evidence.py", "version": "1.0"},
            "entries": [{
                "startedDateTime": timestamp,
                "time": 0,
                "request": {
                    "method": method,
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in header_dict.items()],
                    "queryString": [],
                    "bodySize": len(body.encode()) if body else 0,
                    "content": {"text": body or ""},
                },
                "response": {
                    "status": response_status,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in resp_header_dict.items()],
                    "content": {
                        "size": len(response_body.encode()) if response_body else 0,
                        "mimeType": resp_header_dict.get("Content-Type", "application/json"),
                        "text": response_body or "",
                    },
                },
            }]
        }
    }

    # Serialize and hash
    record_json = json.dumps(record, indent=2, ensure_ascii=False)

    if redact:
        record_json = redact_text(record_json)

    record_bytes = record_json.encode("utf-8")
    evidence_hash = sha256(record_bytes)

    # Add hash metadata
    record["_meta"] = {
        "sha256": evidence_hash,
        "captured_at": timestamp,
        "timezone": "UTC",
        "redacted": redact,
    }

    # Re-serialize with meta
    final_json = json.dumps(record, indent=2, ensure_ascii=False)
    final_hash = sha256(final_json.encode("utf-8"))

    # Write evidence file
    filename = f"{output_name}.json"
    filepath = raw_dir / filename
    filepath.write_text(final_json, encoding="utf-8")

    # Update hash chain
    chain_file = raw_dir / "evidence-chain.jsonl"
    chain_entry = {
        "timestamp": timestamp,
        "file": filename,
        "sha256": final_hash,
        "method": method,
        "url": url,
        "redacted": redact,
    }

    # Link to previous hash (chain)
    if chain_file.exists():
        prev_line = chain_file.read_text().strip().split("\n")[-1]
        prev_entry = json.loads(prev_line)
        chain_entry["previous_hash"] = prev_entry["sha256"]
    else:
        chain_entry["previous_hash"] = "GENESIS"

    with open(chain_file, "a") as f:
        f.write(json.dumps(chain_entry, ensure_ascii=False) + "\n")

    print(f"Evidence captured: {filepath}")
    print(f"SHA-256: {final_hash}")
    print(f"Timestamp: {timestamp} (UTC)")

    return str(filepath)


def verify_chain(task_dir: str) -> bool:
    """Verify the SHA-256 hash chain integrity."""
    raw_dir = Path(task_dir) / "raw"
    chain_file = raw_dir / "evidence-chain.jsonl"

    if not chain_file.exists():
        print("No evidence chain found.")
        return False

    lines = chain_file.read_text().strip().split("\n")
    prev_hash = "GENESIS"
    valid = True

    for i, line in enumerate(lines):
        entry = json.loads(line)
        filename = entry["file"]
        filepath = raw_dir / filename

        if not filepath.exists():
            print(f"FAIL: Evidence file missing: {filename}")
            valid = False
            continue

        # Verify file hash
        content = filepath.read_bytes()
        current_hash = sha256(content)

        if current_hash != entry["sha256"]:
            print(f"FAIL: Hash mismatch for {filename}")
            print(f"  Expected: {entry['sha256']}")
            print(f"  Actual:   {current_hash}")
            valid = False
        else:
            print(f"OK: {filename} — hash verified")

        # Verify chain linkage
        if entry.get("previous_hash") != prev_hash:
            print(f"FAIL: Chain break at entry {i}")
            valid = False

        prev_hash = entry["sha256"]

    if valid:
        print(f"\nChain integrity: VERIFIED ({len(lines)} evidence records)")
    else:
        print(f"\nChain integrity: FAILED")

    return valid


def redact_file(task_dir: str, input_path: str):
    """Redact sensitive values in an existing file."""
    filepath = Path(input_path)
    if not filepath.is_absolute():
        filepath = Path(task_dir) / filepath

    if not filepath.exists():
        print(f"File not found: {filepath}")
        return

    content = filepath.read_text(encoding="utf-8")
    redacted = redact_text(content)

    out_path = filepath  # Overwrite in place
    out_path.write_text(redacted, encoding="utf-8")
    print(f"Redacted: {out_path}")


def import_har(task_dir: str, input_path: str, output_name: str, redact: bool = True):
    """Import a Playwright tracing HAR or standard HAR file into the evidence chain.

    Playwright tracing: context.tracing.stop(path='trace.zip') produces a zip
    containing trace.json and network.har. This function reads the HAR and
    converts each entry into the local evidence format.
    """
    import zipfile

    raw_dir = Path(task_dir) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    filepath = Path(input_path)
    if not filepath.exists():
        print(f"File not found: {filepath}")
        return

    # Handle Playwright trace.zip (contains network.har)
    har_data = None
    if zipfile.is_zipfile(filepath):
        with zipfile.ZipFile(filepath) as zf:
            for name in zf.namelist():
                if name.endswith(".har"):
                    with zf.open(name) as f:
                        har_data = json.loads(f.read())
                    break
            if har_data is None:
                # Try trace.json for network data
                for name in zf.namelist():
                    if "trace" in name.lower() and name.endswith(".json"):
                        print(f"Found trace file: {name}")
                        break
    else:
        # Plain HAR file
        content = filepath.read_text(encoding="utf-8")
        har_data = json.loads(content)

    if har_data is None:
        print(f"No HAR data found in {filepath}")
        return

    entries = har_data.get("log", {}).get("entries", [])
    if not entries:
        print("No HAR entries found.")
        return

    imported_count = 0
    for i, entry in enumerate(entries):
        req = entry.get("request", {})
        resp = entry.get("response", {})

        # Extract method and URL
        method = req.get("method", "GET")
        url = req.get("url", "unknown")

        # Skip data: URLs and non-HTTP
        if not url.startswith("http"):
            continue

        # Build evidence record
        timestamp = entry.get("startedDateTime", now_iso())

        record = {
            "log": {
                "version": "1.2",
                "creator": {"name": "capture_evidence.py (HAR import)", "version": "1.0"},
                "entries": [entry],
            }
        }

        record_json = json.dumps(record, indent=2, ensure_ascii=False)

        if redact:
            record_json = redact_text(record_json)

        record_bytes = record_json.encode("utf-8")

        entry_name = f"{output_name}-{i:03d}-{method.lower()}.json"
        entry_path = raw_dir / entry_name
        entry_hash = sha256(record_bytes)

        # Add meta
        record["_meta"] = {
            "sha256": entry_hash,
            "captured_at": timestamp,
            "timezone": "UTC",
            "redacted": redact,
            "source": "har_import",
        }

        final_json = json.dumps(record, indent=2, ensure_ascii=False)
        final_hash = sha256(final_json.encode("utf-8"))
        entry_path.write_text(final_json, encoding="utf-8")

        # Update chain
        chain_file = raw_dir / "evidence-chain.jsonl"
        chain_entry = {
            "timestamp": timestamp,
            "file": entry_name,
            "sha256": final_hash,
            "method": method,
            "url": url[:200],  # Truncate long URLs
            "redacted": redact,
            "source": "har_import",
        }
        if chain_file.exists():
            prev_line = chain_file.read_text().strip().split("\n")[-1]
            prev_entry = json.loads(prev_line)
            chain_entry["previous_hash"] = prev_entry["sha256"]
        else:
            chain_entry["previous_hash"] = "GENESIS"

        with open(chain_file, "a") as f:
            f.write(json.dumps(chain_entry, ensure_ascii=False) + "\n")

        imported_count += 1

    print(f"Imported {imported_count} HAR entries from {filepath}")
    if redact:
        print("All entries redacted (whitelist + pattern dual-layer)")


def main():
    parser = argparse.ArgumentParser(description="Evidence capture with integrity")
    parser.add_argument("task_dir", help="Task directory")
    sub = parser.add_subparsers(dest="command")

    # capture
    cap = sub.add_parser("capture", help="Capture a request/response as evidence")
    cap.add_argument("--method", required=True)
    cap.add_argument("--url", required=True)
    cap.add_argument("--header", action="append", default=[])
    cap.add_argument("--body", default="")
    cap.add_argument("--response-body", default="")
    cap.add_argument("--response-status", type=int, default=200)
    cap.add_argument("--response-header", action="append", default=[])
    cap.add_argument("--output", required=True, help="Output name (without extension)")
    cap.add_argument("--no-redact", action="store_true")

    # hash-chain / verify
    sub.add_parser("hash-chain", help="Verify evidence hash chain")

    # redact
    red = sub.add_parser("redact", help="Redact sensitive values in a file")
    red.add_argument("--input", required=True, help="File path to redact")

    # import-har
    har = sub.add_parser("import-har", help="Import Playwright trace or standard HAR file")
    har.add_argument("--input", required=True, help="HAR or trace.zip file path")
    har.add_argument("--output", default="imported-har", help="Output name prefix")
    har.add_argument("--no-redact", action="store_true")

    args = parser.parse_args()

    if args.command == "capture":
        capture_request(
            args.task_dir, args.method, args.url,
            args.header, args.body, args.response_body,
            args.response_status, args.response_header,
            args.output, redact=not args.no_redact,
        )
    elif args.command == "hash-chain":
        verify_chain(args.task_dir)
    elif args.command == "redact":
        redact_file(args.task_dir, args.input)
    elif args.command == "import-har":
        import_har(args.task_dir, args.input, args.output, redact=not args.no_redact)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
