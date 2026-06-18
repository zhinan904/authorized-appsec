#!/usr/bin/env python3
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def read_text(path: Path, default=""):
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_task_md(text: str) -> dict:
    """Parse flat key-value pairs from task.md. Only handles '- key: value' lines.
    Nested structures (finding_counts, pending_focus, session_contexts) are not parsed
    and must be derived from other sources (e.g., findings.md counts)."""
    data = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("- "):
            body = line[2:]
            if ":" in body:
                key, value = body.split(":", 1)
                data[key.strip()] = value.strip()
    return data


def normalize_task_paths(task_dir: Path):
    task_path = task_dir / "task.md"
    if not task_path.exists():
        return
    text = task_path.read_text(encoding="utf-8")
    updated = text

    lines = updated.splitlines()
    has_results_root = any(line.strip().startswith("- results_root:") for line in lines)
    has_task_dir = any(line.strip().startswith("- task_dir:") for line in lines)
    if not (has_results_root and has_task_dir):
        out = []
        inserted = False
        for line in lines:
            out.append(line)
            if not inserted and line.strip().startswith("- target_type:"):
                if not has_results_root:
                    out.append(f"- results_root: {task_dir.parent}")
                if not has_task_dir:
                    out.append(f"- task_dir: {task_dir}")
                inserted = True
        if inserted:
            updated = "\n".join(out)

    if updated != text:
        task_path.write_text(updated.rstrip() + "\n", encoding="utf-8")


def extract_field(block: str, field: str) -> str:
    pattern = rf"\*\*{re.escape(field)}\*\*:[ \t]*(.*?)(?=\n\*\*[^*\n]+?\*\*:|\n---|\Z)"
    match = re.search(pattern, block, flags=re.S)
    return match.group(1).strip() if match else ""


def clean_inline(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


def skill_root() -> Path:
    return Path(__file__).resolve().parent.parent


def redact_sensitive(text: str) -> str:
    text = text or ""
    replacements = [
        (r"(?im)^(Authorization:\s*(?:Bearer|Basic)\s+).+$", r"\1<REDACTED>"),
        (r"(?im)^(Cookie:\s*).+$", r"\1<REDACTED>"),
        (r"(?im)^(Set-Cookie:\s*).+$", r"\1<REDACTED>"),
        (r"(?i)([?&](?:token|access_token|jwt|password|passwd|secret|openid|unionid|userid|loginid|key)=)[^&\s`'\"<>),]+", r"\1<REDACTED>"),
        (r'(?i)("(?:token|access_token|jwt|password|passwd|secret|openId|unionId|userId|loginId|key)"\s*:\s*")[^"]*"', r'\1<REDACTED>"'),
    ]
    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text)
    return text


def sanitize_poc(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            continue
        lines.append(raw.rstrip())
    text = "\n".join(lines).strip()
    text = redact_sensitive(text)
    return text[:4000]


def extract_raw_paths(text: str) -> list[str]:
    paths = []
    for match in re.findall(r"\b(?:raw|screenshots)/[A-Za-z0-9._/@:+-]+", text or ""):
        clean = match.rstrip(".,;)")
        if clean not in paths:
            paths.append(clean)
    return paths


AUTO_POC_PREFIXES = (
    "Safe PoC / reproduction outline:",
    "No explicit live PoC block was recorded in findings.md. Safe reproduction outline:",
)


def build_poc_boundary(target: str, evidence_summary: str, raw_refs: list[str], boundary: str) -> str:
    target = redact_sensitive(extract_endpoint_hint(target)) or "affected endpoint from findings.md"
    evidence_summary = redact_sensitive(clean_inline(evidence_summary)) or "the documented response difference"
    raw_list = ", ".join(raw_refs) if raw_refs else "findings.md and evidence-index.json"
    parts = [
        "Safe PoC / reproduction outline:",
        f"1. Request: `{target}`.",
        f"2. Replay exactly one bounded request in the approved scope; redact Authorization, Cookie, and user identifiers.",
        f"3. Confirm the observation: {evidence_summary}.",
        f"4. Cross-check supporting raw evidence: {raw_list}.",
    ]
    if boundary:
        parts.append(f"Validation boundary: {redact_sensitive(clean_inline(boundary))}")
    return "\n".join(parts)


def extract_endpoint_hint(value: str) -> str:
    text = value or ""
    snippets = re.findall(r"`([^`]*(?:GET|POST|PUT|DELETE|PATCH|/)[^`]*)`", text, flags=re.I)
    if snippets:
        return clean_inline(snippets[0])
    for raw in text.splitlines():
        line = raw.strip().lstrip("-* ").strip()
        if not line:
            continue
        if re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b|/", line, flags=re.I):
            return clean_inline(line)
    return clean_inline(text)


def insert_missing_poc_fields(findings_md: str, parsed_findings: list[dict]) -> str:
    if not parsed_findings:
        return findings_md
    by_id = {item.get("finding_id"): item for item in parsed_findings}
    sections = re.split(r"(\n(?=##\s+F-\d+))", findings_md)
    out = []
    for section in sections:
        fid_match = re.search(r"^##\s+(F-\d+)\b", section, flags=re.M)
        if not fid_match:
            out.append(section)
            continue
        fid = fid_match.group(1)
        finding = by_id.get(fid)
        current_poc = extract_field(section, "PoC")
        if not finding or finding.get("status") in {"false_positive", "not_applicable"}:
            out.append(section)
            continue
        auto_current = current_poc and any(current_poc.startswith(prefix) for prefix in AUTO_POC_PREFIXES)
        if auto_current:
            affected = extract_field(section, "Affected")
            evidence_text = extract_field(section, "Evidence")
            boundary_text = extract_field(section, "Boundary")
            description = clean_inline(extract_field(section, "Description"))
            poc_text = sanitize_poc(
                build_poc_boundary(
                    affected,
                    summarize_evidence(evidence_text) or finding.get("title", fid),
                    extract_raw_paths(evidence_text),
                    boundary_text or derive_boundary(finding.get("title", ""), description, evidence_text, ""),
                )
            )
        else:
            poc_text = sanitize_poc(finding.get("poc") or finding.get("poc_boundary") or "")
        if not poc_text:
            out.append(section)
            continue
        if current_poc:
            if auto_current:
                section = re.sub(
                    r"\*\*PoC\*\*:\s*.*?(?=\n\*\*[^*\n]+?\*\*:|\n---|\Z)",
                    f"**PoC**:\n{poc_text}\n",
                    section,
                    count=1,
                    flags=re.S,
                )
            out.append(section)
            continue
        poc_block = f"\n**PoC**:\n{poc_text}\n"
        if re.search(r"\n\*\*Boundary\*\*:", section):
            section = re.sub(r"\n\*\*Boundary\*\*:", poc_block + "\n**Boundary**:", section, count=1)
        elif re.search(r"\n\*\*Remediation\*\*:", section):
            section = re.sub(r"\n\*\*Remediation\*\*:", poc_block + "\n**Remediation**:", section, count=1)
        elif re.search(r"\n\*\*Status\*\*:", section):
            section = re.sub(r"\n\*\*Status\*\*:", poc_block + "\n**Status**:", section, count=1)
        else:
            section = section.rstrip() + poc_block
        out.append(section)
    return "".join(out)


def parse_findings_table(text: str) -> dict:
    table = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cols = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cols) < 4 or not re.match(r"^F-\d+$", cols[0]):
            continue
        table[cols[0]] = {
            "title": cols[1],
            "severity": normalize_severity(cols[2].split()[0]),
            "status": cols[3].lower().replace(" ", "_"),
        }
    return table


def normalize_severity(value: str) -> str:
    value = str(value or "").strip().lower()
    if value in {"critical", "high", "medium", "low", "info"}:
        return value
    return "info"


def infer_confidence(severity: str, description: str) -> float:
    """Infer confidence based on severity and description."""
    d = description.lower()

    # High confidence for confirmed findings
    if "confirmed" in d or "verified" in d or "validated" in d:
        return 0.95
    if "proof" in d or "evidence" in d or "response" in d:
        return 0.9

    # Medium confidence based on severity
    if severity == "critical":
        return 0.85
    if severity == "high":
        return 0.8
    if severity == "medium":
        return 0.75
    if severity == "low":
        return 0.7

    # Default
    return 0.75


def infer_category(title: str) -> str:
    t = title.lower()
    # --- New specific categories first (before broad legacy patterns can steal them) ---
    # AI / LLM — check before "unauthorized", "leak", "exposure"
    if "prompt injection" in t or "jailbreak" in t or "llm injection" in t:
        return "prompt_injection"
    if "tool use" in t or "tool-use" in t or "function call" in t or "tool abuse" in t:
        return "tool_use_abuse"
    if re.search(r"\brag\b", t) or ("vector" in t and ("db" in t or "database" in t or "poison" in t)):
        return "rag_poison"
    if "system prompt" in t or "system instruction" in t:
        return "system_prompt_leak"
    if "cost" in t and ("dos" in t or "exhaust" in t or "amplif" in t):
        return "llm_cost_dos"
    # gRPC / protobuf — check before "auth"
    if "grpc" in t or "protobuf" in t:
        return "grpc_auth_bypass"
    # K8s / cloud-native — check before "unauthorized"
    if "kubernetes" in t or "k8s" in t or ("privilege" in t and "escala" in t):
        return "k8s_priv_esc"
    if "kubelet" in t:
        return "kubelet_exposure"
    if "etcd" in t:
        return "etcd_exposure"
    if "container escape" in t or "docker escape" in t:
        return "container_escape"
    if "origin ip" in t or "cdn bypass" in t or "waf bypass" in t:
        return "origin_disclosed"
    if ("oss" in t or "cos" in t or "obs" in t or "s3" in t) and ("public" in t or "expos" in t or "bucket" in t):
        return "cloud_bucket_exposed"
    if "http/2" in t or "http2" in t or "single-packet" in t:
        return "http2_race_condition"
    # DOM XSS — check before broad "xss"
    if "dom" in t and "xss" in t:
        return "dom_xss"
    # NoSQL — check before broad "sql"
    if "nosql" in t or "mongodb" in t:
        return "nosqli"
    # --- Legacy core categories ---
    if "backup exposure" in t or "source code exposure" in t or ".git" in t or ".env exposure" in t or "source exposure" in t:
        return "backup_exposure"
    if "sql" in t or "sqli" in t:
        return "sqli"
    if "xss" in t or "cross-site script" in t:
        return "xss"
    if "ssrf" in t or "server-side request" in t:
        return "ssrf"
    if "xxe" in t or "xml external" in t:
        return "xxe"
    if "unauthorized" in t or "unauth" in t or "idor" in t or "bola" in t or "authorization" in t or "access control" in t:
        return "unauthorized_access"
    # Specific categories that would otherwise be caught by broad rules below
    if "password policy" in t or "account lockout" in t:
        return "password_policy"
    if "default credential" in t or "default password" in t:
        return "default_credentials"
    if "error handling" in t or "error disclosur" in t or "stack trace" in t or "debug mode" in t or "verbose error" in t:
        return "error_handling"
    if "security header" in t or "csp bypass" in t or "clickjacking" in t or "x-frame" in t:
        return "security_headers"
    if "path traversal" in t or "directory traversal" in t:
        return "path_traversal"
    if "cloud security" in t or "cloud storage" in t or "cloud metadata" in t or "s3 bucket" in t:
        return "cloud_security"
    if "session" in t and ("management" in t or "fixation" in t or "timeout" in t or "concurrent session" in t):
        return "session_management"
    if "admin panel" in t or "admin interface" in t or "admin console" in t:
        return "admin_panel"
    if "client-side" in t or "local storage" in t or "session storage" in t:
        return "client_side_review"
    if "http method" in t or "http verb" in t or "method override" in t:
        return "http_methods"
    if "soap" in t or "wsdl" in t:
        return "soap_wsdl"
    if "mobile" in t and ("api" in t or "application" in t):
        return "api_mobile"
    # Broad rules (come after specific ones)
    if "weak password" in t or "weak cred" in t:
        return "weak_credentials"
    if "disclosure" in t or "leak" in t or ("exposure" in t and "backup" not in t and ".env" not in t and "source code" not in t):
        return "information_disclosure"
    if "deserialization" in t:
        return "deserialization"
    if "rce" in t or "remote code" in t or "command injection" in t:
        return "rce"
    if "csrf" in t or "cross-site request" in t:
        return "csrf"
    if "jwt" in t or "json web token" in t:
        return "auth"
    if "oauth" in t:
        return "auth"
    if "mfa" in t or "2fa" in t or ("bypass" in t and ("mfa" in t or "2fa" in t or "auth" in t or "login" in t or "otp" in t)):
        return "auth"
    if "file upload" in t:
        return "file_upload"
    if "file inclusion" in t or "lfi" in t or "rfi" in t:
        return "file_inclusion"
    if "websocket" in t or "ws://" in t or "wss://" in t:
        return "websocket"
    if "ssti" in t or "template injection" in t:
        return "ssti"
    if "ldap" in t:
        return "ldap_injection"
    if "open redirect" in t:
        return "open_redirect"
    if "host header" in t:
        return "host_header"
    if "rate limit" in t:
        return "rate_limiting"
    if "password reset" in t:
        return "auth"
    if "smuggling" in t:
        return "request_smuggling"
    if "crlf" in t:
        return "crlf_injection"
    # Race condition — after http2_race_condition which is more specific
    if "race condition" in t or "concurrent" in t:
        return "race_condition"
    if "cache poison" in t:
        return "cache_poisoning"
    if "prototype pollution" in t:
        return "prototype_pollution"
    if "subdomain takeover" in t:
        return "subdomain_takeover"
    if "cors" in t:
        return "cors_misconfiguration"
    return "misc"


OWASP_CWE_MAP = {
    "sqli": ("A03:2021-Injection", "CWE-89"),
    "xss": ("A03:2021-Injection", "CWE-79"),
    "ssrf": ("A10:2021-Server-Side Request Forgery", "CWE-918"),
    "xxe": ("A05:2021-Security Misconfiguration", "CWE-611"),
    "unauthorized_access": ("API1:2023-BOLA", "CWE-639"),
    "weak_credentials": ("A07:2021-Identification and Authentication Failures", "CWE-521"),
    "information_disclosure": ("A01:2021-Broken Access Control", "CWE-200"),
    "rce": ("A03:2021-Injection", "CWE-78"),
    "deserialization": ("A08:2021-Software and Data Integrity Failures", "CWE-502"),
    "csrf": ("A01:2021-Broken Access Control", "CWE-352"),
    "auth": ("A07:2021-Identification and Authentication Failures", "CWE-287"),
    "file_upload": ("A04:2021-Insecure Design", "CWE-434"),
    "file_inclusion": ("A01:2021-Broken Access Control", "CWE-98"),
    "websocket": ("API9:2023-Security Misconfiguration", "CWE-346"),
    "ssti": ("A03:2021-Injection", "CWE-1336"),
    "ldap_injection": ("A03:2021-Injection", "CWE-90"),
    "nosqli": ("A03:2021-Injection", "CWE-943"),
    "open_redirect": ("A01:2021-Broken Access Control", "CWE-601"),
    "host_header": ("A05:2021-Security Misconfiguration", "CWE-644"),
    "rate_limiting": ("API4:2023-Unrestricted Resource Consumption", "CWE-770"),
    "request_smuggling": ("A05:2021-Security Misconfiguration", "CWE-444"),
    "crlf_injection": ("A03:2021-Injection", "CWE-113"),
    "cache_poisoning": ("A05:2021-Security Misconfiguration", "CWE-444"),
    "race_condition": ("A04:2021-Insecure Design", "CWE-362"),
    "prototype_pollution": ("A08:2021-Software and Data Integrity Failures", "CWE-1321"),
    "subdomain_takeover": ("A01:2021-Broken Access Control", "CWE-350"),
    "cors_misconfiguration": ("A05:2021-Security Misconfiguration", "CWE-942"),
    "dom_xss": ("A03:2021-Injection", "CWE-79"),
    "default_credentials": ("A07:2021-Identification and Authentication Failures", "CWE-798"),
    "error_handling": ("A05:2021-Security Misconfiguration", "CWE-209"),
    "security_headers": ("A05:2021-Security Misconfiguration", "CWE-693"),
    "path_traversal": ("A01:2021-Broken Access Control", "CWE-22"),
    "cloud_security": ("A05:2021-Security Misconfiguration", "CWE-200"),
    "session_management": ("A07:2021-Identification and Authentication Failures", "CWE-613"),
    "admin_panel": ("A01:2021-Broken Access Control", "CWE-425"),
    "client_side_review": ("A05:2021-Security Misconfiguration", "CWE-798"),
    "backup_exposure": ("A01:2021-Broken Access Control", "CWE-540"),
    "http_methods": ("A01:2021-Broken Access Control", "CWE-650"),
    "soap_wsdl": ("A03:2021-Injection", "CWE-20"),
    "api_mobile": ("API8:2023-Security Misconfiguration", "CWE-295"),  # CWE-295 covers certificate validation; mobile API issues span multiple CWEs
    "password_policy": ("A07:2021-Identification and Authentication Failures", "CWE-521"),
}


def infer_owasp_cwe(category: str) -> tuple:
    return OWASP_CWE_MAP.get(category, ("", ""))


DISTILLATION_CORE_CATEGORIES = {
    "sqli",
    "ssrf",
    "xxe",
    "unauthorized_access",
    "auth",
    "rce",
    "deserialization",
    "file_upload",
    "file_inclusion",
    "path_traversal",
    "request_smuggling",
    "cache_poisoning",
    "race_condition",
    "prototype_pollution",
    "subdomain_takeover",
    "nosqli",
    "ldap_injection",
    "ssti",
    "cloud_security",
    "api_mobile",
    "default_credentials",
    "weak_credentials",
}


DISTILLATION_LOW_VALUE_CATEGORIES = {
    "security_headers",
    "http_methods",
    "error_handling",
    "password_policy",
}


LOW_VALUE_DISTILLATION_PATTERNS = [
    "missing security header",
    "security header missing",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "clickjacking",
    "no waf",
    "without waf",
    "waf not detected",
    "http trace",
    "trace method",
    "http method only",
    "version disclosure",
    "banner disclosure",
    "server banner",
    "tls",
    "ssl",
    "cookie httponly",
    "cookie secure",
    "samesite",
    "\u76ee\u5f55\u6d4f\u89c8",
    "\u7248\u672c\u6cc4\u9732",
    "\u670d\u52a1\u7aef\u7248\u672c",
    "\u7f3a\u5c11\u5b89\u5168\u5934",
    "\u672a\u914d\u7f6e\u5b89\u5168\u5934",
    "\u672a\u68c0\u6d4b\u5230waf",
    "\u672a\u68c0\u6d4b\u5230 waf",
    "trace\u65b9\u6cd5",
    "trace \u65b9\u6cd5",
    "cookie\u5c5e\u6027",
]


HIGH_VALUE_DISTILLATION_TERMS = [
    "auth",
    "authorization",
    "authentication",
    "access control",
    "idor",
    "bola",
    "privilege",
    "permission",
    "tenant",
    "multi-tenant",
    "business logic",
    "workflow",
    "state transition",
    "signature",
    "signing",
    "jwt",
    "oauth",
    "mfa",
    "2fa",
    "password reset",
    "session",
    "token",
    "secret",
    "hardcoded",
    "credential",
    "admin",
    "internal",
    "cve",
    "exploit",
    "public exploit",
    "known vulnerable",
    "known vulnerability",
    "metadata",
    "mini program",
    "miniprogram",
    "wechat",
    "wxapkg",
    "delete",
    "write",
    "payment",
    "order",
    "invoice",
    "\u8d8a\u6743",
    "\u672a\u6388\u6743",
    "\u9274\u6743",
    "\u8ba4\u8bc1",
    "\u6743\u9650",
    "\u79df\u6237",
    "\u4e1a\u52a1\u903b\u8f91",
    "\u7b7e\u540d",
    "\u4ee4\u724c",
    "\u5bc6\u94a5",
    "\u51ed\u8bc1",
    "\u5f31\u53e3\u4ee4",
    "\u9ed8\u8ba4\u53e3\u4ee4",
    "\u540e\u53f0",
    "\u5185\u7f51",
    "\u5143\u6570\u636e",
    "\u5c0f\u7a0b\u5e8f",
    "\u5fae\u4fe1",
    "\u5220\u9664",
    "\u5199\u5165",
    "\u652f\u4ed8",
    "\u8ba2\u5355",
]


CHAIN_DISTILLATION_TERMS = [
    "chain",
    "chained",
    "attack chain",
    "multi-step",
    "two-step",
    "pivot",
    "bypass",
    "combine",
    "combined",
    "cors with credentials",
    "credentialed cors",
    "cross-host",
    "same-host web",
    "backend host",
    "from mini program to web",
    "rate limit bypass",
    "waf bypass",
    "idor to",
    "read then write",
    "login bypass",
    "auth bypass",
    "\u7ec4\u5408",
    "\u653b\u51fb\u94fe",
    "\u94fe\u8def",
    "\u591a\u6b65\u9aa4",
    "\u7ed5\u8fc7",
    "\u4e32\u8054",
    "\u8054\u52a8",
    "\u5c0f\u7a0b\u5e8f\u5230web",
    "\u5c0f\u7a0b\u5e8f\u5230 web",
    "\u540e\u7aef\u63a5\u53e3",
]


def contains_any_term(text: str, terms: list[str]) -> bool:
    low = (text or "").lower()
    return any(term.lower() in low for term in terms)


def assess_distillation_candidate(
    title: str,
    category: str,
    severity: str,
    description: str,
    evidence_text: str,
    boundary_text: str,
    reproduction: str,
    target: str,
    status: str,
    imported_unreviewed: bool,
) -> dict:
    """Decide whether a finding is valuable enough for L3 distillation."""
    combined = "\n".join([title or "", category or "", description or "", evidence_text or "", boundary_text or "", reproduction or "", target or ""])
    chain_value = contains_any_term(combined, CHAIN_DISTILLATION_TERMS)
    high_value = category in DISTILLATION_CORE_CATEGORIES or contains_any_term(combined, HIGH_VALUE_DISTILLATION_TERMS)
    low_value = category in DISTILLATION_LOW_VALUE_CATEGORIES or contains_any_term(combined, LOW_VALUE_DISTILLATION_PATTERNS)

    endpoint = redact_sensitive(extract_endpoint_hint(target) or title or category or "finding")
    reuse_pattern = clean_inline(f"{category}: {endpoint}")[:180]

    if imported_unreviewed:
        return {
            "distillation_candidate": False,
            "distillation_reason": "not eligible: imported report requires manual review before distillation",
            "complexity": "not_applicable",
            "chain_value": False,
            "reuse_pattern": reuse_pattern,
        }
    if status != "confirmed":
        return {
            "distillation_candidate": False,
            "distillation_reason": "not eligible: finding is not confirmed",
            "complexity": "not_applicable",
            "chain_value": False,
            "reuse_pattern": reuse_pattern,
        }
    if severity in {"low", "info"}:
        return {
            "distillation_candidate": False,
            "distillation_reason": "not eligible: low/info severity is not worth L3 distillation by default",
            "complexity": "not_applicable",
            "chain_value": chain_value,
            "reuse_pattern": reuse_pattern,
        }
    if low_value and not chain_value and not high_value:
        return {
            "distillation_candidate": False,
            "distillation_reason": "not eligible: ordinary configuration/banner/header issue has low reuse value",
            "complexity": "direct",
            "chain_value": False,
            "reuse_pattern": reuse_pattern,
        }
    if chain_value:
        return {
            "distillation_candidate": True,
            "distillation_reason": "eligible: confirmed multi-step, bypass, or cross-surface attack chain pattern",
            "complexity": "chain",
            "chain_value": True,
            "reuse_pattern": reuse_pattern,
        }
    if severity in {"critical", "high"} and (high_value or not low_value):
        complexity = "complex" if high_value else "direct"
        return {
            "distillation_candidate": True,
            "distillation_reason": "eligible: confirmed high-impact finding with reusable validation pattern",
            "complexity": complexity,
            "chain_value": False,
            "reuse_pattern": reuse_pattern,
        }
    if severity == "medium" and high_value:
        return {
            "distillation_candidate": True,
            "distillation_reason": "eligible: medium severity but high-value vulnerability class or business/security-control pattern",
            "complexity": "complex",
            "chain_value": False,
            "reuse_pattern": reuse_pattern,
        }
    return {
        "distillation_candidate": False,
        "distillation_reason": "not eligible: no complex, high-impact, or reusable attack-chain pattern identified",
        "complexity": "direct",
        "chain_value": False,
        "reuse_pattern": reuse_pattern,
    }


def infer_severity_reason(title: str, category: str, description: str, severity: str) -> str:
    """Infer severity reason based on finding characteristics."""
    t = title.lower()
    d = description.lower()

    # Critical reasons
    if severity == "critical":
        if "rce" in t or "remote code" in t or "command injection" in t:
            return "Remote code execution confirmed, enables full system control"
        if "deserialization" in t or category == "deserialization":
            return "Deserialization vulnerability with gadget chain, can lead to RCE"
        if "mass" in d or ">100" in d or ("database" in d and "dump" in d):
            return "Mass data exposure confirmed, sensitive data for multiple users"
        return "Critical impact confirmed through validation"

    # High reasons - exploitable info or direct attack capability
    if severity == "high":
        if category == "sqli":
            if "union" in d or "data" in d:
                return "SQL injection with data extraction capability confirmed"
            return "SQL injection confirmed, enables database data access"
        if category == "information_disclosure":
            if "cve" in d or "exploit" in d:
                return "Exposed version has known CVE with public exploit"
            if "admin" in d or "internal" in d:
                return "Exposed admin/internal endpoint, expands attack surface"
            if "credential" in d or "secret" in d or "password" in d:
                return "Exposed credentials or secrets, enables direct access"
            if "config" in d:
                return "Exposed configuration with sensitive settings"
            return "Information exposure enables further attacks"
        if category == "unauthorized_access":
            return "Authentication/authorization bypass confirmed, enables unauthorized access"
        if category == "ssrf":
            if "cloud" in d or "metadata" in d:
                return "SSRF can access cloud metadata, credential retrieval risk"
            return "SSRF confirmed, internal network reachable"
        if category == "xxe":
            return "XXE confirmed, file read capability demonstrated"
        if category == "auth":
            if "jwt" in t or "json web token" in t:
                return "JWT signature validation flaw, token forgery possible"
            if "oauth" in t:
                return "OAuth flow vulnerability, authorization bypass possible"
            return "Authentication/authorization vulnerability confirmed, enables unauthorized access"

    # Medium reasons
    if severity == "medium":
        if category == "unauthorized_access":
            return "Single-object IDOR, limited to one other user's data"
        if category == "xss":
            return "XSS confirmed, requires user interaction for exploitation"
        if category == "ssrf":
            return "SSRF localhost proof only, no internal service exploitation"
        if category == "sqli":
            return "SQL injection error-based only, no data extraction confirmed"
        if category == "file_inclusion":
            return "LFI test file readable, no credentials accessed"
        return "Medium severity vulnerability, requires conditions for exploitation"

    # Low reasons
    if severity == "low":
        if "header" in d or "csp" in d or "frame" in d:
            return "Missing security header, limited impact"
        if "cookie" in d:
            return "Cookie attribute issue, session security affected"
        return "Low impact vulnerability, minor security concern"

    # Info reasons
    if severity == "info":
        if "path" in d or "endpoint" in d:
            return "Path/endpoint discovered, no sensitive data exposed"
        if "version" in d and "cve" not in d:
            return "Version disclosed, no known CVE for this version"
        if "tech" in d or "stack" in d:
            return "Technology fingerprint, no exploitable version identified"
        return "Discovery finding, no direct security impact"

    return "Severity based on vulnerability type and validation results"


def split_numbered_items(text: str) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    lines = []
    for raw in text.splitlines():
        raw = raw.strip()
        if re.match(r"^\d+\.\s+", raw):
            lines.append(re.sub(r"^\d+\.\s+", "", raw).strip())
    if lines:
        return lines
    parts = re.split(r"\s+(?=\d+\.\s*)", clean_inline(text))
    extracted = []
    for part in parts:
        part = re.sub(r"^\d+\.\s*", "", part).strip()
        if part:
            extracted.append(part)
    return extracted


def summarize_evidence(evidence_text: str) -> str:
    text = (evidence_text or "").strip()
    if not text:
        return ""
    if text.startswith("```"):
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                continue
            if stripped.startswith("- ") or stripped.startswith("* "):
                lines.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#") and len(stripped) > 5:
                lines.append(stripped[:200])
        return "; ".join(lines[:4]) if lines else "See raw response and evidence index for details."
    numbered = re.findall(r"\d+\.\s*(.+?)(?=\s+\d+\.|$)", clean_inline(text))
    if numbered:
        return "; ".join(numbered[:4])
    bullets = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("- "):
            bullets.append(line[2:].strip())
    if bullets:
        return "; ".join(bullets[:4])
    return clean_inline(text)[:240]


def derive_boundary(title: str, description: str, evidence_text: str, reproduction: str) -> str:
    parts = []
    tl = title.lower()
    if "unauthorized" in tl or "unauth" in tl:
        parts.append("Current conclusion based on actual validation of unauthorized access capability")
    if "default credential" in tl or "default password" in tl:
        parts.append("Login verified with known default credentials, no data browsing or modification beyond authentication proof")
    if "error handling" in tl or "error disclosur" in tl or "stack trace" in tl:
        parts.append("Error response observed and documented, no further exploitation of revealed information performed")
    if "security header" in tl or "csp" in tl:
        parts.append("Header configuration analyzed, bypass techniques confirmed without data compromise")
    if "path traversal" in tl or "directory traversal" in tl:
        parts.append("File reading confirmed to system test files only, no sensitive data extraction attempted")
    if "cloud security" in tl or "cloud storage" in tl or "cloud metadata" in tl:
        parts.append("Cloud service enumeration performed, no data accessed or modified beyond configuration verification")
    if "session management" in tl or "session fixation" in tl or "session timeout" in tl:
        parts.append("Session behavior analyzed, no active session hijacking or user impersonation attempted")
    if "admin" in tl and ("panel" in tl or "interface" in tl):
        parts.append("Admin interface identified and access verified, no administrative actions performed")
    if "backup" in tl or "source code" in tl:
        parts.append("Exposed files identified, no file content extraction beyond proof of accessibility")
    if "http method" in tl or "http verb" in tl:
        parts.append("HTTP method behavior verified, no data modification or deletion beyond method availability check")
    if "soap" in tl or "wsdl" in tl:
        parts.append("WSDL endpoint identified and analyzed, no SOAP action tampering beyond detection scope")
    if "mobile" in tl:
        parts.append("Mobile API behavior analyzed, no mobile-specific data accessed beyond configuration review")
    if "password policy" in tl or "account lockout" in tl:
        parts.append("Password policy weakness identified, no credential cracking or account compromise performed")
    if "disclosure" in tl or "leak" in tl or "exposure" in tl:
        parts.append("Current conclusion based on observed leaked content, subsequent exploitation not completed")
    if "SQL" in title.upper():
        parts.append("Current conclusion based on parameter behavior and response difference confirmation, no database read or destructive operations executed")
    if "RCE" in title.upper():
        parts.append("Current conclusion does not indicate command execution, only risk confirmed or high confidence established")
    if "delete" in reproduction.lower() or "DELETE" in reproduction:
        parts.append("If write or delete operations involved, manual review needed to confirm test data cleanup")
    if not parts:
        parts.append("Boundary not specified; manual review required to define validation boundary")
    return "; ".join(parts)


def parse_fingerprint_md(text: str) -> dict:
    result = {"tech_stack": [], "waf": "", "started_at": "unknown"}
    started = re.search(r"-\s*Started:\s*(.+)", text)
    if started:
        result["started_at"] = started.group(1).strip()

    # Support section headers in English (Chinese headers would require additional patterns)
    tech_section = None
    if "## Tech Stack" in text:
        tech_section = re.search(r"## Tech Stack\s*\n\n\|.+?\|\n\|[-| ]+\|\n(.*?)(?:\n## |\Z)", text, flags=re.S)

    if tech_section:
        vals = []
        for line in tech_section.group(1).splitlines():
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cols) >= 2 and cols[1]:
                component = cols[0].strip() if len(cols) > 1 and cols[0].strip() else ""
                entry = f"{component}: {cols[1]}" if component else cols[1]
                vals.append(entry)
        result["tech_stack"] = vals[:5]

    waf_section = None
    if "## WAF Detection" in text:
        waf_section = re.search(r"## WAF Detection\s*\n\n\|.+?\|\n\|[-| ]+\|\n(.*?)(?:\n## |\Z)", text, flags=re.S)
    elif "## WAF" in text:
        waf_section = re.search(r"## WAF\s*\n\n\|.+?\|\n\|[-| ]+\|\n(.*?)(?:\n## |\Z)", text, flags=re.S)

    if waf_section:
        lines = []
        for line in waf_section.group(1).splitlines():
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cols) >= 2 and cols[1]:
                lines.append(f"{cols[0]}={cols[1]}")
        result["waf"] = " ; ".join(lines[:4])
    else:
        waf = re.search(r"\|\s*WAF\s*\|\s*(.+?)\s*\|", text)
        if waf:
            result["waf"] = waf.group(1).strip()
    return result


def parse_findings_md(text: str, task_meta: dict = None) -> list[dict]:
    # Unify parsing: first try ## heading split (same as generate_report.py),
    # then fall back to --- delimiter
    findings_table = parse_findings_table(text)
    sections = re.split(r"\n(?=##\s+F-\d+)", text.strip())
    if not any("F-" in s for s in sections):
        sections = re.split(r"\n---\n", text.strip())
    findings = []
    counter = 1
    for chunk in sections:
        match = re.search(r"##\s+(F-\d+)\s+[\u2014\u2013\-]+\s+(.+?)\s+\[(.+?)\]", chunk)
        if not match:
            match = re.search(r"##\s+(F-\d+)\s+[\u2014\u2013\-]+\s+(.+)$", chunk, flags=re.M)
            if match:
                title_raw = match.group(2).strip()
                sev_match = re.search(r"\b(Critical|High|Medium|Low|Info)\b", title_raw, re.I)
                finding_id = match.group(1)
                if sev_match:
                    title = re.sub(r"[\u2014\u2013\-]+\s*$", "", title_raw[:sev_match.start()].strip()).strip()
                else:
                    title = re.sub(r"[\u2014\u2013\-]+\s*$", "", title_raw).strip()
                severity = normalize_severity(sev_match.group(1)) if sev_match else findings_table.get(finding_id, {}).get("severity", "info")
            else:
                continue
        else:
            finding_id, title, severity = match.group(1), match.group(2).strip(), normalize_severity(match.group(3))
            severity = findings_table.get(finding_id, {}).get("severity", severity)
        description = clean_inline(extract_field(chunk, "Description"))
        affected = extract_field(chunk, "Affected")
        source_phase = extract_field(chunk, "Source Phase")
        remediation = extract_field(chunk, "Remediation")
        discovered_at = extract_field(chunk, "Discovered At")
        evidence_text = extract_field(chunk, "Evidence")
        boundary_text = extract_field(chunk, "Boundary")
        reproduction = extract_field(chunk, "Reproduction")
        poc_text = extract_field(chunk, "PoC") or extract_field(chunk, "Proof Payload") or reproduction
        poc = sanitize_poc(poc_text)
        status_text = clean_inline(extract_field(chunk, "Status")).lower()
        table_status = findings_table.get(finding_id, {}).get("status", "")
        if table_status and table_status not in {"", "-"}:
            status = table_status
        elif "false_positive" in status_text or "false positive" in status_text:
            status = "false_positive"
        elif "suspicious" in status_text:
            status = "suspicious"
        elif "confirmed" in status_text:
            status = "confirmed"
        else:
            status = "confirmed"
        remediation_items = split_numbered_items(remediation)
        category = infer_category(title)
        evidence_summary = summarize_evidence(evidence_text) or title
        raw_refs = extract_raw_paths(evidence_text)

        if not source_phase:
            source_phase = (task_meta or {}).get("current_phase", "")

        # Extract or infer severity_reason
        severity_reason = extract_field(chunk, "Severity Reason")
        if not severity_reason:
            severity_reason = infer_severity_reason(title, category, description, severity)

        # Extract or infer OWASP category and CWE
        owasp_category = extract_field(chunk, "OWASP Category")
        cwe_id = extract_field(chunk, "CWE")
        if not owasp_category or not cwe_id:
            inferred_owasp, inferred_cwe = infer_owasp_cwe(category)
            if not owasp_category:
                owasp_category = inferred_owasp
            if not cwe_id:
                cwe_id = inferred_cwe

        imported_unreviewed = (
            (task_meta or {}).get("target_type") == "imported_report"
            and str((task_meta or {}).get("import_reviewed", "")).lower() not in {"true", "yes", "1"}
        )
        knowledge_candidate = status == "confirmed" and severity in {"critical", "high", "medium"} and not imported_unreviewed
        distillation = assess_distillation_candidate(
            title,
            category,
            severity,
            description,
            evidence_text,
            boundary_text,
            reproduction,
            affected,
            status,
            imported_unreviewed,
        )
        memory_candidate = bool(distillation["distillation_candidate"])

        findings.append(
            {
                "finding_id": finding_id,
                "title": title,
                "category": category,
                "severity": severity,
                "severity_reason": severity_reason,
                "owasp_category": owasp_category,
                "cwe_id": cwe_id,
                "priority": "P0" if severity in {"critical", "high"} else ("P1" if severity == "medium" else ("P2" if severity == "low" else "P3")),
                "status": status,
                "fact_summary": description or title,
                "boundary": boundary_text or derive_boundary(title, description, evidence_text, reproduction),
                "target": affected,
                "target_type": "endpoint" if affected else "unknown",
                "evidence_refs": [f"E-{counter:03d}"],
                "poc": poc,
                "poc_boundary": "" if poc else build_poc_boundary(
                    affected,
                    evidence_summary,
                    raw_refs,
                    boundary_text or derive_boundary(title, description, evidence_text, reproduction),
                ),
                "recommended_next_action": remediation_items[0] if remediation_items else (clean_inline(remediation) or "To be added"),
                "recommended_actions": remediation_items,
                "confidence": infer_confidence(severity, description or ""),
                "created_at": discovered_at or "",
                "knowledge_candidate": knowledge_candidate,
                "memory_candidate": memory_candidate,
                "distillation_candidate": distillation["distillation_candidate"],
                "distillation_reason": distillation["distillation_reason"],
                "complexity": distillation["complexity"],
                "chain_value": distillation["chain_value"],
                "reuse_pattern": distillation["reuse_pattern"],
                "_evidence_summary": evidence_summary,
                "_raw_refs": raw_refs,
                "_source_phase": source_phase,
            }
        )
        counter += 1
    return findings


def build_evidence_index(task_dir: Path, findings: list) -> list[dict]:
    raw_dir = task_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    raw_files = sorted(p for p in raw_dir.glob("*") if p.is_file()) if raw_dir.exists() else []
    evidence = []
    for idx, finding in enumerate(findings, start=1):
        fid = finding.get("finding_id", f"F-{idx:03d}")
        poc_path = raw_dir / f"poc-{fid}.txt"
        poc = finding.get("poc", "").strip()
        if poc:
            poc_path.write_text(
                f"# PoC for {fid}\n\n"
                f"## Target\n{finding.get('target', '')}\n\n"
                f"## Minimal Sanitized PoC\n{poc}\n",
                encoding="utf-8",
            )
        elif finding.get("status") == "confirmed":
            poc_path.write_text(
                f"# PoC for {fid}\n\n"
                "## Safe Reproduction Outline\n"
                f"{finding.get('poc_boundary', '')}\n\n"
                "## Evidence Summary\n"
                f"{redact_sensitive(finding.get('_evidence_summary', ''))}\n",
                encoding="utf-8",
            )

        explicit_refs = finding.get("_raw_refs", []) or []
        raw_ref = explicit_refs[0] if explicit_refs else "findings.md"
        evidence_type = "finding_record"
        if poc_path.exists():
            raw_ref = str(poc_path.relative_to(task_dir))
            evidence_type = "poc"
        elif raw_files:
            raw_ref = str(raw_files[min(idx - 1, len(raw_files) - 1)].relative_to(task_dir))
            evidence_type = "raw_output"
        evidence.append(
            {
                "evidence_id": f"E-{idx:03d}",
                "type": evidence_type,
                "source_tool": "manual",
                "target": finding.get("target", ""),
                "summary": finding.get("_evidence_summary", finding.get("title", "")),
                "raw_ref": {"path": raw_ref},
                "related_paths": explicit_refs,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    return evidence


def host_from_target(target: str) -> str:
    parsed = urlparse(target or "")
    return parsed.netloc or (target or "unknown-target")


def summarize_current_tech(task_dir: Path, summary: dict) -> list[str]:
    candidates = []
    fingerprint = parse_fingerprint_md(read_text(task_dir / "01-fingerprint.md", ""))
    for item in fingerprint.get("tech_stack", []) or []:
        if item and item not in candidates:
            candidates.append(item)
    for item in summary.get("tech_stack", []) or []:
        if item and item not in candidates and item != "unknown":
            candidates.append(item)
    return candidates[:8]


def mermaid_label(value: str, limit: int = 80) -> str:
    value = redact_sensitive(clean_inline(str(value or "")))
    value = value.replace('"', "'").replace("[", "(").replace("]", ")")
    return value[:limit] + ("..." if len(value) > limit else "")


def build_attack_graph(task_dir: Path, summary: dict, findings: list, evidence: list):
    confirmed = [item for item in findings if item.get("status") == "confirmed"]
    target = summary.get("target", "")
    tech = summarize_current_tech(task_dir, summary)
    now = datetime.now(timezone.utc).isoformat()
    evidence_by_id = {item.get("evidence_id"): item for item in evidence}

    lines = [
        f"# Attack Graph - {host_from_target(target)}",
        "",
        f"**Task ID**: {summary.get('task_id', task_dir.name)}",
        f"**Generated At**: {now}",
        "**Generation Rule**: current task evidence only; L3 history and stack templates are not graph sources.",
        "",
        "## Current Evidence Inputs",
        "",
        "- task.md",
        "- 01-fingerprint.md",
        "- 02-discovery.md",
        "- findings.md",
        "- findings.json",
        "- evidence-index.json",
        "- raw/poc-F-*.txt",
        "",
        "## Evidence-Supported Technology",
        "",
    ]
    if tech:
        lines.extend(f"- {item}" for item in tech)
    else:
        lines.append("- No technology asserted without current-task evidence.")

    lines.extend([
        "",
        "## Confirmed Finding Nodes",
        "",
        "| Finding ID | Severity | Category | Affected | Evidence |",
        "|------------|----------|----------|----------|----------|",
    ])
    if confirmed:
        for item in confirmed:
            refs = item.get("evidence_refs", []) or []
            raw_paths = []
            for ref in refs:
                raw = (evidence_by_id.get(ref, {}).get("raw_ref", {}) or {}).get("path", "")
                if raw:
                    raw_paths.append(raw)
            lines.append(
                f"| {item.get('finding_id', '')} | {item.get('severity', '')} | "
                f"{item.get('category', '')} | {redact_sensitive(extract_endpoint_hint(item.get('target', '')))[:120]} | "
                f"{', '.join(raw_paths) or ', '.join(refs)} |"
            )
    else:
        lines.append("| - | - | - | No confirmed findings | - |")

    lines.extend(["", "## Graph", "", "```mermaid", "flowchart TD"])
    lines.append(f'    target["Target<br/>{mermaid_label(host_from_target(target), 60)}"]')
    if tech:
        lines.append(f'    fp["Fingerprint<br/>{mermaid_label("; ".join(tech), 90)}"]')
    else:
        lines.append('    fp["Fingerprint<br/>current evidence only"]')
    lines.append("    target --> fp")
    if confirmed:
        for idx, item in enumerate(confirmed, start=1):
            node = f"f{idx}"
            label = f"{item.get('finding_id', '')} {item.get('severity', '')}<br/>{item.get('title', '')}"
            lines.append(f'    {node}["{mermaid_label(label, 100)}"]')
            lines.append(f"    fp --> {node}")
    else:
        lines.append('    none["No confirmed vulnerability nodes"]')
        lines.append("    fp --> none")
    lines.extend(["```", ""])

    lines.extend([
        "## Excluded Historical References",
        "",
        "No L3 entry, historical task, ThinkPHP/Spring/Nacos template, or user-provided example is included as a graph node unless the current task evidence above independently supports it.",
    ])
    (task_dir / "attack-graph.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def ensure_summary(task_dir: Path, task_meta: dict, findings: list, existing: dict) -> dict:
    summary = dict(existing) if isinstance(existing, dict) else {}
    summary["task_id"] = summary.get("task_id") or task_meta.get("task_id", task_dir.name)
    summary["skill_name"] = summary.get("skill_name") or "authorized-appsec"
    summary["target"] = summary.get("target") or task_meta.get("target", "")
    summary["target_type"] = summary.get("target_type") or task_meta.get("target_type", "url")
    task_status = task_meta.get("status", "").strip()
    task_phase = task_meta.get("current_phase", "").strip()
    if task_status:
        summary["phase_status"] = task_status
    elif not summary.get("phase_status"):
        summary["phase_status"] = task_status or "unknown"
    if task_phase:
        summary["current_phase"] = task_phase
    elif not summary.get("current_phase"):
        summary["current_phase"] = task_phase or "unknown"
    summary["results_root"] = str(task_dir.parent)
    summary["task_dir"] = str(task_dir)
    task_started = task_meta.get("started_at", "").strip()
    task_updated = task_meta.get("updated_at", "").strip()
    fingerprint = parse_fingerprint_md(read_text(task_dir / "01-fingerprint.md", ""))
    if task_started:
        summary["started_at"] = task_started
    elif summary.get("started_at") in {"unknown", "", None} and fingerprint.get("started_at"):
        summary["started_at"] = fingerprint.get("started_at")
    elif not summary.get("started_at"):
        summary["started_at"] = "unknown"
    if task_updated:
        summary["ended_at"] = task_updated
    elif not summary.get("ended_at"):
        summary["ended_at"] = task_updated or "unknown"

    tech_stack_value = task_meta.get("tech_stack", "")
    existing_stack = summary.get("tech_stack", [])
    all_versions = existing_stack and all(re.match(r"^\d", str(v)) for v in existing_stack if v)
    if fingerprint.get("tech_stack") and (not existing_stack or all_versions or existing_stack == ["unknown"]):
        summary["tech_stack"] = fingerprint.get("tech_stack")
    elif tech_stack_value and not existing_stack:
        summary["tech_stack"] = [tech_stack_value]
    else:
        summary.setdefault("tech_stack", [])
    if fingerprint.get("waf") and summary.get("waf", "unknown") in {"unknown", "", None}:
        summary["waf"] = fingerprint.get("waf")
    else:
        summary["waf"] = summary.get("waf") or task_meta.get("waf", "unknown")

    confirmed = [item for item in findings if item.get("status") == "confirmed"]
    imported_unreviewed = (
        task_meta.get("target_type") == "imported_report"
        and str(task_meta.get("import_reviewed", "")).lower() not in {"true", "yes", "1"}
    )
    eligible = [
        item
        for item in confirmed
        if item.get("distillation_candidate")
        and item.get("knowledge_candidate")
        and item.get("severity") in {"critical", "high", "medium"}
    ]
    if imported_unreviewed:
        eligible = []
    summary["major_findings"] = [item.get("finding_id") for item in confirmed if item.get("severity") in {"critical", "high"}]
    next_recommendations = []
    for item in findings[:5]:
        actions = item.get("recommended_actions") or []
        if actions:
            next_recommendations.extend(actions[:2])
        elif item.get("recommended_next_action"):
            next_recommendations.append(item.get("recommended_next_action"))
    deduped = []
    seen = set()
    for item in next_recommendations:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
    if deduped and (not summary.get("next_recommendations") or len(summary.get("next_recommendations", [])) <= 1):
        summary["next_recommendations"] = deduped
    summary["boundary_summary"] = summary.get("boundary_summary") or [
        "Only recorded observed facts and validated conclusions",
        "No destructive operations beyond authorized scope executed",
        "Structured summary auto-completed from task notes, requires manual review",
    ]
    summary["risk_summary"] = findings[0].get("fact_summary", "") if findings else summary.get("risk_summary", "")
    summary["report_status"] = summary.get("report_status", "draft")
    summary["knowledge_ready"] = bool(eligible)
    summary["memory_ready"] = bool(eligible)
    summary["distillation_ready"] = bool(eligible)
    summary["distillation_candidate_count"] = len(eligible)
    if imported_unreviewed:
        summary["l3_export_reason"] = "not eligible: imported report requires manual review before distillation/L3 export"
    elif eligible:
        summary["l3_export_reason"] = f"{len(eligible)} confirmed distillation candidate(s)"
    else:
        summary["l3_export_reason"] = "not eligible: no confirmed complex/high-value findings or reusable attack chains"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in confirmed:
        counts[item.get("severity", "info")] = counts.get(item.get("severity", "info"), 0) + 1
    summary["finding_counts"] = counts
    return summary


def main():
    if len(sys.argv) != 2:
        print("Usage: ensure_structured_outputs.py <task_dir>", file=sys.stderr)
        sys.exit(1)

    task_dir = Path(sys.argv[1]).resolve()
    if not task_dir.exists():
        raise SystemExit(f"Task directory not found: {task_dir}")

    normalize_task_paths(task_dir)
    task_meta = parse_task_md(read_text(task_dir / "task.md", ""))
    findings_md = read_text(task_dir / "findings.md", "")
    existing_summary = read_json(task_dir / "summary.json", {})
    existing_findings = read_json(task_dir / "findings.json", None)
    findings = parse_findings_md(findings_md, task_meta)
    findings_with_poc = insert_missing_poc_fields(findings_md, findings)
    if findings_with_poc != findings_md:
        (task_dir / "findings.md").write_text(findings_with_poc.rstrip() + "\n", encoding="utf-8")
        findings_md = findings_with_poc
        findings = parse_findings_md(findings_md, task_meta)

    if not findings and existing_findings is not None:
        if isinstance(existing_findings, list):
            findings = existing_findings
        elif isinstance(existing_findings, dict):
            findings = existing_findings.get("findings", [])
        print(f"warning: no findings parsed from findings.md, keeping {len(findings)} existing findings", file=sys.stderr)

    evidence = build_evidence_index(task_dir, findings)
    summary = ensure_summary(task_dir, task_meta, findings, existing_summary)
    build_attack_graph(task_dir, summary, findings, evidence)

    write_json(task_dir / "findings.json", findings)
    write_json(task_dir / "evidence-index.json", evidence)
    write_json(task_dir / "summary.json", summary)
    print(f"ensured-structured:{task_dir}")


if __name__ == "__main__":
    main()
