#!/usr/bin/env python3
import json
import subprocess
import re
import sys
from urllib.parse import urlparse
from pathlib import Path


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path, default: str = ""):
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def fmt_boundary(boundary):
    if isinstance(boundary, list):
        return "\n".join(f"- {item}" for item in boundary)
    return str(boundary or "")


def count_by_severity(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = str(item.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# Severity ordering for report numbering: higher risk = lower V-XX number.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Chinese severity labels for the customer-facing report.
SEVERITY_CN = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def fid_to_vid_map(findings: list) -> dict:
    """Map internal F-XXX IDs to customer-facing V-XX report IDs.

    V-XX is assigned by severity descending (critical first → V-01), with
    finding_id ascending as the tie-breaker within a severity tier. The F-XXX
    identifier remains the internal single source of truth (findings.json);
    V-XX exists only in the rendered report so the customer never sees the
    internal scheme.
    """
    active = [f for f in findings if f.get("status") not in {"false_positive", "not_applicable"}]
    ordered = sorted(
        active,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 99),
            f.get("finding_id", ""),
        ),
    )
    return {f.get("finding_id", f"item-{i}"): f"V-{i+1:02d}" for i, f in enumerate(ordered)}


def severity_cn(item: dict) -> str:
    return SEVERITY_CN.get(str(item.get("severity", "")).lower(), str(item.get("severity", "")))


def pretty_status(value: str) -> str:
    mapping = {
        "completed": "Completed",
        "in_progress": "In Progress",
        "paused": "Paused",
        "stopped": "Stopped",
        "terminated": "Terminated",
        "failed": "Failed",
        "handoff": "Handoff",
    }
    return mapping.get(str(value).lower(), str(value))


def report_title(summary):
    target = summary.get("target", "")
    host = urlparse(target).netloc or target
    return f"Authorized AppSec Assessment Report - {host or 'unknown-target'}"


def short_target(summary):
    target = summary.get("target", "")
    return urlparse(target).netloc or target


def build_findings_table(findings, vid_map=None, cvss_scores=None):
    """Customer-facing vulnerability summary (一、漏洞汇总).

    V-XX numbering (mapped from internal F-XXX), Chinese severity labels,
    CVSS score, and status. Ordered by severity descending to match the
    customer report convention.
    """
    if vid_map is None:
        vid_map = fid_to_vid_map(findings)
    if cvss_scores is None:
        cvss_scores = {}
    ordered = sorted(
        [f for f in findings if f.get("status") not in {"false_positive", "not_applicable"}],
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 99),
            f.get("finding_id", ""),
        ),
    )
    lines = [
        "| 编号 | 漏洞名称 | 严重等级 | CVSS估分 | 状态 |",
        "|------|---------|---------|---------|------|",
    ]
    status_cn = {"confirmed": "已确认", "suspicious": "疑似", "false_positive": "误报",
                 "not_applicable": "不适用"}
    for item in ordered:
        fid = item.get("finding_id", "")
        vid = vid_map.get(fid, fid)
        title = item.get("title", item.get("fact_summary", ""))
        sev = severity_cn(item)
        cvss = cvss_scores.get(fid, "")
        status = status_cn.get(str(item.get("status", "")).lower(), item.get("status", ""))
        lines.append(f"| {vid} | {title} | {sev} | {cvss} | {status} |")
    return "\n".join(lines)


def build_evidence_table(evidence):
    lines = [
        "| Evidence ID | Type | Source Tool | Target | Summary | Raw Path |",
        "|-------------|------|-------------|--------|---------|----------|",
    ]
    for item in evidence:
        raw_ref = item.get("raw_ref", {}) or {}
        lines.append(
            f"| {item.get('evidence_id', '')} | {item.get('type', '')} | "
            f"{item.get('source_tool', '')} | {item.get('target', '')} | "
            f"{item.get('summary', '')} | {raw_ref.get('path', '')} |"
        )
    return "\n".join(lines)


def build_recommendations(summary, findings, vid_map=None):
    """Customer-facing hardening recommendations (六、安全加固建议).

    Tiered by priority (high: 14 days, medium: 30 days, ongoing), each tying
    a remediation measure back to its V-XX finding so the customer can trace
    advice to evidence.
    """
    if vid_map is None:
        vid_map = fid_to_vid_map(findings)
    high_rows = []   # critical/high → 14 days
    medium_rows = []  # medium/low → 30 days
    for item in findings:
        if item.get("status") in {"false_positive", "not_applicable"}:
            continue
        sev = str(item.get("severity", "")).lower()
        action = item.get("recommended_next_action", "") or item.get("remediation", "")
        if not action:
            continue
        fid = item.get("finding_id", "")
        vid = vid_map.get(fid, fid)
        title = item.get("title", "")
        row = (vid, title, action)
        if sev in {"critical", "high"}:
            high_rows.append(row)
        elif sev in {"medium", "low"}:
            medium_rows.append(row)

    parts = ["## 六、安全加固建议", ""]
    if high_rows:
        parts.extend(["### 高优先级 (14天内)", "", "| 编号 | 漏洞 | 措施 |", "|------|------|------|"])
        for vid, title, action in high_rows:
            parts.append(f"| {vid} | {title} | {action} |")
        parts.append("")
    if medium_rows:
        parts.extend(["### 中优先级 (30天内)", "", "| 编号 | 漏洞 | 措施 |", "|------|------|------|"])
        for vid, title, action in medium_rows:
            parts.append(f"| {vid} | {title} | {action} |")
        parts.append("")
    parts.extend(["### 持续改进", "", "| 领域 | 建议 |", "|------|------|"])
    # "持续改进" is for process/SDL-level guidance only — it must NOT repeat
    # the per-finding remediation measures (those are already in the priority
    # tables above). Only generic, non-finding-specific next_recommendations
    # that are clearly process-level (e.g. "建立安全开发规范") belong here.
    remediation_texts = {row[2] for row in high_rows + medium_rows}
    ongoing = summary.get("next_recommendations", []) or []
    for rec in ongoing:
        if rec and rec not in remediation_texts and not any(
            rec in rt or rt in rec for rt in remediation_texts
        ):
            parts.append(f"| - | {rec} |")
    # Always include baseline SDL/process guidance.
    parts.append("| SDL流程 | 建立安全开发规范，代码审计覆盖前端JS |")
    parts.append("| 安全培训 | 定期开发者安全意识培训 |")
    parts.append("| 定期演练 | 每季度进行渗透测试和安全演练 |")
    parts.append("")
    return "\n".join(parts).strip()


def extract_field(block: str, field: str) -> str:
    pattern = rf"\*\*{re.escape(field)}\*\*:\s*(.*?)(?=\n\*\*[^*\n]+?\*\*:|\n---|\Z)"
    match = re.search(pattern, block, flags=re.S)
    return match.group(1).strip() if match else ""


def sanitize_multiline(value: str) -> str:
    if not value:
        return ""
    value = re.sub(r"```[\s\S]*?```", "[code block omitted for report]", value, flags=re.S).strip()
    return value


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


def sanitize_poc(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    lines = []
    for raw in value.splitlines():
        if raw.strip().startswith("```"):
            continue
        lines.append(raw.rstrip())
    return redact_sensitive("\n".join(lines).strip())[:2000]


def redact_response(text: str) -> str:
    """Redact secrets inside an embedded evidence block (curl/HTTP/JSON).

    Unlike ``redact_sensitive`` (which blanks whole Cookie lines), this keeps
    the customer-visible structure — cookie names, header names, JSON keys —
    so the evidence remains readable and persuasive, and only masks the *value*
    of anything that looks like a credential: 32+ hex session keys/tokens,
    Bearer tokens, password fields, and long cookie values. Test data
    (e.g. ``13800138000``) and paths are deliberately preserved.
    """
    text = text or ""
    replacements = [
        # Authorization Bearer/Basic — keep scheme, mask token.
        (r"(?im)(Authorization:\s*(?:Bearer|Basic)\s+)\S+", r"\1***REDACTED***"),
        # Set-Cookie / Cookie: keep the name, mask long/secret values.
        (r"(?im)((?:Set-)?Cookie:\s*[A-Za-z0-9_.\-]+=)[^;\r\n]+", r"\1***REDACTED***"),
        # Bare 32+ hex blobs that are likely session keys / tokens, anywhere.
        (r"(?<![A-Za-z0-9])([0-9a-fA-F]{32,})(?![A-Za-z0-9])", "***REDACTED***"),
        # JSON "token"/"secret"/"password"/"key" string values.
        (r'(?i)("(?:token|access_token|refresh_token|jwt|secret|password|passwd|sessionKey|session_key)"\s*:\s*")[^"]*"', r'\1***REDACTED***"'),
        # Query-string credential params (keep the key, mask the value).
        (r"(?i)([?&](?:token|access_token|jwt|password|passwd|secret|key|sessionKey)=)[^&\s`'\"<>)]+", r"\1***REDACTED***"),
    ]
    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text)
    return text


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
            "severity": cols[2],
            "status": cols[3],
        }
    return table


def sanitize_evidence(value: str) -> list[str]:
    value = value.strip()
    if not value:
        return []
    if value.startswith("```"):
        lines = []
        for line in value.splitlines():
            line = line.strip()
            if line.startswith("```"):
                continue
            if line.startswith("- ") or line.startswith("* "):
                lines.append(line[2:].strip())
            elif line and not line.startswith("#") and len(line) > 5:
                lines.append(line[:200])
        return lines[:4] or ["See evidence index and raw files for details."]
    lines = []
    for raw in value.splitlines():
        raw = raw.strip()
        if raw.startswith("- "):
            text = raw[2:].strip()
            text = re.sub(r"(\$2[aby]\$[0-9]+\$)[A-Za-z0-9./]+", r"\1<redacted>", text)
            lines.append(text)
    return lines[:4]


def sanitize_reproduction(value: str) -> str:
    if not value:
        return ""
    lines = []
    for raw in value.splitlines():
        raw = raw.strip()
        if raw.startswith("curl ") or raw.startswith("curl.exe ") or raw.startswith("GET ") or raw.startswith("POST "):
            lines.append(redact_sensitive(raw))
    return "\n".join(lines[:3])


def sanitize_remediation(value: str) -> list[str]:
    if not value:
        return []
    items = []
    for raw in value.splitlines():
        raw = raw.strip()
        if re.match(r"^\d+\.\s+", raw):
            items.append(re.sub(r"^\d+\.\s+", "", raw))
    if not items and value:
        items = [sanitize_multiline(value)]
    return items[:4]


def parse_findings_markdown(text: str) -> dict:
    sections = re.split(r"\n## ", text.strip())
    result = {}
    findings_table = parse_findings_table(text)
    for idx, section in enumerate(sections):
        if idx == 0:
            if section.startswith("## "):
                section = section[3:]
            elif section.startswith("# Findings"):
                continue
        section = section if idx == 0 else "## " + section
        title_match = re.search(r"^##\s+(F-\d+)\s+[\u2014\u2013\-]+\s+(.+?)\s+\[", section, flags=re.M)
        if not title_match:
            title_match = re.search(r"^##\s+(F-\d+)\s+[\u2014\u2013\-]+\s+(.+)$", section, flags=re.M)
            if title_match:
                title_raw = title_match.group(2).strip()
                sev_match = re.search(r"\b(Critical|High|Medium|Low|Info)\b", title_raw, re.I)
                if sev_match:
                    parsed_title = re.sub(r"[\u2014\u2013\-]+\s*$", "", title_raw[:sev_match.start()].strip()).strip()
                else:
                    parsed_title = re.sub(r"[\u2014\u2013\-]+\s*$", "", title_raw).strip()
                fid = title_match.group(1)
                result[fid] = {
                    "title": parsed_title,
                    "severity_from_table": findings_table.get(fid, {}).get("severity", ""),
                    "status_from_table": findings_table.get(fid, {}).get("status", ""),
                    "affected": extract_field(section, "Affected"),
                    "source_phase": extract_field(section, "Source Phase"),
                    "description": sanitize_multiline(extract_field(section, "Description")),
                    "evidence": sanitize_evidence(extract_field(section, "Evidence")),
                    "poc": sanitize_poc(extract_field(section, "PoC") or extract_field(section, "Proof Payload")),
                    "reproduction": sanitize_reproduction(extract_field(section, "Reproduction")),
                    "remediation": sanitize_remediation(extract_field(section, "Remediation")),
                    "discovered_at": extract_field(section, "Discovered At"),
                }
                continue
            continue
        fid = title_match.group(1)
        result[fid] = {
            "title": title_match.group(2).strip(),
            "severity_from_table": findings_table.get(fid, {}).get("severity", ""),
            "status_from_table": findings_table.get(fid, {}).get("status", ""),
            "affected": extract_field(section, "Affected"),
            "source_phase": extract_field(section, "Source Phase"),
            "description": sanitize_multiline(extract_field(section, "Description")),
            "evidence": sanitize_evidence(extract_field(section, "Evidence")),
            "poc": sanitize_poc(extract_field(section, "PoC") or extract_field(section, "Proof Payload")),
            "reproduction": sanitize_reproduction(extract_field(section, "Reproduction")),
            "remediation": sanitize_remediation(extract_field(section, "Remediation")),
            "discovered_at": extract_field(section, "Discovered At"),
        }
    return result


def build_findings_details(findings, parsed_findings, findings_md="", vid_map=None, cvss_scores=None):
    """Customer-facing vulnerability details (三、漏洞详情).

    Each finding is rendered as a self-contained block with the FULL evidence
    (curl + HTTP/JSON response) embedded inline after redaction — the customer
    wants to see the raw "发包验证" proof, not a sanitized summary. Internal
    F-XXX ids are shown as a small note alongside the V-XX number.
    """
    if vid_map is None:
        vid_map = fid_to_vid_map(findings)
    if cvss_scores is None:
        cvss_scores = {}
    ordered = sorted(
        [f for f in findings if f.get("status") not in {"false_positive", "not_applicable"}],
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 99),
            f.get("finding_id", ""),
        ),
    )
    parts = ["## 三、漏洞详情", ""]
    for item in ordered:
        fid = item.get("finding_id", "")
        parsed = parsed_findings.get(fid, {})
        vid = vid_map.get(fid, fid)
        title = item.get("title", parsed.get("title", ""))
        sev_cn = severity_cn(item)
        cvss = cvss_scores.get(fid, "")
        level_line = f"{sev_cn} (CVSS {cvss})" if cvss else sev_cn
        affected = parsed.get("affected", item.get("target", "")) or "_未记录_"
        parts.extend([
            f"### {vid}: {title}  *(内部编号 {fid})*",
            "",
            f"**漏洞地址**: {affected}",
            "",
            f"**漏洞级别**: {level_line}",
            "",
            "**描述**:",
            "",
            parsed.get("description", item.get("fact_summary", "_待补充_")) or "_待补充_",
            "",
        ])
        # Full evidence block, extracted from the raw findings.md (NOT the
        # sanitized parsed summary) and redacted inline.
        raw_evidence = _extract_field_from_md(findings_md, fid, "Evidence")
        # Skip auto-injected "Safe PoC / reproduction outline" placeholders —
        # they are repro guides, not real request/response evidence, and must
        # not appear in the customer report.
        poc = parsed.get("poc", "") or item.get("poc", "")
        if poc and re.search(r"Safe PoC|reproduction outline|No explicit live PoC", poc, re.I):
            poc = ""
        if raw_evidence.strip() or poc:
            parts.append("**证据(发包验证)**:")
            parts.append("")
            if raw_evidence.strip():
                parts.extend(_render_evidence_block(raw_evidence))
            if poc and poc not in raw_evidence:
                fence = "http" if re.search(r"\b(GET|POST|PUT|DELETE|PATCH|HTTP/1\.1|curl)\b", poc, re.I) else ""
                parts.extend([f"```{fence}", poc, "```", ""])
        # Cleanup status (new field, optional).
        cleanup = _extract_field_from_md(findings_md, fid, "Cleanup Status")
        if cleanup.strip():
            parts.extend([f"**清理状态**: {cleanup.strip()}", ""])
        # Impact (new field; falls back to severity_reason).
        impact = _extract_field_from_md(findings_md, fid, "Impact") or item.get("severity_reason", "")
        if impact.strip():
            parts.extend([f"**影响**: {impact.strip()}", ""])
        # Remediation.
        remediation = parsed.get("remediation", [])
        if remediation:
            parts.extend(["**修复建议**:", ""])
            parts.extend([f"{i}. {line}" for i, line in enumerate(remediation, 1)])
            parts.append("")
        parts.append("---")
        parts.append("")
    return "\n".join(parts).strip()


def _extract_field_from_md(findings_md: str, fid: str, field: str) -> str:
    """Extract a raw **Field**: value for a given finding from findings.md.

    Unlike the parsed pipeline (which sanitizes/deletes code blocks), this
    returns the field content verbatim so embedded evidence blocks survive
    intact into the report.
    """
    # Locate the finding section by its ## F-XXX heading.
    sec_match = re.search(
        rf"(?m)^##\s+{re.escape(fid)}\b.*?(?=^##\s+F-\d+\b|\Z)",
        findings_md, flags=re.S,
    )
    if not sec_match:
        return ""
    section = sec_match.group(0)
    pattern = rf"\*\*{re.escape(field)}\*\*:\s*(.*?)(?=\n\*\*[^*\n]+?\*\*:|\n---|\Z)"
    m = re.search(pattern, section, flags=re.S)
    return m.group(1).strip() if m else ""


def _render_evidence_block(raw: str) -> list[str]:
    """Render raw evidence content into report lines, redacting secrets.

    Preserves embedded ```bash / ```http / ```json fenced blocks so the
    customer sees the actual request and response. Content outside fences is
    passed through after redaction.
    """
    out = []
    # Split into fenced blocks and free text, keeping the fences.
    segments = re.split(r"(```[\s\S]*?```)", raw)
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        if seg.startswith("```"):
            # Inline-redact inside the fence, keep the fence markers.
            inner = seg[3:].split("\n", 1)
            lang = inner[0].strip()
            body = inner[1].rsplit("```", 1)[0] if len(inner) > 1 else ""
            out.append(f"```{lang}")
            out.append(redact_response(body.rstrip()))
            out.append("```")
            out.append("")
        else:
            out.append(redact_response(seg))
            out.append("")
    return out


def build_asset_profile(summary: dict, fingerprint_md: str) -> str:
    """Customer-facing system asset profile (二、被测系统资产画像).

    Eight sub-sections mirroring the approved report. Data comes from
    01-fingerprint.md (tech stack, WAF, auth, attack surface) and summary.json
    (deployment, external deps, data flow). Missing data degrades to a
    ``_待补充_`` placeholder rather than raising — a partial fingerprint must
    still produce a usable report skeleton.
    """
    parts = ["## 二、被测系统资产画像", ""]
    parts.extend(_asset_2_1_basics(summary))
    parts.extend(_asset_2_2_tech_stack(fingerprint_md))
    parts.extend(_asset_2_3_deployment(summary))
    parts.extend(_asset_2_4_auth(fingerprint_md))
    parts.extend(_asset_2_5_components(fingerprint_md, summary))
    parts.extend(_asset_2_6_modules(fingerprint_md))
    parts.extend(_asset_2_7_data_flow(summary))
    parts.extend(_asset_2_8_external_deps(summary))
    return "\n".join(parts).strip()


def _ph(val) -> str:
    return val if val else "_待补充_"


def _asset_2_1_basics(summary: dict) -> list[str]:
    target = summary.get("target", "")
    deploy = summary.get("deployment", {}) or {}
    parts = ["### 2.1 系统基本信息", "", "| 属性 | 值 |", "|------|-----|"]
    parts.append(f"| 域名/IP | {_ph(target)}{' / ' + deploy.get('ip', '') if deploy.get('ip') else ''} |")
    parts.append(f"| 开放端口(Web) | {_ph(deploy.get('port') or deploy.get('web_port'))} |")
    parts.append(f"| 协议 | {_ph(deploy.get('protocol'))} |")
    parts.append(f"| SSL证书 | {_ph(deploy.get('ssl'))} |")
    parts.append(f"| 响应状态 | {_ph(deploy.get('response_status'))} |")
    parts.append("")
    return parts


def _parse_md_table(md: str, header_hint: str) -> list[list[str]]:
    """Extract rows from a markdown table appearing under a heading."""
    m = re.search(rf"##\s+{re.escape(header_hint)}.*?(?:\n```|\n##|\Z)", md, flags=re.S)
    if not m:
        return []
    rows = []
    for line in m.group(0).splitlines():
        s = line.strip()
        if not s.startswith("|") or re.match(r"^\|[-:\s|]+\|$", s):
            continue
        cols = [c.strip() for c in s.strip("|").split("|")]
        rows.append(cols)
    return rows[1:] if rows else []  # drop header row


def _asset_2_2_tech_stack(fingerprint_md: str) -> list[str]:
    rows = _parse_md_table(fingerprint_md, "Tech Stack")
    parts = ["### 2.2 技术栈全景", "", "| 层级 | 识别结果 | 版本 | 识别依据 |",
             "|------|---------|------|---------|"]
    if rows:
        for r in rows:
            parts.append("| " + " | ".join((r + ["-", "-", "-"])[:4]) + " |")
    else:
        parts.append("| _待补充_ | - | - | - |")
    parts.append("")
    return parts


def _asset_2_3_deployment(summary: dict) -> list[str]:
    deploy = summary.get("deployment", {}) or {}
    parts = ["### 2.3 部署架构", ""]
    fields = [
        ("架构模型", "architecture"), ("WAF/CDN", "waf_cdn"),
        ("反向代理", "reverse_proxy"), ("API网关", "api_gateway"),
        ("云平台/归属", "cloud"),
    ]
    any_data = any(deploy.get(k) for _, k in fields)
    if any_data:
        for label, key in fields:
            if deploy.get(key):
                parts.append(f"- **{label}**: {deploy[key]}")
    else:
        parts.append("- _待补充_")
    parts.append("")
    return parts


def _asset_2_4_auth(fingerprint_md: str) -> list[str]:
    # The fingerprint may label the auth section "Authentication", "Auth", or
    # "Login Mechanism". Try each before giving up.
    rows = []
    for hint in ("Authentication", "Auth", "Login"):
        rows = _parse_md_table(fingerprint_md, hint)
        if rows:
            break
    parts = ["### 2.4 认证鉴权机制", "", "| 项目 | 识别结果 |", "|------|---------|"]
    if rows:
        for r in rows:
            parts.append("| " + " | ".join((r + ["-"])[:2]) + " |")
    else:
        parts.append("| _待补充_ | - |")
    parts.append("")
    return parts


def _asset_2_5_components(fingerprint_md: str, summary: dict) -> list[str]:
    rows = _parse_md_table(fingerprint_md, "Tech Stack")
    parts = ["### 2.5 第三方组件与依赖", "", "| 组件 | 版本 | 已知风险 |",
             "|------|------|---------|"]
    if rows:
        for r in rows:
            parts.append("| " + " | ".join((r + ["-", "-"])[:3]) + " |")
    else:
        parts.append("| _待补充_ | - | - |")
    parts.append("")
    return parts


def _asset_2_6_modules(fingerprint_md: str) -> list[str]:
    rows = _parse_md_table(fingerprint_md, "Attack Surface")
    parts = ["### 2.6 功能模块梳理", "", "| 模块 | 路径/端点 | 认证需求 | 关键功能 |",
             "|------|---------|---------|---------|"]
    if rows:
        for r in rows:
            parts.append("| " + " | ".join((r + ["-", "-", "-"])[:4]) + " |")
    else:
        parts.append("| _待补充_ | - | - | - |")
    parts.append("")
    return parts


def _asset_2_7_data_flow(summary: dict) -> list[str]:
    data_flow = summary.get("data_flow", []) or []
    parts = ["### 2.7 敏感数据识别与数据流", ""]
    if data_flow:
        parts.extend(["| 数据类型 | 传输方式 | 存储方式(推测) | 风险 |",
                      "|---------|---------|--------------|------|"])
        for row in data_flow:
            if isinstance(row, dict):
                parts.append("| " + " | ".join(str(row.get(k, "-")) for k in
                              ("data_type", "transport", "storage", "risk")) + " |")
            else:
                parts.append(f"| {row} | - | - | - |")
    else:
        parts.append("- _待补充_")
    parts.append("")
    return parts


def _asset_2_8_external_deps(summary: dict) -> list[str]:
    deps = summary.get("external_deps", []) or []
    parts = ["### 2.8 外连依赖", ""]
    if deps:
        parts.extend(["| 外连目标 | 用途 | 可控性 |", "|---------|------|--------|"])
        for row in deps:
            if isinstance(row, dict):
                parts.append("| " + " | ".join(str(row.get(k, "-")) for k in
                              ("target", "purpose", "controllable")) + " |")
            else:
                parts.append(f"| {row} | - | - |")
    else:
        parts.append("- _待补充_")
    parts.append("")
    return parts


def build_test_process(coverage_md: str, findings_md: str) -> str:
    """Customer-facing test process (四、测试过程).

    Renders the coverage-checklist as a per-category record in the approved
    A.N / A.N.M numbering style: each category is an ``### A.N`` heading, each
    surface row is an ``#### A.N.M`` sub-item annotated with its test result
    (已发现 / 未发现 / 未充分测试 / 受限 / 不适用). The "Scope Adherence" and
    "Coverage Summary" sections are NOT test-process records and are skipped
    here (they appear elsewhere in the report).
    """
    if not coverage_md or not coverage_md.strip().startswith("#"):
        return ("## 四、测试过程\n\n"
                "> _coverage-checklist.md 未填写。测试前请先填写 templates/coverage-checklist.md。_\n")
    # Category-numbering map: checklist section name → A.N index. Sections not
    # listed here are numbered dynamically, but this keeps the common ones stable.
    parts = ["## 四、测试过程", "",
             "按安服测试标准逐项记录测试状态。未覆盖与受限项必须在报告中体现。\n"]
    # Map a status to the customer-facing result phrase.
    def _result_phrase(status: str, reason: str) -> str:
        s = status.lower()
        if s == "covered":
            return reason.strip() if reason.strip() else "已覆盖"
        if s == "degraded":
            return f"受限（降级）: {reason or '原因未记录'}"
        if s == "not-covered":
            return f"未充分测试: {reason or '原因未记录'}"
        if s == "out-of-scope":
            return f"不适用: {reason or '不在测试范围'}"
        return reason or "未填写"
    cat_idx = 0
    sections = re.split(r"\n## ", coverage_md)
    for sec in sections[1:]:  # skip preamble before first ##
        lines = sec.splitlines()
        if not lines:
            continue
        heading = lines[0].strip()
        # Skip non-test-process sections (they are reported elsewhere).
        if heading.startswith("Coverage Summary") or "Scope Adherence" in heading:
            continue
        cat_idx += 1
        cat_letter = f"A.{cat_idx}"
        parts.append(f"### {cat_letter} {heading}\n")
        item_idx = 0
        for line in lines:
            s = line.strip()
            if not s.startswith("|") or re.match(r"^\|[-:\s|]+\|$", s):
                continue
            cols = [c.strip() for c in s.strip("|").split("|")]
            if len(cols) < 3 or cols[0] in ("Surface", "Class", "Face"):
                continue
            surface, status, reason = cols[0], cols[1].lower(), cols[2]
            if not status:
                status = "not-covered"
                reason = reason or "未填写"
            item_idx += 1
            phrase = _result_phrase(status, reason)
            parts.append(f"#### {cat_letter}.{item_idx} {surface}")
            parts.append("")
            parts.append(phrase)
            parts.append("")
        if item_idx == 0:
            parts.append("_本类别无测试项记录。_")
            parts.append("")
    return "\n".join(parts).strip()


def build_attack_chains(chain_md: str, vid_map: dict) -> str:
    """Customer-facing attack chains (五、攻击链).

    Parses the `### Chain N:` sections of 04-chain.md and renders them as
    AP-XXX chains, mapping referenced F-XXX to V-XX. If no chain file exists
    or no chains are documented, emits an explicit "no chains" note rather
    than silently omitting the section.
    """
    parts = ["## 五、攻击链", ""]
    if not chain_md or "### Chain" not in chain_md:
        parts.append("_未发现可串联的攻击链。单一漏洞均已独立记录，无跨漏洞组合利用路径。_")
        parts.append("")
        return "\n".join(parts).strip()
    chain_blocks = re.split(r"(?:^|\n)### Chain \d+:", chain_md)
    idx = 0
    for block in chain_blocks[1:]:
        idx += 1
        title = block.split("\n", 1)[0].strip().strip("{}").strip()
        ap = f"AP-{idx:03d}"
        parts.append(f"### {ap}: {title}")
        parts.append("")
        def _ref(m):
            fid = "F-" + m.group(1)
            return f"{vid_map.get(fid, fid)} ({fid})"
        rendered = re.sub(r"\bF-(\d+)\b", _ref, block)
        for field in ("Prerequisites", "Hypothetical Impact", "Risk Statement"):
            m = re.search(rf"\*\*{field}\*\*:?\s*(.*?)(?=\n\*\*[A-Z][^*]*\*\*|\Z)", rendered, flags=re.S)
            if m and m.group(1).strip():
                parts.append(f"**{field}**: {m.group(1).strip()}")
                parts.append("")
        parts.append("---")
        parts.append("")
    if idx == 0:
        parts.append("_未发现可串联的攻击链。_")
        parts.append("")
    return "\n".join(parts).strip()


def build_appendix_api_stats(discovery_md: str) -> str:
    """Appendix A: API endpoint statistics from 02-discovery.md."""
    parts = ["## 附录 A: API端点统计", ""]
    if not discovery_md or "Endpoint" not in discovery_md:
        parts.append("_02-discovery.md 未提供端点目录，跳过端点统计。_")
        parts.append("")
        return "\n".join(parts).strip()
    total = 0
    by_auth = {"需认证": 0, "无需认证": 0, "未知": 0}
    for line in discovery_md.splitlines():
        s = line.strip()
        if not s.startswith("|") or re.match(r"^\|[-:\s|]+\|$", s):
            continue
        cols = [c.strip() for c in s.strip("|").split("|")]
        if len(cols) < 4 or cols[0] in ("Endpoint", "Path", "Parameter"):
            continue
        if re.match(r"^/", cols[0]):
            total += 1
            auth_col = cols[3].lower() if len(cols) > 3 else ""
            if "no" in auth_col or "否" in cols[3]:
                by_auth["无需认证"] += 1
            elif "yes" in auth_col or "是" in cols[3] or "auth" in auth_col:
                by_auth["需认证"] += 1
            else:
                by_auth["未知"] += 1
    parts.extend(["| 分类 | 数量 |", "|------|------|", f"| 需认证 | {by_auth['需认证']} |",
                  f"| 无需认证 | {by_auth['无需认证']} |", f"| 未知 | {by_auth['未知']} |",
                  f"| **总计** | **{total}** |", ""])
    if total == 0:
        parts.insert(-1, "_未识别到端点记录。_")
    return "\n".join(parts).strip()


def build_appendix_waf(fingerprint_md: str) -> str:
    """Appendix B: WAF behavior analysis from 01-fingerprint.md."""
    parts = ["## 附录 B: WAF行为分析", ""]
    rows = _parse_md_table(fingerprint_md, "WAF") or _parse_md_table(fingerprint_md, "CDN")
    if rows:
        parts.extend(["| 属性 | 值 |", "|------|-----|"])
        for r in rows:
            parts.append("| " + " | ".join((r + ["-"])[:2]) + " |")
    else:
        parts.append("_01-fingerprint.md 未提供 WAF/CDN 信息，或目标未部署 WAF。_")
    parts.append("")
    return "\n".join(parts).strip()


def build_appendix_test_limits(summary: dict) -> str:
    """Appendix C: test limitation notes (e.g. WAF IP ban, account shortage)."""
    parts = ["## 附录 C: 测试限制说明", ""]
    meta = summary.get("report_meta", {}) or {}
    limits = meta.get("test_limitations", "")
    if limits:
        parts.append(str(limits))
    else:
        parts.append("_无特殊测试限制。所有测试均在授权范围内完成。_")
    parts.append("")
    return "\n".join(parts).strip()


def build_appendix_severity(skill_root: Path) -> str:
    """Appendix D: concise severity classification reference.

    Extracts only the customer-relevant parts (severity level definitions +
    the per-class default-severity table) rather than dumping the entire 200+
    line classification document.
    """
    parts = ["## 附录 D: 安全测试标准参考", "",
             "> 数据来源: severity-classification.md（摘要）\n"]
    sev_path = skill_root / "templates" / "severity-classification.md"
    content = read_text(sev_path, "")
    if content:
        # Extract the Severity Levels summary table.
        levels = re.search(
            r"## Severity Levels.*?(?:\n## |\Z)", content, flags=re.S)
        # Extract the default-severity tables (Injection through Modern Protocol).
        defaults = re.search(
            r"## Vulnerability Type Default Severity.*?(?:\n## [A-Z]|\Z)",
            content, flags=re.S)
        # Extract the "Vulnerability Type Default Severity" intro + its tables.
        # The tables under it are the per-class reference the customer wants.
        tables = re.findall(
            r"### (Injection|Authentication|Frontend|Information|Business Logic|"
            r"AI / LLM|Cloud Native|Modern Protocol)[^\n]*\n\n(\|[^\n]+\|\n\|[-:\s|]+\|\n(?:\|[^\n]+\|\n?)+)",
            content)
        if levels:
            parts.append("### 等级定义\n")
            # Keep only the table rows, not the prose around them.
            for line in levels.group(0).splitlines():
                s = line.strip()
                if s.startswith("|") and "Level" in s or s.startswith("|---") or (s.startswith("| **") ):
                    parts.append(s)
            parts.append("")
        if tables:
            cat_cn = {
                "Injection": "注入/执行类", "Authentication": "认证/授权类",
                "Frontend": "前端类", "Information": "信息泄露类",
                "Business Logic": "业务逻辑类", "AI / LLM": "AI/LLM类",
                "Cloud Native": "云原生/K8s类", "Modern Protocol": "现代协议类",
            }
            for name, table in tables:
                parts.append(f"### {cat_cn.get(name, name)}\n")
                parts.append(table.rstrip())
                parts.append("")
        else:
            parts.extend([
                "| 等级 | 判定依据 |",
                "|------|---------|",
                "| 严重 | RCE、批量数据泄露、获取系统控制权 |",
                "| 高危 | 注入类确认、越权访问敏感数据 |",
                "| 中危 | 有限影响注入、CSRF绕过、业务逻辑缺陷 |",
                "| 低危 | 信息泄露、安全头缺失、配置缺陷 |",
                "| 信息 | 纯发现项，无直接安全影响 |",
                "",
            ])
    else:
        parts.extend([
            "| 等级 | 判定依据 |",
            "|------|---------|",
            "| 严重 | RCE、批量数据泄露、获取系统控制权 |",
            "| 高危 | 注入类确认、越权访问敏感数据 |",
            "| 中危 | 有限影响注入、CSRF绕过、业务逻辑缺陷 |",
            "| 低危 | 信息泄露、安全头缺失、配置缺陷 |",
            "| 信息 | 纯发现项，无直接安全影响 |",
        ])
    parts.append("")
    return "\n".join(parts).strip()


def check_report_redaction(report_text: str) -> list[str]:
    """Post-render redaction verification.

    After the report is assembled (with evidence blocks redacted inline),
    scan the rendered text for bare 32+ hex blobs that look like leaked
    session keys / tokens. A hit means redact_response missed something.
    """
    leaked = re.findall(r"(?<![A-Za-z0-9])([0-9a-fA-F]{32,})(?![A-Za-z0-9])", report_text)
    if leaked:
        return [
            f"unredacted secret-like value in rendered report: {v[:16]}... "
            f"(redact_response should have masked it)" for v in leaked[:5]
        ]
    return []


def parse_fingerprint_summary(text: str, summary: dict) -> str:
    tech = []
    m = re.search(r"## Tech Stack\n\n\| Component \| Value \|\n\|[-| ]+\|\n(.*?)(?:\n## |\Z)", text, flags=re.S)
    if m:
        for line in m.group(1).splitlines():
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cols) >= 2:
                tech.append((cols[0], cols[1]))

    security = []
    m = re.search(r"## Security Headers\n\n(.*?)(?:\n## |\Z)", text, flags=re.S)
    if m:
        for line in m.group(1).splitlines():
            line = line.strip()
            if line.startswith("- "):
                security.append(line[2:])

    attack_surface = []
    m = re.search(r"## Attack Surface\n\n\| Priority \| Vulnerability \| Reason \|\n\|[-| ]+\|\n(.*?)(?:\n## |\Z)", text, flags=re.S)
    if m:
        for line in m.group(1).splitlines():
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cols) >= 3:
                attack_surface.append((cols[0], cols[1], cols[2]))

    lines = ["## 5. Target Fingerprint & Environment", "", "### 5.1 Basic Environment", ""]
    lines.extend(["| Item | Value |", "|------|-------|"])
    if tech:
        for key, value in tech[:6]:
            lines.append(f"| {key} | {value} |")
    else:
        lines.append(f"| Tech Stack | {', '.join(summary.get('tech_stack', []) or [])} |")
    lines.extend(["", "### 5.2 Security & Protection", ""])
    if security:
        lines.extend([f"- {item}" for item in security[:4]])
    else:
        lines.append("- No additional security headers")
    lines.extend(["", "### 5.3 Attack Surface Summary", ""])
    if attack_surface:
        lines.extend([f"- {pri} / {vuln}: {reason}" for pri, vuln, reason in attack_surface[:5]])
    else:
        lines.append("- No additional attack surface summary")
    return "\n".join(lines).strip()


def run_l3_export(task_dir: Path, l3_root: Path) -> tuple[bool, str]:
    script_path = Path(__file__).with_name("export_to_l3.py")
    if not script_path.exists():
        return False, "export_to_l3.py not found"
    try:
        result = subprocess.run(
            [sys.executable, str(script_path), str(task_dir), str(l3_root)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        return False, f"failed to launch export_to_l3.py: {exc}"

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if result.returncode == 2 and "l3-export-skipped" in detail:
            return False, detail
        return False, detail or f"export_to_l3.py exited with code {result.returncode}"
    return True, (result.stdout or "ok").strip()


def run_ensure_structured(task_dir: Path) -> tuple[bool, str]:
    script_path = Path(__file__).with_name("ensure_structured_outputs.py")
    if not script_path.exists():
        return False, "ensure_structured_outputs.py not found"
    try:
        result = subprocess.run(
            [sys.executable, str(script_path), str(task_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        return False, f"failed to launch ensure_structured_outputs.py: {exc}"

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        return False, detail or f"ensure_structured_outputs.py exited with code {result.returncode}"
    return True, (result.stdout or "ok").strip()


def build_coverage_gaps_section(coverage_text: str) -> str:
    """Build the 'Test Coverage & Gaps' report section from coverage-checklist.md.

    Per the checklist rule, degraded + not-covered rows MUST appear in the report.
    Also includes the scope-adherence verdict.
    """
    if not coverage_text:
        return "## 6. Test Coverage & Gaps\n\n_Coverage checklist not available._\n"

    parsed = parse_coverage_checklist(coverage_text)
    gaps = parsed["gaps"]
    violations = parsed["scope_violations"]

    lines = ["## 6. Test Coverage & Gaps", ""]

    # Scope adherence verdict
    if parsed["scope_checks"]:
        lines.append("### 6.1 Scope Adherence")
        lines.append("")
        lines.append("| Check | Result |")
        lines.append("|-------|--------|")
        for sc in parsed["scope_checks"]:
            lines.append(f"| {sc['check']} | {sc['result']} |")
        lines.append("")

    # Coverage gaps (degraded + not-covered)
    lines.append("### 6.2 Untested / Degraded Surfaces")
    lines.append("")
    if not gaps:
        lines.append("_All surfaces covered or out-of-scope; no gaps._")
        lines.append("")
    else:
        lines.append("| Surface | Status | Reason |")
        lines.append("|---------|--------|--------|")
        for g in gaps:
            lines.append(f"| {g['surface']} | {g['status']} | {g['reason']} |")
        lines.append("")

    if violations:
        lines.append("> ⚠️ **Scope violation detected** — boundary breach(es) recorded above. Disclosed per scope-adherence rule.")
        lines.append("")

    return "\n".join(lines)


_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT", "TRACE")


def _normalize_host(value: str) -> str:
    value = (value or "").strip().strip("`").lower()
    if not value or value in {"-", "n/a", "none", "unknown", "pending"}:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return host.strip("[]").lower()


def _host_port(value: str) -> tuple[str, int | None]:
    value = (value or "").strip().strip("`")
    if not value:
        return "", None
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or _normalize_host(value)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return (host or "").strip("[]").lower(), port


def _split_csvish(value: str) -> list[str]:
    items = []
    for raw in re.split(r"[,;\s]+", value or ""):
        raw = raw.strip().strip("`")
        if raw:
            items.append(raw)
    return items


def _parse_task_meta(text: str) -> dict:
    meta = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("- ") or ":" not in stripped:
            continue
        key, value = stripped[2:].split(":", 1)
        meta[key.strip()] = value.strip()
    return meta


def _target_default_port(target: str) -> int | None:
    parsed = urlparse(target if "://" in target else f"//{target}")
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _parse_preflight(text: str) -> dict:
    meta = _parse_task_meta(text)
    target = meta.get("target", "")
    target_host = _normalize_host(target)
    allowlist = []
    for item in _split_csvish(meta.get("scope_allowlist", "")):
        host = _normalize_host(item)
        if host and host not in allowlist:
            allowlist.append(host)
    if target_host and target_host not in allowlist:
        allowlist.insert(0, target_host)

    approved_ports = []
    raw_ports = meta.get("approved_ports", "")
    if not str(raw_ports).strip() or str(raw_ports).strip().lower() == "default-for-target":
        port = _target_default_port(target)
        if port:
            approved_ports.append(port)
    else:
        for item in _split_csvish(raw_ports):
            if re.fullmatch(r"\d{1,5}", item):
                approved_ports.append(int(item))

    def filled(key: str, bad: set[str] | None = None) -> bool:
        bad = bad or set()
        value = str(meta.get(key, "")).strip().lower()
        return bool(value) and value not in {"pending", "unknown", "unset", "todo", "tbd"} and value not in bad

    complete_value = str(meta.get("preflight_complete", "")).strip().lower()
    complete = complete_value in {"true", "yes", "y", "complete", "completed", "pass", "passed"}
    required_ok = (
        complete
        and filled("authorization", {"no", "false", "contradicted", "denied"})
        and filled("scope")
        and filled("intensity")
        and filled("automation")
        and filled("credentials")
        and bool(allowlist)
    )
    return {
        "meta": meta,
        "complete": complete,
        "required_ok": required_ok,
        "allowlist": allowlist,
        "approved_ports": approved_ports,
        "target_host": target_host,
    }


def _parse_table_row(line: str) -> list[str]:
    """Split a markdown table row into trimmed cell values. Returns [] for non-rows."""
    s = line.strip()
    if not s.startswith("|"):
        return []
    cells = [c.strip() for c in s.strip("|").split("|")]
    # Drop separator rows like |---|---|
    if cells and all(set(c) <= set("-: ") for c in cells if c):
        return []
    return cells


def _normalize_header_cell(value: str) -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"\s*\([^)]*\)", "", value).strip()
    return re.sub(r"\s+", " ", value)


def _is_header_row(cells: list[str]) -> bool:
    low = {_normalize_header_cell(c) for c in cells}
    return "method" in low and ("path" in low or "url" in low or "target" in low)


def _looks_like_host(value: str) -> bool:
    value = (value or "").strip().strip("`")
    if not value or value.startswith("/") or value.upper() in _HTTP_METHODS:
        return False
    low = value.lower()
    if low in {"yes", "no", "true", "false", "pass", "violation", "in-scope", "out-of-scope", "covered", "degraded", "not-covered"}:
        return False
    if re.fullmatch(r"\d+", value):
        return False
    host = _normalize_host(value)
    return bool(host) and (
        "." in host
        or host == "localhost"
        or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) is not None
        or re.fullmatch(r"[a-z0-9-]+", host) is not None
    )


def _extract_request_rows(text: str) -> list[dict]:
    rows = []
    header = []
    for line in text.splitlines():
        cells = _parse_table_row(line)
        if len(cells) < 2:
            continue
        if _is_header_row(cells):
            header = [_normalize_header_cell(c) for c in cells]
            continue

        method = ""
        host = ""
        path = ""
        status = ""

        if header and len(header) == len(cells):
            for idx, name in enumerate(header):
                cell = cells[idx].strip()
                if name == "method":
                    method = cell.upper()
                elif name in {"host", "target host", "target"}:
                    host = cell
                elif name in {"path", "url", "endpoint"}:
                    path = cell
                elif name in {"status", "status code", "code"}:
                    status = cell

        if not method:
            method = next((c.upper() for c in cells if c.upper() in _HTTP_METHODS), "")
        if not path:
            path = next((c for c in cells if c.startswith("/") or c.startswith("http://") or c.startswith("https://")), "")
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            host = host or (parsed.hostname or "")
            port = parsed.port
            path = parsed.path or "/"
        else:
            _, port = _host_port(host)
        if not host:
            for cell in cells:
                if cell.upper() == method or cell == path or re.fullmatch(r"\d{3}.*", cell.strip()):
                    continue
                if _looks_like_host(cell):
                    host = cell
                    if port is None:
                        _, port = _host_port(host)
                    break
        if not status:
            status = next((c for c in cells if re.fullmatch(r"\d{3}(?:\s+\S+)?", c.strip())), "")
        if method and path:
            rows.append({"method": method, "host": _normalize_host(host), "port": port, "path": path, "status": status, "raw": line.strip()})
    return rows


def _count_request_log_rows(text: str) -> int:
    """Count real request-log table rows in 02-discovery.md.

    A valid row has: an HTTP method token in one cell, AND a path starting with
    '/' (including bare '/') in another cell. Uses cell-level parsing so that
    '/', '/login', '/api/v1/users' all match correctly — the prior regex
    mis-rejected '/' and '/login' because of word-boundary semantics.
    """
    count = 0
    for line in text.splitlines():
        cells = _parse_table_row(line)
        if len(cells) < 2:
            continue
        has_method = any(c.upper() in _HTTP_METHODS for c in cells)
        has_path = any(c.startswith("/") and len(c) >= 1 for c in cells)
        if has_method and has_path:
            count += 1
    return count


def _scope_log_violations(task_dir: Path, preflight: dict) -> list[str]:
    allowlist = set(preflight.get("allowlist", []))
    if not allowlist:
        return []
    violations = []
    for fname in ("02-discovery.md", "03-vuln-test.md"):
        text = _read_task_file(task_dir, fname)
        request_rows = _extract_request_rows(text)
        if fname == "03-vuln-test.md" and _count_vuln_test_entries(text) > 0 and not request_rows:
            violations.append(f"{fname} has validation entries but no scoped request rows with method, host, and path")
            continue
        for idx, row in enumerate(request_rows, start=1):
            host = row.get("host", "")
            port = row.get("port")
            if not host:
                violations.append(f"{fname} row {idx} missing target host: {row.get('raw', '')}")
            elif host not in allowlist:
                violations.append(f"{fname} row {idx} host '{host}' outside scope allowlist {sorted(allowlist)}")
            elif preflight.get("approved_ports") and port is not None and port not in preflight["approved_ports"]:
                violations.append(f"{fname} row {idx} port '{port}' outside approved ports {preflight['approved_ports']}")
    return violations


def _count_vuln_test_entries(text: str) -> int:
    """Count real validation entries in 03-vuln-test.md.

    A real entry is either a numbered test heading (## Test #N / ## F-N) or a
    table row with an HTTP method + path (same shape as a request log).
    Keyword-only detection (e.g. the word 'payload' anywhere) is too loose.
    """
    count = 0
    for line in text.splitlines():
        s = line.strip()
        # Heading-based entry: ## Test #1, ## F-001, ### Test #2
        if re.match(r"^#{1,4}\s+(Test\s*#\d+|F-\d+)", s, re.I):
            count += 1
            continue
        # Table-row-based entry: method + path
        cells = _parse_table_row(s)
        if len(cells) >= 2:
            has_method = any(c.upper() in _HTTP_METHODS for c in cells)
            has_path = any(c.startswith("/") for c in cells)
            if has_method and has_path:
                count += 1
    return count


def _read_task_file(task_dir: Path, fname: str) -> str:
    fpath = task_dir / fname
    if not fpath.exists():
        return ""
    return fpath.read_text(encoding="utf-8")


def parse_coverage_checklist(text: str) -> dict:
    """Parse coverage-checklist.md into structured coverage + scope-adherence data.

    Returns:
      {
        "rows": [{"surface": str, "status": str, "reason": str}, ...],
        "gaps": [{"surface": str, "status": str, "reason": str}, ...],  # degraded + not-covered
        "scope_checks": [{"check": str, "result": str, "evidence": str}, ...],
        "scope_violations": [...],   # checks whose result is "violation"
        "blank_rows": int,           # rows with no status (the failure mode)
      }
    """
    result = {"rows": [], "gaps": [], "scope_checks": [], "scope_violations": [], "blank_rows": 0}
    if not text:
        return result

    # Parse coverage tables: lines like | Surface | Status | Evidence/Reason |
    # Status values: covered, degraded, not-covered, out-of-scope
    in_scope_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if "Scope Adherence" in stripped:
            in_scope_section = True
            continue
        if "Coverage Summary" in stripped:
            in_scope_section = False
            continue
        if not stripped.startswith("|"):
            continue
        cols = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cols) < 3:
            continue

        if in_scope_section:
            # Scope Adherence table: | Check | Result | Evidence |
            check_name, check_result, check_evidence = cols[0], cols[1].lower(), cols[2]
            if check_name in ("Check", "") or check_name.startswith("---"):
                continue
            result["scope_checks"].append({"check": check_name, "result": check_result, "evidence": check_evidence})
            if "violation" in check_result:
                result["scope_violations"].append({"check": check_name, "evidence": check_evidence})
        else:
            # Coverage table: | Surface | Status | Evidence/Reason |
            surface, status, reason = cols[0], cols[1].lower().strip(), cols[2]
            if surface in ("Surface", "Class", "Face", "") or surface.startswith("---"):
                continue
            row = {"surface": surface, "status": status, "reason": reason}
            result["rows"].append(row)
            if status in ("degraded", "not-covered"):
                result["gaps"].append(row)
            elif status == "":
                result["blank_rows"] += 1

    return result


def check_report_gate(task_dir: Path) -> tuple[bool, list[str]]:
    """Report gate: deep-verify the mandatory evidence trail before emitting a report.

    Checks (not just file existence):
      1. 02-discovery.md has a Request Log with at least one logged request
      2. 03-vuln-test.md has validation content (not just a bare template)
      3. coverage-checklist.md has no blank status rows (every surface filled)
      4. coverage-checklist.md Scope Adherence has no violations

    Returns (passed, gap_messages).
    """
    gaps = []
    task_text = _read_task_file(task_dir, "task.md")
    preflight = _parse_preflight(task_text)

    if not task_text:
        gaps.append("task.md missing — preflight boundary cannot be verified")
    elif not preflight["required_ok"]:
        missing = []
        meta = preflight["meta"]
        if not preflight["complete"]:
            missing.append("preflight_complete=true")
        for key in ("authorization", "scope", "intensity", "automation", "credentials"):
            value = str(meta.get(key, "")).strip().lower()
            if not value or value in {"pending", "unknown", "unset", "todo", "tbd"}:
                missing.append(key)
        if not preflight["allowlist"]:
            missing.append("scope_allowlist")
        gaps.append("preflight incomplete — mandatory boundary decisions not recorded: " + ", ".join(missing))

    # --- 02-discovery.md: must contain a Request Log with real entries ---
    disc = _read_task_file(task_dir, "02-discovery.md")
    if not disc:
        gaps.append("02-discovery.md missing — Phase 1-2 discovery log (Request Log + Scope Allowlist)")
    else:
        request_rows = _count_request_log_rows(disc)
        if request_rows == 0:
            gaps.append(
                "02-discovery.md has no logged requests in its Request Log "
                "(a request row is a table row with an HTTP method cell and a path cell starting with '/', "
                "e.g. '| GET | / | 200 |' or '| POST | /login | 302 |') — "
                "discovery phase not auditable"
            )

    # --- 03-vuln-test.md: must have real validation entries ---
    vuln = _read_task_file(task_dir, "03-vuln-test.md")
    if not vuln:
        gaps.append("03-vuln-test.md missing — Phase 3 validation log")
    else:
        entries = _count_vuln_test_entries(vuln)
        if entries == 0:
            gaps.append(
                "03-vuln-test.md has no validation entries "
                "(an entry is a '## Test #N' / '## F-N' heading, or a table row with an HTTP method + path) — "
                "Phase 3 not auditable"
            )

    # --- coverage-checklist.md: no blank rows + no scope violations ---
    cov = _read_task_file(task_dir, "coverage-checklist.md")
    if not cov:
        gaps.append("coverage-checklist.md missing — Coverage + Scope Adherence checklist")
    else:
        parsed = parse_coverage_checklist(cov)
        if parsed["blank_rows"] > 0:
            gaps.append(f"coverage-checklist.md has {parsed['blank_rows']} surface row(s) with blank status — every row must be covered/degraded/not-covered/out-of-scope")
        if parsed["scope_violations"]:
            violations = "; ".join(v["check"] for v in parsed["scope_violations"])
            gaps.append(f"coverage-checklist.md Scope Adherence has violation(s): {violations} — boundary breach blocks the report until disclosed")

    if preflight.get("required_ok"):
        scope_violations = _scope_log_violations(task_dir, preflight)
        if scope_violations:
            gaps.append("request log scope check failed — " + "; ".join(scope_violations[:5]))

    # --- Completeness gate (anti-skip): queue drained + coverage truthful ---
    # Delayed import avoids a circular dependency (check_completeness imports
    # this module to reuse its parsing helpers).
    from check_completeness import check_completeness
    try:
        ok, comp_messages = check_completeness(task_dir, mode="report-gate")
    except Exception as exc:  # pragma: no cover - defensive
        ok, comp_messages = False, [f"completeness check error: {exc}"]
    if not ok:
        gaps.append(
            "completeness gate failed — not all testable surface was actually tested. "
            "Run `python3 scripts/check_completeness.py <task_dir>` for the itemized list. "
            "Outstanding items:"
        )
        # Only the failure block is appended; warnings are surfaced separately below.
        gaps.extend(m for m in comp_messages if not m.startswith("---") and m != "=== COMPLETENESS GATE FAILED ===")

    return (len(gaps) == 0), gaps


def main():
    import argparse as ap
    parser = ap.ArgumentParser(description="Generate authorized AppSec assessment report")
    parser.add_argument("task_dir", help="Task directory")
    parser.add_argument("--export-l3", default=None, help="Export to L3 root")
    parser.add_argument("--format", default="markdown", choices=["markdown", "sarif", "defectdojo"],
                        help="Output format (default: markdown)")
    parser.add_argument("--output", default=None, help="Output file path (default: auto)")
    parser.add_argument("--skip-gate", action="store_true",
                        help="Skip the report gate check (02/03/coverage presence). Use with caution.")
    parser.add_argument("--gate-override-reason", default="",
                        help="Required explanation when --skip-gate is used; written into summary/report")
    args = parser.parse_args()

    task_dir = Path(args.task_dir).resolve()
    l3_root = Path(args.export_l3).resolve() if args.export_l3 else None

    # Report gate: do not emit a formal report if the mandatory evidence trail is absent.
    if args.skip_gate and not args.gate_override_reason.strip():
        print("report-gate-override-denied: --skip-gate requires --gate-override-reason", file=sys.stderr)
        sys.exit(2)

    gate_override_reason = args.gate_override_reason.strip()
    if not args.skip_gate:
        gate_ok, gaps = check_report_gate(task_dir)
        if not gate_ok:
            print("report-gate-failed: mandatory evidence trail incomplete. Fix these before reporting:", file=sys.stderr)
            for g in gaps:
                print(f"  - {g}", file=sys.stderr)
            print("(pass --skip-gate to override, but this is discouraged)", file=sys.stderr)
            sys.exit(2)

    # Single structured sync (was previously run twice in the markdown branch).
    ok, detail = run_ensure_structured(task_dir)
    if not ok:
        print(f"structured-output-warning: {detail}", file=sys.stderr)
    summary = read_json(task_dir / "summary.json", {})
    findings_data = read_json(task_dir / "findings.json", [])
    evidence_data = read_json(task_dir / "evidence-index.json", [])
    findings_md = read_text(task_dir / "findings.md", "_No confirmed vulnerability details_")
    fingerprint_md = read_text(task_dir / "01-fingerprint.md", "_No target fingerprint information_")

    findings = findings_data if isinstance(findings_data, list) else findings_data.get("findings", [])
    evidence = evidence_data if isinstance(evidence_data, list) else evidence_data.get("evidence", [])

    if args.format == "sarif":
        output = generate_sarif(summary, findings, evidence)
        out_path = Path(args.output) if args.output else task_dir / "report.sarif.json"
        out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"sarif:{out_path}")
        return

    if args.format == "defectdojo":
        output = generate_defectdojo(summary, findings, evidence)
        out_path = Path(args.output) if args.output else task_dir / "report.defectdojo.json"
        out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"defectdojo:{out_path}")
        return

    # Default: markdown report
    counts = count_by_severity(findings)
    boundary = fmt_boundary(summary.get("boundary_summary", ""))
    parsed_findings = parse_findings_markdown(findings_md)
    vid_map = fid_to_vid_map(findings)
    report_meta = summary.get("report_meta", {}) or {}
    cvss_scores = report_meta.get("cvss_scores", {}) or {}
    findings_table = build_findings_table(findings, vid_map, cvss_scores)
    findings_detail = build_findings_details(findings, parsed_findings, findings_md, vid_map, cvss_scores)
    asset_profile = build_asset_profile(summary, fingerprint_md)
    recommendations = build_recommendations(summary, findings, vid_map)
    coverage_text = _read_task_file(task_dir, "coverage-checklist.md")
    coverage_md = read_text(task_dir / "coverage-checklist.md", "")
    chain_md = read_text(task_dir / "04-chain.md", "")
    discovery_md = read_text(task_dir / "02-discovery.md", "")
    test_process = build_test_process(coverage_md, findings_md)
    attack_chains = build_attack_chains(chain_md, vid_map)
    skill_root = Path(__file__).resolve().parent.parent
    appendix_a = build_appendix_api_stats(discovery_md)
    appendix_b = build_appendix_waf(fingerprint_md)
    appendix_c = build_appendix_test_limits(summary)
    appendix_d = build_appendix_severity(skill_root)
    coverage_gaps_section = build_coverage_gaps_section(coverage_text)
    gate_override_section = ""
    if args.skip_gate:
        gate_override_section = (
            "\n> **Report Gate Override**: This report was generated with `--skip-gate`. "
            f"Reason: {gate_override_reason}\n"
        )

    started = summary.get("started_at", "unknown")
    ended = summary.get("ended_at", "unknown")
    target_type = summary.get("target_type", "Web应用层面全面渗透测试")
    sev_lines = []
    sev_label_cn = [("critical", "严重"), ("high", "高危"), ("medium", "中危"), ("low", "低危"), ("info", "信息")]
    for key, label in sev_label_cn:
        sev_lines.append(f"- {label}: {counts[key]}")

    report = f"""# 渗透测试报告

**PT编号**: {summary.get('task_id', task_dir.name)}
**目标**: {summary.get('target', '_未指定_')}
**测试时间**: {started} ~ {ended}
**测试范围**: {target_type}
**授权状态**: 已获授权
**测试方法**: PTES/OWASP 混合方法论

---

## 一、漏洞汇总

{findings_table}

漏洞统计:

{chr(10).join(sev_lines)}

---

{asset_profile}

---

{findings_detail}

---

{test_process}

---

{attack_chains}

---

{recommendations}

{coverage_gaps_section}
{gate_override_section}

---

{appendix_a}

{appendix_b}

{appendix_c}

{appendix_d}
"""

    out_path = Path(args.output) if args.output else task_dir / "report.md"
    out_path.write_text(report, encoding="utf-8")

    # Post-render redaction gate: the report may now contain inline evidence
    # blocks; verify no raw secret-like hex survived redaction.
    redaction_failures = check_report_redaction(report)
    if redaction_failures:
        for reason in redaction_failures:
            print(f"  - {reason}", file=sys.stderr)
        print("report-redaction-warning: report.md was generated but may contain "
              "unredacted secrets — review before delivery.", file=sys.stderr)

    if isinstance(summary, dict):
        summary["report_status"] = "draft"
        if args.skip_gate:
            summary["report_gate_override"] = True
            summary["report_gate_override_reason"] = gate_override_reason
        write_json(task_dir / "summary.json", summary)
    print(str(out_path))
    if l3_root is not None:
        ok, detail = run_l3_export(task_dir, l3_root)
        if ok:
            print(f"l3-export: {detail}")
        else:
            print(f"l3-export-warning: {detail}", file=sys.stderr)


def _read_skill_version() -> str:
    """Read the skill version from SKILL.md frontmatter, fallback to 'unknown'."""
    skill_root = Path(__file__).resolve().parent.parent
    skill_md = skill_root / "SKILL.md"
    if skill_md.exists():
        match = re.search(r"Version\*\*:\s*([0-9]+\.[0-9]+\.[0-9]+)", skill_md.read_text(encoding="utf-8"))
        if match:
            return match.group(1)
    return "unknown"


def generate_sarif(summary: dict, findings: list, evidence: list) -> dict:
    """Generate SARIF 2.1.0 output for GitHub/GitLab/SonarQube integration."""
    target = summary.get("target", "unknown")
    task_id = summary.get("task_id", "unknown")

    results = []
    for f in findings:
        severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        sarif_level = severity_map.get(f.get("severity", "info"), "note")
        results.append({
            "ruleId": f.get("category", "unknown"),
            "level": sarif_level,
            "message": {"text": f.get("title", f.get("fact_summary", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                    "region": {"startLine": 1}
                }
            }],
            "properties": {
                "finding_id": f.get("finding_id", ""),
                "severity": f.get("severity", ""),
                "boundary": f.get("boundary", ""),
                "cwe": f.get("cwe_id", ""),
                "owasp": f.get("owasp_category", ""),
            }
        })

    rules = []
    seen_categories = set()
    for f in findings:
        cat = f.get("category", "unknown")
        if cat not in seen_categories:
            seen_categories.add(cat)
            rules.append({"id": cat, "shortDescription": {"text": cat}})

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "authorized-appsec-skill",
                    "version": _read_skill_version(),
                    "informationUri": "https://github.com/zhinan904/authorized-appsec",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {"task_id": task_id, "target": target}
            }]
        }]
    }


def generate_defectdojo(summary: dict, findings: list, evidence: list) -> dict:
    """Generate DefectDojo-compatible JSON for vulnerability import."""
    target = summary.get("target", "unknown")
    dd_findings = []
    for f in findings:
        sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
        dd_findings.append({
            "title": f.get("title", f.get("fact_summary", "")),
            "severity": sev_map.get(f.get("severity", "info"), "Informational"),
            "description": f.get("fact_summary", ""),
            "mitigation": f.get("recommended_next_action", ""),
            "impact": f.get("boundary", ""),
            "references": "",
            "active": True,
            "verified": f.get("status") == "confirmed",
            "false_p": f.get("status") == "false_positive",
            "out_of_scope": False,
            "under_review": f.get("status") == "suspicious",
            "numerical_severity": {"critical": "S0", "high": "S1", "medium": "S2", "low": "S3", "info": "S4"}.get(f.get("severity", "info"), "S4"),
            "endpoint": target,
            "cwe": int(f.get("cwe_id", 0)) if f.get("cwe_id") else 0,
            "found_by": ["authorized-appsec-skill"],
            "tags": [f.get("category", ""), f.get("owasp_category", "")],
            "unique_id_from_tool": f.get("finding_id", ""),
        })

    return {
        "findings": dd_findings,
        "test": {
            "title": f"Authorized AppSec - {summary.get('task_id', 'unknown')}",
            "target_id": target,
            "test_type": "Application Security Assessment",
        },
        "engagement": {
            "name": summary.get("task_id", "unknown"),
            "target_start": summary.get("started_at", ""),
            "target_end": summary.get("ended_at", ""),
        }
    }


if __name__ == "__main__":
    main()
