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


def build_findings_table(findings):
    lines = [
        "| Finding ID | Title | Type | Severity | Priority | Status |",
        "|------------|-------|------|----------|----------|--------|",
    ]
    for item in findings:
        lines.append(
            f"| {item.get('finding_id', '')} | {item.get('title', '')} | "
            f"{item.get('category', '')} | {item.get('severity', '')} | "
            f"{item.get('priority', '')} | {item.get('status', '')} |"
        )
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


def build_recommendations(summary, findings):
    high = []
    medium_low = []
    generic = []
    for item in findings:
        text = item.get("recommended_next_action", "")
        if not text:
            continue
        sev = str(item.get("severity", "")).lower()
        if sev in {"critical", "high"}:
            high.append(text)
        elif sev in {"medium", "low"}:
            medium_low.append(text)
        else:
            generic.append(text)
    generic.extend(summary.get("next_recommendations", []) or [])

    def uniq(items):
        seen = set()
        out = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    high = uniq(high)
    medium_low = uniq(medium_low)
    generic = uniq(generic)

    parts = []
    if high:
        parts.append("### P0 / High Priority\n")
        parts.extend(f"{i}. {text}\n" for i, text in enumerate(high, 1))
    if medium_low:
        parts.append("### P1 / Medium Priority\n")
        parts.extend(f"{i}. {text}\n" for i, text in enumerate(medium_low, 1))
    if generic:
        parts.append("### General Recommendations\n")
        parts.extend(f"{i}. {text}\n" for i, text in enumerate(generic, 1))
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


def build_findings_details(findings, parsed_findings):
    parts = ["## 4. Vulnerability Details", ""]
    for item in findings:
        fid = item.get("finding_id", "")
        parsed = parsed_findings.get(fid, {})
        severity_reason = item.get("severity_reason", "")
        parts.extend(
            [
                f"### {fid} — {item.get('title', parsed.get('title', ''))}",
                "",
                "| Item | Content |",
                "|------|---------|",
                f"| Severity | {item.get('severity', '')} |",
                f"| Severity Reason | {severity_reason or 'See description'} |",
                f"| Priority | {item.get('priority', '')} |",
                f"| Status | {parsed.get('status_from_table') or item.get('status', '')} |",
                f"| Affected Location | {parsed.get('affected', item.get('target', ''))} |",
                f"| Source Phase | {parsed.get('source_phase', '') or item.get('_source_phase', '')} |",
                "",
                "**Vulnerability Description**",
                "",
                parsed.get("description", item.get("fact_summary", "")),
                "",
            ]
        )
        evidence = parsed.get("evidence", [])
        if evidence:
            parts.extend(["**Key Evidence Summary**", ""])
            parts.extend([f"- {line}" for line in evidence])
            parts.append("")
        poc = parsed.get("poc") or item.get("poc", "")
        reproduction = parsed.get("reproduction", "")
        if not poc and reproduction:
            poc = reproduction
        if poc:
            fence = "http" if re.search(r"\b(GET|POST|PUT|DELETE|PATCH|HTTP/1\.1|curl)\b", poc, re.I) else ""
            parts.extend(["**PoC**", "", f"```{fence}", poc, "```", ""])
        elif item.get("poc_boundary"):
            parts.extend(["**PoC**", "", item.get("poc_boundary", ""), ""])
        parts.extend(["**Validation Boundary**", "", item.get("boundary", "No boundary statement provided"), ""])
        remediation = parsed.get("remediation", [])
        if remediation:
            parts.extend(["**Remediation**", ""])
            parts.extend([f"{i}. {line}" for i, line in enumerate(remediation, 1)])
            parts.append("")
        refs = ", ".join(item.get("evidence_refs", []) or [])
        if refs:
            parts.extend([f"**Evidence References**: {refs}", ""])
    return "\n".join(parts).strip()


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


def main():
    import argparse as ap
    parser = ap.ArgumentParser(description="Generate authorized AppSec assessment report")
    parser.add_argument("task_dir", help="Task directory")
    parser.add_argument("--export-l3", default=None, help="Export to L3 root")
    parser.add_argument("--format", default="markdown", choices=["markdown", "sarif", "defectdojo"],
                        help="Output format (default: markdown)")
    parser.add_argument("--output", default=None, help="Output file path (default: auto)")
    args = parser.parse_args()

    task_dir = Path(args.task_dir).resolve()
    l3_root = Path(args.export_l3).resolve() if args.export_l3 else None
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

    task_dir = Path(args.task_dir).resolve()
    l3_root = Path(args.export_l3).resolve() if args.export_l3 else None
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
    counts = count_by_severity(findings)
    boundary = fmt_boundary(summary.get("boundary_summary", ""))
    recommendations = build_recommendations(summary, findings)
    parsed_findings = parse_findings_markdown(findings_md)
    findings_detail = build_findings_details(findings, parsed_findings)
    fingerprint_summary = parse_fingerprint_summary(fingerprint_md, summary)

    report = f"""# {report_title(summary)}

**Task ID**: {summary.get('task_id', task_dir.name)}
**Test Time**: {summary.get('started_at', 'unknown')} ~ {summary.get('ended_at', 'unknown')}
**Status**: {pretty_status(summary.get('phase_status', 'unknown'))}

## 1. Task Overview

| Item | Content |
|------|---------|
| Task ID | {summary.get('task_id', task_dir.name)} |
| Target | {short_target(summary)} |
| Target Type | {summary.get('target_type', '')} |
| Tech Stack | {", ".join(summary.get('tech_stack', []) or [])} |
| Current Status | {pretty_status(summary.get('phase_status', ''))} |
| Completed Phase | {summary.get('current_phase', '')} |

### Task Conclusion

{summary.get('risk_summary', 'Please add task conclusion based on major findings.')}

## 2. Test Boundaries

{boundary or "_No boundary statement provided_"}

## 3. Key Findings Summary

### 3.1 Vulnerability Summary Table

{build_findings_table(findings)}

### 3.2 Vulnerability Statistics

- Critical: {counts['critical']}
- High: {counts['high']}
- Medium: {counts['medium']}
- Low: {counts['low']}
- Info: {counts['info']}

{findings_detail}

{fingerprint_summary}

## 6. Evidence Index

{build_evidence_table(evidence)}

## 7. Remediation Priority & Next Recommendations

{recommendations or "_No next recommendations_"}
"""

    (task_dir / "report.md").write_text(report, encoding="utf-8")
    if isinstance(summary, dict):
        summary["report_status"] = "draft"
        write_json(task_dir / "summary.json", summary)
    print(str(task_dir / "report.md"))
    if l3_root is not None:
        ok, detail = run_l3_export(task_dir, l3_root)
        if ok:
            print(f"l3-export: {detail}")
        else:
            print(f"l3-export-warning: {detail}", file=sys.stderr)


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
                    "version": "2.21.0",
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
