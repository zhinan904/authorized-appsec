#!/usr/bin/env python3
"""Import legacy vulnerability reports into the standard task structure.

Supported input formats:
    .md/.markdown, .html/.htm, .docx, and .doc when LibreOffice is available.
"""
import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree as ET


def skill_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_results_root() -> Path:
    env_root = os.environ.get("PENTEST_RESULTS_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    return Path.home() / "authorized-appsec" / "results"


def write_text(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def slugify(value: str) -> str:
    value = (value or "").lower().replace("https://", "").replace("http://", "")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:50] or "imported-report"


def next_import_seq(results_root: Path) -> int:
    existing = [d for d in results_root.iterdir() if d.is_dir() and d.name.startswith("IMPORTED-")] if results_root.exists() else []
    seqs = []
    for item in existing:
        parts = item.name.split("-")
        if len(parts) >= 3:
            try:
                seqs.append(int(parts[2]))
            except ValueError:
                pass
    return max(seqs, default=0) + 1


def first_url(text: str) -> str:
    match = re.search(r"https?://[^\s<>)\"']+", text or "")
    return match.group(0).rstrip(".,;") if match else ""


def read_markdown(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


class MarkdownHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.heading = 0
        self.in_li = False
        self.in_pre = False
        self.table_row = []
        self.in_cell = False
        self.cell_text = []

    def _append(self, value: str):
        if self.in_cell:
            self.cell_text.append(value)
        else:
            self.parts.append(value)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if re.fullmatch(r"h[1-6]", tag):
            self.heading = int(tag[1])
            self.parts.append("\n" + "#" * self.heading + " ")
        elif tag in {"p", "div", "section", "article"}:
            self.parts.append("\n")
        elif tag == "br":
            self._append("\n")
        elif tag == "li":
            self.parts.append("\n- ")
            self.in_li = True
        elif tag in {"pre", "code"} and not self.in_pre:
            self.in_pre = True
            self.parts.append("\n```\n")
        elif tag == "tr":
            self.table_row = []
        elif tag in {"td", "th"}:
            self.in_cell = True
            self.cell_text = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if re.fullmatch(r"h[1-6]", tag):
            self.heading = 0
            self.parts.append("\n")
        elif tag in {"p", "div", "section", "article", "li"}:
            self.parts.append("\n")
            self.in_li = False
        elif tag in {"pre", "code"} and self.in_pre:
            self.parts.append("\n```\n")
            self.in_pre = False
        elif tag in {"td", "th"}:
            self.table_row.append(clean_inline("".join(self.cell_text)))
            self.cell_text = []
            self.in_cell = False
        elif tag == "tr" and self.table_row:
            self.parts.append("\n| " + " | ".join(self.table_row) + " |\n")
            self.table_row = []

    def handle_data(self, data):
        text = html.unescape(data)
        if self.in_pre:
            self._append(text)
        else:
            self._append(re.sub(r"\s+", " ", text))

    def markdown(self) -> str:
        text = "".join(self.parts)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip() + "\n"


def read_html(path: Path) -> str:
    parser = MarkdownHTMLParser()
    parser.feed(path.read_text(encoding="utf-8", errors="ignore"))
    return parser.markdown()


def xml_text(element) -> str:
    vals = []
    for node in element.iter():
        if node.tag.endswith("}t") and node.text:
            vals.append(node.text)
        elif node.tag.endswith("}tab"):
            vals.append("\t")
        elif node.tag.endswith("}br"):
            vals.append("\n")
    return "".join(vals)


def paragraph_style(element) -> str:
    for node in element.iter():
        if node.tag.endswith("}pStyle"):
            return node.attrib.get("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val", "")
    return ""


def read_docx(path: Path, assets_dir: Path | None = None) -> str:
    parts = []
    with zipfile.ZipFile(path) as zf:
        if assets_dir:
            assets_dir.mkdir(parents=True, exist_ok=True)
            for name in zf.namelist():
                if name.startswith("word/media/") and not name.endswith("/"):
                    dest = assets_dir / Path(name).name
                    dest.write_bytes(zf.read(name))
        document = zf.read("word/document.xml")

    root = ET.fromstring(document)
    body = next((child for child in root if child.tag.endswith("}body")), root)
    for child in body:
        if child.tag.endswith("}p"):
            text = clean_inline(xml_text(child))
            if not text:
                continue
            style = paragraph_style(child).lower()
            if "heading1" in style:
                parts.append(f"# {text}")
            elif "heading2" in style:
                parts.append(f"## {text}")
            elif "heading3" in style:
                parts.append(f"### {text}")
            else:
                parts.append(text)
        elif child.tag.endswith("}tbl"):
            for row in [n for n in child.iter() if n.tag.endswith("}tr")]:
                cells = []
                for cell in [n for n in row if n.tag.endswith("}tc")]:
                    cells.append(clean_inline(xml_text(cell)))
                if cells:
                    parts.append("| " + " | ".join(cells) + " |")
    return "\n\n".join(parts).strip() + "\n"


def convert_doc_to_docx(path: Path, out_dir: Path) -> Path:
    soffice = shutil.which("libreoffice") or shutil.which("soffice")
    if not soffice:
        raise SystemExit(".doc import requires LibreOffice/soffice on PATH")
    result = subprocess.run(
        [soffice, "--headless", "--convert-to", "docx", "--outdir", str(out_dir), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise SystemExit(f"failed to convert .doc to .docx: {detail}")
    converted = out_dir / (path.stem + ".docx")
    if not converted.exists():
        raise SystemExit("LibreOffice conversion did not produce a .docx file")
    return converted


def read_report(path: Path, assets_dir: Path | None = None) -> str:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown", ".txt"}:
        return read_markdown(path)
    if suffix in {".html", ".htm"}:
        return read_html(path)
    if suffix == ".docx":
        return read_docx(path, assets_dir)
    if suffix == ".doc":
        with tempfile.TemporaryDirectory() as tmp:
            converted = convert_doc_to_docx(path, Path(tmp))
            return read_docx(converted, assets_dir)
    raise SystemExit(f"unsupported report format: {path.suffix}")


def clean_inline(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


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


def contains_any(text: str, items: list[str]) -> bool:
    low = text.lower()
    return any(item.lower() in low for item in items)


CN = {
    "critical": ["\u4e25\u91cd", "\u7d27\u6025", "\u81f4\u547d"],
    "high": ["\u9ad8\u5371", "\u9ad8\u98ce\u9669"],
    "medium": ["\u4e2d\u5371", "\u4e2d\u98ce\u9669"],
    "low": ["\u4f4e\u5371", "\u4f4e\u98ce\u9669"],
    "info": ["\u4fe1\u606f", "\u63d0\u793a"],
}


FIELD_LABELS = {
    "title": ["title", "finding", "vulnerability name", "issue", "\u6f0f\u6d1e\u540d\u79f0", "\u6f0f\u6d1e\u6807\u9898", "\u98ce\u9669\u9879"],
    "severity": ["severity", "risk", "risk level", "\u98ce\u9669\u7b49\u7ea7", "\u5371\u5bb3\u7b49\u7ea7", "\u4e25\u91cd\u7a0b\u5ea6"],
    "affected": ["affected", "affected url", "url", "endpoint", "target", "parameter", "\u5f71\u54cd\u5730\u5740", "\u6f0f\u6d1e\u5730\u5740", "\u63a5\u53e3", "\u53c2\u6570"],
    "description": ["description", "details", "summary", "\u6f0f\u6d1e\u63cf\u8ff0", "\u95ee\u9898\u63cf\u8ff0", "\u8be6\u60c5"],
    "evidence": ["evidence", "proof", "result", "\u8bc1\u636e", "\u9a8c\u8bc1\u7ed3\u679c", "\u6d4b\u8bd5\u7ed3\u679c"],
    "poc": ["poc", "proof of concept", "reproduction", "steps to reproduce", "request", "payload", "\u590d\u73b0", "\u590d\u73b0\u6b65\u9aa4", "\u9a8c\u8bc1\u6b65\u9aa4", "\u6d4b\u8bd5\u6b65\u9aa4", "\u8bf7\u6c42\u5305"],
    "remediation": ["remediation", "recommendation", "solution", "fix", "\u4fee\u590d\u5efa\u8bae", "\u6574\u6539\u5efa\u8bae", "\u89e3\u51b3\u65b9\u6848"],
}


ALL_LABELS = sorted({item for values in FIELD_LABELS.values() for item in values}, key=len, reverse=True)


def label_regex(labels: list[str]) -> str:
    escaped = [re.escape(item) for item in labels]
    return r"(?:\*\*)?(?:" + "|".join(escaped) + r")(?:\*\*)?\s*[:：]\s*"


def extract_labeled_block(text: str, labels: list[str]) -> str:
    pattern = re.compile(r"(?im)^\s*" + label_regex(labels) + r"(.*)$")
    match = pattern.search(text)
    if not match:
        return ""
    lines = [match.group(1).strip()]
    pos = match.end()
    for raw in text[pos:].splitlines():
        if re.match(r"^\s*#{1,6}\s+", raw):
            break
        if re.match(r"^\s*" + label_regex(ALL_LABELS), raw, flags=re.I):
            break
        lines.append(raw.rstrip())
    return "\n".join(lines).strip()


def normalize_severity(value: str) -> str:
    low = (value or "").lower()
    if re.search(r"\bcritical\b|\bsevere\b", low) or any(x in value for x in CN["critical"]):
        return "critical"
    if re.search(r"\bhigh\b", low) or any(x in value for x in CN["high"]):
        return "high"
    if re.search(r"\bmedium\b|\bmoderate\b", low) or any(x in value for x in CN["medium"]):
        return "medium"
    if re.search(r"\blow\b", low) or any(x in value for x in CN["low"]):
        return "low"
    if re.search(r"\binfo(?:rmational)?\b", low) or any(x in value for x in CN["info"]):
        return "info"
    return "info"


def title_case_severity(severity: str) -> str:
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}.get(severity, "Info")


def extract_severity(title: str, body: str) -> str:
    labeled = extract_labeled_block(body, FIELD_LABELS["severity"])
    combined = "\n".join([labeled, title, body[:1200]])
    return normalize_severity(combined)


def split_markdown_sections(markdown: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r"(?m)^(#{1,6})\s+(.+?)\s*$", markdown))
    sections = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(markdown)
        title = match.group(2).strip()
        body = markdown[start:end].strip()
        if body:
            sections.append((title, body))
    if not sections:
        sections.append(("Imported Finding", markdown.strip()))
    return sections


def is_finding_section(title: str, body: str) -> bool:
    haystack = f"{title}\n{body}"
    if extract_labeled_block(body, FIELD_LABELS["severity"]) or extract_labeled_block(body, FIELD_LABELS["poc"]):
        return True
    keywords = [
        "vulnerability", "finding", "risk", "xss", "sqli", "sql injection", "idor",
        "cors", "csrf", "ssrf", "rce", "upload", "traversal", "disclosure", "leak",
        "\u6f0f\u6d1e", "\u98ce\u9669", "\u5f31\u53e3\u4ee4", "\u6ce8\u5165", "\u8d8a\u6743", "\u6cc4\u9732",
    ]
    return contains_any(haystack, keywords)


def parse_findings(markdown: str, default_status: str = "confirmed", confirm_without_poc: bool = False) -> list[dict]:
    findings = []
    sections = [(title, body) for title, body in split_markdown_sections(markdown) if is_finding_section(title, body)]
    if not sections:
        sections = [("Imported Finding", markdown.strip())]
    for idx, (heading, body) in enumerate(sections, start=1):
        title = clean_inline(extract_labeled_block(body, FIELD_LABELS["title"]) or heading)
        title = re.sub(r"\[(Critical|High|Medium|Low|Info)\]", "", title, flags=re.I).strip(" -:")
        severity = extract_severity(heading, body)
        affected = extract_labeled_block(body, FIELD_LABELS["affected"]) or first_url(body)
        description = extract_labeled_block(body, FIELD_LABELS["description"]) or body.split("\n\n", 1)[0]
        evidence = extract_labeled_block(body, FIELD_LABELS["evidence"])
        poc = extract_labeled_block(body, FIELD_LABELS["poc"])
        remediation = extract_labeled_block(body, FIELD_LABELS["remediation"]) or "Review the original report and apply the vendor-recommended remediation."
        status = default_status
        if not poc and not confirm_without_poc:
            status = "suspicious"
            poc = "Imported report did not contain an explicit PoC. Review raw/imported-normalized.md and the original report before treating this as confirmed."
        elif not poc:
            poc = "Imported report did not contain an explicit PoC. Confirmation relies on the imported report evidence; retest before external reuse."
        findings.append(
            {
                "finding_id": f"F-{idx:03d}",
                "title": redact_sensitive(title) or f"Imported Finding {idx}",
                "severity": severity,
                "status": status,
                "affected": redact_sensitive(affected or "See imported report"),
                "description": redact_sensitive(description.strip()),
                "evidence": redact_sensitive(evidence or "Original imported report and normalized markdown."),
                "poc": redact_sensitive(poc),
                "remediation": redact_sensitive(remediation),
            }
        )
    return findings


def build_findings_md(task_id: str, source_name: str, target: str, findings: list[dict]) -> str:
    parts = [
        "# Findings",
        "",
        f"**Task**: {task_id}",
        f"**Target**: {target}",
        f"**Imported From**: {source_name}",
        "**Import Note**: This file was generated from a legacy report. Validate imported conclusions before L3 export.",
        "",
    ]
    for item in findings:
        parts.extend(
            [
                f"## {item['finding_id']} — {item['title']} [{title_case_severity(item['severity'])}]",
                "",
                f"**Status**: {item['status']}",
                "",
                f"**Description**:\n{item['description']}",
                "",
                f"**Affected**:\n{item['affected']}",
                "",
                f"**Severity Reason**: Imported report labeled this item as {title_case_severity(item['severity'])}. Verify impact before external reuse.",
                "",
                "**OWASP Category**:",
                "",
                "**CWE**:",
                "",
                "**Boundary**: Imported from a historical report; no live retest was executed during import. Use only the imported PoC/evidence until retested.",
                "",
                f"**Evidence**:\n- Original report: `raw/imported-original{Path(source_name).suffix}`\n- Normalized text: `raw/imported-normalized.md`\n\n{item['evidence']}",
                "",
                f"**PoC**:\n{item['poc']}",
                "",
                f"**Remediation**:\n{item['remediation']}",
                "",
                "---",
                "",
            ]
        )
    return "\n".join(parts).rstrip() + "\n"


def create_task_dir(results_root: Path, source_path: Path, target: str) -> Path:
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    seq = next_import_seq(results_root)
    task_dir = results_root / f"IMPORTED-{today}-{seq:03d}-{slugify(target or source_path.stem)}"
    task_dir.mkdir(parents=True, exist_ok=False)
    for subdir in ["raw", "raw/imported-assets", "sessions", "screenshots"]:
        (task_dir / subdir).mkdir(parents=True, exist_ok=True)
    return task_dir


def run_helper(script_name: str, task_dir: Path) -> tuple[bool, str]:
    script = Path(__file__).resolve().parent / script_name
    result = subprocess.run([sys.executable, str(script), str(task_dir)], capture_output=True, text=True, check=False)
    detail = (result.stdout or result.stderr or "").strip()
    return result.returncode == 0, detail


def import_report(source_path: Path, target: str = "", output_dir: Path | None = None, default_status: str = "confirmed", confirm_without_poc: bool = False, generate_report: bool = True) -> Path:
    source_path = source_path.resolve()
    if not source_path.exists():
        raise SystemExit(f"report file not found: {source_path}")
    results_root = (output_dir or default_results_root()).resolve()
    results_root.mkdir(parents=True, exist_ok=True)

    task_dir = create_task_dir(results_root, source_path, target or source_path.stem)
    raw_dir = task_dir / "raw"
    original_name = f"imported-original{source_path.suffix.lower()}"
    shutil.copy2(source_path, raw_dir / original_name)

    normalized = read_report(source_path, raw_dir / "imported-assets")
    write_text(raw_dir / "imported-normalized.md", normalized)
    target = target or first_url(normalized) or source_path.stem
    findings = parse_findings(normalized, default_status=default_status, confirm_without_poc=confirm_without_poc)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    task_id = task_dir.name
    task_md = f"""# Task Meta

- task_id: {task_id}
- target: {target}
- target_type: imported_report
- import_reviewed: false
- results_root: {results_root}
- task_dir: {task_dir}
- status: completed
- current_phase: imported
- started_at: {now}
- updated_at: {now}

## Summary

- imported_report: {source_path.name}
- finding_count: {len(findings)}
- pending_focus:
  - review imported findings before L3 export
  - retest high-risk findings when possible

## Notes

- This task was generated from a legacy report file.
- Import does not perform live validation.
- Do not export to L3 until PoC, evidence, and boundaries are reviewed.
"""
    write_text(task_dir / "task.md", task_md)
    write_text(task_dir / "findings.md", build_findings_md(task_id, source_path.name, target, findings))
    write_json(
        task_dir / "summary.json",
        {
            "task_id": task_id,
            "skill_name": "authorized-appsec",
            "target": target,
            "target_type": "imported_report",
            "phase_status": "completed",
            "current_phase": "imported",
            "started_at": now,
            "tech_stack": [],
            "major_findings": [],
            "next_recommendations": ["Review imported findings and retest before L3 export"],
            "boundary_summary": [
                "Imported from a legacy report",
                "No live retest executed during import",
                "Do not treat imported conclusions as current-target facts without review",
            ],
            "report_status": "not_generated",
            "knowledge_ready": False,
            "memory_ready": False,
            "l3_export_reason": "not eligible until imported findings are reviewed",
            "import_source": str(source_path),
        },
    )
    write_json(task_dir / "findings.json", [])
    write_json(task_dir / "evidence-index.json", [])

    ok, detail = run_helper("ensure_structured_outputs.py", task_dir)
    if not ok:
        print(f"structured-output-warning: {detail}", file=sys.stderr)
    if generate_report:
        ok, detail = run_helper("generate_report.py", task_dir)
        if not ok:
            print(f"report-warning: {detail}", file=sys.stderr)
    return task_dir


def main():
    parser = argparse.ArgumentParser(description="Import a legacy vulnerability report into a PT task directory")
    parser.add_argument("report_file", help="Legacy report file (.md, .html, .docx, .doc)")
    parser.add_argument("--target", default="", help="Target family/URL for the imported report")
    parser.add_argument("--output-dir", default=None, help="Output root directory (default: $PENTEST_RESULTS_ROOT or ~/authorized-appsec/results/)")
    parser.add_argument("--default-status", choices=["confirmed", "suspicious"], default="confirmed", help="Default status for parsed findings with PoC")
    parser.add_argument("--confirm-without-poc", action="store_true", help="Keep findings confirmed even when the report has no explicit PoC")
    parser.add_argument("--no-generate-report", action="store_true", help="Only import and structure; do not generate report.md")
    args = parser.parse_args()

    task_dir = import_report(
        Path(args.report_file),
        target=args.target,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        default_status=args.default_status,
        confirm_without_poc=args.confirm_without_poc,
        generate_report=not args.no_generate_report,
    )
    print(f"imported-report:{task_dir}")


if __name__ == "__main__":
    main()
