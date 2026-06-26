#!/usr/bin/env python3
"""Generate a batch-level report from aggregated results.

Usage:
    python3 scripts/generate_batch_report.py <batch_dir>

Requires: aggregate.json (run aggregate_batch.py first)
Produces: batch_dir/report.md
"""
import json
import sys
from pathlib import Path


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def severity_emoji(sev: str) -> str:
    return {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}.get(sev, "?")


def main():
    if len(sys.argv) != 2:
        print("Usage: generate_batch_report.py <batch_dir>", file=sys.stderr)
        sys.exit(1)

    batch_dir = Path(sys.argv[1]).resolve()
    aggregate = read_json(batch_dir / "aggregate.json", {})
    if not aggregate:
        raise SystemExit(f"No aggregate.json found. Run aggregate_batch.py first.")

    targets = aggregate.get("targets", [])
    findings = aggregate.get("findings", [])
    sev = aggregate.get("severity_totals", {})

    # Build report
    lines = [
        f"# Batch Report: {aggregate.get('batch_id', batch_dir.name)}",
        "",
        f"**Aggregated**: {aggregate.get('aggregated_at', 'unknown')}",
        f"**Targets**: {aggregate.get('total_targets', 0)}",
        f"**Completed**: {aggregate.get('completed', 0)}",
        f"**Total Findings**: {aggregate.get('total_findings', 0)}",
        "",
        "## Severity Summary",
        "",
        f"- Critical: {sev.get('critical', 0)}",
        f"- High: {sev.get('high', 0)}",
        f"- Medium: {sev.get('medium', 0)}",
        f"- Low: {sev.get('low', 0)}",
        f"- Info: {sev.get('info', 0)}",
        "",
        "## Target Summary",
        "",
        "| Target ID | Target | Status | Findings | Major |",
        "|-----------|--------|--------|----------|-------|",
    ]

    for t in targets:
        fc = t.get("finding_counts", {})
        total = sum(fc.values()) if isinstance(fc, dict) else 0
        major = len(t.get("major_findings", []))
        lines.append(
            f"| {t.get('target_id', '')} | {t.get('target', '')} | {t.get('status', '')} | {total} | {major} |"
        )

    lines.extend(["", "## Cross-Target Findings", ""])

    if findings:
        # Group by severity
        by_sev = {}
        for f in findings:
            s = str(f.get("severity", "info")).lower()
            by_sev.setdefault(s, []).append(f)

        for sev_level in ["critical", "high", "medium", "low", "info"]:
            group = by_sev.get(sev_level, [])
            if not group:
                continue
            lines.append(f"### {sev_level.upper()} ({len(group)})")
            lines.append("")
            for f in group:
                target = f.get("_source_target", "unknown")
                lines.append(f"- **{f.get('finding_id', '')}** [{target}] {f.get('title', '')}")
            lines.append("")
    else:
        lines.append("_No findings aggregated_")
        lines.append("")

    lines.extend([
        "## Per-Target Reports",
        "",
        "See individual target directories for detailed reports.",
        "",
    ])

    report_path = batch_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Generated: {report_path}")


if __name__ == "__main__":
    main()
