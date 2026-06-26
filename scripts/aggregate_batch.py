#!/usr/bin/env python3
"""Aggregate results from completed batch targets.

Usage:
    python3 scripts/aggregate_batch.py <batch_dir>

Reads summary.json from each completed target and produces:
    - batch_dir/aggregate.json  (aggregated findings + stats)
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_findings(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", []) or []
    return []


def collect_task(task_dir: Path, target_id: str | None = None) -> tuple[dict, list]:
    summary = read_json(task_dir / "summary.json", {})
    findings = normalize_findings(read_json(task_dir / "findings.json", []))
    target_id = target_id or task_dir.name
    target_summary = {
        "target_id": target_id,
        "directory": task_dir.name,
        "target": summary.get("target", ""),
        "status": summary.get("phase_status", "unknown"),
        "finding_counts": summary.get("finding_counts", {}),
        "major_findings": summary.get("major_findings", []),
    }
    return target_summary, findings


def main():
    if len(sys.argv) != 2:
        print("Usage: aggregate_batch.py <batch_dir>", file=sys.stderr)
        sys.exit(1)

    batch_dir = Path(sys.argv[1]).resolve()
    targets_dir = batch_dir / "targets"
    if not targets_dir.exists():
        raise SystemExit(f"No targets directory found: {targets_dir}")

    all_findings = []
    target_summaries = []
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    targets_json = read_json(batch_dir / "targets.json", {})
    batch_mode = targets_json.get("batch_mode", "one-task-per-target")

    if batch_mode == "single-batch-task":
        shared_dir = batch_dir / "shared-task"
        if not shared_dir.exists():
            raise SystemExit(f"No shared-task directory found for single-batch-task: {shared_dir}")

        shared_summary, shared_findings = collect_task(shared_dir, target_id=f"{batch_dir.name}-control")
        registry = {item.get("target_id", ""): item for item in targets_json.get("targets", [])}
        counts_by_target = {tid: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0} for tid in registry}
        major_by_target = {tid: [] for tid in registry}

        for finding in shared_findings:
            source_target = finding.get("target_id") or finding.get("_source_target") or shared_dir.name
            finding["_source_target"] = source_target
            all_findings.append(finding)
            sev = str(finding.get("severity", "info")).lower()
            if sev in severity_totals:
                severity_totals[sev] += 1
            if source_target in counts_by_target and sev in counts_by_target[source_target]:
                counts_by_target[source_target][sev] += 1
            if source_target in major_by_target and sev in {"critical", "high"}:
                major_by_target[source_target].append(finding.get("title", ""))

        for target_id, meta in registry.items():
            target_summaries.append({
                "target_id": target_id,
                "directory": shared_dir.name,
                "target": meta.get("target", ""),
                "status": meta.get("status", shared_summary.get("status", "unknown")),
                "finding_counts": counts_by_target.get(target_id, {}),
                "major_findings": major_by_target.get(target_id, []),
            })
    else:
        for task_dir in sorted(targets_dir.iterdir()):
            if not task_dir.is_dir():
                continue
            target_summary, findings = collect_task(task_dir)

            # Extract T-XXX from directory name (e.g., T-001-some-slug -> T-001)
            import re
            m = re.match(r"^(T-\d{3})", task_dir.name)
            target_id = m.group(1) if m else task_dir.name
            target_summary["target_id"] = target_id
            target_summaries.append(target_summary)

            for finding in findings:
                finding["_source_target"] = task_dir.name
                all_findings.append(finding)
                sev = str(finding.get("severity", "info")).lower()
                if sev in severity_totals:
                    severity_totals[sev] += 1

    aggregate = {
        "batch_id": batch_dir.name,
        "aggregated_at": datetime.now(timezone.utc).isoformat(),
        "total_targets": len(target_summaries),
        "completed": sum(1 for t in target_summaries if t["status"] == "completed"),
        "total_findings": len(all_findings),
        "severity_totals": severity_totals,
        "targets": target_summaries,
        "findings": all_findings,
    }

    write_json(batch_dir / "aggregate.json", aggregate)

    # Also write batch-level summary.json
    batch_summary = {
        "batch_id": batch_dir.name,
        "aggregated_at": aggregate["aggregated_at"],
        "total_targets": aggregate["total_targets"],
        "completed": aggregate["completed"],
        "total_findings": aggregate["total_findings"],
        "severity_totals": severity_totals,
        "major_findings": [
            {"finding_id": f.get("finding_id", ""), "title": f.get("title", ""), "severity": f.get("severity", "")}
            for f in all_findings if f.get("severity", "") in ("critical", "high")
        ],
        "next_recommendations": [],
        "report_status": "not_generated",
    }
    write_json(batch_dir / "summary.json", batch_summary)

    print(f"Aggregated: {batch_dir / 'aggregate.json'}")
    print(f"  Targets: {len(target_summaries)}")
    print(f"  Findings: {len(all_findings)}")
    print(f"  Severity: C={severity_totals['critical']} H={severity_totals['high']} M={severity_totals['medium']} L={severity_totals['low']} I={severity_totals['info']}")


if __name__ == "__main__":
    main()
