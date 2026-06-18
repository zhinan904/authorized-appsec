#!/usr/bin/env python3
"""Initialize a single authorized-appsec task directory structure.

Usage:
    python3 scripts/init_task.py <target> [--type url|domain|ip|ip_range] [--output-dir <dir>]

Creates PT-{YYYYMMDD}-{SEQ}-{target_slug}/ with all required files and subdirectories.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def write_text(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def default_results_root() -> Path:
    env_root = os.environ.get("AUTHORIZED_APPSEC_RESULTS_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    return Path.home() / "authorized-appsec" / "results"


def slugify(value: str) -> str:
    value = value.lower().replace("https://", "").replace("http://", "")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:40] or "target"


def next_seq(results_root: Path) -> int:
    if not results_root.exists():
        return 1
    existing = [d for d in results_root.iterdir() if d.is_dir() and d.name.startswith("PT-")]
    if not existing:
        return 1
    seqs = []
    for d in existing:
        parts = d.name.split("-")
        if len(parts) >= 3:
            try:
                seqs.append(int(parts[2]))
            except ValueError:
                pass
    return max(seqs, default=0) + 1


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Initialize a single authorized-appsec task directory")
    parser.add_argument("target", help="Target URL, domain, IP, or IP range")
    parser.add_argument("--type", dest="target_type", default="url",
                        choices=["url", "domain", "ip", "ip_range", "artifact", "mini_program"],
                        help="Target type")
    parser.add_argument("--output-dir", default=None,
                        help="Output root directory (default: $AUTHORIZED_APPSEC_RESULTS_ROOT or ~/authorized-appsec/results/)")
    args = parser.parse_args()

    if args.output_dir:
        results_root = Path(args.output_dir).expanduser()
    else:
        results_root = default_results_root()
    results_root.mkdir(parents=True, exist_ok=True)

    seq = next_seq(results_root)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    slug = slugify(args.target)
    dir_name = f"PT-{today}-{seq:03d}-{slug}"
    task_dir = results_root / dir_name
    task_dir.mkdir(parents=True, exist_ok=True)

    for subdir in ["sessions", "raw", "screenshots"]:
        (task_dir / subdir).mkdir(exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    task_md = f"""# Task Meta

- task_id: {dir_name}
- target: {args.target}
- target_type: {args.target_type}
- results_root: {results_root}
- task_dir: {task_dir}
- status: in_progress
- current_phase: phase_0
- loop_depth: 0
- last_loop_reason: none
- session_contexts:
  - anonymous: valid
  - user: unavailable
  - admin: unavailable
- started_at: {now}
- updated_at: {now}

## Summary

- tech_stack: unknown
- waf: unknown
- finding_counts:
  - critical: 0
  - high: 0
  - medium: 0
  - low: 0
  - info: 0
- pending_focus:
  - complete phase_0 fingerprint
  - identify initial attack surface

## Next Actions

1. run phase_0 fingerprint
2. write 01-fingerprint.md
3. update task.md before phase switch

## Notes

- `current_phase` values: `phase_0` / `phase_1` / `phase_2` / `phase_3` / `phase_4` / `phase_5`
- `status` values: `in_progress` / `paused` / `completed` / `stopped` / `example`
- `loop_depth` tracks phase re-entry count (max 3 before pause and ask user)
- `last_loop_reason` records why a phase was re-entered
- Update this file on every phase switch, new confirmed finding, task pause or resume
- Results for this task stay under `task_dir` above unless the user explicitly requests migration.
- Mini Program artifacts: extract backend hosts and confirm same-host Web surface (`/`, `/login`, `/admin`, feature paths) before declaring scope complete.

## Tools Used

_Capabilities to be filled after running discover-capabilities.sh_

_Run: ./scripts/discover-capabilities.sh <task_dir>/capabilities.json_
"""
    write_text(task_dir / "task.md", task_md)

    findings_md = """# Findings

_No confirmed findings yet._

## F-001 — [Title] [severity]

**Status**: confirmed / suspicious / false_positive

**Description**:

**Affected**:

**Severity Reason**:

**OWASP Category**:

**CWE**:

**Boundary**:

**Evidence**:

**PoC**:

**Remediation**:
"""
    write_text(task_dir / "findings.md", findings_md)

    summary_json = {
        "task_id": dir_name,
        "skill_name": "authorized-appsec",
        "target": args.target,
        "target_type": args.target_type,
        "phase_status": "in_progress",
        "current_phase": "Phase 0",
        "started_at": now,
        "tech_stack": [],
        "major_findings": [],
        "next_recommendations": [],
        "boundary_summary": "",
        "report_status": "not_generated",
        "knowledge_ready": False,
        "memory_ready": False,
        "l3_export_reason": "not evaluated",
    }
    write_json(task_dir / "summary.json", summary_json)

    findings_json = []
    write_json(task_dir / "findings.json", findings_json)

    evidence_json = []
    write_json(task_dir / "evidence-index.json", evidence_json)

    l3_hypotheses_json = {
        "status": "not_run",
        "hypotheses": [],
        "guardrails": [
            "L3 matches are historical hypotheses, not current findings.",
            "Do not report any L3 hypothesis without current-task validation, evidence, and PoC.",
        ],
    }
    write_json(task_dir / "l3-hypotheses.json", l3_hypotheses_json)

    # Update index
    index_path = results_root / "index.md"
    index_line = f"| {dir_name} | {args.target} | {args.target_type} | in_progress | {now} | {dir_name}/ |\n"
    if index_path.exists():
        content = index_path.read_text(encoding="utf-8")
        if not content.endswith("\n"):
            content += "\n"
        content += index_line
        write_text(index_path, content)
    else:
        index_content = f"""# Task Index

| Task ID | Target | Type | Status | Created At | Path |
|--------|--------|------|--------|------------|------|
{index_line.strip()}
"""
        write_text(index_path, index_content)

    print(f"Initialized task: {task_dir}")
    print(f"  Target: {args.target}")
    print(f"  Type: {args.target_type}")
    print(f"  Files: task.md, findings.md, summary.json, findings.json, evidence-index.json, l3-hypotheses.json")
    print(f"  Subdirectories: sessions/, raw/, screenshots/")


if __name__ == "__main__":
    main()
