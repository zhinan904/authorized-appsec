#!/usr/bin/env python3
"""Initialize a batch testing directory structure.

Usage:
    python3 scripts/init_batch.py <batch_dir> <targets_file>

targets_file format (one target per line):
    T-001 https://api.example.com
    T-002 https://web.example.com
    T-003 https://admin.example.com
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:40] or "target"


def parse_targets(targets_file: Path) -> list[dict]:
    targets = []
    for line in targets_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        target_id = parts[0].strip()
        url = parts[1].strip()
        if not re.match(r"^T-\d{3}$", target_id):
            print(f"Warning: skipping invalid target_id format: {target_id}", file=sys.stderr)
            continue
        targets.append({"target_id": target_id, "target": url})
    return targets


def create_target_dir(batch_dir: Path, target: dict, index: int):
    slug = slugify(target["target"])
    dir_name = f"{target['target_id']}-{slug}"
    task_dir = batch_dir / "targets" / dir_name
    task_dir.mkdir(parents=True, exist_ok=True)

    task_md = f"""# Task: {target['target_id']}

- task_id: {dir_name}
- target: {target['target']}
- target_type: url
- status: pending
- current_phase: phase_0
- loop_depth: 0
- last_loop_reason: none
- session_contexts:
  - anonymous: unavailable
  - user: unavailable
  - admin: unavailable
- batch_member: true
- batch_dir: {batch_dir.name}
- scope: (inherited from batch)
- excluded: (inherited from batch)
- allowed_capabilities: (inherited from batch)
- blocked_capabilities: (inherited from batch)
- credentials_scope: (inherited from batch)
- started_at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}
- updated_at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}

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

## Next Actions

1. run phase_0 fingerprint
2. write 01-fingerprint.md
3. update task.md before phase switch
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
        "target": target["target"],
        "target_type": "url",
        "phase_status": "pending",
        "current_phase": "Phase 0",
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "tech_stack": [],
        "major_findings": [],
        "next_recommendations": [],
        "boundary_summary": "",
        "report_status": "not_generated",
        "knowledge_ready": False,
        "memory_ready": False,
    }
    write_json(task_dir / "summary.json", summary_json)

    findings_json = []
    write_json(task_dir / "findings.json", findings_json)

    evidence_json = []
    write_json(task_dir / "evidence-index.json", evidence_json)

    for subdir in ["sessions", "raw", "screenshots"]:
        (task_dir / subdir).mkdir(exist_ok=True)

    return task_dir


def create_shared_task(batch_dir: Path):
    shared_dir = batch_dir / "shared-task"
    shared_dir.mkdir(parents=True, exist_ok=True)
    for subdir in ["slices", "raw", "sessions", "screenshots"]:
        (shared_dir / subdir).mkdir(parents=True, exist_ok=True)

    task_md = f"""# Batch Control Task

- task_id: {batch_dir.name}-control
- role: batch-control
- status: pending
- current_phase: phase_0
- created_at: {datetime.now(timezone.utc).isoformat()}
"""
    write_text(shared_dir / "task.md", task_md)
    write_text(
        shared_dir / "findings.md",
        """# Findings

_No confirmed findings yet._

## F-001 — [Title] [severity]

**Status**: confirmed / suspicious / false_positive

**Target ID**:

**Target**:

**Entrypoint**:

**Description**:

**Affected**:

**Severity Reason**:

**OWASP Category**:

**CWE**:

**Boundary**:

**Evidence**:

**PoC**:

**Remediation**:
""",
    )
    write_json(
        shared_dir / "summary.json",
        {
            "task_id": f"{batch_dir.name}-control",
            "skill_name": "authorized-appsec",
            "target": batch_dir.name,
            "target_type": "batch",
            "phase_status": "pending",
            "current_phase": "phase_0",
            "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "tech_stack": [],
            "major_findings": [],
            "next_recommendations": [],
            "boundary_summary": "",
            "report_status": "not_generated",
            "knowledge_ready": False,
            "memory_ready": False,
        },
    )
    write_json(shared_dir / "findings.json", [])
    write_json(shared_dir / "evidence-index.json", [])


def main():
    if len(sys.argv) < 3:
        print("Usage: init_batch.py <batch_dir> <targets_file> [--mode one-task-per-target|single-batch-task|discovery-first]", file=sys.stderr)
        sys.exit(1)

    batch_dir = Path(sys.argv[1]).resolve()
    targets_file = Path(sys.argv[2]).resolve()

    batch_mode = "one-task-per-target"
    if len(sys.argv) > 3:
        mode_arg = sys.argv[3]
        if mode_arg.startswith("--mode="):
            batch_mode = mode_arg.split("=", 1)[1]
        elif mode_arg == "--mode" and len(sys.argv) > 4:
            batch_mode = sys.argv[4]

    if not targets_file.exists():
        raise SystemExit(f"Targets file not found: {targets_file}")

    targets = parse_targets(targets_file)
    if not targets:
        raise SystemExit("No valid targets found in targets file")

    batch_dir.mkdir(parents=True, exist_ok=True)
    (batch_dir / "targets").mkdir(exist_ok=True)

    if batch_mode == "discovery-first":
        (batch_dir / "discovery").mkdir(exist_ok=True)

    # Create shared task before slices so single-batch-task follows the documented layout.
    create_shared_task(batch_dir)

    # Create target directories (skip per-target dirs for single-batch-task)
    if batch_mode == "single-batch-task":
        # single-batch-task: shared-task only, targets get slice files not full dirs
        for idx, target in enumerate(targets, 1):
            slug = slugify(target["target"])
            slice_file = batch_dir / "shared-task" / "slices" / f"{target['target_id']}-{slug}.md"
            slice_file.write_text(
                f"# Target Slice: {target['target_id']}\n\n"
                f"- target_id: {target['target_id']}\n"
                f"- target: {target['target']}\n"
                f"- status: pending\n\n"
                f"## Phase Notes\n\n_To be filled during testing_\n",
                encoding="utf-8",
            )
    else:
        for idx, target in enumerate(targets, 1):
            create_target_dir(batch_dir, target, idx)

    # Create targets.json
    targets_data = {
        "batch_id": batch_dir.name,
        "authorization": {
            "confirmed": False,
            "confirmed_at": "",
            "confirmed_by": "",
        },
        "scope": [],
        "excluded": [],
        "intensity": "standard",
        "allowed_capabilities": ["http-probing", "fingerprinting", "url-extraction"],
        "blocked_capabilities": ["oob", "cloud-metadata", "internal-probing"],
        "credentials_scope": {
            "allowed": False,
        },
        "batch_mode": batch_mode,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_targets": len(targets),
        "targets": [
            {
                "target_id": t["target_id"],
                "target": t["target"],
                "status": "pending",
                "entrypoints": [],
            }
            for t in targets
        ],
    }
    write_json(batch_dir / "targets.json", targets_data)

    # Create batch.md
    batch_md = f"""# Batch: {batch_dir.name}

- created_at: {datetime.now(timezone.utc).isoformat()}
- total_targets: {len(targets)}
- status: pending

## Targets

| Target ID | URL | Status |
|-----------|-----|--------|
""" + "\n".join(
        f"| {t['target_id']} | {t['target']} | pending |" for t in targets
    )
    write_text(batch_dir / "batch.md", batch_md)

    print(f"Initialized batch: {batch_dir}")
    print(f"  Targets: {len(targets)}")
    print(f"  Directory: {batch_dir}")


if __name__ == "__main__":
    main()
