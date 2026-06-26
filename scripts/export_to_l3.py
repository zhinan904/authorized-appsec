#!/usr/bin/env python3
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_text(path: Path, default=""):
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "item"


def normalize_findings(findings_data):
    if isinstance(findings_data, list):
        return findings_data
    if isinstance(findings_data, dict):
        return findings_data.get("findings", []) or []
    return []


def normalize_evidence(evidence_data):
    if isinstance(evidence_data, list):
        return evidence_data
    if isinstance(evidence_data, dict):
        return evidence_data.get("evidence", []) or []
    return []


def eligible_findings(findings: list) -> list:
    eligible = []
    for finding in findings:
        if str(finding.get("status", "confirmed")).lower() != "confirmed":
            continue
        if not finding.get("knowledge_candidate", False):
            continue
        if not finding.get("distillation_candidate", False):
            continue
        if str(finding.get("severity", "")).lower() not in {"critical", "high", "medium"}:
            continue
        eligible.append(finding)
    return eligible


def update_index(index_path: Path, entry: dict):
    index = read_json(index_path, {"collection": index_path.parent.name, "version": 1, "entries": []})
    entries = index.get("entries", [])
    replaced = False
    for idx, item in enumerate(entries):
        if item.get("id") == entry.get("id"):
            entries[idx] = entry
            replaced = True
            break
    if not replaced:
        entries.append(entry)
    index["entries"] = entries
    write_json(index_path, index)


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def extract_host(summary):
    target = summary.get("target", "")
    return urlparse(target).netloc or target or "unknown-target"


def first_lines(text: str, limit: int = 3):
    return [line.strip() for line in text.splitlines() if line.strip()][:limit]


def collect_phase_hints(task_dir: Path):
    hints = []
    for name in ["01-fingerprint.md", "02-discovery.md", "03-vuln-test.md", "04-chain.md"]:
        text = read_text(task_dir / name, "")
        if text:
            hints.extend(first_lines(text, 2))
    return hints[:8]


def _check_ready(flag_name: str, value, summary: dict) -> bool:
    if value is not None:
        return bool(value)
    return bool(summary.get(flag_name, False))


def export_knowledge_mapping(l3_root: Path, task_dir: Path, summary: dict, findings: list):
    base = l3_root / "internal-knowledge" / "knowledge-mapping"
    entries_dir = base / "entries"
    ensure_dir(entries_dir)

    target_family = extract_host(summary)
    for finding in findings:
        if finding not in eligible_findings([finding]):
            continue
        fid = finding.get("finding_id", "F-000")
        title = finding.get("title", fid)
        category = finding.get("category", "unknown")
        entry_id = f"{summary.get('task_id', task_dir.name)}-{fid}".lower()
        filename = f"{entry_id}.md"
        content = f"""# {title}

## Metadata
- finding_id: {fid}
- category: {category}
- severity: {finding.get('severity', '')}
- target_family: {target_family}
- complexity: {finding.get('complexity', '')}
- chain_value: {finding.get('chain_value', False)}
- distillation_reason: {finding.get('distillation_reason', '')}
- reuse_pattern: {finding.get('reuse_pattern', '')}

## Root Cause
- root_cause: To be refined with original task. Currently auto-generated from confirmed finding summary.

## Exploitability Conditions
- preconditions: {finding.get('boundary', 'To be added')}
- trigger_path: {finding.get('target', finding.get('title', 'To be added'))}

## Impact
- impact: {finding.get('fact_summary', '')}
- observables: See evidence_refs and original evidence index

## Defense
- detection_points: See task evidence and phase files
- mitigations: {finding.get('recommended_next_action', 'To be added')}
- common_false_positives: To be added

## Evidence Linkage
- source_task: {summary.get('task_id', task_dir.name)}
- evidence_refs: {", ".join(finding.get('evidence_refs', []) or [])}
"""
        (entries_dir / filename).write_text(content, encoding="utf-8")
        update_index(
            base / "index.json",
            {
                "id": entry_id,
                "path": f"entries/{filename}",
                "finding_id": fid,
                "category": category,
                "severity": finding.get("severity", ""),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )


def export_rag_entry(l3_root: Path, task_dir: Path, summary: dict, findings: list):
    if not _check_ready("knowledge_ready", None, summary):
        return
    findings = eligible_findings(findings)
    if not findings:
        return
    base = l3_root / "internal-knowledge" / "rag"
    entries_dir = base / "entries"
    ensure_dir(entries_dir)
    task_id = summary.get("task_id", task_dir.name)
    filename = f"{task_id.lower()}-summary.md"
    major = [f.get("title", "") for f in findings if f.get("distillation_candidate", False)][:5]
    hints = collect_phase_hints(task_dir)
    content = f"""# {task_id} Summary

## Summary
This entry is auto-generated from task results for subsequent semantic retrieval.

## Source Task
- task_id: {task_id}
- target_family: {extract_host(summary)}
- date: {summary.get('ended_at', summary.get('updated_at', 'unknown'))}

## Key Facts
""" + "\n".join(f"- {item}" for item in major) + f"""

## Reusable Pattern
""" + "\n".join(f"- {item}" for item in hints[:4]) + f"""

## Limits
- This entry is an auto-summary, specific evidence needs to be traced back to original task directory
- Unconfirmed candidates should not be directly treated as formal conclusions
"""
    (entries_dir / filename).write_text(content, encoding="utf-8")
    update_index(
        base / "index.json",
        {
            "id": f"{task_id.lower()}-summary",
            "path": f"entries/{filename}",
            "title": f"{task_id} Summary",
            "tags": [slugify(extract_host(summary))] + [slugify(x) for x in (summary.get("tech_stack", []) or [])[:4]],
            "source_type": "task-summary",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "confidence": "medium",
        },
    )


def export_assessment_case(l3_root: Path, task_dir: Path, summary: dict, findings: list):
    if not _check_ready("knowledge_ready", None, summary):
        return
    findings = eligible_findings(findings)
    if not findings:
        return
    base = l3_root / "internal-knowledge" / "assessment-cases"
    entries_dir = base / "entries"
    ensure_dir(entries_dir)
    task_id = summary.get("task_id", task_dir.name)
    filename = f"{task_id.lower()}-case.md"
    high_findings = [f.get("title", "") for f in findings if str(f.get("severity", "")).lower() in {"critical", "high"}][:5]
    content = f"""# {task_id} Case

## Scenario
- task_id: {task_id}
- objective: {summary.get('risk_summary', 'To be added')}
- authorized_scope: {extract_host(summary)}

## Confirmed Path
- initial_condition: {summary.get('risk_summary', 'To be added')}
- key step: {high_findings[0] if high_findings else 'To be added'}
- impact_path: {'; '.join(high_findings) if high_findings else 'To be added'}

## Detection and Friction
- detected_controls: {summary.get('waf', 'unknown')}
- blockers: See phase files and task memory

## Reusable Lessons
- what worked: Prioritize validating high-value endpoints and confirmed facts
- what failed: Do not upgrade unconfirmed candidates directly to conclusions
- what to check first next time: Read summary.json, findings.json, evidence-index.json first
"""
    (entries_dir / filename).write_text(content, encoding="utf-8")
    update_index(
        base / "index.json",
        {
            "id": f"{task_id.lower()}-case",
            "path": f"entries/{filename}",
            "stage": "confirmed-case",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def export_task_memory(l3_root: Path, task_dir: Path, summary: dict, findings: list):
    if not _check_ready("memory_ready", None, summary):
        return
    findings = eligible_findings(findings)
    if not findings:
        return
    base = l3_root / "experience" / "task-memory"
    entries_dir = base / "entries"
    ensure_dir(entries_dir)
    task_id = summary.get("task_id", task_dir.name)
    filename = f"{task_id.lower()}-memory.md"
    top = findings[:3]
    content = f"""# Task Memory

## Metadata
- task_id: {task_id}
- task_name: {task_id}
- target: {summary.get('target', '')}
- status: {summary.get('phase_status', '')}
- updated_at: {summary.get('ended_at', summary.get('updated_at', 'unknown'))}

## Confirmed Facts
""" + "\n".join(f"- {item.get('fact_summary', '')}" for item in top) + f"""

## Key Judgments
- confirmed_conclusion: {summary.get('risk_summary', 'To be added')}
- high_probability_inference: See findings.json and major findings in report
- falsified_assumption: To be manually added

## Effective Actions
- best_action: Prioritize drawing conclusions from confirmed findings and evidence index
- weak_action: Do not output formal conclusions based solely on candidates and scan hits

## Next Reuse
- check_first_next_time: Read task.md, summary.json, findings.json first
- distillation_candidates: {", ".join(item.get('finding_id', '') for item in findings if item.get('distillation_candidate', False))}
"""
    (entries_dir / filename).write_text(content, encoding="utf-8")
    update_index(
        base / "index.json",
        {
            "id": f"{task_id.lower()}-memory",
            "path": f"entries/{filename}",
            "status": summary.get("phase_status", ""),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def export_self_distillation(l3_root: Path, task_dir: Path, summary: dict, findings: list):
    if not _check_ready("memory_ready", None, summary):
        return
    findings = eligible_findings(findings)
    if not findings:
        return
    base = l3_root / "experience" / "self-distillation"
    entries_dir = base / "entries"
    ensure_dir(entries_dir)
    task_id = summary.get("task_id", task_dir.name)
    filename = f"{task_id.lower()}-distillation.md"
    hints = collect_phase_hints(task_dir)
    content = f"""# Distilled Experience

## Task Summary
- task_id: {task_id}
- task_type: authorized-appsec
- target_family: {extract_host(summary)}

## Directional Signals
- earliest_signal: {hints[0] if hints else 'To be added'}
- misleading_signal: To be manually added

## Effective Reasoning
- best_mapping_rule: First converge confirmed findings, then add phase details
- best_validation_decision: Only elevate verified facts to final conclusions

## Invalidated Assumptions
- assumption_1: Scan hits do not equal confirmed vulnerabilities
- assumption_2: Phase drafts should not be directly treated as delivery reports

## Reusable Heuristics
- check_first_next_time: summary.json → findings.json → evidence-index.json
- pivot_condition: When high-risk finding aligns with key evidence, prioritize depositing to L3
"""
    (entries_dir / filename).write_text(content, encoding="utf-8")
    update_index(
        base / "index.json",
        {
            "id": f"{task_id.lower()}-distillation",
            "path": f"entries/{filename}",
            "task_type": "authorized-appsec",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def export_context_snapshot(l3_root: Path, task_dir: Path, summary: dict, findings: list, evidence: list):
    if not _check_ready("memory_ready", None, summary):
        return
    findings = eligible_findings(findings)
    if not findings:
        return
    base = l3_root / "experience" / "context"
    entries_dir = base / "entries"
    ensure_dir(entries_dir)
    task_id = summary.get("task_id", task_dir.name)
    filename = f"{task_id.lower()}-context.md"
    content = f"""# Context Snapshot

## Task Goal
- goal: {summary.get('risk_summary', 'To be added')}

## Confirmed Facts
""" + "\n".join(f"- {item.get('fact_summary', '')}" for item in findings[:3]) + f"""

## Core Hypotheses
- hypothesis_1: Confirmed findings may form larger impact chains, need to continue validation within authorized scope
- hypothesis_2: When evidence is insufficient, do not upgrade speculation to confirmed conclusions

## Key Evidence
""" + "\n".join(f"- {item.get('summary', '')}" for item in evidence[:3]) + f"""

## Next Actions
- action_1: Deposit only confirmed distillation candidates into internal knowledge
- action_2: Continue refining task-memory and self-distillation only for confirmed distillation candidates
"""
    (entries_dir / filename).write_text(content, encoding="utf-8")
    index = read_json(base / "index.json", {"collection": "authorized-appsec-context", "version": 1, "entries": [], "profiles": []})
    entries = index.get("entries", [])
    entry = {
        "id": f"{task_id.lower()}-context",
        "path": f"entries/{filename}",
        "kind": "compressed-snapshot",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    replaced = False
    for i, item in enumerate(entries):
        if item.get("id") == entry["id"]:
            entries[i] = entry
            replaced = True
            break
    if not replaced:
        entries.append(entry)
    index["entries"] = entries
    if not index.get("profiles"):
        index["profiles"] = [{"id": "default-recovery-profile", "path": "profiles/default-recovery-profile.md"}]
    write_json(base / "index.json", index)


def main():
    if len(sys.argv) != 3:
        print("Usage: export_to_l3.py <task_dir> <l3_root>", file=sys.stderr)
        sys.exit(1)

    task_dir = Path(sys.argv[1]).resolve()
    l3_root = Path(sys.argv[2]).resolve()
    if not task_dir.exists():
        raise SystemExit(f"Task directory not found: {task_dir}")

    summary = read_json(task_dir / "summary.json", {})
    findings = normalize_findings(read_json(task_dir / "findings.json", {"findings": []}))
    evidence = normalize_evidence(read_json(task_dir / "evidence-index.json", {"evidence": []}))
    findings = eligible_findings(findings)

    if not findings:
        print("l3-export-skipped:no confirmed distillation candidates", file=sys.stderr)
        sys.exit(2)

    export_knowledge_mapping(l3_root, task_dir, summary, findings)
    export_rag_entry(l3_root, task_dir, summary, findings)
    export_assessment_case(l3_root, task_dir, summary, findings)
    export_task_memory(l3_root, task_dir, summary, findings)
    export_self_distillation(l3_root, task_dir, summary, findings)
    export_context_snapshot(l3_root, task_dir, summary, findings, evidence)

    print(f"exported-l3:{l3_root}")


if __name__ == "__main__":
    main()
