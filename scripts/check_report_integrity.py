#!/usr/bin/env python3
"""check_report_integrity.py — Report integrity audit (anti-bypass gate).

Catches the PT-003-style bypass: an agent whose completeness gate FAILED chose
to ignore it and hand-wrote ``report.md`` anyway. ``check_report_gate`` lives
inside ``generate_report.py``, so an agent that never calls that generator can
sidestep it entirely. This script is the independent backstop — it audits the
final artifact (report.md) against the task's recorded state.

A report is "integrity-clean" only if ALL hold:
  1. report.md exists
  2. task.md status == completed
  3. task.md current_phase in {phase_4, phase_5}  (report = Phase 4 artifact)
  4. task.md completeness_checked == true          (gate actually ran and passed)
  5. check_completeness.py passes RIGHT NOW        (not a stale/forged pass)

If report.md exists but any of 2-5 fail, the report was emitted without a
legitimately-finished test effort. The script exits 1 with the specific gaps
and a fix path. Run it both BEFORE publishing a report (pre-check) and AFTER
(post-audit).

Usage:
    python3 scripts/check_report_integrity.py <task_dir>

Exit codes: 0 = report integrity clean (or no report present to judge),
            1 = report present but integrity violations found / crash.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Reuse parsing helpers so this auditor never drifts from how the rest of the
# skill reads task files.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import generate_report as gr  # noqa: E402
import check_completeness as cc  # noqa: E402


# Phases in which a report is a legitimate artifact. phase_5 = optional retest,
# whose own report also presupposes a finished Phase 4.
_REPORT_PHASES = {"phase_4", "phase_5"}

# task.md is not always perfectly normalized; accept truthy variants.
_TRUE_VALUES = {"true", "yes", "y", "1"}


def _truthy(value: str) -> bool:
    return (value or "").strip().lower() in _TRUE_VALUES


def check_report_integrity(task_dir: Path) -> tuple[bool, list[str]]:
    """Return (clean, messages). clean=False means the report is not legit."""
    task_dir = Path(task_dir)
    messages: list[str] = []

    report_path = task_dir / "report.md"
    if not report_path.exists():
        # Nothing to audit — no report means no bypass possible. This is the
        # correct state mid-Phase-3. Not a failure.
        return True, ["no report.md present — nothing to audit (correct state before Phase 4)"]

    # report.md exists from here on — every check below is a potential violation.
    task_path = task_dir / "task.md"
    if not task_path.exists():
        messages.append(
            "report.md exists but task.md is missing — the task state cannot be "
            "verified, so the report's legitimacy is unprovable. Recreate task.md "
            "with the correct phase/status, or delete report.md and regenerate via "
            "the normal Phase 4 flow."
        )
        return False, messages

    meta = gr._parse_task_meta(task_path.read_text(encoding="utf-8"))
    status = (meta.get("status") or "").strip().lower()
    phase = (meta.get("current_phase") or "").strip().lower()
    completeness_flag = _truthy(meta.get("completeness_checked", ""))

    violations: list[str] = []

    if status != "completed":
        violations.append(
            f"task.md status is '{status or '(unset)'}', not 'completed' — a report "
            "implies the task is finished. The agent likely emitted the report while "
            "still mid-test. Set status: completed only after the gate passes, or "
            "delete report.md and return to Phase 3."
        )

    if phase not in _REPORT_PHASES:
        violations.append(
            f"task.md current_phase is '{phase or '(unset)'}', not phase_4/phase_5 — "
            "a report is a Phase 4 artifact and cannot precede it. The agent wrote the "
            "report before reaching Phase 4. Complete the Phase 3 completeness loop first."
        )

    if not completeness_flag:
        violations.append(
            "task.md completeness_checked is not true — the completeness gate never "
            "recorded a pass. A report requires `python3 scripts/check_completeness.py "
            "<task_dir>` to exit 0 first. The agent bypassed the gate to write the report."
        )

    # Re-run the completeness gate live. A previously-passed gate that no longer
    # passes (e.g. the agent edited the queue/coverage after the fact) means the
    # report rests on a stale pass.
    try:
        gate_ok, gate_msgs = cc.check_completeness(task_dir, mode="report-gate")
    except Exception as exc:  # defensive: a crash must never read as "clean"
        gate_ok = False
        gate_msgs = [f"completeness gate crashed when re-run: {exc}"]
    if not gate_ok:
        violations.append(
            "completeness gate does NOT pass right now (re-run live) — the report rests "
            "on a gate that was never passed, or was passed then invalidated. Outstanding:"
        )
        # Surface only the substantive failure lines, not the banner.
        failures = [
            m for m in gate_msgs
            if m.strip() and not m.startswith("===") and not m.startswith("---") and not m.startswith("completeness gate passed")
        ]
        violations.extend(f"    {m}" for m in failures[:12])

    if violations:
        messages.append("=== REPORT INTEGRITY VIOLATIONS ===")
        messages.append(
            f"report.md exists at {report_path} but the task is not in a legitimately-"
            "finished state. This is the bypass pattern: the completeness gate was "
            "skipped or failed, yet a report was written anyway."
        )
        messages.append("")
        messages.extend(violations)
        messages.append("")
        messages.append(
            "Fix: delete report.md, return to Phase 3, run the completeness loop until "
            "`python3 scripts/check_completeness.py <task_dir>` exits 0, set "
            "completeness_checked: true and current_phase: phase_4 in task.md, THEN "
            "regenerate the report through generate_report.py."
        )
        return False, messages

    messages.append(
        "report integrity clean: report.md exists, task is completed/phase_4, "
        "completeness_checked is true, and the completeness gate passes live."
    )
    return True, messages


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report integrity audit — reject reports written without a legitimately-finished gate."
    )
    parser.add_argument("task_dir", help="Task directory containing report.md + task.md")
    args = parser.parse_args()

    # Top-level guard: never crash to a traceback (a crash could be misread as
    # "clean" by a wrapper). Same defensive stance as check_completeness.py.
    try:
        clean, messages = check_report_integrity(Path(args.task_dir))
    except Exception as exc:  # pragma: no cover - defensive
        import traceback
        print("=== REPORT INTEGRITY AUDIT CRASHED (treated as FAIL) ===", file=sys.stderr)
        print(f"error: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1

    stream = sys.stdout if clean else sys.stderr
    for line in messages:
        print(line, file=stream)
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
