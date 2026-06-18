# Task Meta

- task_id: PT-{YYYYMMDD}-{SEQ}-example-com
- target: https://example.com
- target_type: url
- results_root: {RESULTS_ROOT}
- task_dir: {RESULTS_ROOT}/PT-{YYYYMMDD}-{SEQ}-example-com
- status: in_progress
- current_phase: phase_0
- loop_depth: 0
- last_loop_reason: none
- session_contexts:
  - anonymous: valid
  - user: unavailable
  - admin: unavailable
- started_at: YYYY-MM-DD HH:MM
- updated_at: YYYY-MM-DD HH:MM

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

- `current_phase` values: `phase_0` / `phase_1` / `phase_2` / `phase_3` / `phase_4` / `phase_5` (single-task) or `batch_0` through `batch_7` (batch workflow)
- `status` values: `in_progress` / `paused` / `completed` / `stopped` / `example`
- `loop_depth` tracks phase re-entry count: increments when returning to an earlier phase (e.g., Phase 3 finds a new endpoint → back to Phase 1). If `loop_depth` exceeds 3, pause and ask user whether to continue or close the task. Record the reason in `last_loop_reason` (e.g., "new endpoint discovered in phase_3", "scope expansion required").
- Update this file on every phase switch, new confirmed finding, task pause or resume
- Results for this task stay under `task_dir` unless the user explicitly requests migration.
- Mini Program artifacts: extract backend hosts and confirm same-host Web surface (`/`, `/login`, `/admin`, feature paths) before declaring scope complete.
