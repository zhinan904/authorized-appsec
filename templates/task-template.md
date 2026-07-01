# Task Meta

- task_id: PT-{YYYYMMDD}-{SEQ}-example-com
- target: https://example.com
- target_type: url
- preflight_complete: false
- authorization: pending
- scope: pending
- scope_allowlist: example.com
- approved_ports: default-for-target
- intensity: pending
- automation: pending
- credentials: pending
- nuclei_authorized: false
- results_root: {RESULTS_ROOT}
- task_dir: {RESULTS_ROOT}/PT-{YYYYMMDD}-{SEQ}-example-com
- status: in_progress
- current_phase: phase_0
- loop_depth: 0
- last_loop_reason: none
- completeness_checked: false
- user_stop: false
- session_contexts:
  - anonymous: valid
  - user: unavailable
  - admin: unavailable
- started_at: YYYY-MM-DD HH:MM
- updated_at: YYYY-MM-DD HH:MM

## Summary

- preflight:
  - complete: false
  - authorization: pending
  - scope_allowlist: example.com
  - intensity: pending
  - automation: pending
  - credentials: pending
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
- `loop_depth` tracks phase re-entry count: increments when returning to an earlier phase (e.g., Phase 3 finds a new endpoint → back to Phase 1). When `loop_depth` exceeds 3, **notify** the user and ask whether to continue, but do not hard-stop — the completeness loop (see below) legitimately re-enters Phase 3 many times to drain the queue. Record the reason in `last_loop_reason` (e.g., "new endpoint discovered in phase_3", "scope expansion required").
- `completeness_checked`: set to `true` only after `python3 scripts/check_completeness.py <task_dir>` returns exit 0 (queue drained + coverage truthful). Required before Phase 3 → Phase 4. See "Completeness Loop" in SKILL.md.
- `user_stop`: set to `true` only when the user explicitly stops testing (enough / wrap up). This is the sole legitimate way to finish with an unfinished queue; remaining items are reported as "not tested by user decision". Never self-set this to escape an incomplete queue.
- Update this file on every phase switch, new confirmed finding, task pause or resume
- Results for this task stay under `task_dir` unless the user explicitly requests migration.
- Mini Program artifacts: extract backend hosts and confirm same-host Web surface (`/`, `/login`, `/admin`, feature paths) before declaring scope complete.
- Before active probing, set `preflight_complete: true` only after authorization, scope, intensity, automation, and credentials are explicitly decided.
- Every request host in `02-discovery.md` and `03-vuln-test.md` must be present in `scope_allowlist`; free-form `scope` text is not treated as a machine allowlist.
