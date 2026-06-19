# Changelog

## 2.21.0 - 2026-06-18

- Added Apache License 2.0 for public release.
- Converted public skill content to English canonical text.
- Clarified that private deep references and L3 knowledge are excluded from the public release.
- Tightened open-source publishing boundaries for `references/`, `l3/`, task results, raw evidence, and screenshots.
- Kept nuclei and equivalent template scanners opt-in only.
- Preserved evidence-driven reporting, coverage-gap tracking, and L3 hypothesis gating.
- Engineering-consistency polish (no workflow or safety-boundary changes):
  - Synchronized drifted version stamps in `commands/` and `templates/` (`capabilities.md`, `recon.md`, `source-code-review.md`, `threat-modeling.md`, `stack-mapping.md`, `severity-classification.md`) to 2.21.0.
  - Replaced the `rg -P "\p{Han}"` scan in `OPEN_SOURCE_CHECKLIST.md` with a portable BSD/GNU grep fallback; reworked the exclude table into a verified-status table.
  - Removed redundant `l3/experience/` and `l3/internal-knowledge/` lines from `.gitignore` (already covered by `l3/`).
  - Tightened `agents/openai.yaml` URL trigger so a bare "test <url>" no longer auto-invokes the skill without a security context word.
  - Expanded the `capabilities.md` registry-format example to document `binary_paths`, `selected_path`, `requires_explicit_approval`, and `nuclei_templates` fields actually emitted by `discover-capabilities.sh`.
