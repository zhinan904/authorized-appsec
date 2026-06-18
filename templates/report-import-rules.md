# Legacy Report Import Rules

Use these rules when importing historical vulnerability reports from Word, Markdown, HTML, or similar document formats.

## Supported Formats

| Format | Handling |
|--------|----------|
| `.md`, `.markdown`, `.txt` | Read directly as Markdown-like text |
| `.html`, `.htm` | Convert headings, paragraphs, lists, code, and simple tables to Markdown |
| `.docx` | Extract document text and embedded media using OOXML zip/xml parsing |
| `.doc` | Convert through LibreOffice/soffice when available, then parse as `.docx` |

## Import Command

```bash
python3 scripts/import_report.py <report_file> --target <target>
```

Optional:

```bash
python3 scripts/import_report.py <report_file> --target <target> --output-dir <results_root>
python3 scripts/import_report.py <report_file> --target <target> --default-status suspicious
```

## Output Directory

Imported reports create a normal task-like directory:

```text
results/
└── IMPORTED-{YYYYMMDD}-{SEQ}-{slug}/
    ├── task.md
    ├── findings.md
    ├── summary.json
    ├── findings.json
    ├── evidence-index.json
    ├── report.md
    ├── attack-graph.md
    ├── raw/
    │   ├── imported-original.<ext>
    │   ├── imported-normalized.md
    │   ├── imported-assets/
    │   └── poc-F-001.txt
    └── screenshots/
```

## Field Mapping

| Legacy Report Content | Standard Field |
|-----------------------|----------------|
| Vulnerability name / title | Finding title |
| Risk/severity labels | `severity` |
| URL, endpoint, parameter, asset | `Affected` |
| Issue description | `Description` |
| Request packet, payload, reproduction steps | `PoC` |
| Screenshot/response/result text | `Evidence` |
| Remediation/recommendation | `Remediation` |

## Eligibility Rules

Imported reports are not automatically trusted current-target facts.

- Preserve the original report in `raw/imported-original.<ext>`.
- Preserve normalized text in `raw/imported-normalized.md`.
- Mark findings without explicit PoC as `suspicious` unless the importer is explicitly run with `--confirm-without-poc`.
- Do not export imported tasks to L3 until PoC, evidence, and validation boundaries are manually reviewed.
- Review does not require replaying PoCs. Import and distillation are local file-processing steps and must not contact the target unless the user separately authorizes a retest.
- Only mark findings as distillation candidates when they are complex/high-value vulnerabilities or reusable attack chains. Low/info and ordinary missing-header, no-WAF, TRACE/method, banner/version, cookie/TLS, or generic configuration findings should stay out of L3 unless they form part of a confirmed higher-value chain.
- Do not carry secrets, cookies, bearer tokens, or real user identifiers into report-ready PoC text.
- If screenshots are the only evidence, describe the observation and keep the image under `raw/imported-assets/`.

## Review Checklist Before L3

- [ ] Each retained finding has a reproducible PoC or a clear blocked-PoC boundary.
- [ ] Each finding has evidence traceable to `raw/`.
- [ ] Severity matches current classification rules.
- [ ] Duplicate findings across older reports have been merged or excluded.
- [ ] Report-specific assumptions are not promoted into reusable knowledge.
- [ ] At least one retained finding is a confirmed complex/high-value vulnerability or reusable attack chain.
