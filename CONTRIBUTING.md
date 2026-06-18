# Contributing

Contributions should preserve the project's core contract: authorized, evidence-driven web and application security assessment with explicit safety boundaries.

## Ground Rules

- Keep the public workflow non-destructive by default.
- Do not add post-exploitation, persistence, credential dumping, lateral movement, stealth, evasion, malware, or phishing content.
- Do not add real target data, reports, screenshots, credentials, tokens, or raw evidence.
- Keep `SKILL.md`, `commands/`, `templates/`, `payloads/`, and `scripts/` in English.
- Put Chinese documentation in `README.zh-CN.md` or future `docs/zh-CN/` files only.
- Keep scanner usage opt-in where the current policy requires it, especially nuclei and equivalent template scanners.

## Validation

Before opening a change, run:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
bash scripts/check-structure.sh
.venv/bin/python -m pytest tests -q
```

If your change touches generated reports, task initialization, batch behavior, or structured outputs, add or update tests.

## Public Release Boundary

The public repository should not include private extensions or operational data:

- `references/`
- `l3/`
- `results/`
- raw evidence
- screenshots
- HAR/Burp/PCAP files
- real vulnerability reports

If you need to demonstrate behavior, use synthetic targets such as `example.com`, `example.invalid`, or clearly fictional mock data.
