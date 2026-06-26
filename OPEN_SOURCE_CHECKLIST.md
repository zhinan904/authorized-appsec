# Open Source Release Checklist

Use this checklist before publishing the public repository.

## Required Files

- [x] `LICENSE` selected and added by the maintainer.
- [x] `README.md`
- [x] `README.zh-CN.md`
- [x] `SECURITY.md`
- [x] `CONTRIBUTING.md`
- [x] `CHANGELOG.md`
- [x] `.gitignore`

## Exclude From Public Release

Every row below must be absent from the published repository or public archive. Local source workspaces may contain private extensions such as `references/` and `l3/`; `scripts/build-public-package.sh` excludes them from the default public build. Re-run the Checks before each release.

| Item | Excluded via | Status |
|------|--------------|--------|
| `references/` | public build excludes it; private extension only | [x] absent from public archive |
| `l3/` | public build excludes it; local private knowledge only | [x] absent from public archive |
| `results/` | `.gitignore` (task output kept outside the package) | [x] absent |
| `.pytest_cache/` | `.gitignore` | [x] absent from repo (local only) |
| `__pycache__/` | `.gitignore` | [x] absent from repo (local only) |
| `*.pyc` | `.gitignore` | [x] absent from repo (local only) |
| `.DS_Store` | `.gitignore` | [x] absent from repo (local only) |
| raw evidence | kept under task `raw/`, never in the package | [x] absent |
| screenshots | kept under task `screenshots/`, never in the package | [x] absent |
| HAR/Burp/PCAP files | `.gitignore` (`*.har`, `*.burp`, `*.pcap`, `*.pcapng`) | [x] absent |
| real vulnerability reports | not tracked; imported into local tasks only | [x] absent |
| credentials, cookies, tokens, API keys, private keys | never committed; verified by secret scan below | [x] none found |

## Checks

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
bash scripts/check-structure.sh
.venv/bin/python -m pytest tests -q
# Non-ASCII / CJK detection — portable across BSD grep (macOS) and GNU grep (Linux).
# Prefer rg when available; fall back to grep -P (GNU) / LC_ALL=C grep for ASCII range.
if command -v rg >/dev/null 2>&1; then
  rg -n --pcre2 "\p{Han}" . -g '!README.zh-CN.md' -g '!references/**' -g '!l3/**' || true
else
  LC_ALL=C grep -rnP "[\x{4e00}-\x{9fff}]" . --include='*.md' --exclude='README.zh-CN.md' || true
fi
# Secret / sensitive-token scan
rg -n "AKIA|BEGIN .*PRIVATE KEY|Bearer |Authorization:|password|passwd|secret|token|cookie|session|api[_-]?key|access[_-]?key|private[_-]?key" . -g '!references/**' -g '!l3/**' || true
# Leftover local artifacts that should not be committed
find . -name '.DS_Store' -o -name '__pycache__' -o -name '*.pyc' -o -name '.pytest_cache'
```

## Build Public Archive

```bash
bash scripts/build-public-package.sh
tar -tzf dist/authorized-appsec-skill-*.tar.gz | rg "references/|l3/|__pycache__|\\.pyc|\\.pytest_cache|raw/|screenshots/|\\.har|\\.pcap|\\.burp|\\.db"
```

The archive-content scan should return no output.

Expected notes:

- `README.md` may link to `README.zh-CN.md`.
- Security keyword scans may flag intentional examples and payload guidance; review findings manually.
- Apache License 2.0 is included in `LICENSE`.
