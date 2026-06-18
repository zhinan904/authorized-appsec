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

- [ ] `references/`
- [ ] `l3/`
- [ ] `results/`
- [ ] `.pytest_cache/`
- [ ] `__pycache__/`
- [ ] `*.pyc`
- [ ] `.DS_Store`
- [ ] raw evidence
- [ ] screenshots
- [ ] HAR/Burp/PCAP files
- [ ] real vulnerability reports
- [ ] credentials, cookies, tokens, API keys, and private keys

## Checks

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
bash scripts/check-structure.sh
.venv/bin/python -m pytest tests -q
rg -n -P "\p{Han}" . -g '!README.zh-CN.md' -g '!references/**' -g '!l3/**'
rg -n "AKIA|BEGIN .*PRIVATE KEY|Bearer |Authorization:|password|passwd|secret|token|cookie|session|api[_-]?key|access[_-]?key|private[_-]?key" . -g '!references/**' -g '!l3/**'
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
