# Deployment Guide

Practical notes for installing and running this skill inside a Kali Linux (or equivalent security-testing) VM. Covers the three issues most likely to bite on a fresh install: skill registration, read-only package directory, and tool gaps.

## 1. Register the skill so the agent can auto-trigger it

The skill is a plain directory; copying it somewhere is not enough for an agent runtime (e.g. Codex) to discover and auto-invoke it. Install it into the agent's skill directory:

```bash
# Codex CLI skill path on Kali (root user)
sudo mkdir -p /root/.codex/skills
sudo cp -r /path/to/authorized-appsec /root/.codex/skills/authorized-appsec

# Verify the agent sees it — SKILL.md frontmatter (name/description) is what makes it triggerable
ls /root/.codex/skills/authorized-appsec/SKILL.md
```

If the skill is only sitting in a working directory (e.g. `/root/authorized-appsec`) and is not under the agent's skill path, the agent will not auto-trigger it. You would have to point the agent at the directory manually, which defeats the opt-in trigger model. Installing into the skill path is the expected setup.

## 2. Read-only package directory breaks smoke-test

If the package directory is owned by `nobody:nogroup` or otherwise read-only (common after certain copy/deploy methods), `python3 -m py_compile` fails to write `__pycache__/` and `smoke-test.sh` may report false syntax errors.

Two fixes:

```bash
# Option A (recommended): make the package owned by the running user
sudo chown -R "$(id -u):$(id -g)" /root/.codex/skills/authorized-appsec

# Option B: redirect pycache out of the package dir entirely
export PYTHONPYCACHEPREFIX=/tmp/appsec-pycache
bash scripts/smoke-test.sh
```

`smoke-test.sh` has been updated to detect permission errors and fall back to `ast.parse` (a write-free parse), so it no longer reports a permission failure as "syntax error". But Option A is still cleaner because it lets every script write normally.

## 3. Tool gaps after capability discovery

Run discovery first and read the output:

```bash
./scripts/discover-capabilities.sh capabilities.json
```

On a default Kali install the common Web testing tools are present, but these capabilities often report 0 available tools:

| Capability | Typical missing tools | Effect | Action |
|------------|----------------------|--------|--------|
| `oob-callback` | `interactsh-client`, `dnslog-client`, `ceye` | Cannot confirm blind/OOB vulns (blind SSRF, blind XXE, blind SQLi) | Install `interactsh`: `go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| `grpc-client` | `grpcurl`, `grpcui`, `ghz` | Cannot test gRPC endpoints | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` |
| `k8s-client` | `kubectl`, `k9s` | Cannot test Kubernetes API surfaces | `curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"` |

Per the Missing-tool degradation rule in `SKILL.md`: when a capability has 0 tools, degrade to passive extraction and mark it `degraded` in the coverage checklist — do **not** hand-roll bulk manual requests as a substitute.

## 4. macOS AppleDouble files (`._*`)

If the package was unpacked from an archive created on macOS, you may find `._*` files (AppleDouble resource forks). They inflate file counts and confuse checks. Remove them on Linux:

```bash
find /root/.codex/skills/authorized-appsec -name '._*' -delete
find /root/.codex/skills/authorized-appsec -name '.DS_Store' -delete
```

The check scripts and packaging script now exclude `._*`, so leftover files will not affect counts or ship in a built archive — but deleting them keeps the tree clean.

## Post-install verification

```bash
cd /root/.codex/skills/authorized-appsec
bash scripts/check-structure.sh          # structure + payload counts
bash scripts/smoke-test.sh               # syntax + unit tests
./scripts/discover-capabilities.sh capabilities.json   # tool inventory
```

All three should pass cleanly on a writable, owned package directory with `jq` installed (`sudo apt install jq` if missing).
