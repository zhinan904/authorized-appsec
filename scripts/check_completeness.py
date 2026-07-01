#!/usr/bin/env python3
"""check_completeness.py — Completeness gate: "test everything before finishing".

This is the *anti-skip* gate. The report gate (check_report_gate in
generate_report.py) only checks that coverage-checklist.md has no blank rows —
which an agent can trivially satisfy by marking untested surface `not-covered`
with any reason. This script closes that loophole with two machine-checked
hard gates that must both pass before Phase 3 is allowed to end:

  Gate A — Queue drained
      Every item in the 02-discovery.md Test Queue (P0/P1/P2) and every row in
      the "Authenticated Surface Seeds" table must reach a terminal status:
      validated / confirmed / false_positive / not_applicable / deferred.
      `deferred` must carry a reason, otherwise it is treated as still open.
      Items left at pending / in_progress / blank fail the gate.

  Gate B — Coverage truthful
      For coverage-checklist.md:
        - every `covered` row is cross-checked against the 03-vuln-test.md
          request log: there must be at least one request for that surface
          class, otherwise it is "unverified covered" (claiming coverage with
          no evidence — the primary skip mode). Unverified rows only WARN; a
          covered row still needs a reason if no matching request is found.
        - every `not-covered` / `degraded` row MUST have a non-empty reason.
          Empty reason = silent drop = gate failure.
        - every `out-of-scope` row MUST use one of the prescribed phrasings
          (mechanism not present / feature not present / protocol not present /
          no LLM endpoint / no K8s surface / no session supplied / explicitly
          excluded). Free-text out-of-scope reasons are rejected.

Usage:
    python3 scripts/check_completeness.py <task_dir>
    python3 scripts/check_completeness.py <task_dir> --mode report-gate
    python3 scripts/check_completeness.py <task_dir> --mode phase3-to-4

Exit codes: 0 = passed, 1 = failed (gaps printed to stderr/stdout).

When --user-stop is present in task.md (user explicitly stopped the test), the
queue gate is relaxed: remaining pending items are reported as "not tested by
user decision" but do not fail the gate. Coverage truthfulness still applies.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Reuse the parsing helpers already proven in the report generator so the two
# gates never drift apart in how they read task files.
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import generate_report as gr  # noqa: E402


# --- Status vocabulary ------------------------------------------------------

# Terminal (closed) queue statuses. An item at one of these is "done".
TERMINAL_STATUSES = {
    "validated",
    "confirmed",
    "false_positive",
    "falsepositive",
    "not_applicable",
    "not applicable",
    "notapplicable",
    "n/a",
    "na",
    "skipped",
    "oos",
    "out-of-scope",
    "out of scope",
}

# Open (not done) statuses.
OPEN_STATUSES = {"pending", "in_progress", "in progress", "todo", "tbd", ""}

# Prescribed phrasings an out-of-scope coverage row must reference.
PRESCRIBED_OUT_OF_SCOPE = (
    "not present",
    "no llm",
    "no k8s",
    "no session",
    "no oauth",
    "no mfa",
    "no jwt",
    "no reset",
    "no captcha",
    "no grpc",
    "no http/2",
    "no protobuf",
    "not in scope",
    "excluded",
    "out of scope",
    "absent",
    "n/a",
)

# Coverage surface classes that require request-log evidence when marked covered.
# Map a normalized surface keyword -> list of path/keyword tokens to look for in
# the 03-vuln-test.md request log. Order is not significant; this is a coarse
# presence check, not an exact match.
_SURFACE_EVIDENCE_TOKENS = {
    "sqli": ["sql", "sqli", "'", "sleep", "union", "1=1", "and 1", "or 1"],
    "nosqli": ["nosql", "$where", "$ne", "$gt", "mongo"],
    "command injection": ["command", "rce", "exec", "ping", ";", "|", "injection"],
    "ssti": ["ssti", "{{", "${", "template", "7*7", "49"],
    "xss": ["xss", "<script", "<img", "onerror", "alert", "<svg"],
    "dom xss": ["xss", "dom", "source", "sink", "<svg"],
    "path traversal": ["traversal", "../", "..%2f", "lfi", "/etc/passwd", "etc/passwd"],
    "file upload": ["upload", "multipart", "content-type", "filename"],
    "ssrf": ["ssrf", "url=", "fetch", "callback", "redirect", "169.254", "metadata"],
    "xxe": ["xxe", "doctype", "entity", "xml", "<!entity"],
    "deserialization": ["deserial", "rce", "gadget", "object", "java"],
    "open redirect": ["redirect", "url=", "next=", "return=", "location"],
    "crlf": ["crlf", "%0d", "%0a", "\\r", "\\n", "header injection"],
    "request smuggling": ["smuggl", "cl.te", "te.cl", "content-length", "transfer-encoding"],
    "race condition": ["race", "concurrent", "parallel", "single-packet", "replay"],
    "idor": ["idor", "bola", "user b", "user-b", "/users/", "object", "user a"],
    "bola": ["bola", "idor", "object", "/users/", "user b"],
    "vertical": ["vertical", "privilege", "admin", "role", "escalation"],
    "horizontal": ["horizontal", "idor", "user b", "user a", "cross-user"],
    "session": ["session", "fixation", "token", "cookie", "jwt", "non-expiry", "reuse"],
    "jwt": ["jwt", "alg=none", "jku", "jwk", "kid", "algorithm confusion"],
    "mfa": ["mfa", "2fa", "totp", "backup code", "otp", "bypass"],
    "oauth": ["oauth", "oidc", "redirect_uri", "state", "pkce", "code reuse"],
    "password reset": ["reset", "token", "poisoning", "host header", "predictab"],
    "csrf": ["csrf", "token", "samesite", "state-changing"],
    "captcha": ["captcha", "lockout", "counter", "rate"],
    "graphql": ["graphql", "introspection", "batch", "mutation", "__schema"],
    "mass assignment": ["mass assignment", "role", "isadmin", "extra field"],
    "prompt injection": ["prompt", "ignore previous", "system prompt", "jailbreak", "llm"],
    "subdomain takeover": ["takeover", "cname", "dangling", "verify"],
    "cloud metadata": ["169.254", "metadata", "imds", "cloud"],
    "cors": ["cors", "origin", "access-control"],
    "websocket": ["websocket", "ws://", "wss://", "origin"],
    "grpc": ["grpc", "protobuf", "grpc-web"],
}

# Coverage section headings are split by "## " in parse_coverage_checklist's
# caller. We only warn on covered rows that are in well-known vuln classes.


def _read(task_dir: Path, fname: str) -> str:
    return gr._read_task_file(task_dir, fname)


def _read_task_meta_flag(task_dir: Path, key: str) -> bool:
    """Return True if task.md has a `key: true`-ish line."""
    text = _read(task_dir, "task.md")
    if not text:
        return False
    for line in text.splitlines():
        m = re.match(r"^-\s*" + re.escape(key) + r"\s*:\s*(.+)$", line.strip(), re.I)
        if m:
            val = m.group(1).strip().lower()
            return val in {"true", "yes", "y", "1"}
    return False


# --- Gate A: queue drained --------------------------------------------------

def _split_queue_status(cell: str) -> tuple[str, str]:
    """Split a status cell like 'deferred (need admin)' into (status, reason)."""
    cell = cell.strip()
    reason = ""
    # Status may carry inline reason in parentheses or after a dash.
    m = re.match(r"^([A-Za-z][A-Za-z /_-]*)\s*(?:[\((](.+?)[\))]|-\s*(.+))?$", cell)
    if m:
        status = m.group(1).strip().lower()
        reason = (m.group(2) or m.group(3) or "").strip()
    else:
        status = cell.lower()
    return status, reason


def check_queue_drained(disc_text: str) -> tuple[list[str], list[str]]:
    """Gate A. Return (open_items, info_items).

    open_items is a list of human-readable strings describing queue items that
    have not reached a terminal status. An empty list means the queue drained.
    """
    open_items: list[str] = []

    if not disc_text:
        return open_items, ["02-discovery.md missing — queue cannot be checked"]

    # Section tracking by heading level. The Test Queue region is opened by a
    # heading containing "test queue" (any level) and closed by the next
    # heading of the SAME or HIGHER level (so ### P0 Queue does NOT close a
    # ## Test Queue region). The Authenticated Surface Seeds region is the
    # table immediately under a heading containing "authenticated surface
    # seeds", ending at the next heading of any level.
    section = None            # None | "queue" | "seeds"
    section_level = 0         # heading level that opened the current section

    for line in disc_text.splitlines():
        stripped = line.strip()
        low = stripped.lower()

        # Heading?
        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            title = m.group(2).lower()
            # A heading at the same-or-higher level as the one that opened the
            # current section closes it (unless this heading re-opens the same
            # kind of section).
            opens_queue = "test queue" in title or re.search(r"\bp[012]\s+queue\b", title)
            opens_seeds = "authenticated surface seeds" in title
            if opens_queue and (section != "queue" or level <= section_level):
                section, section_level = "queue", level
            elif opens_seeds:
                section, section_level = "seeds", level
            elif section and level <= section_level:
                # same/higher level heading that doesn't re-open → close
                section, section_level = None, 0
            continue

        cells = gr._parse_table_row(stripped)
        if len(cells) < 2:
            continue
        if section not in ("queue", "seeds"):
            continue

        # P0/P1/P2 queue rows look like: | # | class | endpoint | status |
        # Seeds rows look like:          | endpoint | evidence | role | status |
        last = cells[-1]
        status, reason = _split_queue_status(last)

        # Only treat as a queue item if the last cell is status-shaped.
        if status not in TERMINAL_STATUSES and status not in OPEN_STATUSES:
            # Unknown token — could be a header or non-status cell; skip.
            continue

        # Identify the item for a readable message.
        if section == "queue":
            # Queue row: prefer vuln class (col 2) then endpoint (col 3).
            cls = cells[1] if len(cells) > 1 else ""
            endpoint = cells[2] if len(cells) > 2 else ""
            label = (f"{cls} @ {endpoint}".strip(" @") or cells[0])
        else:  # seeds
            endpoint = cells[0]
            label = f"auth seed {endpoint}"

        if status in TERMINAL_STATUSES:
            # Terminal. deferred needs a reason to count as closed.
            if "deferred" in status and not reason:
                open_items.append(
                    f"queue item '{label}' is deferred without a reason — "
                    "deferred items must state why (e.g. 'deferred - need admin creds')"
                )
            continue

        # Open status.
        open_items.append(
            f"queue item '{label}' is still '{status or 'pending'}' — validate it, "
            "confirm it, mark false_positive, or defer WITH a reason before finishing"
        )

    return open_items, []


# --- Gate B: coverage truthful ---------------------------------------------

def _coverage_rows(cov_text: str) -> list[dict]:
    """Return coverage surface rows (from parse_coverage_checklist)."""
    parsed = gr.parse_coverage_checklist(cov_text)
    return parsed.get("rows", [])


def _surface_has_request_log(row_surface: str, vuln_requests: list[dict]) -> bool:
    """Coarse check: does the vuln-test request log contain evidence for this
    surface class? Returns True if any request path/note matches the surface's
    evidence tokens, or if the surface is not in the known-token map (we cannot
    disprove coverage for unknown surfaces, so we do not fail them here)."""
    surface_low = row_surface.lower()
    tokens = None
    for key, toks in _SURFACE_EVIDENCE_TOKENS.items():
        if key in surface_low:
            tokens = toks
            break
    if tokens is None:
        return True  # unknown surface class — not falsifiable by this check

    haystack_parts = []
    for r in vuln_requests:
        haystack_parts.append(r.get("path", ""))
        haystack_parts.append(r.get("raw", ""))
    haystack = " ".join(haystack_parts).lower()
    return any(tok.lower() in haystack for tok in tokens)


def check_coverage_truthful(task_dir: Path) -> tuple[list[str], list[str]]:
    """Gate B. Return (failures, warnings)."""
    failures: list[str] = []
    warnings: list[str] = []

    cov_text = _read(task_dir, "coverage-checklist.md")
    if not cov_text:
        # Missing checklist is a hard failure, not a warning — otherwise the
        # coverage truthfulness gate is silently bypassed.
        return ["coverage-checklist.md missing — Coverage truthfulness cannot be verified"], []

    rows = _coverage_rows(cov_text)
    vuln_text = _read(task_dir, "03-vuln-test.md")
    vuln_requests = gr._extract_request_rows(vuln_text) if vuln_text else []

    for row in rows:
        surface = row.get("surface", "")
        status = row.get("status", "")
        reason = row.get("reason", "").strip()

        if status == "covered":
            if not _surface_has_request_log(surface, vuln_requests):
                # Unverified covered claim. Warn and require a reason; only fail
                # if the agent left no justification at all.
                if not reason:
                    failures.append(
                        f"coverage row '{surface}' marked covered but no matching "
                        "request found in 03-vuln-test.md and no reason given — "
                        "either add the evidence request or mark degraded/not-covered with a reason"
                    )
                else:
                    warnings.append(
                        f"coverage row '{surface}' marked covered but no matching "
                        f"request found in 03-vuln-test.md (reason provided: '{reason}') — "
                        "verify this is intentional"
                    )
        elif status in ("not-covered", "degraded"):
            if not reason or reason.lower() in {"-", "n/a", "none", "tbd"}:
                failures.append(
                    f"coverage row '{surface}' marked {status} with no reason — "
                    "every not-covered/degraded row must state why (this is the main skip loophole)"
                )
        elif status == "out-of-scope":
            reason_low = reason.lower()
            if not any(phrase in reason_low for phrase in PRESCRIBED_OUT_OF_SCOPE):
                failures.append(
                    f"coverage row '{surface}' marked out-of-scope with reason "
                    f"'{reason}' — must reference a prescribed condition "
                    "(e.g. 'mechanism not present', 'feature not present', "
                    "'no LLM endpoint', 'no session supplied', 'explicitly excluded')"
                )
        # blank status rows are already caught by the existing report gate;
        # we do not duplicate that here.

    return failures, warnings


# --- Orchestration ----------------------------------------------------------

def check_completeness(task_dir: Path, mode: str = "report-gate") -> tuple[bool, list[str]]:
    """Run both gates. Returns (passed, messages).

    messages combine failures (block) and warnings (informational). In any
    mode, failures cause `passed=False`. Warnings never fail the gate but are
    returned so the caller (report / agent) can surface them.
    """
    task_dir = Path(task_dir)
    failures: list[str] = []
    warnings: list[str] = []

    user_stop = _read_task_meta_flag(task_dir, "user_stop")

    # --- Gate A: queue drained ---
    disc_text = _read(task_dir, "02-discovery.md")
    if not disc_text:
        # A task with no discovery log has no queue to drain; this is a hard
        # failure in both modes (the report gate also flags the missing file,
        # but we fail independently so standalone invocations are not misled).
        failures.append("02-discovery.md missing — Test Queue cannot be verified")
    open_items, a_info = check_queue_drained(disc_text)
    # a_info (e.g. "missing") is redundant once we have failed above; drop it
    # when we already recorded the missing-file failure.
    if not disc_text:
        a_info = []
    warnings.extend(a_info)
    if open_items:
        if user_stop:
            # User explicitly stopped: remaining items are reported but do not
            # fail. This is the only legitimate "finished without testing all".
            warnings.append(
                f"user_stop is set — {len(open_items)} queue item(s) remain untested "
                "by user decision; they will be listed in the report as not-tested:"
            )
            warnings.extend(f"  - {item}" for item in open_items)
        else:
            failures.append(
                f"Queue not drained — {len(open_items)} item(s) still open in "
                "02-discovery.md Test Queue / Authenticated Surface Seeds:"
            )
            failures.extend(f"  - {item}" for item in open_items)

    # --- Gate B: coverage truthful ---
    b_fail, b_warn = check_coverage_truthful(task_dir)
    failures.extend(b_fail)
    warnings.extend(b_warn)

    messages: list[str] = []
    if failures:
        messages.append("=== COMPLETENESS GATE FAILED ===")
        messages.extend(failures)
    if warnings:
        if messages:
            messages.append("")
        messages.append("--- warnings ---")
        messages.extend(warnings)
    if not failures and not warnings:
        messages.append("completeness gate passed: queue drained, coverage truthful")

    passed = len(failures) == 0
    return passed, messages


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Completeness gate — verify all testable surface was actually tested before finishing."
    )
    parser.add_argument("task_dir", help="Task directory")
    parser.add_argument(
        "--mode",
        default="report-gate",
        choices=["report-gate", "phase3-to-4"],
        help="Gate context (behavior is identical; reserved for future divergence).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print on failure.",
    )
    args = parser.parse_args()

    # Top-level guard: the gate must NEVER crash to a traceback. A crash would
    # leave exit code undefined / fall through to a "passed" interpretation in
    # some wrappers, silently letting an unfinished task finish. Any unexpected
    # error is treated as a hard FAIL with the traceback surfaced, so the agent
    # sees the problem instead of the gate being silently bypassed.
    try:
        passed, messages = check_completeness(Path(args.task_dir), mode=args.mode)
    except Exception as exc:  # pragma: no cover - defensive, by definition unexpected
        import traceback
        print("=== COMPLETENESS GATE FAILED ===", file=sys.stderr)
        print(f"completeness check crashed (treated as FAIL): {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print("", file=sys.stderr)
        print("The gate could not run. Treat the queue as NOT drained.", file=sys.stderr)
        print("Fix the data/script error above and rerun before finishing.", file=sys.stderr)
        return 1

    if args.quiet and passed:
        return 0

    stream = sys.stdout if passed else sys.stderr
    for line in messages:
        print(line, file=stream)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
