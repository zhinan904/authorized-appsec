#!/usr/bin/env python3
"""check_completeness.py — Completeness gate: "test everything before finishing".

This is the *anti-skip* gate. The report gate (check_report_gate in
generate_report.py) only checks that coverage-checklist.md has no blank rows —
which an agent can trivially satisfy by marking untested surface `not-covered`
with any reason. This script closes that loophole with three machine-checked
gates that must all pass before Phase 3 is allowed to end:

  Gate 0 — Queue exists & adequate (anti-skip-by-omission)
      Gate A only checks items *in* the queue, so an agent that never builds a
      Test Queue section has "nothing to drain" and passes trivially. Gate 0
      closes that: 02-discovery.md MUST contain a Test Queue section with at
      least one recognizable queue item (hard fail if missing/empty), and the
      queue SHOULD cover a reasonable fraction of discovered endpoints (warn if
      < 30% — many targets have homogeneous endpoints, so this is advisory).

  Gate A — Queue drained
      Every item in the 02-discovery.md Test Queue (P0/P1/P2) and every row in
      the "Authenticated Surface Seeds" table must reach a terminal status:
      validated / confirmed / false_positive / deferred.
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


def check_queue_drained(disc_text: str) -> tuple[list[str], list[str], int]:
    """Gate A. Return (open_items, info_items, total_count).

    open_items is a list of human-readable strings describing queue items that
    have not reached a terminal status. An empty list means the queue drained.
    total_count is the number of recognized queue/seed items (any status), used
    by Gate 0 to judge whether a queue was built at all.
    """
    open_items: list[str] = []
    total_count = 0

    if not disc_text:
        return open_items, ["02-discovery.md missing — queue cannot be checked"], 0

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
        total_count += 1

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

    return open_items, [], total_count


# --- Gate 0: queue adequacy (anti-skip-by-omission) ------------------------

# Minimum (queue items) / (endpoints discovered) ratio. Below this the queue is
# suspected of being a stub/skeleton built to look complete. WARN only — many
# real targets have large numbers of homogeneous endpoints (e.g. a dozen CRUD
# variants of the same resource), so a hard fail here would over-fire. The hard
# fail is reserved for the case where NO queue was built at all.
MIN_QUEUE_TO_ENDPOINT_RATIO = 0.3


def _queue_section_present(disc_text: str) -> bool:
    """True if a Test Queue section heading exists anywhere in the discovery doc.

    Mirrors the heading predicate used by check_queue_drained so the two never
    disagree on what counts as the queue section.
    """
    for line in (disc_text or "").splitlines():
        m = re.match(r"^(#{1,6})\s+(.*)$", line.strip())
        if m:
            title = m.group(2).lower()
            if "test queue" in title or re.search(r"\bp[012]\s+queue\b", title):
                return True
    return False


def count_endpoints_in_catalog(disc_text: str) -> int:
    """Count endpoint rows inside the 'Endpoints Catalog' section only.

    Unlike build_appendix_api_stats (which scans the whole doc and would also
    count directory-scan hits like ``| /admin | 403 |``), this restricts to the
    Endpoints Catalog region and counts table data rows whose first cell looks
    like an endpoint. Accepts both absolute paths (``/api/users``) and bare
    script names some agents write (``login.php``). Header/separator rows are
    already filtered by gr._parse_table_row.
    """
    if not disc_text:
        return 0
    in_catalog = False
    catalog_level = 0
    count = 0
    for line in disc_text.splitlines():
        m = re.match(r"^(#{1,6})\s+(.*)$", line.strip())
        if m:
            level = len(m.group(1))
            title = m.group(2).lower()
            if "endpoints catalog" in title:
                in_catalog, catalog_level = True, level
            elif in_catalog and level <= catalog_level:
                # same/higher heading closes the catalog region
                in_catalog = False
            continue
        if not in_catalog:
            continue
        cells = gr._parse_table_row(line.strip())
        if not cells:
            continue
        first = cells[0].strip().lower()
        if (
            first.startswith("/")
            or first.startswith("http://")
            or first.startswith("https://")
            # bare script/file names some agents record (login.php, users.json)
            or re.search(r"\.(php|asp|aspx|jsp|jspx|do|action|html|htm|json|xml|cgi)(\?|$|\s)", first)
        ):
            count += 1
    return count


def _count_discovery_methods(disc_text: str) -> tuple[int, list[str]]:
    """Detect which attack-surface discovery methods left evidence in 02-discovery.md.

    Returns (count, names). Used by Gate 0 to warn when only one method was
    used — relying on a single method (typically JS extraction) is the primary
    cause of missed endpoints, because interaction-triggered endpoints are
    invisible to static analysis alone. The signals are deliberately coarse and
    conservative: we look for chapter/section markers each method produces, not
    an exact accounting.

    Method A — static extraction: an Endpoints Catalog with ≥1 endpoint.
    Method B — dictionary brute-force: a non-empty "Directory Scanning" /
               "Content Discovery" / "Fuzzing" section.
    Method C — runtime/business-flow: multi-role session traces in the Request
               Log, OR a non-empty Authenticated Surface Seeds section.
    Method D — historical/associative: a section mentioning robots/sitemap/
               swagger/openapi/.well-known/source-map. (Best-effort; not every
               task records this, so it only adds to the count, never gates.)
    """
    if not disc_text:
        return 0, []
    low = disc_text.lower()
    names: list[str] = []

    # Method A — static extraction (Endpoints Catalog populated).
    if count_endpoints_in_catalog(disc_text) > 0:
        names.append("static extraction (Endpoints Catalog)")

    # Method B — directory/content brute-force section present and non-trivial.
    # Look for the section heading, then check it has at least one data row.
    has_brute = False
    in_section = False
    for line in disc_text.splitlines():
        m = re.match(r"^(#{1,6})\s+(.*)$", line.strip())
        if m:
            title = m.group(2).lower()
            in_section = any(
                kw in title
                for kw in ("directory scanning", "content discovery", "fuzzing", "brute")
            )
            continue
        if in_section:
            cells = gr._parse_table_row(line.strip())
            if cells:  # any table row under the section counts as evidence
                has_brute = True
                break
    if has_brute:
        names.append("directory/content brute-force")

    # Method C — runtime traffic / business-flow traversal: multi-role session
    # traces in the Request Log, or a populated Authenticated Surface Seeds.
    role_tokens = ("anonymous", "session", "user a", "user b", "user-a", "user-b",
                   "merchant", "admin", "low-priv", "high-priv", "tenant")
    role_hits = sum(1 for t in role_tokens if t in low)
    has_surface_seeds = re.search(r"authenticated surface seeds", low) and any(
        gr._parse_table_row(l.strip())
        for l in disc_text.splitlines()
    )
    # Heuristic: ≥2 distinct role tokens, or surface-seeds rows, indicate
    # flows were actually walked rather than a single anonymous crawl.
    if role_hits >= 2 or has_surface_seeds:
        names.append("runtime traffic / business-flow traversal")

    # Method D — historical/associative (additive only, never the deciding method).
    if any(kw in low for kw in ("robots.txt", "sitemap", "swagger", "openapi",
                                  ".well-known", "source map", "source-map", ".js.map")):
        names.append("historical/associative")

    return len(names), names


def check_queue_adequacy(
    disc_text: str, total_queue_items: int
) -> tuple[list[str], list[str]]:
    """Gate 0. Return (failures, warnings).

    The anti-skip gate that Gate A cannot catch on its own: Gate A only checks
    that items *in* the queue drained, so an agent that simply never builds a
    Test Queue section has "nothing to drain" and passes trivially. This gate
    rejects that omission.

    - Hard fail: no Test Queue section heading at all, OR zero recognized queue
      items (Test Queue + Authenticated Surface Seeds combined).
    - Warn (non-blocking): queue covers < MIN_QUEUE_TO_ENDPOINT_RATIO of the
      endpoints discovered — likely a stub/skeleton queue. Many real targets
      have homogeneous endpoints, so this is advisory, not a hard gate.
    """
    failures: list[str] = []
    warnings: list[str] = []

    if not disc_text:
        # The missing-file case is already recorded as a hard failure by the
        # orchestrator; nothing for Gate 0 to add here.
        return failures, warnings

    if not _queue_section_present(disc_text):
        failures.append(
            "Test Queue section missing from 02-discovery.md — no prioritized "
            "queue was built (Phase 1 output incomplete). Gate A has nothing to "
            "drain, which is exactly the skip-by-omission this gate exists to "
            "catch. Build a P0/P1/P2 Test Queue for the discovered endpoints "
            "before finishing."
        )
        # A missing section implies zero items too, but one clear message beats two.
        return failures, warnings

    if total_queue_items == 0:
        failures.append(
            "Test Queue section exists but contains zero recognizable queue "
            "items (no rows with a status in the last column). An empty queue "
            "cannot establish coverage. Populate it with the surfaces you intend "
            "to test or legitimately exclude."
        )
        return failures, warnings

    endpoints = count_endpoints_in_catalog(disc_text)
    if endpoints > 0:
        ratio = total_queue_items / endpoints
        if ratio < MIN_QUEUE_TO_ENDPOINT_RATIO:
            warnings.append(
                f"queue covers {total_queue_items} item(s) but {endpoints} endpoint(s) "
                f"were discovered in the Endpoints Catalog (ratio {ratio:.0%} < "
                f"{MIN_QUEUE_TO_ENDPOINT_RATIO:.0%}) — the queue may be a stub. "
                "Verify major endpoints each have a corresponding test item; this is a "
                "warning, not a block."
            )

    # Discovery-method diversity (anti-single-method). Relying on one discovery
    # method (e.g. JS extraction alone) is the #1 cause of missed endpoints:
    # interaction-triggered endpoints are invisible to static analysis. Warn — do
    # not fail — when fewer than 2 methods left evidence. A genuine static-only
    # site (no flows to walk) may legitimately show 1; the warning is advisory.
    method_count, method_names = _count_discovery_methods(disc_text)
    if method_count < 2:
        found = ", ".join(method_names) if method_names else "none detected"
        warnings.append(
            f"only {method_count} discovery method(s) evident ({found}) — "
            "single-method discovery (typically JS extraction) misses "
            "interaction-triggered endpoints (checkout, refund, password-reset, "
            "etc.) that only appear when a business flow is walked. Add runtime "
            "traffic recording via business-flow traversal and/or directory "
            "brute-force. This is the primary cause of low coverage; warning, not a block."
        )

    return failures, warnings


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
    open_items, a_info, total_queue_items = check_queue_drained(disc_text)
    # a_info (e.g. "missing") is redundant once we have failed above; drop it
    # when we already recorded the missing-file failure.
    if not disc_text:
        a_info = []
    warnings.extend(a_info)

    # --- Gate 0: queue adequacy (anti-skip-by-omission) ---
    # Must run alongside Gate A: Gate A only checks that items *in* the queue
    # drained, so an agent that never built a queue has nothing to drain and
    # would pass trivially. Gate 0 rejects the missing/empty queue itself.
    # Runs after Gate A's scan so it can reuse total_queue_items (one pass).
    g0_fail, g0_warn = check_queue_adequacy(disc_text, total_queue_items)
    failures.extend(g0_fail)
    warnings.extend(g0_warn)

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
