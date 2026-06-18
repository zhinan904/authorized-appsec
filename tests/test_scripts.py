#!/usr/bin/env python3
"""Tests for authorized-appsec skill scripts.

Run with: .venv/bin/python -m pytest tests/test_scripts.py -v
Or standalone: python tests/test_scripts.py
"""
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from init_task import next_seq, slugify, write_text, write_json, main as init_task_main
from init_batch import parse_targets, create_target_dir, slugify as batch_slugify, main as init_batch_main
from ensure_structured_outputs import (
    parse_task_md, parse_findings_md, normalize_severity,
    infer_category, infer_confidence, OWASP_CWE_MAP, ensure_summary,
    build_evidence_index, build_attack_graph, normalize_task_paths,
    insert_missing_poc_fields, redact_sensitive as redact_structured_sensitive,
)
from export_to_l3 import eligible_findings
from generate_report import redact_sensitive as redact_report_sensitive
from import_report import import_report, read_html, read_docx, parse_findings as parse_imported_findings
from retrieve_l3 import compute_score, registrable_domain
from auto_l3_hypotheses import generate as generate_l3_hypotheses


class TestInitTask:
    def test_slugify_url(self):
        assert slugify("https://example.com") == "example-com"

    def test_slugify_ip(self):
        assert slugify("192.168.1.1") == "192-168-1-1"

    def test_slugify_strip_protocol(self):
        assert slugify("http://test.local") == "test-local"

    def test_slugify_limit_40(self):
        long = "https://" + "a" * 50 + ".com"
        assert len(slugify(long)) <= 40

    def test_slugify_empty_fallback(self):
        assert slugify("!!!") == "target"

    def test_next_seq_empty_dir(self, tmp_path):
        assert next_seq(tmp_path) == 1

    def test_next_seq_with_existing(self, tmp_path):
        (tmp_path / "PT-20260506-001-example").mkdir()
        assert next_seq(tmp_path) == 2

    def test_next_seq_multiple_existing(self, tmp_path):
        (tmp_path / "PT-20260506-001-example").mkdir()
        (tmp_path / "PT-20260506-002-another").mkdir()
        assert next_seq(tmp_path) == 3

    def test_write_json(self, tmp_path):
        write_json(tmp_path / "test.json", {"key": "value"})
        data = json.loads((tmp_path / "test.json").read_text())
        assert data["key"] == "value"

    def test_init_task_creates_structure(self, tmp_path):
        import argparse
        sys.argv = ["init_task.py", "https://test.example.com", "--output-dir", str(tmp_path)]
        init_task_main()
        dirs = [d.name for d in tmp_path.iterdir() if d.is_dir()]
        assert len(dirs) == 1
        task_dir = tmp_path / dirs[0]
        assert (task_dir / "task.md").exists()
        assert (task_dir / "findings.md").exists()
        assert (task_dir / "summary.json").exists()
        assert (task_dir / "l3-hypotheses.json").exists()
        findings = json.loads((task_dir / "findings.json").read_text())
        assert isinstance(findings, list), f"findings.json should be list, got {type(findings)}"
        task_md = (task_dir / "task.md").read_text()
        assert f"- results_root: {tmp_path}" in task_md
        assert "- task_dir:" in task_md
        hypotheses = json.loads((task_dir / "l3-hypotheses.json").read_text())
        assert hypotheses["status"] == "not_run"
        assert hypotheses["hypotheses"] == []

    def test_init_task_mini_program_note(self, tmp_path):
        sys.argv = ["init_task.py", "/tmp/app.wxapkg", "--type", "mini_program", "--output-dir", str(tmp_path)]
        init_task_main()
        task_dir = next(d for d in tmp_path.iterdir() if d.is_dir())
        task_md = (task_dir / "task.md").read_text()
        summary = json.loads((task_dir / "summary.json").read_text())
        assert summary["target_type"] == "mini_program"
        assert "same-host Web surface" in task_md


class TestBatchScripts:
    def test_init_batch_single_task_mode_creates_documented_shared_layout(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("T-001 https://one.example.com\nT-002 https://two.example.com\n")
        batch_dir = tmp_path / "BATCH-20260531-001"

        old_argv = sys.argv[:]
        try:
            sys.argv = ["init_batch.py", str(batch_dir), str(targets), "--mode", "single-batch-task"]
            init_batch_main()
        finally:
            sys.argv = old_argv

        shared = batch_dir / "shared-task"
        assert (shared / "task.md").exists()
        assert (shared / "findings.md").exists()
        assert (shared / "findings.json").exists()
        assert (shared / "evidence-index.json").exists()
        assert (shared / "raw").is_dir()
        assert (shared / "sessions").is_dir()
        assert (shared / "screenshots").is_dir()
        assert (shared / "slices" / "T-001-https-one-example-com.md").exists()
        assert not (batch_dir / "slices").exists()

    def test_aggregate_single_batch_task_reads_shared_findings(self, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("T-001 https://one.example.com\nT-002 https://two.example.com\n")
        batch_dir = tmp_path / "BATCH-20260531-001"
        old_argv = sys.argv[:]
        try:
            sys.argv = ["init_batch.py", str(batch_dir), str(targets), "--mode", "single-batch-task"]
            init_batch_main()
        finally:
            sys.argv = old_argv

        shared = batch_dir / "shared-task"
        (shared / "findings.json").write_text(json.dumps([
            {
                "finding_id": "F-001",
                "target_id": "T-002",
                "title": "Broken authorization",
                "severity": "high",
                "status": "confirmed",
            }
        ]))
        result = subprocess.run(
            [sys.executable, str(SKILL_ROOT / "scripts" / "aggregate_batch.py"), str(batch_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        aggregate = json.loads((batch_dir / "aggregate.json").read_text())
        assert aggregate["total_targets"] == 2
        assert aggregate["total_findings"] == 1
        assert aggregate["severity_totals"]["high"] == 1
        t2 = next(item for item in aggregate["targets"] if item["target_id"] == "T-002")
        assert t2["finding_counts"]["high"] == 1


class TestProcessControl:
    def test_add_tool_pid_initializes_pid_file(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        result = subprocess.run(
            ["bash", str(SKILL_ROOT / "scripts" / "task-control.sh"), "add-tool-pid", str(task_dir), "--pid", "12345", "--name", "ffuf"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        pid_file = task_dir / ".task-pids.json"
        data = json.loads(pid_file.read_text())
        assert data["tool_pids"][0]["pid"] == "12345"
        assert data["tool_pids"][0]["name"] == "ffuf"

    def test_monitor_uses_pid_argument(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        result = subprocess.run(
            ["bash", str(SKILL_ROOT / "scripts" / "task-control.sh"), "monitor", str(task_dir), "--pid", "12345"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads((task_dir / ".task-pids.json").read_text())
        assert data["main_pid"] == "12345"

    def test_check_task_does_not_match_its_own_detector(self, tmp_path):
        task_dir = tmp_path / "task"
        (task_dir / "raw").mkdir(parents=True)
        (task_dir / "task.md").write_text("- target: example.invalid\n")
        result = subprocess.run(
            ["bash", str(SKILL_ROOT / "scripts" / "check-task.sh"), str(task_dir), "--skip-connectivity"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "Running processes: 0" in result.stdout
        assert "[RUN]" not in result.stdout


class TestEnsureStructuredOutputs:
    def test_parse_task_md(self):
        text = "- task_id: PT-test\n- status: completed\n- current_phase: phase_4"
        result = parse_task_md(text)
        assert result.get("task_id") == "PT-test"
        assert result.get("status") == "completed"
        assert result.get("current_phase") == "phase_4"

    def test_parse_findings_md_bracket_format(self):
        md = "## F-001 — SQL Injection [Critical]\n\n**Description**: Test\n**Affected**: /api\n**Remediation**: 1. Fix\n**Status**: confirmed\n"
        findings = parse_findings_md(md)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["title"] == "SQL Injection"

    def test_parse_findings_md_emdash_format(self):
        md = "## F-002 — XSS Reflected — High\n\n**Description**: Test\n**Affected**: /search\n**Remediation**: 1. Fix\n**Status**: confirmed\n"
        findings = parse_findings_md(md)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["title"] == "XSS Reflected"

    def test_parse_findings_md_source_phase_fallback(self):
        md = "## F-001 — SQL Injection [Critical]\n\n**Description**: Test\n**Affected**: /api\n**Remediation**: 1. Fix\n**Status**: confirmed\n"
        findings = parse_findings_md(md, {"current_phase": "phase_3"})
        assert findings[0]["_source_phase"] == "phase_3"

    def test_normalize_severity(self):
        assert normalize_severity("Critical") == "critical"
        assert normalize_severity("high") == "high"
        assert normalize_severity("Medium") == "medium"
        assert normalize_severity("unknown") == "info"

    def test_infer_category(self):
        assert infer_category("SQL Injection Found") == "sqli"
        assert infer_category("XSS Reflected") == "xss"
        assert infer_category("Default Credentials") == "default_credentials"
        assert infer_category("JWT Token Bypass") == "auth"
        assert infer_category("Broken Authorization on object lookup") == "unauthorized_access"

    def test_owasp_cwe_mapping(self):
        assert OWASP_CWE_MAP["cache_poisoning"][1] == "CWE-444"
        assert OWASP_CWE_MAP["websocket"][1] == "CWE-346"
        assert OWASP_CWE_MAP["deserialization"][1] == "CWE-502"

    def test_ensure_summary_phase_status_override(self, tmp_path):
        (tmp_path / "task.md").write_text("- status: completed\n- current_phase: phase_4\n- target: https://test.com\n")
        (tmp_path / "01-fingerprint.md").write_text("")
        existing = {"phase_status": "in_progress", "current_phase": "phase_0"}
        summary = ensure_summary(tmp_path, {"status": "completed", "current_phase": "phase_4", "target": "https://test.com"}, [], existing)
        assert summary["phase_status"] == "completed"
        assert summary["current_phase"] == "phase_4"

    def test_evidence_refs_alignment(self):
        md = "## F-001 — SQL Injection [Critical]\n\n**Description**: Test\n**Affected**: /api\n**Remediation**: 1. Fix\n**Status**: confirmed\n"
        findings = parse_findings_md(md)
        assert findings[0]["evidence_refs"] == ["E-001"]

    def test_findings_json_is_list(self, tmp_path):
        write_json(tmp_path / "findings.json", [])
        data = json.loads((tmp_path / "findings.json").read_text())
        assert isinstance(data, list)

    def test_tech_stack_force_refresh_on_versions(self, tmp_path):
        (tmp_path / "task.md").write_text("- status: completed\n- target: https://test.com\n")
        (tmp_path / "01-fingerprint.md").write_text("## Tech Stack\n\n| Component | Version |\n|-----------|---------|\n| Apache | 2.4.39 |\n\n## Started\n\n2026-05-06 05:35\n")
        existing = {"tech_stack": ["2.4.39", "5.4.45"]}
        summary = ensure_summary(tmp_path, {"status": "completed", "target": "https://test.com"}, [], existing)
        assert "Apache" in " ".join(summary.get("tech_stack", []))

    def test_parse_poc_redacts_sensitive_values(self):
        md = (
            "## F-001 — Broken Auth [High]\n\n"
            "**Description**: Auth bypass\n"
            "**Affected**: /api/me\n"
            "**PoC**:\n"
            "GET /api/me?token=abc123 HTTP/1.1\n"
            "Authorization: Bearer secret-token\n"
            "Cookie: sid=secret\n"
            "**Evidence**: raw/auth.txt\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert "secret-token" not in finding["poc"]
        assert "sid=secret" not in finding["poc"]
        assert "token=<REDACTED>" in finding["poc"]

    def test_redaction_preserves_non_secret_hex_evidence(self):
        md = (
            "## F-001 — Traceable Error [Low]\n\n"
            "**Description**: Error response exposes trace metadata\n"
            "**Affected**: /api/orders/507f1f77bcf86cd799439011\n"
            "**Evidence**: trace_id=0123456789abcdef01234567 object_id=507f1f77bcf86cd799439011\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert "0123456789abcdef01234567" in finding["_evidence_summary"]
        assert "0123456789abcdef01234567" in finding["poc_boundary"]
        assert "507f1f77bcf86cd799439011" in finding["target"]

    def test_redaction_preserves_markdown_backtick_after_query_value(self):
        md = (
            "## F-001 — Broken Auth [High]\n\n"
            "**Description**: Test\n"
            "**Affected**: `GET /api/me?openId=abc123`\n"
            "**Evidence**: raw/auth.txt\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert "`GET /api/me?openId=<REDACTED>`" in finding["poc_boundary"]

    def test_redaction_masks_passwd_and_key_without_hex_blanket(self):
        text = (
            "GET /api?passwd=s3cr3t&key=apikey123&id=507f1f77bcf86cd799439011\n"
            "{\"passwd\":\"s3cr3t\",\"key\":\"apikey123\",\"object\":\"507f1f77bcf86cd799439011\"}"
        )
        structured = redact_structured_sensitive(text)
        report = redact_report_sensitive(text)
        for value in (structured, report):
            assert "passwd=<REDACTED>" in value
            assert "key=<REDACTED>" in value
            assert '"passwd":"<REDACTED>"' in value
            assert '"key":"<REDACTED>"' in value
            assert "507f1f77bcf86cd799439011" in value

    def test_build_evidence_index_creates_safe_poc_outline(self, tmp_path):
        (tmp_path / "raw").mkdir()
        findings = parse_findings_md(
            "## F-001 — IDOR [High]\n\n"
            "**Description**: Another object is reachable\n"
            "**Affected**: /api/object/123\n"
            "**Evidence**: raw/idor-response.json\n"
            "**Boundary**: Single-object proof only\n"
            "**Status**: confirmed\n"
        )
        evidence = build_evidence_index(tmp_path, findings)
        poc_text = (tmp_path / "raw" / "poc-F-001.txt").read_text()
        assert "Safe Reproduction Outline" in poc_text
        assert "raw/idor-response.json" in poc_text
        assert "Single-object proof only" in poc_text
        assert evidence[0]["raw_ref"]["path"] == "raw/poc-F-001.txt"

    def test_insert_missing_poc_fields_updates_findings_md(self):
        md = (
            "# Findings\n\n"
            "## F-001 — IDOR [High]\n\n"
            "**Description**: Another object is reachable\n\n"
            "**Affected**: `GET /api/object/123`\n\n"
            "**Evidence**: raw/idor-response.json\n\n"
            "**Boundary**: Single-object proof only\n\n"
            "**Status**: confirmed\n"
        )
        findings = parse_findings_md(md)
        updated = insert_missing_poc_fields(md, findings)
        assert "**PoC**:" in updated
        assert "GET /api/object/123" in updated
        assert updated.index("**PoC**:") < updated.index("**Boundary**:")

    def test_insert_missing_poc_fields_refreshes_auto_poc(self):
        md = (
            "# Findings\n\n"
            "## F-001 — Broken Auth [High]\n\n"
            "**Description**: Test\n\n"
            "**Affected**: `GET /api/me?openId=abc123`\n\n"
            "**Evidence**: raw/auth.txt\n\n"
            "**PoC**:\n"
            "No explicit live PoC block was recorded in findings.md. Safe reproduction outline:\n"
            "1. Use the same approved scope and session context recorded for `GET /api/me?openId=<REDACTED>\n\n"
            "**Status**: confirmed\n"
        )
        findings = parse_findings_md(md)
        updated = insert_missing_poc_fields(md, findings)
        assert "Safe PoC / reproduction outline:" in updated
        assert "`GET /api/me?openId=<REDACTED>`" in updated

    def test_insert_missing_poc_fields_updates_suspicious_findings_md(self):
        md = (
            "# Findings\n\n"
            "## F-008 — Architectural anti-pattern [High]\n\n"
            "**Description**: Needs code review\n\n"
            "**Affected**: `GET /api/object/{id}`\n\n"
            "**Evidence**: raw/review.txt\n\n"
            "**Status**: suspicious\n"
        )
        findings = parse_findings_md(md)
        updated = insert_missing_poc_fields(md, findings)
        assert "**PoC**:" in updated

    def test_distillation_candidate_high_auth_true(self):
        md = (
            "## F-001 — Broken Authorization IDOR [High]\n\n"
            "**Description**: Another tenant object is reachable without authorization checks.\n"
            "**Affected**: GET /api/orders/123\n"
            "**Evidence**: raw/idor.txt\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert finding["distillation_candidate"] is True
        assert finding["memory_candidate"] is True
        assert finding["complexity"] in {"complex", "chain"}

    def test_distillation_candidate_medium_missing_headers_false(self):
        md = (
            "## F-001 — Missing Security Headers [Medium]\n\n"
            "**Description**: X-Frame-Options and Content-Security-Policy are missing.\n"
            "**Affected**: /\n"
            "**Evidence**: raw/headers.txt\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert finding["knowledge_candidate"] is True
        assert finding["distillation_candidate"] is False
        assert finding["memory_candidate"] is False

    def test_distillation_candidate_medium_business_logic_chain_true(self):
        md = (
            "## F-001 — Business Logic Payment Bypass [Medium]\n\n"
            "**Description**: Multi-step order workflow allows payment state bypass after replaying signed callback.\n"
            "**Affected**: POST /api/order/callback\n"
            "**Evidence**: raw/payment-chain.txt\n"
            "**Boundary**: Test order only, no real payment or shipment action.\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert finding["distillation_candidate"] is True
        assert finding["chain_value"] is True
        assert finding["complexity"] == "chain"

    def test_distillation_candidate_high_exploitable_version_true(self):
        md = (
            "## F-001 — Version Disclosure With Known CVE [High]\n\n"
            "**Description**: Exposed version has a known CVE with public exploit and reachable admin endpoint.\n"
            "**Affected**: /admin\n"
            "**Evidence**: raw/version.txt\n"
            "**Status**: confirmed\n"
        )
        finding = parse_findings_md(md)[0]
        assert finding["distillation_candidate"] is True

    def test_normalize_task_paths_adds_missing_metadata(self, tmp_path):
        task_dir = tmp_path / "PT-20260530-001-example"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "# Task Meta\n\n"
            "- task_id: PT-20260530-001-example\n"
            "- target: https://example.com\n"
            "- target_type: url\n"
            f"resume: python3 resume.py {task_dir}\n"
        )
        normalize_task_paths(task_dir)
        task_md = (task_dir / "task.md").read_text()
        assert str(task_dir) in task_md
        assert f"- results_root: {tmp_path}" in task_md

    def test_attack_graph_uses_current_task_only(self, tmp_path):
        findings = parse_findings_md(
            "## F-001 — IDOR [High]\n\n"
            "**Description**: Object access confirmed\n"
            "**Affected**: /api/object/123\n"
            "**PoC**: GET /api/object/123\n"
            "**Evidence**: raw/idor-response.json\n"
            "**Status**: confirmed\n"
        )
        (tmp_path / "raw").mkdir()
        evidence = build_evidence_index(tmp_path, findings)
        summary = {
            "task_id": "PT-20260530-001-example",
            "target": "https://current.example.com",
            "tech_stack": ["Jetty"],
        }
        (tmp_path / "01-fingerprint.md").write_text("## Tech Stack\n\n| Component | Value |\n|-----------|-------|\n| App server | Jetty |\n")
        build_attack_graph(tmp_path, summary, findings, evidence)
        graph = (tmp_path / "attack-graph.md").read_text()
        assert "current.example.com" in graph
        assert "F-001" in graph
        assert "www.nsfjq.com" not in graph
        assert "Spring Boot / Nacos" not in graph
        assert "L3 history" in graph

    def test_l3_export_requires_confirmed_eligible_findings(self):
        findings = [
            {"finding_id": "F-001", "severity": "high", "status": "suspicious", "knowledge_candidate": True, "distillation_candidate": True},
            {"finding_id": "F-002", "severity": "low", "status": "confirmed", "knowledge_candidate": True, "distillation_candidate": True},
            {"finding_id": "F-003", "severity": "medium", "status": "confirmed", "knowledge_candidate": False, "distillation_candidate": True},
            {"finding_id": "F-004", "severity": "medium", "status": "confirmed", "knowledge_candidate": True, "distillation_candidate": False},
            {"finding_id": "F-005", "severity": "medium", "status": "confirmed", "knowledge_candidate": True, "distillation_candidate": True},
        ]
        assert [item["finding_id"] for item in eligible_findings(findings)] == ["F-005"]

    def test_export_to_l3_exits_nonzero_without_candidates(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "summary.json").write_text(json.dumps({"task_id": "PT-test"}))
        (task_dir / "findings.json").write_text("[]")
        (task_dir / "evidence-index.json").write_text("[]")
        result = subprocess.run(
            [sys.executable, str(SKILL_ROOT / "scripts" / "export_to_l3.py"), str(task_dir), str(tmp_path / "l3")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
        assert "l3-export-skipped" in result.stderr

    def test_generate_report_reports_l3_skip_as_warning(self, tmp_path):
        old_argv = sys.argv[:]
        try:
            sys.argv = ["init_task.py", "https://test.example.com", "--output-dir", str(tmp_path)]
            init_task_main()
        finally:
            sys.argv = old_argv
        task_dir = next(d for d in tmp_path.iterdir() if d.is_dir())
        result = subprocess.run(
            [sys.executable, str(SKILL_ROOT / "scripts" / "generate_report.py"), str(task_dir), "--export-l3", str(tmp_path / "l3")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "l3-export-warning" in result.stderr
        assert "l3-export: ok" not in result.stdout


class TestImportReport:
    def test_parse_imported_findings_from_markdown(self):
        md = (
            "# SQL Injection\n\n"
            "Severity: High\n\n"
            "Affected: GET /news?id=1\n\n"
            "Description: id parameter is injectable.\n\n"
            "PoC: GET /news?id=1-0\n\n"
            "Remediation: Use parameterized queries.\n"
        )
        findings = parse_imported_findings(md)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"
        assert findings[0]["status"] == "confirmed"
        assert "GET /news" in findings[0]["poc"]

    def test_read_html_converts_report_text(self, tmp_path):
        html = tmp_path / "report.html"
        html.write_text("<html><body><h1>XSS</h1><p>Severity: Medium</p><pre>GET /?q=&lt;script&gt;</pre></body></html>")
        text = read_html(html)
        assert "# XSS" in text
        assert "Severity: Medium" in text
        assert "GET /?q=<script>" in text

    def test_import_markdown_creates_standard_task(self, tmp_path):
        report = tmp_path / "old-report.md"
        report.write_text(
            "# IDOR\n\n"
            "Severity: High\n\n"
            "Affected: GET /api/object/123\n\n"
            "Description: Object access is not authorized.\n\n"
            "PoC: GET /api/object/123\n\n"
            "Evidence: 200 response for another object.\n\n"
            "Remediation: Enforce object authorization.\n"
        )
        out = tmp_path / "results"
        task_dir = import_report(report, target="https://example.com", output_dir=out)
        assert task_dir.name.startswith("IMPORTED-")
        assert (task_dir / "raw" / "imported-original.md").exists()
        assert (task_dir / "raw" / "imported-normalized.md").exists()
        assert (task_dir / "findings.md").read_text().count("**PoC**") == 1
        findings = json.loads((task_dir / "findings.json").read_text())
        assert findings[0]["status"] == "confirmed"
        assert findings[0]["knowledge_candidate"] is False
        assert findings[0]["distillation_candidate"] is False
        summary = json.loads((task_dir / "summary.json").read_text())
        assert summary["knowledge_ready"] is False
        assert summary["distillation_ready"] is False
        assert "manual review" in summary["l3_export_reason"]
        assert (task_dir / "report.md").exists()

    def test_import_without_poc_marks_suspicious(self, tmp_path):
        report = tmp_path / "old-report.md"
        report.write_text("# Missing Headers\n\nSeverity: Medium\n\nAffected: /\n\nDescription: Headers missing.\n")
        task_dir = import_report(report, target="https://example.com", output_dir=tmp_path / "results", generate_report=False)
        findings = json.loads((task_dir / "findings.json").read_text())
        assert findings[0]["status"] == "suspicious"
        assert findings[0]["knowledge_candidate"] is False
        assert findings[0]["distillation_candidate"] is False

    def test_read_minimal_docx(self, tmp_path):
        docx = tmp_path / "report.docx"
        document_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Hardcoded Token</w:t></w:r></w:p>
    <w:p><w:r><w:t>Severity: High</w:t></w:r></w:p>
    <w:p><w:r><w:t>PoC: GET /api?token=secret</w:t></w:r></w:p>
  </w:body>
</w:document>
"""
        with zipfile.ZipFile(docx, "w") as zf:
            zf.writestr("word/document.xml", document_xml)
        text = read_docx(docx)
        assert "# Hardcoded Token" in text
        findings = parse_imported_findings(text)
        assert findings[0]["severity"] == "high"
        assert "token=<REDACTED>" in findings[0]["poc"]


class TestRetrieveL3:
    def test_registrable_domain_handles_multi_label_suffix(self):
        assert registrable_domain("api.example.com.cn") == "example.com.cn"
        assert registrable_domain("admin.example.co.uk") == "example.co.uk"
        assert registrable_domain("sub.example.com") == "example.com"

    def test_compute_score_does_not_match_public_suffix_only(self):
        assert compute_score(
            "Historical finding for unrelated.com.cn",
            {},
            "api.example.com.cn",
            "",
        ) == 0
        assert compute_score(
            "Historical finding for example.com.cn",
            {},
            "api.example.com.cn",
            "",
        ) >= 5

    def test_compute_score_does_not_return_severity_only_match(self):
        assert compute_score(
            "Default admin takeover pattern",
            {"category": "default_credentials", "severity": "critical"},
            "",
            "cors",
        ) == 0


class TestAutoL3Hypotheses:
    def create_l3_fixture(self, tmp_path):
        l3_root = tmp_path / "l3"
        km = l3_root / "internal-knowledge" / "knowledge-mapping"
        entries = km / "entries"
        entries.mkdir(parents=True)
        (entries / "chain.md").write_text(
            "# Recognizing The Same Admin-Platform Risk Class\n\n"
            "## Metadata\n- category: attack_chain_recognition\n\n"
            "Strong signals include /admin-api, code data msg, Vue Vite, user role config token modules.\n"
        )
        (entries / "secret.md").write_text(
            "# Sensitive Config Secret Exposure\n\n"
            "## Metadata\n- category: sensitive_config_exposure\n\n"
            "Configuration APIs expose bucket endpoint access key api secret fields.\n"
        )
        (km / "index.json").write_text(json.dumps({
            "collection": "knowledge-mapping",
            "version": 1,
            "entries": [
                {
                    "id": "chain",
                    "path": "entries/chain.md",
                    "category": "attack_chain_recognition",
                    "severity": "high",
                },
                {
                    "id": "secret",
                    "path": "entries/secret.md",
                    "category": "sensitive_config_exposure",
                    "severity": "critical",
                },
            ],
        }))
        return l3_root

    def test_auto_l3_hypotheses_match_but_do_not_report(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text("- target: https://example.invalid\n")
        (task_dir / "summary.json").write_text("{}")
        (task_dir / "01-fingerprint.md").write_text(
            "Vue Vite Element Plus /admin-api/system/auth/login\n"
            '{"code":0,"data":{},"msg":""}\n'
            "/admin-api/infra/file-config/page bucket endpoint storage\n"
        )
        l3_root = self.create_l3_fixture(tmp_path)
        data = generate_l3_hypotheses(task_dir, l3_root)
        assert data["status"] == "matched"
        categories = {item["category"] for item in data["hypotheses"]}
        assert "attack_chain_recognition" in categories
        assert "sensitive_config_exposure" in categories
        for item in data["hypotheses"]:
            assert item["status"] == "hypothesis_only"
            assert item["reporting_allowed"] is False
            assert item["requires_current_task_validation"] is True

    def test_auto_l3_hypotheses_no_match_without_current_signals(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text("- target: https://example.invalid\n")
        (task_dir / "summary.json").write_text("{}")
        (task_dir / "01-fingerprint.md").write_text("Static landing page only")
        data = generate_l3_hypotheses(task_dir, self.create_l3_fixture(tmp_path))
        assert data["status"] == "not_matched"
        assert data["hypotheses"] == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
