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
from generate_report import (
    redact_sensitive as redact_report_sensitive,
    _count_request_log_rows,
    _count_vuln_test_entries,
    parse_coverage_checklist,
    build_coverage_gaps_section,
    check_report_gate,
    fid_to_vid_map, severity_cn, build_findings_table, build_findings_details,
    build_recommendations, build_asset_profile, redact_response,
    build_test_process, build_attack_chains, build_appendix_api_stats,
    build_appendix_waf, build_appendix_test_limits, check_report_redaction,
)
from import_report import import_report, read_html, read_docx, parse_findings as parse_imported_findings
from retrieve_l3 import compute_score, registrable_domain
from auto_l3_hypotheses import generate as generate_l3_hypotheses
from request_guard import main as request_guard_main
import request_guard


class TestReportFormatZh:
    """Tests for the customer-facing Chinese report format (V-XX, asset
    profile, inline evidence with redaction). Locks down the format alignment
    with the approved company report template.
    """

    def test_fid_to_vid_orders_by_severity_desc(self):
        findings = [
            {"finding_id": "F-001", "severity": "low", "status": "confirmed"},
            {"finding_id": "F-002", "severity": "critical", "status": "confirmed"},
            {"finding_id": "F-003", "severity": "high", "status": "confirmed"},
        ]
        vid = fid_to_vid_map(findings)
        assert vid["F-002"] == "V-01"
        assert vid["F-003"] == "V-02"
        assert vid["F-001"] == "V-03"

    def test_fid_to_vid_excludes_false_positives(self):
        findings = [
            {"finding_id": "F-001", "severity": "critical", "status": "false_positive"},
            {"finding_id": "F-002", "severity": "low", "status": "confirmed"},
        ]
        vid = fid_to_vid_map(findings)
        assert "F-001" not in vid
        assert vid["F-002"] == "V-01"

    def test_findings_table_uses_vid_and_chinese(self):
        findings = [{"finding_id": "F-001", "severity": "high", "status": "confirmed", "title": "SQL注入"}]
        table = build_findings_table(findings, cvss_scores={"F-001": 7.5})
        assert "V-01" in table
        assert "F-001" not in table
        assert "高危" in table
        assert "7.5" in table
        assert "已确认" in table

    def test_redact_response_masks_long_hex(self):
        text = '"DYNAMIC_PASSWORD_SESSION_KEK": "0fe666c3646d468eae6f7bd2052056dc"'
        out = redact_response(text)
        assert "0fe666c3646d468eae6f7bd2052056dc" not in out
        assert "***REDACTED***" in out

    def test_redact_response_masks_set_cookie_value_keeps_name(self):
        text = "Set-Cookie: KAPTCHA_SESSION_KEY=962619aec0c94c878d9cd9f3e016d41f; Path=/"
        out = redact_response(text)
        assert "KAPTCHA_SESSION_KEY" in out
        assert "962619aec0c94c878d9cd9f3e016d41f" not in out

    def test_redact_response_preserves_test_phone(self):
        text = "curl 'https://x.com/api?mobile=13800138000&type=login'"
        out = redact_response(text)
        assert "13800138000" in out

    def test_findings_details_embeds_redacted_evidence(self):
        findings_md = (
            "# Findings\n\n## F-001 — SQL注入 [high]\n\n"
            "**Status**: confirmed\n"
            "**Description**: union-based injection\n"
            "**Affected**: /api?id=1\n"
            "**Evidence**:\n"
            "```bash\ncurl 'https://x.com/api?id=1'\n```\n"
            "```http\nSet-Cookie: SESS=ab1234567890abcdef1234567890abcd\n```\n"
            "**Remediation**:\n1. Use parameterized queries\n"
        )
        findings = [{"finding_id": "F-001", "severity": "high", "status": "confirmed", "title": "SQL注入"}]
        from generate_report import parse_findings_markdown
        parsed = parse_findings_markdown(findings_md)
        details = build_findings_details(findings, parsed, findings_md)
        assert "### V-01: SQL注入" in details
        assert "内部编号 F-001" in details
        assert "证据(发包验证)" in details
        assert "ab1234567890abcdef1234567890abcd" not in details
        assert "***REDACTED***" in details

    def test_findings_details_skips_auto_poc_outline(self):
        findings_md = (
            "# Findings\n\n## F-001 — XSS [medium]\n\n"
            "**Status**: confirmed\n**Description**: x\n**Affected**: /\n"
            "**PoC**:\nSafe PoC / reproduction outline:\n1. do x\n"
        )
        findings = [{"finding_id": "F-001", "severity": "medium", "status": "confirmed", "title": "XSS"}]
        from generate_report import parse_findings_markdown
        parsed = parse_findings_markdown(findings_md)
        details = build_findings_details(findings, parsed, findings_md)
        assert "Safe PoC" not in details
        assert "reproduction outline" not in details

    def test_asset_profile_has_all_8_sections(self):
        summary = {"target": "https://x.com", "deployment": {"port": "443"}}
        profile = build_asset_profile(summary, "# Fingerprint\n")
        for n in range(1, 9):
            assert f"### 2.{n}" in profile
        assert "_待补充_" in profile

    def test_recommendations_tiered_by_severity(self):
        findings = [
            {"finding_id": "F-001", "severity": "critical", "status": "confirmed",
             "title": "RCE", "recommended_next_action": "patch now"},
            {"finding_id": "F-002", "severity": "low", "status": "confirmed",
             "title": "Header", "recommended_next_action": "add header"},
        ]
        recs = build_recommendations({}, findings)
        assert "高优先级 (14天内)" in recs
        assert "中优先级 (30天内)" in recs
        assert "持续改进" in recs
        assert "V-01" in recs and "V-02" in recs

    def test_test_process_renders_coverage_rows(self):
        md = (
            "# Checklist\n\n## Unauthenticated Vulnerability Surface\n\n"
            "| Class | Status | Evidence / Reason |\n|---|---|---|\n"
            "| SQLi | covered | union-based confirmed |\n"
            "| SSRF | not-covered | no url-fetch endpoint found |\n"
            "| XSS | degraded | WAF blocked payloads |\n"
        )
        out = build_test_process(md, "")
        # A.N numbering style
        assert "### A.1" in out
        assert "#### A.1.1" in out
        # Result phrases (covered/degraded/not-covered)
        assert "已覆盖" in out or "union-based confirmed" in out
        assert "未充分测试" in out
        assert "受限（降级）" in out

    def test_test_process_skips_scope_adherence(self):
        md = (
            "# Checklist\n\n## Unauthenticated Vulnerability Surface\n\n"
            "| Class | Status | Evidence / Reason |\n|---|---|---|\n"
            "| SQLi | covered | confirmed |\n\n"
            "## Scope Adherence (mandatory before report done)\n\n"
            "| Check | Result | Evidence |\n|---|---|---|\n"
            "| All hosts in scope | pass | ok |\n"
        )
        out = build_test_process(md, "")
        assert "Scope Adherence" not in out
        assert "All hosts in scope" not in out

    def test_attack_chains_maps_fid_to_vid(self):
        chain_md = (
            "### Chain 1: SQLi → Credential Leak\n\n"
            "**Prerequisites**:\n- F-001 SQL Injection confirmed\n\n"
            "**Risk Statement**:\nSQLi can leak creds.\n"
        )
        out = build_attack_chains(chain_md, {"F-001": "V-01"})
        assert "### AP-001" in out
        assert "V-01 (F-001)" in out

    def test_attack_chains_none_documented(self):
        out = build_attack_chains("", {})
        assert "未发现可串联的攻击链" in out

    def test_check_report_redaction_catches_leaked_hex(self):
        leaked = "token: aabbccdd11223344aabbccdd11223344"
        assert len(check_report_redaction(leaked)) > 0

    def test_check_report_redaction_passes_clean(self):
        assert check_report_redaction("token: ***REDACTED***") == []

    def test_generate_report_produces_chinese_structure(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "raw").mkdir()
        (task_dir / "summary.json").write_text(json.dumps({
            "task_id": "PT-001", "target": "https://x.com",
            "phase_status": "completed", "started_at": "2026-01-01",
        }))
        (task_dir / "evidence-index.json").write_text("[]")
        (task_dir / "findings.json").write_text("[]")
        (task_dir / "findings.md").write_text("# Findings\n\n_No confirmed findings yet._\n")
        (task_dir / "01-fingerprint.md").write_text("")
        result = subprocess.run(
            [sys.executable, str(SKILL_ROOT / "scripts" / "generate_report.py"), str(task_dir),
             "--skip-gate", "--gate-override-reason", "unit test"],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        report = (task_dir / "report.md").read_text()
        for sec in ["一、漏洞汇总", "二、被测系统资产画像", "三、漏洞详情",
                     "四、测试过程", "五、攻击链", "六、安全加固建议"]:
            assert sec in report
        for app in ["附录 A", "附录 B", "附录 C", "附录 D"]:
            assert app in report


class TestInitTask:
    def test_slugify_url(self):
        assert slugify("https://example.com") == "example-com"

    def test_slugify_ip(self):
        assert slugify("192.0.2.1") == "192-0-2-1"

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
        assert "- preflight_complete: false" in task_md
        assert "- authorization: pending" in task_md
        assert "- scope_allowlist: test.example.com" in task_md
        hypotheses = json.loads((task_dir / "l3-hypotheses.json").read_text())
        assert hypotheses["status"] == "not_run"
        assert hypotheses["hypotheses"] == []

    def test_init_task_records_completed_preflight(self, tmp_path):
        old_argv = sys.argv[:]
        try:
            sys.argv = [
                "init_task.py",
                "https://test.example.com",
                "--output-dir",
                str(tmp_path),
                "--authorized",
                "--scope",
                "https://test.example.com only",
                "--scope-allowlist",
                "test.example.com",
                "--intensity",
                "gentle",
                "--automation",
                "fingerprinting,http-probing",
                "--credentials",
                "none",
            ]
            init_task_main()
        finally:
            sys.argv = old_argv
        task_dir = next(d for d in tmp_path.iterdir() if d.is_dir())
        task_md = (task_dir / "task.md").read_text()
        summary = json.loads((task_dir / "summary.json").read_text())
        assert "- preflight_complete: true" in task_md
        assert "- authorization: confirmed" in task_md
        assert summary["preflight"]["complete"] is True
        assert summary["preflight"]["scope_allowlist"] == ["test.example.com"]

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


class TestRequestGuard:
    def write_task(
        self,
        task_dir,
        port,
        allowlist="127.0.0.1",
        complete=True,
        target_host="127.0.0.1",
        approved_ports=None,
        include_approved_ports=True,
    ):
        task_dir.mkdir()
        task_dir.joinpath("raw").mkdir()
        approved_ports = str(port) if approved_ports is None else approved_ports
        ports_line = f"- approved_ports: {approved_ports}\n" if include_approved_ports else ""
        task_dir.joinpath("task.md").write_text(
            f"- target: http://{target_host}:{port}\n"
            f"- preflight_complete: {'true' if complete else 'false'}\n"
            "- authorization: confirmed\n"
            "- scope: localhost fixture only\n"
            f"- scope_allowlist: {allowlist}\n"
            f"{ports_line}"
            "- intensity: gentle\n"
            "- automation: guarded-request\n"
            "- credentials: none\n"
        )

    def fake_response(self, monkeypatch):
        def fake_request_once(parsed, path, method, headers, body, timeout, insecure):
            payload = (body or b"").decode("utf-8", errors="replace")
            body_text = f"ok {path} {payload}".encode()
            return {
                "status": 200,
                "reason": "OK",
                "headers": [("Content-Type", "text/plain"), ("Set-Cookie", "sid=secret")],
                "body": body_text,
                "truncated": False,
            }
        monkeypatch.setattr(request_guard, "request_once", fake_request_once)

    def test_request_guard_logs_discovery_request_and_raw_evidence(self, tmp_path, monkeypatch):
        self.fake_response(monkeypatch)
        port = 8080
        task_dir = tmp_path / "task"
        self.write_task(task_dir, port)
        rc = request_guard_main([
            str(task_dir),
            f"http://127.0.0.1:{port}/login?token=secret",
            "--phase",
            "discovery",
            "--json-output",
        ])
        assert rc == 0
        discovery = (task_dir / "02-discovery.md").read_text()
        assert "| GET | 127.0.0.1:8080 | /login?token=<REDACTED> | 200 | yes | request_guard |" in discovery
        assert "token=secret" not in discovery
        raw_files = list((task_dir / "raw").glob("guarded-discovery-*.txt"))
        assert len(raw_files) == 1
        raw = raw_files[0].read_text()
        assert "token=<REDACTED>" in raw
        assert "Set-Cookie: <REDACTED>" in raw
        assert "ok /login?token=<REDACTED>" in raw

    def test_request_guard_logs_phase3_post_when_marked_idempotent(self, tmp_path, monkeypatch):
        self.fake_response(monkeypatch)
        port = 8081
        task_dir = tmp_path / "task"
        self.write_task(task_dir, port)
        rc = request_guard_main([
            str(task_dir),
            f"http://127.0.0.1:{port}/api/search",
            "--phase",
            "3",
            "--method",
            "POST",
            "--idempotent-post",
            "--body",
            '{"q":"appsec-test"}',
        ])
        assert rc == 0
        vuln = (task_dir / "03-vuln-test.md").read_text()
        assert "## Guarded Request Log" in vuln
        assert "| POST | 127.0.0.1:8081 | /api/search | 200 | yes | request_guard |" in vuln
        raw_files = list((task_dir / "raw").glob("guarded-vuln-*.txt"))
        assert raw_files
        assert "## Request Body" in raw_files[0].read_text()
        assert '{"q":"appsec-test"}' in raw_files[0].read_text()

    def test_request_guard_blocks_incomplete_preflight_before_request(self, tmp_path, monkeypatch):
        called = {"value": False}
        monkeypatch.setattr(request_guard, "request_once", lambda *a, **k: called.update(value=True))
        port = 8082
        task_dir = tmp_path / "task"
        self.write_task(task_dir, port, complete=False)
        try:
            request_guard_main([str(task_dir), f"http://127.0.0.1:{port}/", "--phase", "discovery"])
        except SystemExit as exc:
            assert "preflight incomplete" in str(exc)
        else:
            raise AssertionError("request_guard should have blocked incomplete preflight")
        assert called["value"] is False
        assert not (task_dir / "02-discovery.md").exists()

    def test_request_guard_blocks_host_outside_allowlist(self, tmp_path, monkeypatch):
        called = {"value": False}
        monkeypatch.setattr(request_guard, "request_once", lambda *a, **k: called.update(value=True))
        port = 8083
        task_dir = tmp_path / "task"
        self.write_task(task_dir, port, allowlist="example.com", target_host="example.com")
        try:
            request_guard_main([str(task_dir), f"http://127.0.0.1:{port}/", "--phase", "discovery"])
        except SystemExit as exc:
            assert "scope violation blocked" in str(exc)
        else:
            raise AssertionError("request_guard should have blocked out-of-scope host")
        assert called["value"] is False
        assert not (task_dir / "02-discovery.md").exists()

    def test_request_guard_blocks_out_of_scope_host_header(self, tmp_path, monkeypatch):
        called = {"value": False}
        monkeypatch.setattr(request_guard, "request_once", lambda *a, **k: called.update(value=True))
        port = 8088
        task_dir = tmp_path / "task"
        self.write_task(task_dir, port)
        try:
            request_guard_main([
                str(task_dir),
                f"http://127.0.0.1:{port}/",
                "--phase",
                "discovery",
                "--header",
                "Host: evil.example",
            ])
        except SystemExit as exc:
            assert "header 'Host' host 'evil.example' not in scope_allowlist" in str(exc)
        else:
            raise AssertionError("request_guard should have blocked out-of-scope Host header")
        assert called["value"] is False
        assert not (task_dir / "02-discovery.md").exists()

    def test_request_guard_default_for_target_blocks_other_ports(self, tmp_path, monkeypatch):
        called = {"value": False}
        monkeypatch.setattr(request_guard, "request_once", lambda *a, **k: called.update(value=True))
        task_dir = tmp_path / "task"
        self.write_task(task_dir, 8084, approved_ports="default-for-target")
        try:
            request_guard_main([str(task_dir), "http://127.0.0.1:8085/", "--phase", "discovery"])
        except SystemExit as exc:
            assert "not in approved_ports [8084]" in str(exc)
        else:
            raise AssertionError("request_guard should have blocked non-target default port")
        assert called["value"] is False
        assert not (task_dir / "02-discovery.md").exists()

    def test_request_guard_missing_approved_ports_defaults_to_target_port(self, tmp_path, monkeypatch):
        called = {"value": False}
        monkeypatch.setattr(request_guard, "request_once", lambda *a, **k: called.update(value=True))
        task_dir = tmp_path / "task"
        self.write_task(task_dir, 8086, include_approved_ports=False)
        try:
            request_guard_main([str(task_dir), "http://127.0.0.1:8087/", "--phase", "discovery"])
        except SystemExit as exc:
            assert "not in approved_ports [8086]" in str(exc)
        else:
            raise AssertionError("request_guard should have defaulted missing approved_ports to target port")
        assert called["value"] is False
        assert not (task_dir / "02-discovery.md").exists()

    def test_request_guard_blocks_post_without_idempotent_marker(self, tmp_path, monkeypatch):
        called = {"value": False}
        monkeypatch.setattr(request_guard, "request_once", lambda *a, **k: called.update(value=True))
        port = 8084
        task_dir = tmp_path / "task"
        self.write_task(task_dir, port)
        try:
            request_guard_main([str(task_dir), f"http://127.0.0.1:{port}/api", "--phase", "3", "--method", "POST"])
        except SystemExit as exc:
            assert "blocked by default" in str(exc)
        else:
            raise AssertionError("request_guard should have blocked POST by default")
        assert called["value"] is False
        assert not (task_dir / "03-vuln-test.md").exists()


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
            [
                sys.executable,
                str(SKILL_ROOT / "scripts" / "generate_report.py"),
                str(task_dir),
                "--export-l3",
                str(tmp_path / "l3"),
                "--skip-gate",
                "--gate-override-reason",
                "unit-test legacy fixture",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "l3-export-warning" in result.stderr
        assert "l3-export: ok" not in result.stdout
        summary = json.loads((task_dir / "summary.json").read_text())
        assert summary["report_gate_override"] is True
        assert summary["report_gate_override_reason"] == "unit-test legacy fixture"

    def test_generate_report_skip_gate_requires_reason(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text("- target: https://example.com\n")
        (task_dir / "summary.json").write_text(json.dumps({"target": "https://example.com"}))
        (task_dir / "findings.json").write_text("[]")
        (task_dir / "evidence-index.json").write_text("[]")
        result = subprocess.run(
            [sys.executable, str(SKILL_ROOT / "scripts" / "generate_report.py"), str(task_dir), "--skip-gate"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
        assert "requires --gate-override-reason" in result.stderr


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


class TestReportGateParsing:
    """Regression tests for the report-gate deep checks and coverage parsing."""

    # --- _count_request_log_rows: edge-case paths must not be mis-rejected ---

    def test_request_log_counts_root_path(self):
        """Bare '/' must count as a valid request path (was mis-rejected by old regex)."""
        md = "## Request Log\n| GET | / | 200 | yes |\n"
        assert _count_request_log_rows(md) == 1

    def test_request_log_counts_login_path(self):
        """/login must count (word-boundary regex previously failed here)."""
        md = "| 1 | GET | host | /login | 302 | yes |\n"
        assert _count_request_log_rows(md) == 1

    def test_request_log_counts_multiple_rows(self):
        md = (
            "| # | Method | Host | Path | Status |\n"
            "|---|---|---|---|---|\n"
            "| 1 | GET | h | / | 200 |\n"
            "| 2 | POST | h | /api/v1/users | 201 |\n"
            "| 3 | DELETE | h | /api/v1/users/1 | 204 |\n"
        )
        assert _count_request_log_rows(md) == 3

    def test_request_log_ignores_separator_rows(self):
        md = "|---|--------|------|------|--------|-----------|\n"
        assert _count_request_log_rows(md) == 0

    def test_request_log_zero_for_empty(self):
        assert _count_request_log_rows("# Discovery\n_No requests_\n") == 0

    # --- _count_vuln_test_entries: keyword-only must NOT pass ---

    def test_vuln_test_counts_heading_entries(self):
        md = "## Test #1: SQLi\nResult: not vulnerable\n## Test #2: XSS\nResult: confirmed\n"
        assert _count_vuln_test_entries(md) == 2

    def test_vuln_test_counts_f_finding_headings(self):
        md = "## F-001 — CORS [Medium]\n**Result**: confirmed\n"
        assert _count_vuln_test_entries(md) == 1

    def test_vuln_test_counts_table_rows(self):
        md = "| GET | /search?q=1 | 200 | not vulnerable |\n"
        assert _count_vuln_test_entries(md) == 1

    def test_vuln_test_keyword_only_does_not_count(self):
        """A paragraph mentioning 'payload' with no structured entry must be 0."""
        md = "# Validation\n\nWe tested payload variants but wrote no entries.\n" + "x" * 200
        assert _count_vuln_test_entries(md) == 0

    # --- parse_coverage_checklist: gaps + scope violations ---

    def test_coverage_parses_degraded_and_not_covered(self):
        md = (
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "| Subdomains | not-covered | single host |\n"
            "| GraphQL | degraded | no endpoint |\n"
        )
        parsed = parse_coverage_checklist(md)
        assert len(parsed["gaps"]) == 2
        assert parsed["gaps"][0]["status"] == "not-covered"
        assert parsed["gaps"][1]["status"] == "degraded"
        assert parsed["blank_rows"] == 0

    def test_coverage_counts_blank_status_rows(self):
        md = (
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "| Subdomains |  |  |\n"
        )
        parsed = parse_coverage_checklist(md)
        assert parsed["blank_rows"] == 1

    def test_coverage_detects_scope_violation(self):
        md = (
            "## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All targets in scope | violation | probed other.com |\n"
            "| Out-of-scope not probed | pass | none |\n"
        )
        parsed = parse_coverage_checklist(md)
        assert len(parsed["scope_violations"]) == 1
        assert "All targets in scope" in parsed["scope_violations"][0]["check"]

    def test_coverage_no_violation_when_all_pass(self):
        md = (
            "## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All targets in scope | pass | ok |\n"
        )
        parsed = parse_coverage_checklist(md)
        assert len(parsed["scope_violations"]) == 0

    # --- build_coverage_gaps_section: gaps appear in report output ---

    def test_report_section_includes_gaps(self):
        md = (
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| GraphQL | degraded | no endpoint |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        section = build_coverage_gaps_section(md)
        assert "Test Coverage & Gaps" in section
        assert "GraphQL" in section
        assert "degraded" in section

    def test_report_section_flags_violation(self):
        md = (
            "## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | violation | breach |\n"
        )
        section = build_coverage_gaps_section(md)
        assert "Scope violation detected" in section

    # --- check_report_gate: integration (full task dir) ---

    def test_gate_blocks_empty_task(self, tmp_path):
        """An initialized-but-unfilled task must not pass the gate."""
        import json
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text("- target: https://example.com\n")
        (task_dir / "summary.json").write_text("{}")
        # No 02/03/coverage files
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("preflight incomplete" in g for g in gaps)
        assert any("02-discovery.md" in g for g in gaps)

    def test_gate_blocks_shallow_files(self, tmp_path):
        """60-byte garbage files must not pass the deep gate."""
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        junk = "a" * 65
        (task_dir / "02-discovery.md").write_text(junk)
        (task_dir / "03-vuln-test.md").write_text(junk)
        (task_dir / "coverage-checklist.md").write_text(junk)
        ok, gaps = check_report_gate(task_dir)
        assert ok is False

    def test_gate_blocks_scope_violation(self, tmp_path):
        """A scope violation in coverage-checklist must block the report."""
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com only\n"
            "- scope_allowlist: example.com\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n| Method | Host | Path | Status |\n|---|---|---|---|\n| GET | example.com | / | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "## Test #1: SQLi\n"
            "| Method | Host | Path | Outcome |\n"
            "|---|---|---|---|\n"
            "| GET | example.com | / | not vulnerable |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | violation | breach |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("violation" in g for g in gaps)

    def test_gate_blocks_request_host_outside_scope_allowlist(self, tmp_path):
        """Request logs are machine-checked against task.md scope_allowlist."""
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com only\n"
            "- scope_allowlist: example.com\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| Method | Host | Path | Status |\n"
            "|---|---|---|---|\n"
            "| GET | api.example.com | / | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "| Method | Host | Path | Outcome |\n"
            "|---|---|---|---|\n"
            "| GET | example.com | /login | not vulnerable |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("outside scope allowlist" in g for g in gaps)

    def test_gate_blocks_missing_request_host_when_preflight_complete(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com only\n"
            "- scope_allowlist: example.com\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text("## Request Log\n| GET | / | 200 | yes |\n")
        (task_dir / "03-vuln-test.md").write_text("## Test #1\n| GET | /login | 200 | not vulnerable |\n")
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("missing target host" in g for g in gaps)

    def test_gate_blocks_vuln_validation_without_scoped_request_rows(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com only\n"
            "- scope_allowlist: example.com\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| Method | Host | Path | Status |\n"
            "|---|---|---|---|\n"
            "| GET | example.com | / | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "## Test #1: SQLi\n"
            "**Result**: not vulnerable\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("no scoped request rows" in g for g in gaps)

    def test_gate_blocks_request_port_outside_approved_ports(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com:443 only\n"
            "- scope_allowlist: example.com\n"
            "- approved_ports: 443\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| Method | Host | Path | Status |\n"
            "|---|---|---|---|\n"
            "| GET | example.com:8080 | / | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "| Method | Host | Path | Outcome |\n"
            "|---|---|---|---|\n"
            "| GET | example.com:443 | /login | not vulnerable |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("outside approved ports" in g for g in gaps)

    def test_gate_parses_wrapper_host_requested_header_with_port(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: http://example.com:8080\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: http://example.com:8080 only\n"
            "- scope_allowlist: example.com\n"
            "- approved_ports: 8080\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |\n"
            "|---|--------|------------------|------|--------|-----------|------|-------|\n"
            "| 1 | GET | example.com:8081 | / | 200 | yes | request_guard | raw/ref.txt |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "| # | Method | Host (requested) | Path | Status | In Scope? | Tool | Notes |\n"
            "|---|--------|------------------|------|--------|-----------|------|-------|\n"
            "| 1 | GET | example.com:8080 | /login | 200 | yes | request_guard | raw/ref.txt |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("outside approved ports [8080]" in g for g in gaps)

    def test_gate_treats_default_for_target_as_target_port_only(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com only\n"
            "- scope_allowlist: example.com\n"
            "- approved_ports: default-for-target\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| Method | Host | Path | Status |\n"
            "|---|---|---|---|\n"
            "| GET | example.com:8443 | / | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "| Method | Host | Path | Outcome |\n"
            "|---|---|---|---|\n"
            "| GET | example.com:443 | /login | not vulnerable |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("outside approved ports [443]" in g for g in gaps)

    def test_gate_missing_approved_ports_defaults_to_target_port(self, tmp_path):
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: http://example.com:8080\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: http://example.com:8080 only\n"
            "- scope_allowlist: example.com\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| Method | Host | Path | Status |\n"
            "|---|---|---|---|\n"
            "| GET | example.com:8081 | / | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "| Method | Host | Path | Outcome |\n"
            "|---|---|---|---|\n"
            "| GET | example.com:8080 | /login | not vulnerable |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is False
        assert any("outside approved ports [8080]" in g for g in gaps)

    def test_gate_passes_well_filled_task(self, tmp_path):
        """A correctly filled task with no violations must pass."""
        task_dir = tmp_path / "task"
        task_dir.mkdir()
        (task_dir / "task.md").write_text(
            "- target: https://example.com\n"
            "- preflight_complete: true\n"
            "- authorization: confirmed\n"
            "- scope: https://example.com only\n"
            "- scope_allowlist: example.com\n"
            "- intensity: gentle\n"
            "- automation: fingerprinting,http-probing\n"
            "- credentials: none\n"
        )
        (task_dir / "02-discovery.md").write_text(
            "## Request Log\n"
            "| Method | Host | Path | Status |\n"
            "|---|---|---|---|\n"
            "| GET | example.com | /login | 200 |\n"
        )
        (task_dir / "03-vuln-test.md").write_text(
            "## Test #1: XSS\n"
            "| Method | Host | Path | Outcome |\n"
            "|---|---|---|---|\n"
            "| GET | example.com | /search | confirmed |\n"
        )
        (task_dir / "coverage-checklist.md").write_text(
            "## Discovery Surface\n"
            "| Surface | Status | Reason |\n"
            "|---------|--------|--------|\n"
            "| Dir brute | covered | done |\n"
            "\n## Scope Adherence\n"
            "| Check | Result | Evidence |\n"
            "|-------|--------|----------|\n"
            "| All in scope | pass | ok |\n"
        )
        ok, gaps = check_report_gate(task_dir)
        assert ok is True
        assert gaps == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
