#!/usr/bin/env python3
"""Tests for infer_category covering all category enum values.

Run with: .venv/bin/python -m pytest tests/test_infer_category.py -v
Or standalone: python tests/test_infer_category.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ensure_structured_outputs import infer_category, infer_owasp_cwe, OWASP_CWE_MAP


class TestInferCategoryClassic:
    def test_sqli(self):
        assert infer_category("SQL Injection in login") == "sqli"

    def test_sqli_abbr(self):
        assert infer_category("Blind SQLi via search") == "sqli"

    def test_xss(self):
        assert infer_category("Reflected XSS in search") == "xss"

    def test_xss_full(self):
        assert infer_category("Cross-Site Scripting") == "xss"

    def test_ssrf(self):
        assert infer_category("SSRF via fetch URL") == "ssrf"

    def test_ssrf_full(self):
        assert infer_category("Server-Side Request Forgery") == "ssrf"

    def test_xxe(self):
        assert infer_category("XXE in upload endpoint") == "xxe"

    def test_xxe_full(self):
        assert infer_category("XML External Entity") == "xxe"

    def test_unauthorized_idor(self):
        assert infer_category("IDOR on user profile") == "unauthorized_access"

    def test_unauthorized_bola(self):
        assert infer_category("BOLA object access") == "unauthorized_access"

    def test_unauthorized_access_control(self):
        assert infer_category("Broken Access Control") == "unauthorized_access"

    def test_unauthorized_unauth(self):
        assert infer_category("Unauthenticated API endpoint") == "unauthorized_access"

    def test_rce(self):
        assert infer_category("RCE via command injection") == "rce"

    def test_rce_full(self):
        assert infer_category("Remote Code Execution") == "rce"

    def test_command_injection(self):
        assert infer_category("Command Injection in ping") == "rce"

    def test_deserialization(self):
        assert infer_category("Java Deserialization RCE") == "deserialization"

    def test_csrf(self):
        assert infer_category("CSRF on password change") == "csrf"

    def test_csrf_full(self):
        assert infer_category("Cross-Site Request Forgery") == "csrf"

    def test_auth_jwt(self):
        assert infer_category("JWT Token Bypass") == "auth"

    def test_auth_jwt_full(self):
        assert infer_category("JSON Web Token none algorithm") == "auth"

    def test_auth_oauth(self):
        assert infer_category("OAuth callback bypass") == "auth"

    def test_auth_mfa(self):
        assert infer_category("MFA bypass via replay") == "auth"

    def test_auth_2fa(self):
        assert infer_category("2FA bypass on login") == "auth"

    def test_auth_password_reset(self):
        assert infer_category("Password Reset token reuse") == "auth"

    def test_file_upload(self):
        assert infer_category("File Upload webshell") == "file_upload"

    def test_file_inclusion_lfi(self):
        assert infer_category("LFI via path parameter") == "file_inclusion"

    def test_file_inclusion_rfi(self):
        assert infer_category("RFI from external host") == "file_inclusion"

    def test_file_inclusion_full(self):
        assert infer_category("File Inclusion vulnerability") == "file_inclusion"

    def test_websocket(self):
        assert infer_category("WebSocket hijacking") == "websocket"

    def test_ssti(self):
        assert infer_category("SSTI in template engine") == "ssti"

    def test_ssti_full(self):
        assert infer_category("Template Injection") == "ssti"

    def test_ldap(self):
        assert infer_category("LDAP Injection in search") == "ldap_injection"

    def test_nosql(self):
        assert infer_category("NoSQL Injection in MongoDB") == "nosqli"

    def test_mongodb(self):
        assert infer_category("MongoDB operator injection") == "nosqli"

    def test_open_redirect(self):
        assert infer_category("Open Redirect via URL param") == "open_redirect"

    def test_host_header(self):
        assert infer_category("Host Header poisoning") == "host_header"

    def test_rate_limiting(self):
        assert infer_category("Rate Limiting absent on login") == "rate_limiting"

    def test_request_smuggling(self):
        assert infer_category("HTTP Smuggling CL.TE") == "request_smuggling"

    def test_crlf(self):
        assert infer_category("CRLF Injection in header") == "crlf_injection"

    def test_cache_poisoning(self):
        assert infer_category("Cache Poisoning via unkeyed header") == "cache_poisoning"

    def test_race_condition(self):
        assert infer_category("Race Condition on coupon") == "race_condition"

    def test_prototype_pollution(self):
        assert infer_category("Prototype Pollution in merge") == "prototype_pollution"

    def test_subdomain_takeover(self):
        assert infer_category("Subdomain Takeover CNAME") == "subdomain_takeover"

    def test_cors(self):
        assert infer_category("CORS misconfiguration with credentials") == "cors_misconfiguration"

    def test_dom_xss(self):
        assert infer_category("DOM XSS in postMessage") == "dom_xss"


class TestInferCategorySpecific:
    def test_password_policy(self):
        assert infer_category("Password Policy weakness") == "password_policy"

    def test_account_lockout(self):
        assert infer_category("Account Lockout bypass") == "password_policy"

    def test_default_credentials(self):
        assert infer_category("Default Credentials on admin") == "default_credentials"

    def test_default_password(self):
        assert infer_category("Default Password exposed") == "default_credentials"

    def test_error_handling(self):
        assert infer_category("Error Handling stack trace") == "error_handling"

    def test_error_disclosure(self):
        assert infer_category("Error Disclosure in response") == "error_handling"

    def test_debug_mode(self):
        assert infer_category("Debug Mode enabled") == "error_handling"

    def test_security_headers(self):
        assert infer_category("Security Headers missing") == "security_headers"

    def test_csp_bypass(self):
        assert infer_category("CSP Bypass via base-uri") == "security_headers"

    def test_clickjacking(self):
        assert infer_category("Clickjacking via framing") == "security_headers"

    def test_x_frame(self):
        assert infer_category("X-Frame-Options missing") == "security_headers"

    def test_path_traversal(self):
        assert infer_category("Path Traversal via ../") == "path_traversal"

    def test_directory_traversal(self):
        assert infer_category("Directory Traversal read") == "path_traversal"

    def test_cloud_security(self):
        assert infer_category("Cloud Security metadata exposure") == "cloud_security"

    def test_cloud_storage(self):
        assert infer_category("Cloud Storage misconfiguration") == "cloud_security"

    def test_s3_bucket(self):
        assert infer_category("S3 Bucket enumeration") == "cloud_bucket_exposed"

    def test_session_management(self):
        assert infer_category("Session Management fixation") == "session_management"

    def test_session_timeout(self):
        assert infer_category("Session Timeout too long") == "session_management"

    def test_admin_panel(self):
        assert infer_category("Admin Panel exposed") == "admin_panel"

    def test_admin_interface(self):
        assert infer_category("Admin Interface accessible") == "admin_panel"

    def test_client_side_review(self):
        assert infer_category("Client-Side token in localStorage") == "client_side_review"

    def test_local_storage(self):
        assert infer_category("Local Storage secret leak") == "client_side_review"

    def test_backup_exposure(self):
        assert infer_category("Backup Exposure .sql dump") == "backup_exposure"

    def test_git_exposure(self):
        assert infer_category(".git directory exposure") == "backup_exposure"

    def test_env_exposure(self):
        assert infer_category(".env exposure on web root") == "backup_exposure"

    def test_http_methods(self):
        assert infer_category("HTTP Method PUT enabled") == "http_methods"

    def test_http_verb(self):
        assert infer_category("HTTP Verb tampering") == "http_methods"

    def test_soap_wsdl(self):
        assert infer_category("SOAP WSDL exposure") == "soap_wsdl"

    def test_mobile_api(self):
        assert infer_category("Mobile API weak auth") == "api_mobile"

    def test_weak_credentials(self):
        assert infer_category("Weak Credential reuse") == "weak_credentials"

    def test_weak_cred(self):
        assert infer_category("Weak Cred on ssh") == "weak_credentials"

    def test_information_disclosure(self):
        assert infer_category("Information Disclosure via debug") == "information_disclosure"

    def test_leak(self):
        assert infer_category("Memory Leak in headers") == "information_disclosure"


class TestInferCategoryAI:
    def test_prompt_injection(self):
        assert infer_category("Prompt Injection via chat") == "prompt_injection"

    def test_jailbreak(self):
        assert infer_category("LLM Jailbreak bypass") == "prompt_injection"

    def test_llm_injection(self):
        assert infer_category("LLM Injection attack") == "prompt_injection"

    def test_tool_use_abuse(self):
        assert infer_category("Tool Use abuse via prompt") == "tool_use_abuse"

    def test_tool_use_hyphen(self):
        assert infer_category("Tool-Use bypass filter") == "tool_use_abuse"

    def test_function_call(self):
        assert infer_category("Function Call unauthorized") == "tool_use_abuse"

    def test_rag_poison(self):
        assert infer_category("RAG vector DB poison") == "rag_poison"

    def test_rag_vector_database(self):
        assert infer_category("Vector database query abuse") == "rag_poison"

    def test_system_prompt_leak(self):
        assert infer_category("System Prompt leakage") == "system_prompt_leak"

    def test_system_instruction(self):
        assert infer_category("System Instruction extraction") == "system_prompt_leak"

    def test_llm_cost_dos(self):
        assert infer_category("Cost DoS via long prompt") == "llm_cost_dos"

    def test_llm_cost_exhaust(self):
        assert infer_category("LLM Cost Exhaust via prompt") == "llm_cost_dos"


class TestInferCategoryGRPC:
    def test_grpc(self):
        assert infer_category("gRPC auth bypass") == "grpc_auth_bypass"

    def test_protobuf(self):
        assert infer_category("Protobuf field manipulation") == "grpc_auth_bypass"


class TestInferCategoryCloudNative:
    def test_k8s(self):
        assert infer_category("K8s API unauthenticated") == "k8s_priv_esc"

    def test_kubernetes(self):
        assert infer_category("Kubernetes RBAC bypass") == "k8s_priv_esc"

    def test_kubelet(self):
        assert infer_category("Kubelet API exposure") == "kubelet_exposure"

    def test_etcd(self):
        assert infer_category("etcd unauthenticated read") == "etcd_exposure"

    def test_container_escape(self):
        assert infer_category("Container Escape via cgroup") == "container_escape"

    def test_docker_escape(self):
        assert infer_category("Docker Escape socket") == "container_escape"

    def test_origin_ip(self):
        assert infer_category("Origin IP disclosed") == "origin_disclosed"

    def test_cdn_bypass(self):
        assert infer_category("CDN Bypass to origin") == "origin_disclosed"

    def test_waf_bypass(self):
        assert infer_category("WAF Bypass via encoding") == "origin_disclosed"

    def test_cloud_bucket_oss(self):
        assert infer_category("Aliyun OSS bucket public exposure") == "cloud_bucket_exposed"

    def test_cloud_bucket_cos(self):
        assert infer_category("Tencent COS bucket public access") == "cloud_bucket_exposed"

    def test_cloud_bucket_obs(self):
        assert infer_category("Huawei OBS bucket exposed") == "cloud_bucket_exposed"

    def test_cloud_bucket_s3(self):
        assert infer_category("S3 bucket public data exposure") == "cloud_bucket_exposed"


class TestInferCategoryHTTP2:
    def test_http2_race(self):
        assert infer_category("HTTP/2 Race Condition") == "http2_race_condition"

    def test_http2_abbr(self):
        assert infer_category("HTTP2 single-packet attack") == "http2_race_condition"

    def test_single_packet(self):
        assert infer_category("Single-packet race condition") == "http2_race_condition"


class TestInferCategoryFallback:
    def test_misc_fallback(self):
        assert infer_category("Unknown vulnerability type") == "misc"

    def test_empty_string(self):
        assert infer_category("") == "misc"


class TestOWASPCWE:
    def test_all_mapped_categories_have_owasp(self):
        for category in OWASP_CWE_MAP:
            owasp, cwe = infer_owasp_cwe(category)
            assert owasp, f"{category} missing OWASP mapping"
            assert cwe.startswith("CWE-"), f"{category} has invalid CWE: {cwe}"

    def test_ai_categories_have_mapping(self):
        for cat in ["prompt_injection", "tool_use_abuse", "rag_poison", "system_prompt_leak", "llm_cost_dos"]:
            # AI categories may not be in OWASP_CWE_MAP (they're newer),
            # but infer_owasp_cwe should return empty tuple gracefully
            result = infer_owasp_cwe(cat)
            assert isinstance(result, tuple)

    def test_grpc_cloud_categories_graceful(self):
        for cat in ["grpc_auth_bypass", "k8s_priv_esc", "kubelet_exposure", "etcd_exposure",
                     "container_escape", "origin_disclosed", "cloud_bucket_exposed", "http2_race_condition"]:
            result = infer_owasp_cwe(cat)
            assert isinstance(result, tuple)


if __name__ == "__main__":
    try:
        import pytest
        sys.exit(pytest.main([__file__, "-v"]))
    except ImportError:
        # Standalone runner when pytest is not available
        import traceback
        classes = [cls for name, cls in sorted(globals().items())
                   if isinstance(cls, type) and name.startswith("Test")]
        total = passed = failed = 0
        for cls in classes:
            instance = cls()
            for method_name in sorted(dir(instance)):
                if not method_name.startswith("test_"):
                    continue
                total += 1
                try:
                    getattr(instance, method_name)()
                    passed += 1
                    print(f"  PASS  {cls.__name__}.{method_name}")
                except Exception as e:
                    failed += 1
                    print(f"  FAIL  {cls.__name__}.{method_name}: {e}")
        print(f"\n{total} tests: {passed} passed, {failed} failed")
        sys.exit(1 if failed else 0)
