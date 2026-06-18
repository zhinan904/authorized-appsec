#!/usr/bin/env python3
"""Generate L3-backed hypotheses from current-task fingerprints.

This script only creates a testing queue aid. It must not create confirmed
findings or report conclusions.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from retrieve_l3 import compute_score


DEFAULT_CATEGORIES = [
    "attack_chain_recognition",
    "default_credentials",
    "sensitive_config_exposure",
    "token_exposure",
    "idor",
    "waf_bypass",
    "weak_authentication_controls",
    "client_side_secret_exposure",
    "prompt_injection",
    "tool_use_abuse",
    "rag_vector_boundary",
    "grpc_service_exposure",
    "k8s_cluster_exposure",
    "cloud_origin_exposure",
    "http2_race_condition",
]

SIGNALS = [
    # --- Legacy high-confidence signals (proven across many tasks) ---
    {
        "id": "admin_api_namespace",
        "label": "Admin API namespace",
        "patterns": [r"/admin-api(?:/|\b)", r"\badmin[-_ ]?api\b"],
        "weight": 2,
        "confidence": "high",
    },
    {
        "id": "json_code_data_msg",
        "label": "JSON response envelope code/data/msg",
        "patterns": [r"\bcode\b[\s\S]{0,80}\bdata\b[\s\S]{0,80}\bmsg\b", r'"code"\s*:\s*[^,\n]+[\s\S]{0,160}"data"\s*:'],
        "weight": 2,
        "confidence": "high",
    },
    {
        "id": "vue_vite_admin",
        "label": "Vue/Vite-style admin frontend",
        "patterns": [r"\bVue(?:\.js)?\b", r"\bVite\b", r"\bElement Plus\b", r"\bVITE_[A-Z0-9_]+\b", r"/assets/.*\.js", r"/js/.*\.js"],
        "weight": 2,
        "confidence": "high",
    },
    {
        "id": "admin_identity_modules",
        "label": "User/role/department administrative modules",
        "patterns": [r"\buser\b", r"\brole\b", r"\bdept(?:artment)?\b", r"\btenant\b", r"\bmenu\b"],
        "weight": 1,
        "confidence": "medium",
    },
    {
        "id": "config_modules",
        "label": "Infra/file/system configuration modules",
        "patterns": [r"\binfra\b", r"\bfile[-_ ]?config\b", r"\bsystem[-_ ]?config\b", r"\bstorage\b", r"\bbucket\b", r"\bendpoint\b"],
        "weight": 1,
        "confidence": "medium",
    },
    {
        "id": "oauth_social_token_modules",
        "label": "OAuth/social-user/token modules",
        "patterns": [r"\boauth", r"\bsocial[-_ ]?user\b", r"\btoken\b", r"\bopenid\b", r"\bissuer\b"],
        "weight": 1,
        "confidence": "medium",
    },
    {
        "id": "login_feature_flags",
        "label": "Login feature flags",
        "patterns": [r"\bcaptcha\b", r"\btenant\b", r"\bVITE_.*CAPTCHA", r"\bVITE_.*TENANT"],
        "weight": 1,
        "confidence": "high",
    },
    {
        "id": "waf_normalization_clues",
        "label": "WAF/CDN and path-normalization clues",
        "patterns": [r"\bwaf\b", r"\bcdn\b", r"\b403\b", r"\bblocked\b", r"\bencoded path\b", r"\bdot[- ]segment\b", r"\bnormalize"],
        "weight": 1,
        "confidence": "low",
    },
    # --- AI / LLM signals ---
    {
        "id": "llm_chat_api",
        "label": "LLM chat/completion API endpoint",
        "patterns": [r"/api/chat", r"/api/completion", r"/v1/chat/completions", r"/v1/completions", r"/v1/embeddings"],
        "weight": 2,
        "confidence": "medium",
        "suggest_payload": "ai-security.md",
    },
    {
        "id": "llm_framework",
        "label": "LLM framework detected in stack trace or source",
        "patterns": [r"\bLangChain\b", r"\bLlamaIndex\b", r"\bOpenAI\b", r"\bmodel.*gpt", r"\bmodel.*claude", r"\bDeepSeek\b"],
        "weight": 2,
        "confidence": "low",
        "suggest_payload": "ai-security.md",
    },
    {
        "id": "llm_tool_use",
        "label": "LLM tool/function calling interface",
        "patterns": [r"\btools?\s*:", r"\bfunction_call", r"\bfunctions?\s*:", r"tool_choice", r"function_calling"],
        "weight": 2,
        "confidence": "low",
        "suggest_payload": "ai-security.md",
    },
    # --- gRPC signals ---
    {
        "id": "grpc_endpoint",
        "label": "gRPC service detected",
        "patterns": [r"grpc-status", r"application/grpc", r"grpc-web", r"grpc-web-text", r"grpc\.reflection"],
        "weight": 2,
        "confidence": "high",
        "suggest_payload": "grpc-protobuf.md",
    },
    {
        "id": "protobuf_exposure",
        "label": "Protobuf definitions accessible",
        "patterns": [r"\.proto\b", r"\.pb\.go\b", r"protobuf", r"google\.protobuf"],
        "weight": 2,
        "confidence": "medium",
        "suggest_payload": "grpc-protobuf.md",
    },
    # --- K8s / cloud-native signals ---
    {
        "id": "k8s_api",
        "label": "Kubernetes API server",
        "patterns": [r"/api/v1/namespaces", r"/api/v1/pods", r"/healthz", r"/livez", r"kubernetes\.default\.svc"],
        "weight": 2,
        "confidence": "low",
        "suggest_payload": "cloud-security.md",
    },
    {
        "id": "kubelet",
        "label": "Kubelet API exposed",
        "patterns": [r":10250/", r"/pods\b.*container", r"kubelet"],
        "weight": 2,
        "confidence": "medium",
        "suggest_payload": "cloud-security.md",
    },
    {
        "id": "cloud_metadata_host",
        "label": "Cloud metadata endpoint reachable",
        "patterns": [r"169\.254\.169\.254", r"metadata\.google\.internal", r"100\.100\.100\.200", r"metadata\.tencentyun\.com"],
        "weight": 2,
        "confidence": "high",
        "suggest_payload": "cloud-security.md",
    },
    {
        "id": "chinese_cloud_bucket",
        "label": "Chinese cloud storage bucket",
        "patterns": [r"\.oss-[a-z]+\.aliyuncs\.com", r"\.cos\.[a-z]+\.myqcloud\.com", r"\.obs\.[a-z]+\.myhuaweicloud\.com"],
        "weight": 2,
        "confidence": "high",
        "suggest_payload": "cloud-security.md",
    },
    # --- HTTP/2 / modern protocol signals ---
    {
        "id": "http2_race_surface",
        "label": "HTTP/2 race condition surface",
        "patterns": [r"HTTP/2", r"h2\b", r"race.?condition", r"coupon", r"transfer\b", r"redeem"],
        "weight": 1,
        "confidence": "low",
        "suggest_payload": "http2-single-packet.md",
    },
    # --- WAF origin signals ---
    {
        "id": "cdn_waf_fingerprint",
        "label": "CDN/WAF fingerprint detected",
        "patterns": [r"Aliyungf_TC", r"Server:\s*Tengine", r"Server:\s*EdgeOne", r"X-SafeLine", r"yunjiasu", r"WSCloud", r"NSFOCUS_WAF", r"sangfor"],
        "weight": 2,
        "confidence": "high",
        "suggest_payload": "waf-origin-discovery.md",
    },
]


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def default_l3_root() -> Path:
    env_root = os.environ.get("AUTHORIZED_APPSEC_L3_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    return Path.home() / "authorized-appsec" / "l3"


def task_corpus(task_dir: Path) -> str:
    parts = []
    for name in [
        "task.md",
        "summary.json",
        "01-fingerprint.md",
        "02-discovery.md",
        "capabilities.json",
    ]:
        parts.append(read_text(task_dir / name))
    return "\n".join(parts)


def detect_signals(text: str) -> list[dict]:
    detected = []
    for signal in SIGNALS:
        hits = []
        for pattern in signal["patterns"]:
            match = re.search(pattern, text, flags=re.I)
            if match:
                hits.append(match.group(0)[:80])
        if hits:
            detected.append({
                "id": signal["id"],
                "label": signal["label"],
                "weight": signal["weight"],
                "confidence": signal.get("confidence", "medium"),
                "evidence": hits[:3],
            })
    return detected


def load_l3_entries(l3_root: Path) -> list[dict]:
    entries = []
    for base_rel, source in [
        ("internal-knowledge/knowledge-mapping", "knowledge-mapping"),
        ("internal-knowledge/rag", "rag"),
        ("experience/task-memory", "task-memory"),
    ]:
        base = l3_root / base_rel
        index = read_json(base / "index.json", {"entries": []})
        for item in index.get("entries", []):
            path = base / item.get("path", "")
            if not path.exists():
                continue
            content = read_text(path)
            entries.append({
                "source": source,
                "id": item.get("id") or item.get("title") or path.stem,
                "category": item.get("category", ""),
                "severity": item.get("severity", ""),
                "path": str(path),
                "content": content,
                "meta": item,
            })
    return entries


def category_hits(l3_entries: list[dict], categories: list[str], limit: int) -> list[dict]:
    hits = []
    for category in categories:
        scored = []
        for entry in l3_entries:
            score = compute_score(entry["content"], entry["meta"], "", category)
            if score > 0:
                scored.append((score, entry))
        for score, entry in sorted(scored, key=lambda item: item[0], reverse=True)[:limit]:
            hits.append({
                "category": category,
                "entry_id": entry["id"],
                "source": entry["source"],
                "severity": entry["severity"],
                "path": entry["path"],
                "score": score,
            })
    return hits


def build_hypotheses(detected: list[dict], l3_hits: list[dict]) -> list[dict]:
    categories = []
    signal_ids = {item["id"] for item in detected}
    # Map signal ID → confidence from detected results
    confidence_map = {item["id"]: item.get("confidence", "medium") for item in detected}

    # Original signal → category mappings
    if "admin_api_namespace" in signal_ids and "json_code_data_msg" in signal_ids:
        categories.append("attack_chain_recognition")
    if "login_feature_flags" in signal_ids:
        categories.extend(["default_credentials", "weak_authentication_controls"])
    if "config_modules" in signal_ids:
        categories.append("sensitive_config_exposure")
    if "oauth_social_token_modules" in signal_ids:
        categories.append("token_exposure")
    if "admin_identity_modules" in signal_ids:
        categories.append("idor")
    if "waf_normalization_clues" in signal_ids:
        categories.append("waf_bypass")
    if "vue_vite_admin" in signal_ids:
        categories.append("client_side_secret_exposure")

    # AI / LLM signals
    if "llm_chat_api" in signal_ids or "llm_framework" in signal_ids:
        categories.append("prompt_injection")
    if "llm_tool_use" in signal_ids:
        categories.append("tool_use_abuse")
    if "llm_chat_api" in signal_ids and "config_modules" in signal_ids:
        categories.append("rag_vector_boundary")

    # gRPC signals
    if "grpc_endpoint" in signal_ids or "protobuf_exposure" in signal_ids:
        categories.append("grpc_service_exposure")

    # K8s / cloud-native signals
    if "k8s_api" in signal_ids or "kubelet" in signal_ids:
        categories.append("k8s_cluster_exposure")

    # Cloud signals
    if "cloud_metadata_host" in signal_ids or "chinese_cloud_bucket" in signal_ids:
        categories.append("cloud_origin_exposure")

    # HTTP/2 signals
    if "http2_race_surface" in signal_ids:
        categories.append("http2_race_condition")

    # WAF origin signals
    if "cdn_waf_fingerprint" in signal_ids:
        categories.append("cloud_origin_exposure")

    # Build hypotheses with payload suggestions and confidence routing
    signal_lookup = {s["id"]: s for s in SIGNALS}
    available = {hit["category"]: hit for hit in l3_hits}
    hypotheses = []
    hypotheses_queued = []
    for category in dict.fromkeys(categories):
        hit = available.get(category)
        # Collect payload suggestions from signals that triggered this category
        suggestions = []
        contributing_signals = _signal_ids_for_category(category, signal_ids, signal_lookup)
        for sig_id in contributing_signals:
            sig = signal_lookup.get(sig_id, {})
            if sig.get("suggest_payload"):
                suggestions.append(sig["suggest_payload"])

        # Determine category confidence: use lowest confidence among contributing signals
        cat_confidence = "high"
        for sig_id in contributing_signals:
            sig_conf = confidence_map.get(sig_id, "medium")
            if sig_conf == "low":
                cat_confidence = "low"
                break
            if sig_conf == "medium":
                cat_confidence = "medium"

        entry = {
            "category": category,
            "status": "hypothesis_only",
            "confidence": cat_confidence,
            "reporting_allowed": False,
            "requires_current_task_validation": True,
            "l3_reference": hit,
            "suggested_payloads": list(dict.fromkeys(suggestions)),
            "test_queue_note": f"Use L3 {category} only to prioritize Phase 1/3 validation; do not report unless current-task evidence confirms it.",
        }

        # Low-confidence hypotheses go to separate queue, not Phase 1 default
        if cat_confidence == "low":
            entry["queue"] = "hypotheses_queued"
            entry["test_queue_note"] += " Low-confidence signal — requires manual review before Phase 1 testing."
            hypotheses_queued.append(entry)
        else:
            entry["queue"] = "phase_1"
            hypotheses.append(entry)

    return hypotheses, hypotheses_queued


def _signal_ids_for_category(category: str, signal_ids: set, signal_lookup: dict) -> set:
    """Return signal IDs that map to a given category."""
    mapping = {
        "prompt_injection": {"llm_chat_api", "llm_framework"},
        "tool_use_abuse": {"llm_tool_use"},
        "rag_vector_boundary": {"llm_chat_api", "config_modules"},
        "grpc_service_exposure": {"grpc_endpoint", "protobuf_exposure"},
        "k8s_cluster_exposure": {"k8s_api", "kubelet"},
        "cloud_origin_exposure": {"cloud_metadata_host", "chinese_cloud_bucket", "cdn_waf_fingerprint"},
        "http2_race_condition": {"http2_race_surface"},
    }
    return mapping.get(category, set()) & signal_ids


def generate(task_dir: Path, l3_root: Path, min_score: int = 3, limit: int = 2) -> dict:
    corpus = task_corpus(task_dir)
    detected = detect_signals(corpus)
    score = sum(item["weight"] for item in detected)
    matched = score >= min_score and len(detected) >= 2

    l3_hits = []
    hypotheses = []
    hypotheses_queued = []
    if matched and l3_root.exists():
        entries = load_l3_entries(l3_root)
        l3_hits = category_hits(entries, DEFAULT_CATEGORIES, limit)
        hypotheses, hypotheses_queued = build_hypotheses(detected, l3_hits)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task_dir": str(task_dir),
        "l3_root": str(l3_root),
        "status": "matched" if matched else "not_matched",
        "match_score": score,
        "min_score": min_score,
        "detected_signals": detected,
        "l3_available": l3_root.exists(),
        "hypotheses": hypotheses,
        "hypotheses_queued": hypotheses_queued,
        "guardrails": [
            "L3 matches are historical hypotheses, not current findings.",
            "Do not write a finding or report conclusion from l3-hypotheses.json alone.",
            "A reportable finding requires current-task Phase 3 validation, evidence, and PoC or a documented safe PoC boundary.",
            "Do not reuse historical credentials, tokens, secrets, personal data, or target-specific payloads.",
            "Low-confidence hypotheses (hypotheses_queued) must be manually reviewed before entering Phase 1 testing queue.",
        ],
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate L3-backed hypothesis queue from current task fingerprints")
    parser.add_argument("task_dir", help="Task directory")
    parser.add_argument("--l3-root", default=None, help="L3 root (default: $AUTHORIZED_APPSEC_L3_ROOT or ~/authorized-appsec/l3)")
    parser.add_argument("--min-score", type=int, default=3, help="Minimum signal score to trigger L3 hypotheses")
    parser.add_argument("--limit", type=int, default=2, help="L3 entries per category")
    parser.add_argument("--output", default=None, help="Output JSON path (default: <task_dir>/l3-hypotheses.json)")
    args = parser.parse_args()

    task_dir = Path(args.task_dir).resolve()
    if not task_dir.exists():
        raise SystemExit(f"Task directory not found: {task_dir}")
    l3_root = Path(args.l3_root).expanduser().resolve() if args.l3_root else default_l3_root()
    output = Path(args.output).resolve() if args.output else task_dir / "l3-hypotheses.json"
    data = generate(task_dir, l3_root, args.min_score, args.limit)
    write_json(output, data)
    print(f"l3-hypotheses:{output}")
    print(f"status:{data['status']} score:{data['match_score']} hypotheses:{len(data['hypotheses'])} queued:{len(data['hypotheses_queued'])}")


if __name__ == "__main__":
    main()
