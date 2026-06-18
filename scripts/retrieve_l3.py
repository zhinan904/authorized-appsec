#!/usr/bin/env python3
"""Retrieve relevant L3 knowledge for a new task.

Usage:
    python3 scripts/retrieve_l3.py <l3_root> [--target <target>] [--category <cat>] [--limit <n>]

Searches L3 knowledge base for entries matching target domain or vulnerability category.
Outputs relevant entries sorted by relevance score.
"""
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


MULTI_LABEL_PUBLIC_SUFFIXES = {
    "ac.cn",
    "com.cn",
    "edu.cn",
    "gov.cn",
    "net.cn",
    "org.cn",
    "co.jp",
    "ne.jp",
    "or.jp",
    "co.kr",
    "or.kr",
    "com.hk",
    "com.tw",
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "com.sg",
}


def read_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path, default=""):
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def extract_host(target: str) -> str:
    return urlparse(target).netloc or target or ""


def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip().strip(".")
    if not host:
        return ""
    host = host.split("@")[-1].split(":")[0]
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return host

    suffix = ".".join(parts[-2:])
    if suffix in MULTI_LABEL_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def compute_score(content: str, entry_meta: dict, target_host: str, category: str) -> float:
    """Compute relevance score. Higher = more relevant."""
    score = 0.0
    content_lower = content.lower()
    host_lower = target_host.lower() if target_host else ""
    cat_lower = category.lower() if category else ""

    # Exact domain match in content (highest weight)
    if host_lower and host_lower in content_lower:
        score += 10.0

    # Registrable domain match, e.g. "example.com" or "example.com.cn".
    if host_lower:
        domain_root = registrable_domain(host_lower)
        if len(domain_root) > 3 and domain_root in content_lower:
            score += 5.0

    # Category match in entry metadata
    entry_cat = str(entry_meta.get("category", "")).lower()
    if cat_lower and cat_lower == entry_cat:
        score += 8.0
    elif cat_lower and cat_lower in entry_cat:
        score += 4.0

    # Category keyword in content
    if cat_lower and cat_lower in content_lower:
        score += 3.0

    # Tag match (for RAG entries)
    tags = entry_meta.get("tags", [])
    for tag in tags:
        tag_lower = str(tag).lower()
        if host_lower and tag_lower in host_lower:
            score += 6.0
        if cat_lower and tag_lower == cat_lower:
            score += 4.0

    # Severity is only a tie-breaker after a real target/category/tag/content match.
    if score > 0:
        severity = str(entry_meta.get("severity", "")).lower()
        if severity == "critical":
            score += 2.0
        elif severity == "high":
            score += 1.5
        elif severity == "medium":
            score += 1.0

    return score


def search_knowledge_mapping(l3_root: Path, target_host: str, category: str) -> list[dict]:
    base = l3_root / "internal-knowledge" / "knowledge-mapping"
    index = read_json(base / "index.json", {"entries": []})
    results = []
    for entry in index.get("entries", []):
        entry_path = base / entry.get("path", "")
        if not entry_path.exists():
            continue
        content = read_text(entry_path)
        score = compute_score(content, entry, target_host, category)
        if score > 0:
            results.append({
                "source": "knowledge-mapping",
                "id": entry.get("id", ""),
                "category": entry.get("category", ""),
                "severity": entry.get("severity", ""),
                "content": content[:500],
                "score": score,
            })
    return results


def search_rag(l3_root: Path, target_host: str, category: str) -> list[dict]:
    base = l3_root / "internal-knowledge" / "rag"
    index = read_json(base / "index.json", {"entries": []})
    results = []
    for entry in index.get("entries", []):
        entry_path = base / entry.get("path", "")
        if not entry_path.exists():
            continue
        content = read_text(entry_path)
        score = compute_score(content, entry, target_host, category)
        if score > 0:
            results.append({
                "source": "rag",
                "id": entry.get("id", ""),
                "title": entry.get("title", ""),
                "content": content[:500],
                "score": score,
            })
    return results


def search_task_memory(l3_root: Path, target_host: str, category: str) -> list[dict]:
    base = l3_root / "experience" / "task-memory"
    index = read_json(base / "index.json", {"entries": []})
    results = []
    for entry in index.get("entries", []):
        entry_path = base / entry.get("path", "")
        if not entry_path.exists():
            continue
        content = read_text(entry_path)
        score = compute_score(content, entry, target_host, category)
        if score > 0:
            results.append({
                "source": "task-memory",
                "id": entry.get("id", ""),
                "status": entry.get("status", ""),
                "content": content[:500],
                "score": score,
            })
    return results


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: retrieve_l3.py <l3_root> [--target <target>] [--category <cat>] [--limit <n>]", file=sys.stderr)
        sys.exit(1)

    l3_root = Path(args[0]).resolve()
    target = ""
    category = ""
    limit = 5

    i = 1
    while i < len(args):
        if args[i] == "--target" and i + 1 < len(args):
            target = args[i + 1]
            i += 2
        elif args[i] == "--category" and i + 1 < len(args):
            category = args[i + 1]
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        else:
            i += 1

    target_host = extract_host(target)
    if not target_host and not category:
        print("Provide --target or --category to search", file=sys.stderr)
        sys.exit(1)

    results = []
    results.extend(search_knowledge_mapping(l3_root, target_host, category))
    results.extend(search_rag(l3_root, target_host, category))
    results.extend(search_task_memory(l3_root, target_host, category))

    # Sort by relevance score descending
    results.sort(key=lambda r: r.get("score", 0), reverse=True)
    results = results[:limit]

    if not results:
        print("No relevant L3 knowledge found.")
        return

    print(f"# L3 Knowledge: {target_host or category}")
    print(f"\nFound {len(results)} relevant entries (sorted by relevance):\n")

    for r in results:
        score = r.get("score", 0)
        print(f"## [{r['source']}] {r.get('id', r.get('title', ''))} (score: {score:.1f})")
        if r.get("category"):
            print(f"- Category: {r['category']}")
        if r.get("severity"):
            print(f"- Severity: {r['severity']}")
        print()
        print(r.get("content", "")[:300])
        print()
        print("---")
        print()


if __name__ == "__main__":
    main()
