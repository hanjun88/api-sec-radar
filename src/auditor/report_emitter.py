"""
report_emitter.py: 审计报告双轨生成器
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def emit_audit_report(
    scan_results: List[Dict[str, Any]] = None,
    output_dir: str = "reports",
    scan_summary: Dict[str, Any] = None,
    elapsed_ms: float = 0.0,
    concurrency: int = 0,
    target_matrix_size: int = 0,
) -> Dict[str, Any]:
    if scan_results is None:
        scan_results = []
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)

    md_path = Path(output_dir) / f"audit_{timestamp}.md"
    json_path = Path(output_dir) / f"audit_{timestamp}.json"

    if scan_summary is None:
        scan_summary = _compute_summary(scan_results)

    verdict_dist = {
        "VULNERABLE": scan_summary.get("vulnerable", 0),
        "SAFE": scan_summary.get("safe", 0),
        "BLOCKED": scan_summary.get("blocked", 0),
        "INCONCLUSIVE": scan_summary.get("inconclusive", 0),
        "ERROR": scan_summary.get("error", 0),
    }

    vulnerable_items = [r for r in scan_results if r.get("verdict") == "VULNERABLE"]
    vulnerable_items.sort(key=lambda r: r.get("confidence", 0.0), reverse=True)

    md_content = _render_markdown(
        timestamp=timestamp,
        target_matrix_size=target_matrix_size or len(scan_results),
        verdict_dist=verdict_dist,
        vulnerable_items=vulnerable_items,
        elapsed_ms=elapsed_ms,
        concurrency=concurrency,
        scan_results=scan_results,
    )
    md_path.write_text(md_content, encoding="utf-8")

    json_content = {
        "timestamp": timestamp,
        "scan_time_utc": datetime.utcnow().isoformat() + "Z",
        "target_matrix_size": target_matrix_size or len(scan_results),
        "verdict_distribution": verdict_dist,
        "elapsed_ms": elapsed_ms,
        "concurrency": concurrency,
        "vulnerable_endpoints": [
            {
                "endpoint": r.get("endpoint"),
                "url": r.get("url"),
                "method": r.get("method"),
                "confidence": r.get("confidence"),
                "similarity": r.get("similarity"),
                "primary_status": r.get("primary_status"),
                "secondary_status": r.get("secondary_status"),
                "technical_root_cause": r.get("evidence", {}).get("technical_root_cause", r.get("technical_root_cause", "")),
            }
            for r in vulnerable_items
        ],
        "all_results": scan_results,
    }
    json_path.write_text(json.dumps(json_content, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "status": "DELIVERED",
        "markdown_path": str(md_path),
        "json_path": str(json_path),
        "timestamp": timestamp,
    }


def _compute_summary(results: List[Dict[str, Any]]) -> Dict[str, int]:
    stats = {
        "total": len(results),
        "vulnerable": 0,
        "safe": 0,
        "blocked": 0,
        "inconclusive": 0,
        "error": 0,
    }
    for r in results:
        v = str(r.get("verdict", "")).upper()
        if v == "VULNERABLE":
            stats["vulnerable"] += 1
        elif v == "SAFE":
            stats["safe"] += 1
        elif v == "BLOCKED":
            stats["blocked"] += 1
        elif v == "INCONCLUSIVE":
            stats["inconclusive"] += 1
        elif v == "ERROR":
            stats["error"] += 1
    return stats


def _render_markdown(
    timestamp: str,
    target_matrix_size: int,
    verdict_dist: Dict[str, int],
    vulnerable_items: List[Dict[str, Any]],
    elapsed_ms: float,
    concurrency: int,
    scan_results: List[Dict[str, Any]],
) -> str:
    lines = []
    lines.append("# API 越权审计报告")
    lines.append("")
    lines.append(f"**生成时间**: {timestamp} (UTC)")
    lines.append(f"**目标矩阵规模**: {target_matrix_size} 端点")
    lines.append(f"**扫描耗时**: {elapsed_ms:.2f} ms")
    lines.append(f"**并发度**: {concurrency}")
    lines.append("")

    lines.append("## 五态判定分布")
    lines.append("")
    lines.append("| 判定 | 数量 | 占比 |")
    lines.append("|------|------|------|")
    total = sum(verdict_dist.values()) or 1
    for verdict in ["VULNERABLE", "SAFE", "BLOCKED", "INCONCLUSIVE", "ERROR"]:
        count = verdict_dist.get(verdict, 0)
        pct = count / total * 100
        lines.append(f"| {verdict} | {count} | {pct:.1f}% |")
    lines.append("")

    if vulnerable_items:
        lines.append("## VULNERABLE 端点明细（按置信度降序）")
        lines.append("")
        lines.append("| # | 端点 | 方法 | 置信度 | 相似度 | Primary状态 | Secondary状态 | 根因 |")
        lines.append("|---|------|------|--------|--------|-------------|---------------|------|")
        for i, item in enumerate(vulnerable_items, 1):
            endpoint = item.get("endpoint", "N/A")
            method = item.get("method", "N/A")
            confidence = item.get("confidence", 0.0)
            similarity = item.get("similarity", 0.0)
            primary_status = item.get("primary_status", 0)
            secondary_status = item.get("secondary_status", 0)
            root_cause = item.get("evidence", {}).get("technical_root_cause", item.get("technical_root_cause", ""))
            if len(str(root_cause)) > 80:
                root_cause = str(root_cause)[:77] + "..."
            lines.append(f"| {i} | {endpoint} | {method} | {confidence:.2f} | {similarity:.2f} | {primary_status} | {secondary_status} | {root_cause} |")
        lines.append("")

    lines.append("## 证据链摘要")
    lines.append("")
    for item in scan_results:
        verdict = item.get("verdict", "UNKNOWN")
        if str(verdict) not in ("VULNERABLE", "BLOCKED"):
            continue
        endpoint = item.get("endpoint", "N/A")
        evidence = item.get("evidence", {})
        primary_status = evidence.get("primary_status", item.get("primary_status", 0))
        secondary_status = evidence.get("secondary_status", item.get("secondary_status", 0))
        similarity = evidence.get("similarity", item.get("similarity", 0.0))
        elapsed = evidence.get("elapsed_ms", item.get("elapsed_ms", 0))
        lines.append(f"- **{verdict}** `{endpoint}`: primary={primary_status}, secondary={secondary_status}, sim={similarity:.2f}, elapsed={elapsed}ms")
    lines.append("")

    lines.append("---")
    lines.append("*报告由 api-sec-radar 自动生成*")

    return "\n".join(lines)
