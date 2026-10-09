"""
report_emitter.py: 审计报告落盘器（Markdown + JSON 双通道）

将 batch_differential_scan 的扫描结果序列化为确定性报告：

- Markdown: 人类可读的判定分布总表 + 漏洞明细表；
- JSON: 机器可消费的完整证据链（verdict_distribution + results）。

文件名约定：``audit_<YYYYMMDD_HHMMSS>.{md,json}``（同一次调用时间戳一致）。
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from typing import Any

# 判定分布固定展示顺序（保证 Markdown 总表稳定可 diff）
VERDICT_ORDER: list[str] = [
    "VULNERABLE",
    "PRIV_ESCALATION",
    "SUSPECT",
    "SAFE",
    "LIKELY_SAFE",
    "BLOCKED",
    "INCONCLUSIVE",
    "ERROR",
]


def _now_stamp() -> str:
    """统一的文件名时间戳（同一次调用内 md/json 一致）。"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _normalize_results(scan_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not scan_results:
        return []
    return [r for r in scan_results if isinstance(r, dict)]


def _verdict_of(result: dict[str, Any]) -> str:
    verdict = result.get("verdict", "UNKNOWN")
    return str(verdict).upper() if verdict is not None else "UNKNOWN"


def _build_markdown(
    doc: dict[str, Any],
    results: list[dict[str, Any]],
    distribution: dict[str, int],
) -> str:
    lines: list[str] = []
    lines.append("# API 越权差分审计报告")
    lines.append("")
    lines.append(f"- 生成时间: `{doc['generated_at']}`")
    lines.append(f"- 扫描编号: `{doc['scan_id']}`")
    lines.append(f"- 目标程序: `{doc['program_name']}`")
    lines.append(f"- 端点总数: **{doc['total_endpoints']}**")
    lines.append("")

    lines.append("## 判定分布")
    lines.append("")
    lines.append("| 判定 | 数量 |")
    lines.append("|---|---:|")
    for verdict in VERDICT_ORDER:
        lines.append(f"| {verdict} | {distribution.get(verdict, 0)} |")
    # 非标准判定（防御性展示，防未来新增判定被静默丢弃）
    for verdict in sorted(set(distribution) - set(VERDICT_ORDER)):
        lines.append(f"| {verdict} | {distribution[verdict]} |")
    lines.append("")

    vulnerable = [r for r in results if _verdict_of(r) == "VULNERABLE"]
    lines.append("## 漏洞明细")
    lines.append("")
    if vulnerable:
        lines.append("| 端点 | 方法 | 判定 | 置信度 | 相似度 | primary | secondary |")
        lines.append("|---|---|---|---:|---:|---:|---:|")
        for r in vulnerable:
            endpoint = str(r.get("endpoint", r.get("url", "UNKNOWN")))
            method = str(r.get("method", "-"))
            confidence = r.get("confidence", 0.0)
            similarity = r.get("similarity", 0.0)
            primary_status = r.get("primary_status", 0)
            secondary_status = r.get("secondary_status", 0)
            lines.append(
                f"| {endpoint} | {method} | {_verdict_of(r)} "
                f"| {confidence} | {similarity} | {primary_status} | {secondary_status} |"
            )
        lines.append("")
        lines.append("## 证据链")
        lines.append("")
        for r in vulnerable:
            endpoint = str(r.get("endpoint", r.get("url", "UNKNOWN")))
            lines.append(f"### {endpoint}")
            lines.append("")
            root_cause = r.get("technical_root_cause") or (
                r.get("evidence", {}) or {}
            ).get("technical_root_cause", "Differential access scan completed.")
            lines.append(f"- 根因: {root_cause}")
            evidence = r.get("evidence", {})
            if isinstance(evidence, dict) and evidence:
                lines.append(f"- 证据: `{json.dumps(evidence, ensure_ascii=False, default=str)}`")
            lines.append("")
    else:
        lines.append("本轮扫描未发现 VULNERABLE 判定端点。")
        lines.append("")

    lines.append("## 全量结果")
    lines.append("")
    if results:
        lines.append("| 端点 | 判定 | 置信度 |")
        lines.append("|---|---|---:|")
        for r in results:
            endpoint = str(r.get("endpoint", r.get("url", "UNKNOWN")))
            lines.append(f"| {endpoint} | {_verdict_of(r)} | {r.get('confidence', 0.0)} |")
    else:
        lines.append("（空结果集）")
    lines.append("")
    return "\n".join(lines)


def emit_audit_report(
    scan_results: list[dict[str, Any]] | None = None,
    output_dir: str = ".",
    scan_id: str = "",
    program_name: str = "",
) -> dict[str, Any]:
    """
    将扫描结果落盘为 Markdown + JSON 双通道审计报告。

    Args:
        scan_results: batch_differential_scan 风格的结果列表（可为空）。
        output_dir: 输出目录（不存在则递归创建）。
        scan_id: 扫描编号（缺省时由时间戳生成）。
        program_name: 目标程序名（可选，仅写入报告头部）。

    Returns:
        ``{"status": "DELIVERED", "markdown_path", "json_path",
        "verdict_distribution", "total_endpoints", ...}``
    """
    results = _normalize_results(scan_results)
    stamp = _now_stamp()

    counter: Counter = Counter(_verdict_of(r) for r in results)
    distribution: dict[str, int] = {v: counter.get(v, 0) for v in VERDICT_ORDER}
    for verdict, count in counter.items():
        if verdict not in distribution:
            distribution[verdict] = count

    generated_at = datetime.now().isoformat(timespec="seconds")
    resolved_scan_id = scan_id or f"SCAN-{stamp}"

    doc: dict[str, Any] = {
        "generated_at": generated_at,
        "scan_id": resolved_scan_id,
        "program_name": program_name,
        "total_endpoints": len(results),
        "verdict_distribution": distribution,
        "vulnerable_count": distribution.get("VULNERABLE", 0),
        "results": results,
    }

    os.makedirs(output_dir, exist_ok=True)
    md_path = os.path.join(output_dir, f"audit_{stamp}.md")
    json_path = os.path.join(output_dir, f"audit_{stamp}.json")

    markdown = _build_markdown(doc, results, distribution)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, default=str)

    return {
        "status": "DELIVERED",
        "markdown_path": md_path,
        "json_path": json_path,
        "scan_id": resolved_scan_id,
        "generated_at": generated_at,
        "total_endpoints": len(results),
        "verdict_distribution": distribution,
    }
