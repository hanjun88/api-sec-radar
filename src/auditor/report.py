"""
report.py: batch 扫描结果 → Markdown + JSON 审计报告落盘。

输入为 ``batch_differential_scan`` 的聚合输出（dict，含 ``all_results``
/``scan_summary``；也兼容裸 list 或单条结果 dict），输出一对同名
``.md`` / ``.json`` 报告文件。供 ``live_scan_feeder`` 或 MCP 工具调用。
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_VERDICT_ORDER = (
    "VULNERABLE",
    "PRIV_ESCALATION",
    "SUSPECT",
    "BLOCKED",
    "INCONCLUSIVE",
    "ERROR",
    "SAFE",
    "LIKELY_SAFE",
)


def _collect_results(scan_result: Any) -> List[Dict[str, Any]]:
    """兼容三种输入形状：聚合 dict / 裸 list / 单条结果 dict。"""
    if isinstance(scan_result, list):
        return [r for r in scan_result if isinstance(r, dict)]
    if isinstance(scan_result, dict):
        for key in ("all_results", "results", "scan_results", "vulnerabilities"):
            val = scan_result.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
        if "endpoint" in scan_result or "verdict" in scan_result:
            return [scan_result]
    return []


def _verdict_distribution(results: List[Dict[str, Any]]) -> Dict[str, int]:
    dist: Dict[str, int] = {}
    for r in results:
        v = str(r.get("verdict", "UNKNOWN")).upper()
        dist[v] = dist.get(v, 0) + 1
    ordered = {v: dist[v] for v in _VERDICT_ORDER if v in dist}
    ordered.update({v: c for v, c in dist.items() if v not in ordered})
    return ordered


def _evidence_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    ev = finding.get("evidence")
    ev = ev if isinstance(ev, dict) else {}
    return {
        "primary_status": ev.get("primary_status", finding.get("primary_status", 0)),
        "secondary_status": ev.get("secondary_status", finding.get("secondary_status", 0)),
        "similarity": ev.get("similarity", finding.get("similarity", 0.0)),
        "details": ev,
    }


def _render_markdown(
    target: str,
    scan_time: str,
    results: List[Dict[str, Any]],
    dist: Dict[str, int],
    total: int,
) -> str:
    lines = [
        "# API 差分审计报告",
        "",
        f"- **目标**: {target or '（未指定）'}",
        f"- **扫描时间**: {scan_time}",
        f"- **扫描条目数**: {total}",
        "",
        "## Verdict 分布",
        "",
        "| Verdict | 数量 |",
        "|---|---|",
    ]
    for v, c in dist.items():
        lines.append(f"| {v} | {c} |")
    if not dist:
        lines.append("| （无结果） | 0 |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not results:
        lines.append("（本轮扫描未产出任何 finding。）")
        lines.append("")
    for i, r in enumerate(results, 1):
        endpoint = r.get("endpoint", r.get("url", "UNKNOWN"))
        verdict = str(r.get("verdict", "UNKNOWN")).upper()
        confidence = r.get("confidence", r.get("confidence_score", 0.0))
        ev = _evidence_summary(r)
        lines.append(f"### {i}. `{endpoint}`")
        lines.append("")
        lines.append(f"- **verdict**: {verdict}")
        lines.append(f"- **confidence**: {confidence}")
        lines.append(f"- **primary_status**: {ev['primary_status']}")
        lines.append(f"- **secondary_status**: {ev['secondary_status']}")
        lines.append(f"- **similarity**: {ev['similarity']}")
        detail_str = json.dumps(ev["details"], ensure_ascii=False, indent=2)
        lines.append("- **evidence**:")
        lines.append("")
        lines.append("```json")
        lines.append(detail_str)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def emit_audit_report(
    scan_result: Any,
    target: str = "",
    output_dir: str = "reports",
    scan_time: Optional[str] = None,
) -> Dict[str, Any]:
    """将 batch 扫描结果渲染为 Markdown + JSON 审计报告并落盘。

    Args:
        scan_result: ``batch_differential_scan`` 聚合输出（dict 含
            ``all_results``；也兼容裸 list / 单条结果 dict）。
        target: 扫描目标（如基址 URL）；为空时尝试从结果首条 url 推断。
        output_dir: 报告落盘目录（不存在则创建）。
        scan_time: ISO 时间戳；为空时取当前 UTC 时间。

    Returns:
        ``{"markdown_path", "json_path", "finding_count",
        "verdict_distribution"}``。返回绝对路径。
    """
    results = _collect_results(scan_result)
    dist = _verdict_distribution(results)
    total = len(results)
    stamp = scan_time or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not target and results:
        first = results[0]
        target = str(first.get("url") or first.get("endpoint") or "")

    os.makedirs(output_dir, exist_ok=True)
    slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = os.path.abspath(os.path.join(output_dir, f"audit-report-{slug}.md"))
    json_path = os.path.abspath(os.path.join(output_dir, f"audit-report-{slug}.json"))

    md_body = _render_markdown(target, stamp, results, dist, total)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_body)

    findings = [
        {
            "endpoint": r.get("endpoint", r.get("url", "UNKNOWN")),
            "verdict": str(r.get("verdict", "UNKNOWN")).upper(),
            "confidence": r.get("confidence", r.get("confidence_score", 0.0)),
            "evidence": _evidence_summary(r),
        }
        for r in results
    ]
    json_doc = {
        "target": target,
        "scan_time": stamp,
        "finding_count": total,
        "verdict_distribution": dist,
        "findings": findings,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_doc, f, ensure_ascii=False, indent=2)

    return {
        "markdown_path": md_path,
        "json_path": json_path,
        "finding_count": total,
        "verdict_distribution": dist,
    }
