"""
artifact_contract.py: VulnEvidencePayload 工件契约（全链路数据总线格式）

态势大屏（Layer 3）消费的统一工件结构。审计引擎（Layer 1）产出、
数据中继（Layer 2）广播的都是这一契约：

    {
      "endpoint": str,
      "verdict": "VULNERABLE" | "SAFE" | "BLOCKED" | "INCONCLUSIVE",
      "confidence": float,
      "evidence": {
          "primary_status", "secondary_status", "response_similarity",
          "elapsed_ms", "timestamp"
      },
      "technical_root_cause": str
    }
"""

from __future__ import annotations

import time
from typing import Any


def normalize_verdict(raw: str) -> str:
    """将审计引擎的原始判定映射为前端三态枚举。"""
    upper = str(raw).upper()
    if "VULN" in upper or "BOLA" in upper or "BROKEN" in upper:
        return "VULNERABLE"
    if "BLOCK" in upper or "SAFE_GUARD" in upper or "INVARIANT" in upper:
        return "BLOCKED"
    if "SAFE" in upper or "SECURE" in upper or "OK" in upper:
        return "SAFE"
    return "INCONCLUSIVE"


def _evidence_block(
    evidence: Any, fallback: dict[str, Any] | None = None
) -> dict[str, Any]:
    """统一提取证据块（兼容 scan_result 内嵌/外层两种布局）。"""
    fallback = fallback or {}
    if not isinstance(evidence, dict):
        evidence = {}
    return {
        "primary_status": int(evidence.get("primary_status", fallback.get("primary_status", 0)) or 0),
        "secondary_status": int(
            evidence.get("secondary_status", fallback.get("secondary_status", 0)) or 0
        ),
        # 生产者（core.execute / batch_scan）发 "similarity"；
        # 兼容旧布局的 "response_similarity"，优先读前者，
        # 否则 dashboard 相似度恒为 0.0
        "response_similarity": float(
            evidence.get("similarity",
                         evidence.get("response_similarity",
                                      fallback.get("similarity",
                                                   fallback.get("response_similarity", 0.0)))
                         ) or 0.0
        ),
        "elapsed_ms": int(evidence.get("elapsed_ms", fallback.get("elapsed_ms", 0)) or 0),
        "timestamp": int(time.time() * 1000),
    }


def build_artifact_from_scan_result(scan_item: dict[str, Any]) -> dict[str, Any]:
    """将 batch_differential_scan 的单条结果转换为 VulnEvidencePayload。"""
    endpoint = scan_item.get("endpoint", scan_item.get("url", "UNKNOWN"))
    verdict_raw = scan_item.get("verdict", scan_item.get("vulnerability_detected", "UNKNOWN"))
    if isinstance(verdict_raw, bool):
        verdict_raw = "VULNERABLE" if verdict_raw else "SAFE"
    verdict = normalize_verdict(str(verdict_raw))

    return {
        "endpoint": endpoint,
        "verdict": verdict,
        "confidence": float(
            scan_item.get("confidence_score", scan_item.get("confidence", 0.8))
        ),
        "evidence": _evidence_block(scan_item.get("evidence", {}), scan_item),
        "technical_root_cause": scan_item.get(
            "root_cause_analysis",
            scan_item.get("technical_root_cause", "Differential access scan completed."),
        ),
    }


def build_artifact_from_poc(poc_report: dict[str, Any]) -> dict[str, Any]:
    """将 PoCReport 转换为 VulnEvidencePayload（severity → verdict 归一）。"""
    severity = str(poc_report.get("severity", "medium")).lower()
    if severity in ("critical", "high", "medium"):
        verdict = "VULNERABLE"
    elif severity == "low":
        verdict = "INCONCLUSIVE"
    else:
        verdict = "SAFE"

    evidence = poc_report.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    return {
        "endpoint": poc_report.get("endpoint", poc_report.get("url", "UNKNOWN")),
        "verdict": verdict,
        "confidence": float(poc_report.get("confidence", 0.8)),
        "evidence": _evidence_block(evidence, poc_report),
        "technical_root_cause": poc_report.get(
            "root_cause", "Differential access scan completed."
        ),
    }


def build_artifacts(
    poc_reports: list[dict[str, Any]] | None = None,
    scan_results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    构建推送工件流：优先 PoC 报告；无 PoC 时回退扫描结果。

    优先级：PoC（已分级、已发敏）> 原始扫描结果。
    """
    artifacts: list[dict[str, Any]] = []
    if poc_reports:
        artifacts.extend(build_artifact_from_poc(p) for p in poc_reports if isinstance(p, dict))
    elif scan_results:
        artifacts.extend(
            build_artifact_from_scan_result(r) for r in scan_results if isinstance(r, dict)
        )
    return artifacts
