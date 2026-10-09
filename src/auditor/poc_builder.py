"""
poc_builder.py: 漏洞 PoC 报告构建器

将 scan_result 单条结果升成为可直接提交漏洞平台的 PoCReport：

- severity 分级：BOLA/IDOR + 高相似度 → critical，其余按判定降级；
- 赏金估算：severity → 金额映射表（与 sample_pipeline_result 契约对齐）；
- 请求头发敏（***REDACTED***），证据链透传，附带修复建议。
"""

from __future__ import annotations

import uuid
from typing import Any

from .batch_scan import RICH_EVIDENCE_VERDICTS

# 纳入 PoC 生成的判定（高风险判定）——单一事实来源在 batch_scan
POC_VERDICTS = set(RICH_EVIDENCE_VERDICTS)

# Severity 固定顺序（报告展示与统计用）
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

# 赏金估算表（USD）：与契约样例 (critical 5000 + high 4000 = 9000) 对齐
BOUNTY_TABLE: dict[str, float] = {
    "critical": 5000.0,
    "high": 2000.0,
    "medium": 500.0,
    "low": 100.0,
    "informational": 0.0,
}

# 严重度 → 修复建议
_REMEDIATION_HINTS = {
    "BOLA/IDOR": (
        "Bind object lookup to the caller identity "
        "(e.g. filter by current_user.tenant_id / owner_id) and return a "
        "uniform 404 for foreign objects to avoid resource existence disclosure."
    ),
    "BFLA": (
        "Enforce function-level authorization: verify the caller role before "
        "dispatching privileged operations, not only authentication."
    ),
    "PRIV_ESCALATION": (
        "Audit the privilege resolution chain: the secondary identity must not "
        "receive elevated access; re-validate role claims server-side."
    ),
}


def _new_poc_id() -> str:
    return f"POC-{uuid.uuid4().hex[:12].upper()}"


def classify_severity(result: dict[str, Any]) -> str:
    """根据判定 + 可审计性 + 相似度划分 severity。"""
    verdict = str(result.get("verdict", "")).upper()
    auditable = bool(result.get("is_auditable"))
    similarity = float(result.get("similarity", 0.0) or 0.0)

    if verdict == "VULNERABLE":
        if auditable and similarity >= 0.95:
            return "critical"
        return "high"
    if verdict == "PRIV_ESCALATION":
        return "high"
    if verdict == "SUSPECT":
        return "medium"
    return "low"


def _vulnerability_type(result: dict[str, Any]) -> str:
    verdict = str(result.get("verdict", "")).upper()
    if verdict == "PRIV_ESCALATION":
        return "PRIV_ESCALATION"
    if result.get("is_auditable"):
        return "BOLA/IDOR"
    return "BFLA"


def build_poc_report(result: dict[str, Any]) -> dict[str, Any]:
    """
    将单条 scan_result 构建为 PoCReport dict。

    仅对 POC_VERDICTS 中的判定生成；其它判定返回空 dict（调用方应过滤）。
    """
    verdict = str(result.get("verdict", "")).upper()
    if verdict not in POC_VERDICTS:
        return {}

    severity = classify_severity(result)
    vuln_type = _vulnerability_type(result)
    method = str(result.get("method", "GET")).upper()
    url = str(result.get("url", ""))
    endpoint = str(result.get("endpoint", f"{method} {url}"))

    evidence = result.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    primary_status = int(result.get("primary_status", 0) or 0)
    secondary_status = int(result.get("secondary_status", 0) or 0)
    similarity = float(result.get("similarity", 0.0) or 0.0)

    root_cause = (
        result.get("technical_root_cause")
        or evidence.get("technical_root_cause")
        or "Differential access scan completed without an enforced ownership check."
    )

    return {
        "poc_id": _new_poc_id(),
        "endpoint": endpoint,
        "method": method,
        "url": url,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "confidence": float(result.get("confidence", 0.0) or 0.0),
        "similarity": similarity,
        "primary_status": primary_status,
        "secondary_status": secondary_status,
        "primary_request": {
            "method": method,
            "url": url,
            "headers": {"Authorization": "***REDACTED***"},
            "expected_status": primary_status,
        },
        "secondary_request": {
            "method": method,
            "url": url,
            "headers": {"Authorization": "***REDACTED***"},
            "expected_status": secondary_status,
        },
        "evidence": {
            "status_match": evidence.get(
                "status_match", primary_status == secondary_status
            ),
            "primary_status": primary_status,
            "secondary_status": secondary_status,
            "similarity": similarity,
            "threshold": evidence.get("threshold", 0.85),
            "content_length_delta": evidence.get("content_length_delta", 0),
        },
        "root_cause": str(root_cause),
        "remediation_hint": _REMEDIATION_HINTS.get(
            vuln_type, "Enforce caller-bound authorization checks server-side."
        ),
    }


def build_poc_reports(
    scan_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """批量构建 PoCReport（按 confidence 降序，便于人工复核）。"""
    reports: list[dict[str, Any]] = []
    for r in scan_results or []:
        if not isinstance(r, dict):
            continue
        report = build_poc_report(r)
        if report:
            reports.append(report)
    reports.sort(key=lambda r: r.get("confidence", 0.0), reverse=True)
    return reports


def severity_distribution(poc_reports: list[dict[str, Any]]) -> dict[str, int]:
    """severity 分布（固定键集合，便于前端/报告稳定消费）。"""
    dist: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for report in poc_reports or []:
        sev = str(report.get("severity", "informational"))
        dist[sev] = dist.get(sev, 0) + 1
    return dist


def estimate_bounty(poc_reports: list[dict[str, Any]]) -> tuple[float, dict[str, float]]:
    """
    估算赏金总额与分级明细。

    Returns:
        ``(estimated_bounty, bounty_breakdown)``。
    """
    breakdown: dict[str, float] = {}
    total = 0.0
    for report in poc_reports or []:
        sev = str(report.get("severity", "informational"))
        amount = BOUNTY_TABLE.get(sev, 0.0)
        breakdown[sev] = breakdown.get(sev, 0.0) + amount
        total += amount
    return round(total, 2), breakdown
