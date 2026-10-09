"""
pipeline_orchestrator.py: 全链路自动化审计编排器

把割裂的模块编排为一条确定性流水线（Spec → Ingest → Scan → PoC → Bounty → Report）：

    sources (OpenAPI 白盒 / HAR 黑盒)
        → 摄入与对象级引用识别
        → 范围过滤（ScopePolicy，out_of_scope_filtered）
        → 批量差分扫描（run_batch_scan，P0-INVARIANT-03 熔断 + 对抗门禁）
        → PoC 报告构建（severity 分级 + 请求头发敏）
        → 赏金估算
        → 报告落盘（emit_audit_report，可选）

输出结构与 tests/test_pipeline_contract.py 的 PipelineResult 契约对齐：
pipeline_id / ingestion / scan / poc / target_matrix / scan_result /
poc_reports / estimated_bounty / bounty_breakdown / status / errors。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .batch_scan import run_batch_scan
from .har_ingestor import parse_har
from .openapi import (
    filter_auditable,
    filter_safe_methods,
    parse_openapi_spec,
)
from .poc_builder import build_poc_reports, estimate_bounty, severity_distribution
from .report_emitter import emit_audit_report
from .scope import ScopePolicy


@dataclass
class PipelineSource:
    """
    流水线摄入源。

    Args:
        source_type: ``"openapi"`` 或 ``"har"``。
        content: OpenAPI/HAR 的 JSON 字符串或文件路径。
        base_url_override: 覆盖 spec 中的 servers/host（仅 openapi 生效）。
    """
    source_type: str  # "openapi" | "har"
    content: str
    base_url_override: str = ""

    def __post_init__(self) -> None:
        st = (self.source_type or "").lower()
        if st not in ("openapi", "har"):
            raise ValueError(f"INVALID_SOURCE_TYPE: 仅支持 openapi/har，得到 {self.source_type!r}")
        self.source_type = st
        if not self.content or not str(self.content).strip():
            raise ValueError("EMPTY_SOURCE_CONTENT: 摄入源内容为空")


@dataclass
class PipelineConfig:
    """流水线配置（全部具备安全默认值）。"""
    program_id: str = "PROG-AUTO"
    program_name: str = "Automated Audit Program"
    primary_token: str = ""
    secondary_token: str = ""
    secret_key: str = ""
    allow_write: bool = False  # P0-INVARIANT-03：写操作默认熔断
    similarity_threshold: float = 0.85
    max_concurrency: int = 3
    interval_ms: int = 100
    fast_mode: bool = False
    timeout_per_request: float = 10.0
    mock_id_value: str = "1001"
    only_auditable: bool = False
    only_safe_methods: bool = False
    scope: ScopePolicy = field(default_factory=ScopePolicy)
    output_dir: str | None = None  # 非空时落盘审计报告
    ws_bridge_url: str = ""  # 非空时把工件推流至 WebSocket 网关（best-effort）


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ingest_sources(
    sources: list[PipelineSource],
    config: PipelineConfig,
    errors: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """摄入全部来源 → 范围过滤 → (target_matrix, ingestion_stats)。"""
    raw_matrix: list[dict[str, Any]] = []
    source_types: list[str] = []
    total_ingested = 0

    for source in sources:
        try:
            if source.source_type == "openapi":
                matrix = parse_openapi_spec(
                    spec_content_or_path=source.content,
                    base_url_override=source.base_url_override or None,
                    primary_headers=_identity_headers(config.primary_token),
                    secondary_headers=_identity_headers(config.secondary_token),
                    mock_id_value=config.mock_id_value,
                )
            else:  # har
                matrix = parse_har(
                    content_or_path=source.content,
                    primary_headers=_identity_headers(config.primary_token),
                    secondary_headers=_identity_headers(config.secondary_token),
                )
            total_ingested += len(matrix)
            raw_matrix.extend(matrix)
            source_types.append(source.source_type)
        except Exception as e:
            errors.append({
                "stage": "ingestion",
                "source_type": source.source_type,
                "error": str(e),
                "type": type(e).__name__,
            })

    # 范围过滤（授权边界硬约束）
    in_scope, out_of_scope = config.scope.filter_matrix(raw_matrix)

    # 可选的矩阵瘦身（初步扫描场景）
    if config.only_auditable:
        in_scope = filter_auditable(in_scope)
    if config.only_safe_methods:
        in_scope = filter_safe_methods(in_scope)

    ingestion = {
        "total_ingested": total_ingested,
        "in_scope": len(in_scope),
        "out_of_scope_filtered": out_of_scope,
        "auditable_count": sum(1 for e in in_scope if e.get("is_auditable")),
        "safe_method_count": sum(1 for e in in_scope if e.get("is_safe_method")),
        "sources": source_types,
    }
    return in_scope, ingestion


def _identity_headers(token: str) -> dict[str, str] | None:
    """token → 身份请求头；空 token 返回 None（沿用矩阵默认）。"""
    token = (token or "").strip()
    if not token:
        return None
    return {"Authorization": f"Bearer {_raw_token(token)}"}


def _raw_token(token: str) -> str:
    """
    剥离 token 的 scheme 前缀，得到裸 token。

    ``build_hook_chain`` 的 ``apply_bearer_token`` 会自动补 ``Bearer `` 前缀，
    因此下发给批量扫描引擎的 token 必须是裸值，避免 ``Bearer Bearer x`` 双前缀。
    """
    token = (token or "").strip()
    for scheme in ("bearer ", "basic ", "token "):
        if token.lower().startswith(scheme):
            return token[len(scheme):].strip()
    return token


def run_pipeline(
    sources: list[PipelineSource],
    config: PipelineConfig | None = None,
) -> dict[str, Any]:
    """
    执行一次全链路自动化审计。

    Args:
        sources: 摄入源列表（OpenAPI / HAR 可混合）。
        config: 流水线配置；缺省使用安全默认值。

    Returns:
        PipelineResult dict（契约见模块 docstring）。
    """
    config = config or PipelineConfig()
    if not sources:
        raise ValueError("EMPTY_SOURCES: 至少需要一个摄入源")

    errors: list[dict[str, Any]] = []
    pipeline_id = f"PIPE-{uuid.uuid4().hex[:12].upper()}"
    scan_id = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
    started_at = _iso_now()
    start_ts = time.time()

    # Phase 1: 摄入 + 范围过滤
    target_matrix, ingestion = _ingest_sources(sources, config, errors)

    # Phase 2: 批量差分扫描
    scan_result: dict[str, Any] = {
        "status": "SKIPPED",
        "scan_summary": {
            "total": 0, "vulnerable": 0, "safe": 0, "blocked": 0,
            "inconclusive": 0, "error": 0, "auditable_vulnerable": 0,
        },
        "elapsed_ms": 0.0,
        "concurrency": 0,
        "vulnerable_endpoints": [],
        "all_results": [],
    }
    if target_matrix:
        try:
            scan_result = run_batch_scan(
                target_matrix=target_matrix,
                max_concurrency=config.max_concurrency,
                interval_ms=config.interval_ms,
                allow_write=config.allow_write,
                secret_key=config.secret_key,
                primary_token=_raw_token(config.primary_token),
                secondary_token=_raw_token(config.secondary_token),
                similarity_threshold=config.similarity_threshold,
                fast_mode=config.fast_mode,
                timeout_per_request=config.timeout_per_request,
            )
        except Exception as e:
            errors.append({
                "stage": "scan",
                "error": str(e),
                "type": type(e).__name__,
            })

    scan_summary = scan_result.get("scan_summary", {})
    scan_stats = {
        "scan_id": scan_id,
        "status": "completed" if scan_result.get("status") == "DELIVERED" else "failed",
        "total_targets": ingestion["in_scope"],
        "scanned": scan_summary.get("total", 0),
        "vulnerable": scan_summary.get("vulnerable", 0),
        "safe": scan_summary.get("safe", 0),
        "blocked": scan_summary.get("blocked", 0),
        "inconclusive": scan_summary.get("inconclusive", 0),
        "error": scan_summary.get("error", 0),
        "elapsed_ms": scan_result.get("elapsed_ms", 0.0),
    }

    # Phase 3: PoC 构建 + 严重度分级
    poc_reports = build_poc_reports(scan_result.get("all_results", []))
    by_severity = severity_distribution(poc_reports)

    # Phase 4: 赏金估算
    estimated_bounty, bounty_breakdown = estimate_bounty(poc_reports)

    # Phase 5: 报告落盘（可选）
    report_paths: dict[str, str] = {}
    if config.output_dir:
        try:
            emitted = emit_audit_report(
                scan_results=scan_result.get("all_results", []),
                output_dir=config.output_dir,
                scan_id=scan_id,
                program_name=config.program_name,
            )
            report_paths = {
                "markdown_path": emitted["markdown_path"],
                "json_path": emitted["json_path"],
            }
        except Exception as e:
            errors.append({
                "stage": "report",
                "error": str(e),
                "type": type(e).__name__,
            })

    finished_at = _iso_now()
    elapsed_ms = round((time.time() - start_ts) * 1000, 2)

    # Phase 6: 工件推流（可选，best-effort，失败仅记录）
    pushed_artifacts = 0
    if config.ws_bridge_url and (poc_reports or scan_result.get("all_results")):
        try:
            pushed_artifacts = _push_artifacts(config, scan_result, poc_reports)
        except Exception as e:
            errors.append({
                "stage": "stream",
                "error": str(e),
                "type": type(e).__name__,
            })

    result: dict[str, Any] = {
        "pipeline_id": pipeline_id,
        "program_id": config.program_id,
        "program_name": config.program_name,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_ms": elapsed_ms,
        "ingestion": ingestion,
        "scan": scan_stats,
        "poc": {
            "total_vulnerabilities": len(poc_reports),
            "by_severity": by_severity,
        },
        "target_matrix": target_matrix,
        "scan_result": scan_result,
        "poc_reports": poc_reports,
        "estimated_bounty": estimated_bounty,
        "bounty_breakdown": bounty_breakdown,
        "status": "completed" if not errors else "completed_with_errors",
        "errors": errors,
        "report_paths": report_paths,
        "pushed_artifacts": pushed_artifacts,
    }
    return result


def _push_artifacts(
    config: PipelineConfig,
    scan_result: dict[str, Any],
    poc_reports: list[dict[str, Any]],
) -> int:
    """把 PoC 工件推流至 WebSocket 网关（延迟导入，避免强依赖 websockets）。"""
    from .pipeline_bridge import push_poc_artifacts

    return push_poc_artifacts(
        poc_reports=poc_reports,
        ws_url=config.ws_bridge_url,
        fallback_results=scan_result.get("all_results", []),
    )
