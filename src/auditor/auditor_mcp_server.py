"""
api_access_auditor/server.py — MCP 服务入口

启动: python -m api_access_auditor.server
传输: stdio

工具面（MCP Python SDK v2 MCPServer）：
- differential_access_test / probe_endpoint: 单端点差分审计
- ingest_openapi: OpenAPI/Swagger 契约摄入（白盒通道）
- batch_differential_scan(_fast): 批量差分扫描
- emit_audit_report: 扫描结果落盘（Markdown + JSON）
- run_full_pipeline: 全链路自动化审计（摄入→扫描→PoC→赏金→报告→推流）
- verify_remediation: 修复补丁静态 AST 验证
"""

from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from mcp.server.mcpserver import MCPServer

from .batch_scan import run_batch_scan
from .core import (
    ApiAccessAuditor,
    DifferentialTestInput,
    RequestIdentity,
)
from .multi_agent import (
    AgentContext,
    AuditOrchestrator,
    DiffAgent,
    EvidenceAgent,
    ParallelPipeline,
    ReconAgent,
    RemediationAgent,
)
from .openapi import filter_auditable, filter_safe_methods, parse_openapi_spec
from .pipeline_orchestrator import (
    PipelineConfig,
    PipelineSource,
    run_pipeline,
)
from .report_emitter import emit_audit_report as emit_report
from .sandbox_verifier import verify_python_patch
from .scope import ScopePolicy

mcp = MCPServer("api-access-auditor")
_auditor = ApiAccessAuditor()
_orchestrator = AuditOrchestrator()


def _coerce_headers(raw: str | dict[str, str] | None) -> dict[str, str]:
    """兼容 dict 或 JSON string 两种 headers 入参。"""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        return json.loads(raw)
    return {}


@mcp.tool()
def differential_access_test(
    url: str,
    method: str = "GET",
    primary_headers: str | dict[str, str] | None = None,
    secondary_headers: str | dict[str, str] | None = None,
    primary_label: str = "primary",
    secondary_label: str = "secondary",
    primary_body: str = "",
    secondary_body: str = "",
    similarity_threshold: float = 0.85,
    allow_write: bool = False,
) -> dict[str, Any]:
    """
    API 访问控制差分测试。
    对同一端点发送两个不同身份的请求，对比状态码与响应体相似度，
    判定是否存在越权（IDOR / BOLA）。输出确定性证据链。
    """
    try:
        ph = _coerce_headers(primary_headers)
        sh = _coerce_headers(secondary_headers)
    except json.JSONDecodeError as e:
        return {"status": "FAIL", "error": f"headers 解析失败: {e}"}

    try:
        params = DifferentialTestInput(
            primary=RequestIdentity(
                label=primary_label, method=method, url=url,
                headers=ph, body=primary_body or None,
            ),
            secondary=RequestIdentity(
                label=secondary_label, method=method, url=url,
                headers=sh, body=secondary_body or None,
            ),
            similarity_threshold=similarity_threshold,
            allow_write=allow_write,
        )
    except ValueError as e:
        return {"status": "VALIDATION_ERROR", "error_detail": str(e)}

    result = _auditor.execute(params)
    return {
        "status": "DELIVERED",
        "verdict": result.verdict,
        "confidence": result.confidence,
        "similarity": result.similarity,
        "primary": result.primary.model_dump(),
        "secondary": result.secondary.model_dump(),
        "evidence": result.evidence,
    }


@mcp.tool()
def probe_endpoint(
    url: str,
    method: str = "GET",
    headers: str | dict[str, str] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    端点探测：发送单次请求，返回状态码、响应指纹与耗时。
    """
    try:
        hdrs = _coerce_headers(headers)
    except json.JSONDecodeError as e:
        return {"status": "FAIL", "error": f"headers 解析失败: {e}"}

    try:
        identity = RequestIdentity(
            label="probe", method=method, url=url, headers=hdrs, timeout=timeout,
        )
    except ValueError as e:
        return {"status": "VALIDATION_ERROR", "error_detail": str(e)}

    params = DifferentialTestInput(primary=identity, secondary=identity)
    result = _auditor.execute(params)
    return {
        "status": "DELIVERED",
        "status_code": result.primary.status_code,
        "content_length": result.primary.content_length,
        "content_hash": result.primary.content_hash,
        "content_type": result.primary.content_type,
        "elapsed_ms": result.primary.elapsed_ms,
        "body_preview": result.primary.body_preview,
    }


@mcp.tool()
def ingest_openapi(
    spec_content_or_path: str,
    base_url_override: str = "",
    secondary_headers_json: str = "",
    primary_headers_json: str = "",
    mock_id_value: str = "1001",
    only_auditable: bool = False,
    only_safe_methods: bool = False,
) -> dict[str, Any]:
    """
    摄入 OpenAPI 3.0 / Swagger 2.0 规范文档，输出标准化待测矩阵。
    白盒契约文档通道，与 HAR 黑盒流量通道同构，下游可直接批量差分扫描。
    """
    try:
        secondary_headers = (
            json.loads(secondary_headers_json) if secondary_headers_json.strip() else None
        )
        primary_headers = (
            json.loads(primary_headers_json) if primary_headers_json.strip() else None
        )
    except json.JSONDecodeError as e:
        return {"status": "FAIL", "error": f"headers_json 解析失败: {e}"}

    try:
        matrix = parse_openapi_spec(
            spec_content_or_path=spec_content_or_path,
            base_url_override=base_url_override or None,
            secondary_headers=secondary_headers,
            primary_headers=primary_headers,
            mock_id_value=mock_id_value,
        )
    except (OSError, ValueError) as e:
        # ValueError 覆盖 json.JSONDecodeError 与路径 allowlist 拒绝
        # （PATH_NOT_ALLOWED / SPEC_PATH_INVALID）
        return {"status": "FAIL", "error": f"OpenAPI 解析失败: {e}"}

    total = len(matrix)
    if only_auditable:
        matrix = filter_auditable(matrix)
    if only_safe_methods:
        matrix = filter_safe_methods(matrix)

    return {
        "status": "DELIVERED",
        "total_endpoints": total,
        "returned_endpoints": len(matrix),
        "auditable_count": sum(1 for e in matrix if e.get("is_auditable")),
        "safe_method_count": sum(1 for e in matrix if e.get("is_safe_method")),
        "target_matrix": matrix,
    }


@mcp.tool()
def batch_differential_scan(
    target_matrix: list[dict[str, Any]],
    max_concurrency: int = 3,
    interval_ms: int = 100,
    allow_write: bool = False,
    secret_key: str = "",
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
    timeout_per_request: float = 10.0,
    only_auditable: bool = False,
) -> dict[str, Any]:
    """
    批量执行待测矩阵差分扫描。
    - 并发度按矩阵规模分级自适应（≤100→max, 101-500→min(max,5),
      501-2000→min(max,8), >2000→min(max,10)），上限 10
    - 非幂等写操作受 P0-INVARIANT-03 熔断保护
    - 动态 Hook：每条请求重新计算 Timestamp/Nonce/HMAC 签名
    - 错误隔离：单条失败不影响整体
    - 限速 interval 下沉到 worker 线程，不阻塞任务提交
    - 结果 >100 条时自动压缩非漏洞条目证据
    - 聚合输出：按 VULNERABLE/SAFE/BLOCKED/INCONCLUSIVE/ERROR 分类统计
    - only_auditable=True 时先过滤非 auditable 端点（如 /health），
      被过滤条数见返回值的 skipped_non_auditable（默认 False，保持兼容）
    """
    return run_batch_scan(
        target_matrix=target_matrix,
        max_concurrency=max_concurrency,
        interval_ms=interval_ms,
        allow_write=allow_write,
        secret_key=secret_key,
        primary_token=primary_token,
        secondary_token=secondary_token,
        similarity_threshold=similarity_threshold,
        fast_mode=False,
        timeout_per_request=timeout_per_request,
        only_auditable=only_auditable,
    )


@mcp.tool()
def batch_differential_scan_fast(
    target_matrix: list[dict[str, Any]],
    max_concurrency: int = 3,
    interval_ms: int = 100,
    allow_write: bool = False,
    secret_key: str = "",
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
    timeout_per_request: float = 10.0,
    only_auditable: bool = False,
) -> dict[str, Any]:
    """
    批量差分扫描的快速变体：跳过非 auditable 端点的详细证据收集，
    只收集 verdict 与关键状态码，适用于大规模初步扫描（1000+ 端点）。

    与 batch_differential_scan 接口完全一致，仅证据收集更轻量；
    only_auditable=True 时先过滤非 auditable 端点再扫描（默认 False）。
    """
    return run_batch_scan(
        target_matrix=target_matrix,
        max_concurrency=max_concurrency,
        interval_ms=interval_ms,
        allow_write=allow_write,
        secret_key=secret_key,
        primary_token=primary_token,
        secondary_token=secondary_token,
        similarity_threshold=similarity_threshold,
        fast_mode=True,
        timeout_per_request=timeout_per_request,
        only_auditable=only_auditable,
    )


@mcp.tool()
def emit_audit_report(
    scan_results: list[dict[str, Any]],
    output_dir: str = "audit_reports",
    scan_id: str = "",
    program_name: str = "",
) -> dict[str, Any]:
    """
    将扫描结果落盘为 Markdown + JSON 双通道审计报告。

    - 文件名：audit_<YYYYMMDD_HHMMSS>.{md,json}（同一次调用时间戳一致）
    - JSON 含 verdict_distribution 与全量结果；Markdown 含判定分布总表与漏洞明细
    - output_dir 不存在时递归创建
    """
    return emit_report(
        scan_results=scan_results,
        output_dir=output_dir,
        scan_id=scan_id,
        program_name=program_name,
    )


@mcp.tool()
def run_full_pipeline(
    openapi_spec: str = "",
    har_content: str = "",
    base_url_override: str = "",
    program_id: str = "PROG-AUTO",
    program_name: str = "Automated Audit Program",
    primary_token: str = "",
    secondary_token: str = "",
    secret_key: str = "",
    allow_write: bool = False,
    similarity_threshold: float = 0.85,
    max_concurrency: int = 3,
    interval_ms: int = 100,
    timeout_per_request: float = 10.0,
    mock_id_value: str = "1001",
    only_auditable: bool = False,
    fast_mode: bool = False,
    output_dir: str = "",
    ws_bridge_url: str = "",
    scope_include_hosts: str = "",
    scope_include_paths: str = "",
    scope_exclude_paths: str = "",
) -> dict[str, Any]:
    """
    全链路自动化审计流水线：摄入 → 范围过滤 → 差分扫描 → PoC → 赏金 → 报告 → 推流。

    - openapi_spec / har_content 至少提供一个（JSON 字符串或文件路径）
    - scope_* 为逗号分隔的授权范围约束（host 精确/子域匹配 / 路径正则）
    - 非幂等写操作受 P0-INVARIANT-03 熔断保护（allow_write 默认 False）
    - ws_bridge_url 非空时，漏洞工件 best-effort 推送至 WebSocket 广播网关
    """
    sources: list[PipelineSource] = []
    if openapi_spec.strip():
        sources.append(PipelineSource(
            source_type="openapi",
            content=openapi_spec,
            base_url_override=base_url_override,
        ))
    if har_content.strip():
        sources.append(PipelineSource(source_type="har", content=har_content))
    if not sources:
        return {"status": "FAIL", "error": "openapi_spec 与 har_content 不能同时为空"}

    def _split_csv(raw: str) -> list[str]:
        return [p.strip() for p in (raw or "").split(",") if p.strip()]

    config = PipelineConfig(
        program_id=program_id,
        program_name=program_name,
        primary_token=primary_token,
        secondary_token=secondary_token,
        secret_key=secret_key,
        allow_write=allow_write,
        similarity_threshold=similarity_threshold,
        max_concurrency=max_concurrency,
        interval_ms=interval_ms,
        fast_mode=fast_mode,
        timeout_per_request=timeout_per_request,
        mock_id_value=mock_id_value,
        only_auditable=only_auditable,
        output_dir=output_dir or None,
        ws_bridge_url=ws_bridge_url,
        scope=ScopePolicy(
            include_hosts=_split_csv(scope_include_hosts) or None,
            include_path_patterns=_split_csv(scope_include_paths),
            exclude_path_patterns=_split_csv(scope_exclude_paths),
        ),
    )
    try:
        return run_pipeline(sources=sources, config=config)
    except Exception as e:
        return {"status": "FAIL", "error": str(e), "type": type(e).__name__}


@mcp.tool()
def verify_remediation(
    test_url: str,
    patch_code_snippet: str,
    original_handler_snippet: str = "",
    primary_token: str = "token-alice",
    secondary_token: str = "token-bob",
) -> dict[str, Any]:
    """
    对生成的修复补丁执行沙盒语法编译与行级安全语义断言。

    注意：本工具只做静态验证（AST 编译 + 行级语义特征），
    不做运行时复测。verified_safe 仅表示补丁源码包含
    租户绑定与 404 实体屏蔽特征，不保证运行时行为。
    物理状态码（primary_status_post_fix /
    secondary_status_post_fix）为静态推断值，非实测。

    验证流程：
    1. 静态编译检查（SyntaxError → COMPILE_ERROR）
    2. 行级安全语义断言（必须包含 tenant_id/owner_id/current_user/user_id + 404/NOT_FOUND）
    """
    result = verify_python_patch(
        test_url=test_url,
        original_handler_snippet=original_handler_snippet,
        patch_code_snippet=patch_code_snippet,
        primary_token=primary_token,
        secondary_token=secondary_token,
    )
    return {"status": "DELIVERED", **result}


# ── Multi-Agent 编排工具（蚁后 / 工蚁架构）──────────────


@mcp.tool()
def multi_agent_recon(
    urls: list[str],
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
) -> dict[str, Any]:
    """
    Multi-Agent 侦察：并行派发侦察蚁探测 URL 列表。

    蚁后（编排者）拆解 URL 列表 → MapReduce pipeline
    并行派发侦察蚁（只读 GET）→ 归巢汇总。
    侦察蚁只读，不产生写流量（P0-INVARIANT-03）。
    """
    context = AgentContext(
        task_id=f"recon-{uuid.uuid4().hex[:8]}",
        allow_write=False,
        primary_token=primary_token,
        secondary_token=secondary_token,
        similarity_threshold=similarity_threshold,
    )
    pipeline = _orchestrator.plan_recon(urls, context)
    summary = _orchestrator.run_pipeline(pipeline, context, urls)
    return {"status": "DELIVERED", **summary}


@mcp.tool()
def multi_agent_diff_sweep(
    endpoints: list[dict[str, Any]],
    allow_write: bool = False,
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
) -> dict[str, Any]:
    """
    Multi-Agent 差分扫描：并行派发差分蚁测试端点矩阵。

    蚁后拆解端点矩阵 → MapReduce pipeline 并行派发
    差分蚁 → 归巢汇总。差分蚁的写操作默认物理熔断
    （allow_write=False），需显式 allow_write=True。
    """
    context = AgentContext(
        task_id=f"diff-{uuid.uuid4().hex[:8]}",
        allow_write=allow_write,
        primary_token=primary_token,
        secondary_token=secondary_token,
        similarity_threshold=similarity_threshold,
    )
    pipeline = _orchestrator.plan_diff_sweep(endpoints, context)
    summary = _orchestrator.run_pipeline(pipeline, context, endpoints)
    return {"status": "DELIVERED", **summary}


@mcp.tool()
def multi_agent_full_audit(
    urls: list[str],
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
) -> dict[str, Any]:
    """
    Multi-Agent 全链路审计：侦察 → 差分 → 取证（顺序依赖）。

    蚁后维护计划 DAG：侦察蚁（只读）→ 差分蚁 →
    取证蚁（PoC 生成）。顺序 pipeline 保证依赖顺序。
    """
    context = AgentContext(
        task_id=f"audit-{uuid.uuid4().hex[:8]}",
        allow_write=False,
        primary_token=primary_token,
        secondary_token=secondary_token,
        similarity_threshold=similarity_threshold,
    )
    pipeline = _orchestrator.plan_full_audit(urls, context)
    # 全链路计划以第一个 URL 为任务载体（顺序依赖）
    task = {"url": urls[0]} if urls else {}
    summary = _orchestrator.run_pipeline(pipeline, context, task)
    return {"status": "DELIVERED", **summary}


@mcp.tool()
def multi_agent_parallel(
    tasks: list[dict[str, Any]],
    agent_type: str = "diff",
    allow_write: bool = False,
    primary_token: str = "",
    secondary_token: str = "",
    max_workers: int = 4,
) -> dict[str, Any]:
    """
    Multi-Agent 并行派发：同构工蚁并行执行异构任务。

    agent_type: recon | diff | evidence | remediation
    Parallel pipeline：工蚁并发执行（线程池），
    适用于无依赖的并行任务面。
    """
    agent_classes = {
        "recon": ReconAgent,
        "diff": DiffAgent,
        "evidence": EvidenceAgent,
        "remediation": RemediationAgent,
    }
    cls = agent_classes.get(agent_type)
    if cls is None:
        return {
            "status": "FAIL",
            "error": f"UNKNOWN_AGENT_TYPE: {agent_type}（支持 recon/diff/evidence/remediation）",
        }
    context = AgentContext(
        task_id=f"parallel-{uuid.uuid4().hex[:8]}",
        allow_write=allow_write,
        primary_token=primary_token,
        secondary_token=secondary_token,
    )
    agents = [cls() for _ in tasks]
    pipeline = ParallelPipeline(
        name=f"parallel-{agent_type}",
        agents=agents,
        max_workers=max_workers,
    )
    # 并行 pipeline：每个工蚁取对应任务
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=pipeline.max_workers) as pool:
        futures = [
            pool.submit(agent.run, context, task)
            for agent, task in zip(agents, tasks, strict=False)
        ]
        for future in futures:
            r = future.result()
            results.append({
                "agent_id": r.agent_id,
                "agent_type": r.agent_type,
                "status": r.status,
                "output": r.output,
                "error": r.error,
            })
    completed = sum(1 for r in results if r["status"] == "completed")
    return {
        "status": "DELIVERED",
        "pipeline": pipeline.name,
        "total_agents": len(results),
        "completed": completed,
        "failed": len(results) - completed,
        "results": results,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
