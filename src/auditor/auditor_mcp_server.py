"""
api_access_auditor/server.py — MCP 服务入口

启动: python -m api_access_auditor.server
传输: stdio
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Union

from mcp.server.fastmcp import FastMCP

from .core import (
    ApiAccessAuditor,
    DifferentialTestInput,
    RequestIdentity,
)
from .hook import RequestHook, build_hook_chain
from .openapi import parse_openapi_spec, filter_auditable, filter_safe_methods
from .report import emit_audit_report as _emit_audit_report
from .sandbox_verifier import verify_python_patch

mcp = FastMCP("api-access-auditor")
_auditor = ApiAccessAuditor()


def _coerce_headers(raw: Union[str, Dict[str, str], None]) -> Dict[str, str]:
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
    primary_headers: Optional[Union[str, Dict[str, str]]] = None,
    secondary_headers: Optional[Union[str, Dict[str, str]]] = None,
    primary_label: str = "primary",
    secondary_label: str = "secondary",
    primary_body: str = "",
    secondary_body: str = "",
    similarity_threshold: float = 0.85,
    allow_write: bool = False,
) -> Dict[str, Any]:
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
    headers: Optional[Union[str, Dict[str, str]]] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
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
) -> Dict[str, Any]:
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
    except (json.JSONDecodeError, FileNotFoundError, OSError) as e:
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


def _execute_single_entry(
    entry: Dict[str, Any],
    allow_write: bool,
    secret: Optional[str],
    primary_token: Optional[str],
    secondary_token: Optional[str],
    similarity_threshold: float,
    interval: float = 0.0,
    fast_mode: bool = False,
    timeout_per_request: float = 10.0,
) -> Dict[str, Any]:
    """执行单条待测矩阵条目的差分测试。线程安全：每个调用创建独立 auditor 实例。

    Args:
        entry: 待测矩阵条目。
        allow_write: 是否放行写操作。
        secret: 可选 HMAC 密钥。
        primary_token: 可选主身份 token。
        secondary_token: 可选次身份 token。
        similarity_threshold: 越权判定阈值。
        interval: 本 worker 开始前的限速 sleep 秒数（在 worker 内部 sleep，
            不阻塞主线程的任务提交循环）。
        fast_mode: 快速模式：跳过非 auditable 端点的详细证据收集，
            仅保留 verdict 与关键状态码，用于大规模初步扫描。
        timeout_per_request: 单请求超时（秒），透传给 RequestIdentity。
    """
    # 限速下沉到 worker 线程内，避免阻塞主线程批量提交任务
    if interval > 0:
        time.sleep(interval)

    method = entry.get("method", "GET").upper()
    url = entry.get("url", "")
    body = entry.get("json_body")

    # 先合并矩阵中已有的静态 headers，再动态计算签名（动态头必须后应用，防止被静态覆盖）
    primary_headers = dict(entry.get("primary_headers", {}))
    secondary_headers = dict(entry.get("secondary_headers", {}))
    dyn_p, dyn_s = build_hook_chain(
        method=method,
        url=url,
        body=body,
        secret=secret,
        primary_token=primary_token,
        secondary_token=secondary_token,
    )
    primary_headers.update(dyn_p)
    secondary_headers.update(dyn_s)

    auditor = ApiAccessAuditor()
    try:
        params = DifferentialTestInput(
            primary=RequestIdentity(
                label="primary", method=method, url=url,
                headers=primary_headers, body=body, timeout=timeout_per_request,
            ),
            secondary=RequestIdentity(
                label="secondary", method=method, url=url,
                headers=secondary_headers, body=body, timeout=timeout_per_request,
            ),
            similarity_threshold=similarity_threshold,
            allow_write=allow_write,
        )
        result = auditor.execute(params)
        entry_result: Dict[str, Any] = {
            "endpoint": f"{method} {entry.get('path_template', url)}",
            "url": url,
            "method": method,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "similarity": result.similarity,
            "is_auditable": entry.get("is_auditable", False),
            "is_safe_method": entry.get("is_safe_method", True),
            "primary_status": result.primary.status_code,
            "secondary_status": result.secondary.status_code,
            "evidence": result.evidence,
        }
        # 快速模式：非 auditable 端点不收集详细证据
        if fast_mode and not entry.get("is_auditable", False):
            entry_result["evidence"] = {
                "primary_status": result.primary.status_code,
                "secondary_status": result.secondary.status_code,
                "similarity": result.similarity,
                "_fast_mode": True,
            }
        return entry_result
    except Exception as e:
        return {
            "endpoint": f"{method} {entry.get('path_template', url)}",
            "url": url,
            "method": method,
            "verdict": "ERROR",
            "confidence": 0.0,
            "similarity": 0.0,
            "is_auditable": entry.get("is_auditable", False),
            "is_safe_method": entry.get("is_safe_method", True),
            "primary_status": 0,
            "secondary_status": 0,
            "evidence": {"error": str(e), "type": type(e).__name__},
        }
    finally:
        auditor.cleanup()


def _compress_batch_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量结果压缩：结果 > 100 条时，非 VULNERABLE 条目的 evidence 精简为
    只保留 verdict 与关键状态码，控制返回负载与内存。
    """
    if len(results) <= 100:
        return results
    compressed: List[Dict[str, Any]] = []
    for r in results:
        if r.get("verdict") == "VULNERABLE":
            compressed.append(r)
            continue
        slim = dict(r)
        slim["evidence"] = {
            "primary_status": r.get("primary_status", 0),
            "secondary_status": r.get("secondary_status", 0),
            "similarity": r.get("similarity", 0.0),
            "_compressed": True,
        }
        compressed.append(slim)
    return compressed


def _batch_concurrency(max_concurrency: int, matrix_size: int) -> int:
    """与 orchestrator 对齐的分级并发度（上限 10）。

    - 矩阵 ≤ 100：使用请求的 max_concurrency
    - 100 < 矩阵 ≤ 500：min(max_concurrency, 5)
    - 500 < 矩阵 ≤ 2000：min(max_concurrency, 8)
    - 矩阵 > 2000：min(max_concurrency, 10)
    """
    if matrix_size <= 100:
        return max(1, min(int(max_concurrency), 10))
    if matrix_size <= 500:
        return max(1, min(int(max_concurrency), 5))
    if matrix_size <= 2000:
        return max(1, min(int(max_concurrency), 8))
    return max(1, min(int(max_concurrency), 10))


def _run_batch_scan(
    target_matrix: List[Dict[str, Any]],
    max_concurrency: int,
    interval_ms: int,
    allow_write: bool,
    secret_key: str,
    primary_token: str,
    secondary_token: str,
    similarity_threshold: float,
    fast_mode: bool = False,
    timeout_per_request: float = 10.0,
) -> Dict[str, Any]:
    """批量差分扫描的共享实现。

    限速 interval 下沉到 worker 线程内部 sleep，不再阻塞主线程的任务提交。
    结果超过 100 条时自动压缩非 VULNERABLE 条目的 evidence。
    并发度按矩阵规模分级自适应（上限 10）。
    """
    concurrency = _batch_concurrency(max_concurrency, len(target_matrix))
    interval = max(0, interval_ms) / 1000.0
    secret = secret_key or None
    p_token = primary_token or None
    s_token = secondary_token or None

    results: List[Dict[str, Any]] = []
    start_time = time.time()
    index_map: Dict[int, int] = {}  # future index -> original matrix index

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {}
        for idx, entry in enumerate(target_matrix):
            future = executor.submit(
                _execute_single_entry,
                entry, allow_write, secret, p_token, s_token,
                similarity_threshold, interval, fast_mode, timeout_per_request,
            )
            futures[future] = idx
            # 原实现此处 time.sleep(interval) 会阻塞提交循环；
            # 现已改为在 worker 函数内部 sleep，主线程立即把所有任务提交完。

        for future in as_completed(futures):
            result = future.result()
            result["_matrix_index"] = futures[future]
            results.append(result)

    # 保持原始矩阵顺序
    results.sort(key=lambda r: r.pop("_matrix_index", 0))

    # 大批量结果压缩：>100 条时精简非漏洞条目证据
    results = _compress_batch_results(results)

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # 聚合统计
    stats = {
        "total": len(results),
        "vulnerable": sum(1 for r in results if r["verdict"] == "VULNERABLE"),
        "safe": sum(1 for r in results if r["verdict"] == "SAFE"),
        "blocked": sum(1 for r in results if r["verdict"] == "BLOCKED"),
        "inconclusive": sum(1 for r in results if r["verdict"] == "INCONCLUSIVE"),
        "error": sum(1 for r in results if r["verdict"] == "ERROR"),
        "auditable_vulnerable": sum(
            1 for r in results if r["verdict"] == "VULNERABLE" and r.get("is_auditable")
        ),
    }

    # 高风险端点优先排序
    vulnerable = [r for r in results if r["verdict"] == "VULNERABLE"]
    vulnerable.sort(key=lambda r: r["confidence"], reverse=True)

    return {
        "status": "DELIVERED",
        "scan_summary": stats,
        "elapsed_ms": elapsed_ms,
        "concurrency": concurrency,
        "vulnerable_endpoints": vulnerable,
        "all_results": results,
    }


@mcp.tool()
def batch_differential_scan(
    target_matrix: List[Dict[str, Any]],
    max_concurrency: int = 3,
    interval_ms: int = 100,
    allow_write: bool = False,
    secret_key: str = "",
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
    timeout_per_request: float = 10.0,
) -> Dict[str, Any]:
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
    """
    return _run_batch_scan(
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
    )


@mcp.tool()
def batch_differential_scan_fast(
    target_matrix: List[Dict[str, Any]],
    max_concurrency: int = 3,
    interval_ms: int = 100,
    allow_write: bool = False,
    secret_key: str = "",
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
    timeout_per_request: float = 10.0,
) -> Dict[str, Any]:
    """
    批量差分扫描的快速变体：跳过非 auditable 端点的详细证据收集，
    只收集 verdict 与关键状态码，适用于大规模初步扫描（1000+ 端点）。

    与 batch_differential_scan 接口完全一致，仅证据收集更轻量。
    """
    return _run_batch_scan(
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
    )


@mcp.tool()
def verify_remediation(
    test_url: str,
    patch_code_snippet: str,
    original_handler_snippet: str = "",
    primary_token: str = "token-alice",
    secondary_token: str = "token-bob",
) -> Dict[str, Any]:
    """
    对生成的修复补丁执行沙盒语法编译与行级安全语义断言（纯静态检查，
    不发起任何真实网络请求，``verified_safe`` 恒为 False）。

    诚实声明：本工具当前只做静态验证——
    1. 静态编译检查（SyntaxError → COMPILE_ERROR）
    2. AST 级行级安全语义断言（必须同时包含 tenant_filter 绑定与 404 实体屏蔽）
    静态通过记为 remediation_status=STATIC_AST_PASSED。真正的"闭环"（修复后
    Context A 200 / Context B 404 的物理重放验证）为后续 feature，见 README。
    """
    result = verify_python_patch(
        test_url=test_url,
        original_handler_snippet=original_handler_snippet,
        patch_code_snippet=patch_code_snippet,
        primary_token=primary_token,
        secondary_token=secondary_token,
    )
    return {"status": "DELIVERED", **result}


@mcp.tool()
def emit_audit_report(
    scan_result: Dict[str, Any],
    target: str = "",
    output_dir: str = "reports",
) -> Dict[str, Any]:
    """
    将 batch_differential_scan 聚合结果渲染为 Markdown + JSON 审计报告并落盘。
    报告包含目标、时间、扫描条目数、verdict 分布，以及每条 finding 的
    endpoint / verdict / confidence / evidence。
    """
    try:
        out = _emit_audit_report(scan_result, target=target, output_dir=output_dir)
    except (OSError, ValueError) as e:
        return {"status": "FAIL", "error": f"报告落盘失败: {e}"}
    return {"status": "DELIVERED", **out}


if __name__ == "__main__":
    mcp.run(transport="stdio")
