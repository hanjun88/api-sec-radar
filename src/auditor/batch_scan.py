"""
batch_scan.py: 待测矩阵批量差分扫描引擎（无 MCP 依赖的共享实现）

从 ``auditor_mcp_server`` 抽出的核心扫描循环，供 MCP 工具层与
``pipeline_orchestrator`` 全链路编排共用，保证两条消费路径行为一致：

- 并发度按矩阵规模分级自适应（上限 10）；
- 限速 interval 下沉到 worker 线程，不阻塞任务提交；
- 每条请求先过统一请求安全门禁（URL/Header/方法覆盖/写熔断/对抗检测），
  阻断项以 BLOCKED 判定进入结果流，绝不静默放行；
- 可选 only_auditable 预过滤（默认关闭）：排除非对象级引用端点后再扫描；
- 结果 >100 条时自动压缩非漏洞条目证据；
- 错误隔离：单条失败不影响整体。

符合 P0-INVARIANT-03：非幂等写操作（POST/PUT/PATCH/DELETE 等）默认物理熔断。
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .adversarial_guard import validate_request_security
from .core import ApiAccessAuditor, DifferentialTestInput, RequestIdentity
from .hook import build_hook_chain
from .openapi import filter_auditable

# 富证据 verdict：这些判定的完整证据链必须保留（PoC 生成依赖），
# 批量压缩时不得精简。LIKELY_SAFE 语义偏安全，不含越权证据。
RICH_EVIDENCE_VERDICTS = {"VULNERABLE", "PRIV_ESCALATION", "SUSPECT"}


def execute_single_entry(
    entry: dict[str, Any],
    allow_write: bool,
    secret: str | None,
    primary_token: str | None,
    secondary_token: str | None,
    similarity_threshold: float,
    interval: float = 0.0,
    fast_mode: bool = False,
    timeout_per_request: float = 10.0,
) -> dict[str, Any]:
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

    # 统一请求安全门禁：URL/Header/方法覆盖/写熔断/对抗检测（P0-INVARIANT-03 前置守卫）
    gate_ok, gate_reason, gate_findings = validate_request_security(
        url=url,
        method=method,
        headers=primary_headers,
        body=body,
        allow_write=allow_write,
    )
    if not gate_ok:
        return {
            "endpoint": f"{method} {entry.get('path_template', url)}",
            "url": url,
            "method": method,
            "verdict": "BLOCKED",
            "confidence": 1.0,
            "similarity": 0.0,
            "is_auditable": entry.get("is_auditable", False),
            "is_safe_method": entry.get("is_safe_method", True),
            "primary_status": 0,
            "secondary_status": 0,
            "evidence": {
                "blocked_by": "REQUEST_SECURITY_GATE",
                "reason": gate_reason,
                "findings": gate_findings,
            },
        }

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
        entry_result: dict[str, Any] = {
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
        # 门禁 info 级发现（方法覆盖 / body 编码等）附带进证据链，供审计留痕
        info_findings = [f for f in (gate_findings or []) if not f.get("blocked")]
        if info_findings:
            entry_result["evidence"] = dict(entry_result["evidence"])
            entry_result["evidence"]["security_findings"] = info_findings
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


def compress_batch_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """批量结果压缩：结果 > 100 条时，非富证据条目的 evidence 精简为
    只保留 verdict 与关键状态码，控制返回负载与内存。

    富证据 verdict（VULNERABLE / PRIV_ESCALATION / SUSPECT）保留完整
    证据链：poc_builder.POC_VERDICTS 依赖这些证据生成 PoC 报告，
    压缩会导致 PoC 缺失根因与相似度。
    """
    if len(results) <= 100:
        return results
    compressed: list[dict[str, Any]] = []
    for r in results:
        if r.get("verdict") in RICH_EVIDENCE_VERDICTS:
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


def batch_concurrency(max_concurrency: int, matrix_size: int) -> int:
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


def run_batch_scan(
    target_matrix: list[dict[str, Any]],
    max_concurrency: int = 3,
    interval_ms: int = 100,
    allow_write: bool = False,
    secret_key: str = "",
    primary_token: str = "",
    secondary_token: str = "",
    similarity_threshold: float = 0.85,
    fast_mode: bool = False,
    timeout_per_request: float = 10.0,
    only_auditable: bool = False,
) -> dict[str, Any]:
    """批量差分扫描的共享实现。

    限速 interval 下沉到 worker 线程内部 sleep，不阻塞主线程批量提交任务。
    结果超过 100 条时自动压缩非 VULNERABLE 条目的 evidence。
    并发度按矩阵规模分级自适应（上限 10）。

    Args:
        only_auditable: 为 True 时先过滤掉非 auditable 端点（is_auditable=False，
            如 /health 等无对象级引用的集合端点）再扫描，被过滤条数记入
            返回值的 ``skipped_non_auditable``。默认 False 保持既有行为，
            供调用方按需开启纵深防御。
    """
    # 可选的 auditable 过滤（纵深防御：直接传裸矩阵时排除非对象级引用端点）
    skipped_non_auditable = 0
    if only_auditable:
        filtered = filter_auditable(target_matrix)
        skipped_non_auditable = len(target_matrix) - len(filtered)
        target_matrix = filtered

    concurrency = batch_concurrency(max_concurrency, len(target_matrix))
    interval = max(0, interval_ms) / 1000.0
    secret = secret_key or None
    p_token = primary_token or None
    s_token = secondary_token or None

    results: list[dict[str, Any]] = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {}
        for idx, entry in enumerate(target_matrix):
            future = executor.submit(
                execute_single_entry,
                entry, allow_write, secret, p_token, s_token,
                similarity_threshold, interval, fast_mode, timeout_per_request,
            )
            futures[future] = idx

        for future in as_completed(futures):
            result = future.result()
            result["_matrix_index"] = futures[future]
            results.append(result)

    # 保持原始矩阵顺序
    results.sort(key=lambda r: r.pop("_matrix_index", 0))

    # 大批量结果压缩：>100 条时精简非漏洞条目证据
    results = compress_batch_results(results)

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
        "skipped_non_auditable": skipped_non_auditable,
        "vulnerable_endpoints": vulnerable,
        "all_results": results,
    }
