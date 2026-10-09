"""
pipeline_bridge.py: 审计工件 → WebSocket 广播网关推流器

全链路最后一跳：把 orchestrator 产出的漏洞证据推送到
ws_bridge_server（ws://host:8765），由网关广播至 3D 态势大屏。

- 同步门面 ``push_poc_artifacts`` / ``push_pipeline_artifacts``（内部 asyncio.run）；
- 连接建立后一次性推送全部工件并读取网关回执（若有）；
- 网关不可达时抛出异常由调用方决定降级（orchestrator 记录 errors，不抛断业务）。
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any

from .artifact_contract import build_artifacts


async def _push_async(ws_url: str, artifacts: list[dict[str, Any]]) -> int:
    import json

    import websockets

    pushed = 0
    async with websockets.connect(ws_url) as ws:
        for artifact in artifacts:
            await ws.send(json.dumps(artifact))
            pushed += 1
    return pushed


def push_artifacts(ws_url: str, artifacts: list[dict[str, Any]]) -> int:
    """
    推送工件列表至 WebSocket 网关，返回成功推送条数。

    兼容两种调用上下文：
    - 同步上下文（无运行中的事件循环）：直接 ``asyncio.run``；
    - 异步上下文（调用方已在事件循环内，如 artifact_emitter 的 async run）：
      在独立线程的新事件循环中执行，避免 ``asyncio.run() cannot be called
      from a running event loop``。

    Raises:
        网络/依赖异常原样上抛（由调用方降级处理）。
    """
    if not ws_url or not artifacts:
        return 0
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_push_async(ws_url, artifacts))
    # 已在事件循环中：委托独立线程的独立循环执行
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(
            lambda: asyncio.run(_push_async(ws_url, artifacts))
        ).result()


def push_poc_artifacts(
    poc_reports: list[dict[str, Any]] | None = None,
    ws_url: str = "",
    fallback_results: list[dict[str, Any]] | None = None,
) -> int:
    """
    PoC 优先的工件推流（无 PoC 时回退扫描结果）。

    Returns:
        成功推送条数。
    """
    artifacts = build_artifacts(poc_reports=poc_reports, scan_results=fallback_results)
    return push_artifacts(ws_url=ws_url, artifacts=artifacts)


def push_pipeline_artifacts(
    pipeline_result: dict[str, Any],
    ws_url: str = "",
) -> int:
    """
    推送完整 PipelineResult 的工件（PoC 优先，扫描结果兜底）。

    Returns:
        成功推送条数。
    """
    artifacts = build_artifacts(
        poc_reports=pipeline_result.get("poc_reports") or [],
        scan_results=(pipeline_result.get("scan_result") or {}).get("all_results") or [],
    )
    return push_artifacts(ws_url=ws_url, artifacts=artifacts)
