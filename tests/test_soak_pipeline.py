"""
test_soak_pipeline.py: 三层架构全链路 soak 测试

真实驱动「漏洞靶场 → MCP 审计引擎（stdio 子进程）→ live_scan_feeder →
WebSocket 广播网关 → 前端态势客户端」整条流水线，验证：

  1. MCP 引擎可被 feeder 通过真实 stdio 协议驱动（非 mock）；
  2. 真实差分扫描能从靶场检出 BOLA 漏洞（主链路核心价值）；
  3. 产出的 VulnEvidencePayload 能经广播网关抵达前端客户端；
  4. 停止信号能干净地终止推流循环并回收 MCP 子进程。

这是「真实审计数据 → 3D 拓扑渲染」这条主链路的端到端可用性证据。
前两层各自的协议级测试见 ``test_mcp_protocol.py`` / ``test_pipeline.py``；
本文件补的是**跨层串联**这一段，此前的覆盖盲区。
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

import pytest

pytest.importorskip("websockets", reason="websockets 未安装，跳过全链路 soak 测试")
pytest.importorskip("mcp", reason="mcp 未安装，跳过全链路 soak 测试")

from src.pipeline.live_scan_feeder import LiveScanFeeder
from src.pipeline.ws_bridge_server import BridgeServer

# 前端三态 + 引擎未定态：feeder 归一化后只应产出这四种
VALID_VERDICTS = {"VULNERABLE", "SAFE", "BLOCKED", "INCONCLUSIVE"}

TARGET_ARTIFACTS = 6
SOAK_TIMEOUT_SEC = 90.0
MCP_READY_TIMEOUT_SEC = 30.0


def _build_spec(base_url: str) -> Dict[str, Any]:
    """构造指向靶场的 OpenAPI 规范。

    含三类端点，覆盖三种判定路径：
      - ``/api/v1/accounts/{id}``：BOLA——任意 token 可读他人账户 ⇒ VULNERABLE
      - ``/api/v1/secure/{id}``：属主独占，非属主 403 ⇒ SAFE（正确拒绝）
      - ``/api/v1/health``：无对象引用，非可审计端点
    ``{id}`` 会被解析器替换为探测值 ``1001``（靶场中属 alice）。
    """
    id_param = [
        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
    ]
    return {
        "openapi": "3.0.0",
        "info": {"title": "Soak Target", "version": "1.0.0"},
        "servers": [{"url": base_url}],
        "paths": {
            "/api/v1/accounts/{id}": {
                "get": {"summary": "BOLA candidate", "parameters": id_param}
            },
            "/api/v1/secure/{id}": {
                "get": {"summary": "Owner-only endpoint", "parameters": id_param}
            },
            "/api/v1/health": {"get": {"summary": "Health check"}},
        },
    }


def _start_fault_server() -> Tuple[HTTPServer, str]:
    """启动一个对所有请求返回 500 的故障靶场，用于注入「靶场故障」场景。"""
    class _FaultHandler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # noqa: D401 - 静默日志
            return

        def _send_500(self) -> None:
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._send_500()

        def do_PUT(self) -> None:  # noqa: N802
            self._send_500()

    srv = HTTPServer(("127.0.0.1", 0), _FaultHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


async def _run_soak(
    base_url: str,
    kill_mcp_after: int = 0,
    fault_base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """跑一轮完整流水线：真网关 + 真 MCP 子进程 + 真前端客户端。

    H6 故障注入扩展：
      - ``kill_mcp_after``：收集到该数量工件后，直接 ``kill`` 掉 MCP 子进程，
        模拟「扫描中 MCP 崩溃」，验证 feeder 能降级续扫（重连后继续）。
      - ``fault_base_url``：用故障靶场（始终 500）替换正常靶场，验证 feeder
        对靶场故障降级而不崩溃。
    """
    import websockets

    bridge = BridgeServer(host="127.0.0.1", port=0)
    server = await websockets.serve(bridge.handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    ws_url = f"ws://127.0.0.1:{port}"

    # 前端态势客户端（真实 WebSocket 长连接）
    dashboard = await websockets.connect(ws_url)

    spec_url = fault_base_url if fault_base_url else base_url
    feeder = LiveScanFeeder(
        ws_url=ws_url,
        openapi_spec=_build_spec(spec_url),
        scan_interval_sec=0.05,
    )

    collected: List[Dict[str, Any]] = []
    mcp_proc = None
    kill_done = False
    task = asyncio.create_task(feeder.run())

    try:
        deadline = time.time() + SOAK_TIMEOUT_SEC
        while time.time() < deadline and len(collected) < TARGET_ARTIFACTS:
            try:
                raw = await asyncio.wait_for(dashboard.recv(), timeout=3.0)
            except asyncio.TimeoutError:
                if task.done():
                    # run() 已返回（MCP 启动失败或已停止），无需继续等
                    break
                continue
            collected.append(json.loads(raw))
            # 记录 MCP 子进程引用，供 stop 后验证回收
            if mcp_proc is None and feeder.mcp is not None and feeder.mcp.process is not None:
                mcp_proc = feeder.mcp.process
            # H6：注入「扫描中 MCP 崩溃」
            if (
                kill_mcp_after
                and not kill_done
                and len(collected) >= kill_mcp_after
                and feeder.mcp is not None
                and feeder.mcp.process is not None
            ):
                feeder.mcp.process.kill()
                kill_done = True
    finally:
        feeder.stop()
        task_exc: Optional[BaseException] = None
        try:
            await asyncio.wait_for(task, timeout=20.0)
        except asyncio.TimeoutError:
            task.cancel()
        except Exception as e:  # run() 抛出未处理异常（应不发生）
            task_exc = e
        await dashboard.close()
        server.close()
        await server.wait_closed()

    return {
        "collected": collected,
        "scan_count": feeder.scan_count,
        "artifact_count": feeder.artifact_count,
        "bridge_received": bridge.received_count,
        "bridge_broadcast": bridge.broadcast_count,
        "mcp_proc": mcp_proc,
        "task_exception": task_exc,
        "mcp_killed": kill_done,
    }


def test_full_pipeline_soak(mock_target_server: str) -> None:
    """靶场 → MCP → feeder → 网关 → 客户端：全链路必须跑通且能干净收尾。"""
    result = asyncio.run(_run_soak(mock_target_server))

    # ① MCP 引擎必须真的被驱动起来。
    #    run() 在 MCP 启动失败时会静默 return，scan_count 保持 0——这是关键区分点。
    assert result["scan_count"] >= 1, (
        f"MCP 审计引擎未完成任何扫描轮次（scan_count={result['scan_count']}）；"
        "可能是 python -m src.auditor.auditor_mcp_server 启动失败。"
    )

    # ② 前端客户端必须真的收到广播工件
    collected = result["collected"]
    assert collected, "WebSocket 网关未向客户端广播任何工件"

    # ③ 每个工件结构合法（前端拓扑渲染的数据契约）
    for art in collected:
        assert art.get("endpoint"), f"工件缺少 endpoint: {art}"
        assert art.get("verdict") in VALID_VERDICTS, f"非法 verdict: {art.get('verdict')}"
        confidence = art.get("confidence")
        assert isinstance(confidence, (int, float)), f"confidence 非数值: {confidence!r}"
        assert 0.0 <= float(confidence) <= 1.0, f"confidence 越界: {confidence}"
        assert isinstance(art.get("evidence"), dict), "工件缺少 evidence 结构"
        assert "primary_status" in art["evidence"], "evidence 缺少 primary_status"

    # ④ 主链路核心价值：靶场的 BOLA 端点必须被检出为 VULNERABLE
    vuln_endpoints = [a["endpoint"] for a in collected if a["verdict"] == "VULNERABLE"]
    assert any("/api/v1/accounts/" in ep for ep in vuln_endpoints), (
        f"未从靶场检出 BOLA 漏洞；实际 verdict 集合: "
        f"{sorted({a['verdict'] for a in collected})}；"
        f"实际端点: {sorted({a['endpoint'] for a in collected})}"
    )

    # ④b 假阳性门禁：无对象级引用的端点不得进入推送工件。
    #     差分引擎只看「两个身份响应是否等价」，不判可审计性；/api/v1/health
    #     双方都 200 且内容相同，若不按 only_auditable 过滤就会被误报为越权。
    assert not any("/api/v1/health" in a["endpoint"] for a in collected), (
        "非可审计端点 /api/v1/health 被纳入扫描——会被差分引擎误判为 VULNERABLE"
    )

    # ⑤ 网关确实完成了「接收 → 广播」
    assert result["bridge_received"] > 0, "网关未接收到任何上游推流"
    assert result["bridge_broadcast"] > 0, "网关未向任何客户端广播"

    # ⑥ 停止后 MCP 子进程必须被回收（不留僵尸进程）
    mcp_proc = result["mcp_proc"]
    assert mcp_proc is not None, "未能捕获 MCP 子进程引用（说明 MCP 未真正启动）"
    assert mcp_proc.poll() is not None, (
        f"MCP 子进程 (pid={mcp_proc.pid}) 在 stop() 后仍未终止，存在泄漏"
    )


def test_soak_fault_target_500(mock_target_server: str) -> None:
    """H6：靶场全程返回 500 时，feeder 必须降级而不崩溃（不抛未处理异常）。"""
    srv, fault_url = _start_fault_server()
    try:
        result = asyncio.run(_run_soak(mock_target_server, fault_base_url=fault_url))
    finally:
        srv.shutdown()
        srv.server_close()

    # ① 降级关键：run() 不得抛出未处理异常（即便靶场全 500）。
    assert result["task_exception"] is None, (
        f"靶场 500 故障下 feeder 崩溃: {result['task_exception']}"
    )
    # ② MCP 引擎仍被持续驱动（未因靶场故障静默空转退出）。
    assert result["scan_count"] >= 1, "靶场 500 故障下 MCP 未被执行任何扫描"


def test_soak_kill_mcp_mid_scan(mock_target_server: str) -> None:
    """H6：扫描中主动 kill MCP 子进程，feeder 必须降级续扫而不崩溃。

    验证 M6 的重连逻辑：进程崩溃后 feeder 退避重连，恢复后继续差分扫描，
    扫描轮次应超过注入 kill 的阈值。
    """
    result = asyncio.run(_run_soak(mock_target_server, kill_mcp_after=2))

    # ① 降级关键：run() 不得抛出未处理异常。
    assert result["task_exception"] is None, (
        f"MCP 崩溃下 feeder 崩溃: {result['task_exception']}"
    )
    # ② 故障注入确实发生。
    assert result["mcp_killed"] is True, "未注入 MCP kill（测试逻辑错误）"
    # ③ 可续扫：重连恢复后扫描轮次超过注入阈值（证明未永久停止）。
    assert result["scan_count"] > 2, (
        f"MCP 崩溃后 feeder 未续扫；scan_count={result['scan_count']}"
    )
