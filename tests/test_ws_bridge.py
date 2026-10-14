"""
test_ws_bridge.py: ws_bridge_server 的广播韧性与生命周期单测（H5）

覆盖此前未测、实为真实缺陷的分支：
  - 两次 broadcast 之间掉线的客户端，广播自身应能清理（except→unregister），
    且不得抛异常（老代码依赖 handler 的 finally 才清理，存在漏清窗口）；
  - 单条慢/挂起连接不得拖垮其他客户端的广播（每连接超时 + 并发，M8）；
  - start()/stop() 事件循环：网关能起来、能服务连接，stop() 能干净返回。
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("websockets", reason="websockets 未安装，跳过网关单测")

import websockets  # noqa: E402

from src.pipeline.ws_bridge_server import BridgeServer  # noqa: E402


async def _serve() -> tuple[BridgeServer, object, int]:
    """在随机端口启动网关，返回 (bridge, server, port)。"""
    bridge = BridgeServer(host="127.0.0.1", port=0)
    server = await websockets.serve(bridge.handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return bridge, server, port


def test_broadcast_cleans_client_dropped_between_broadcasts() -> None:
    """两次 broadcast 之间掉线的客户端，广播自身应清理且不抛异常（H5 核心缺陷）。

    旧实现依赖 handler 的 finally 才把死连接移出 self.clients；若掉线后
    handler 尚未运行 finally（仍在 async-for 上等待消息），则下一次广播时该
    死连接仍在集合内。此处断言：关闭一个 client 后，下一次 broadcast 能自行
    将其清理（except→unregister），bridge.clients 收缩且无异常外泄。
    """

    async def scenario() -> tuple[int, int]:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        c1 = await websockets.connect(uri)
        c2 = await websockets.connect(uri)
        await asyncio.sleep(0.2)
        assert len(bridge.clients) == 2

        # 第一次广播：两个客户端都应收到
        await bridge.broadcast("msg-1")
        assert len(bridge.clients) == 2

        # 两次广播之间，关闭 c2（此时 handler 的 finally 可能尚未触发）
        await c2.close()

        # 第二次广播：不得抛异常，且应自行清理已掉线的 c2
        await bridge.broadcast("msg-2")
        remaining = len(bridge.clients)

        await c1.close()
        server.close()
        await server.wait_closed()
        return remaining, len(bridge.clients)

    remaining, final = asyncio.run(scenario())
    # c2 已被广播的 except→unregister 清理，剩余仅 c1
    assert remaining == 1, f"掉线客户端未被广播清理，剩余: {remaining}"
    assert final == 0, "关闭 c1 后客户端集合未清空"


def test_broadcast_per_connection_timeout_does_not_block_others() -> None:
    """单条慢/挂起连接不得拖垮其他客户端的广播（M8）：超时即丢弃，好连接照常收到。"""

    async def scenario() -> str:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        good = await websockets.connect(uri)
        await asyncio.sleep(0.2)
        assert len(bridge.clients) == 1

        # 注入一个 send 会挂起远超超时的假客户端，模拟坏连接
        class SlowClient:
            remote_address = ("slow-client", 0)

            async def send(self, _msg: str) -> None:
                await asyncio.sleep(30)  # 远超默认 2s 超时

        slow = SlowClient()
        bridge.clients.add(slow)

        # 好连接应在超时窗口内照常收到广播，不被 SlowClient 阻塞
        recv_task = asyncio.create_task(good.recv())
        await bridge.broadcast("hello")
        result = await asyncio.wait_for(recv_task, timeout=2)

        # 坏连接应被广播的超时分支清理
        assert slow not in bridge.clients, "超时坏连接未被广播清理"

        await good.close()
        server.close()
        await server.wait_closed()
        return result

    assert asyncio.run(scenario()) == "hello"


def test_start_stop_event_loop() -> None:
    """start() 在事件循环内拉起服务、能接受连接；stop() 能干净终止循环（H5）。"""

    async def scenario() -> bool:
        bridge = BridgeServer(host="127.0.0.1", port=0)
        task = asyncio.create_task(bridge.start())

        # 等待 start() 完成绑定（bound_port 填充）
        for _ in range(100):
            if bridge.bound_port:
                break
            await asyncio.sleep(0.02)

        assert bridge.bound_port, "start() 未绑定端口"
        # 网关确实在监听并可接受连接
        uri = f"ws://127.0.0.1:{bridge.bound_port}"
        async with websockets.connect(uri) as ws:
            await ws.send(json_dummy())
        connected_ok = True

        # stop() 应让 start() 的无限循环退出，task 可 await 完成
        bridge.stop()
        await asyncio.wait_for(task, timeout=5)
        return connected_ok

    assert asyncio.run(scenario()) is True


def json_dummy() -> str:
    import json

    return json.dumps({"endpoint": "/x", "verdict": "SAFE"})
