"""
test_pipeline.py: WebSocket 广播网关端到端测试

以真实 socket 驱动 BridgeServer（非 mock），验证广播语义：
推流方发出的工件广播至其他客户端，且**不回发给发送者自身**。

注：本文件用 ``asyncio.run`` 显式驱动，不依赖 pytest-asyncio
（该插件在部分环境缺失，见 requirements.txt 声明）。
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("websockets", reason="websockets 未安装，跳过网关端到端测试")

import websockets  # noqa: E402  - importorskip 后导入

from src.pipeline.ws_bridge_server import BridgeServer  # noqa: E402


async def _serve() -> tuple[BridgeServer, object, int]:
    """在随机端口启动网关，返回 (bridge, server, port)。"""
    bridge = BridgeServer(host="127.0.0.1", port=0)
    server = await websockets.serve(bridge.handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return bridge, server, port


def test_artifact_broadcast_to_other_clients() -> None:
    """推流方发出的工件应被其他客户端收到。"""
    received: list[str] = []

    async def scenario() -> None:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        async with (
            websockets.connect(uri) as feeder,
            websockets.connect(uri) as dashboard,
        ):
            await asyncio.sleep(0.2)
            assert len(bridge.clients) == 2

            await feeder.send(json.dumps({"endpoint": "/api/v1/accounts/1001", "verdict": "VULNERABLE"}))
            received.append(await asyncio.wait_for(dashboard.recv(), timeout=3))

        server.close()
        await server.wait_closed()

    asyncio.run(scenario())

    payload = json.loads(received[0])
    assert payload["endpoint"] == "/api/v1/accounts/1001"
    assert payload["verdict"] == "VULNERABLE"


def test_sender_does_not_receive_echo() -> None:
    """推流方不接收自身消息的回显（网关契约：广播排除发送者）。"""
    async def scenario() -> bool:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        async with (
            websockets.connect(uri) as feeder,
            websockets.connect(uri) as dashboard,
        ):
            await asyncio.sleep(0.2)
            await feeder.send(json.dumps({"endpoint": "/x", "verdict": "SAFE"}))
            await asyncio.wait_for(dashboard.recv(), timeout=3)

            try:
                await asyncio.wait_for(feeder.recv(), timeout=0.5)
                return True  # 收到回显（违反契约）
            except asyncio.TimeoutError:
                return False

        server.close()
        await server.wait_closed()

    assert asyncio.run(scenario()) is False


def test_non_json_message_forwarded_without_crash() -> None:
    """非 JSON 消息原样透传，网关不得崩溃。"""
    received: list[str] = []

    async def scenario() -> None:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        async with (
            websockets.connect(uri) as feeder,
            websockets.connect(uri) as dashboard,
        ):
            await asyncio.sleep(0.2)
            await feeder.send("not-json-at-all")
            received.append(await asyncio.wait_for(dashboard.recv(), timeout=3))

        server.close()
        await server.wait_closed()

    asyncio.run(scenario())

    assert received[0] == "not-json-at-all"


def test_client_disconnect_is_cleaned_up() -> None:
    """客户端断开后从注册表移除，避免向死连接广播。"""
    async def scenario() -> int:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        dashboard = await websockets.connect(uri)
        await asyncio.sleep(0.2)
        assert len(bridge.clients) == 1
        await dashboard.close()
        await asyncio.sleep(0.4)
        remaining = len(bridge.clients)

        server.close()
        await server.wait_closed()
        return remaining

    assert asyncio.run(scenario()) == 0


def test_broadcast_with_no_clients_is_noop() -> None:
    """无客户端时广播为安全空操作，计数不递增。"""
    async def scenario() -> tuple[int, int]:
        bridge, server, _ = await _serve()
        await bridge.broadcast("hello")
        counts = (bridge.received_count, bridge.broadcast_count)
        server.close()
        await server.wait_closed()
        return counts

    received, broadcast = asyncio.run(scenario())
    assert (received, broadcast) == (0, 0)


def test_counters_track_received_and_broadcast() -> None:
    """接收与广播计数随真实流量递增。"""
    async def scenario() -> tuple[int, int]:
        bridge, server, port = await _serve()
        uri = f"ws://127.0.0.1:{port}"
        async with (
            websockets.connect(uri) as feeder,
            websockets.connect(uri) as dashboard,
        ):
            await asyncio.sleep(0.2)
            await feeder.send(json.dumps({"endpoint": "/a", "verdict": "SAFE"}))
            await asyncio.wait_for(dashboard.recv(), timeout=3)
            await asyncio.sleep(0.1)
            counts = (bridge.received_count, bridge.broadcast_count)

        server.close()
        await server.wait_closed()
        return counts

    received, broadcast = asyncio.run(scenario())
    assert received == 1
    assert broadcast == 1
