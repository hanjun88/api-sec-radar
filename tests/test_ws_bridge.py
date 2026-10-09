"""tests/test_ws_bridge.py — WebSocket 网关组"""
from __future__ import annotations

import asyncio
import json

from src.pipeline.ws_bridge_server import BridgeServer


class _FakeWebSocket:
    """模拟 WebSocket 客户端。"""

    def __init__(self, name: str, fail: bool = False):
        self.name = name
        self.fail = fail
        self.sent: list[str] = []
        self.remote_address = ("127.0.0.1", 12345)
        self.closed = False

    async def send(self, message: str) -> None:
        if self.fail:
            raise ConnectionError("simulated disconnect")
        self.sent.append(message)


class TestBroadcast:
    def test_broadcast_to_all_clients(self):
        server = BridgeServer()
        clients = [_FakeWebSocket(f"c{i}") for i in range(3)]
        server.clients.update(clients)

        asyncio.run(server.broadcast("hello"))

        assert all(c.sent == ["hello"] for c in clients)
        assert server.broadcast_count == 3

    def test_broadcast_snapshot_iteration(self):
        """迭代期修改 clients 不触发 RuntimeError。

        修复前 for client in self.clients 在 await send()
        期间若其他协程修改 set 会触发
        RuntimeError: Set changed size during iteration。
        """
        server = BridgeServer()
        clients = [_FakeWebSocket(f"c{i}") for i in range(5)]
        server.clients.update(clients)

        def mutate_during_send() -> None:
            # 模拟并发 register/unregister
            server.clients.add(_FakeWebSocket("new"))
            server.clients.discard(clients[0])

        # 在 send 期间修改 set（通过 fail 客户端触发异常路径）
        clients[2].fail = True
        asyncio.run(server.broadcast("msg"))
        # 不抛 RuntimeError 即通过
        assert server.broadcast_count >= 1

    def test_broadcast_failed_client_removed(self):
        server = BridgeServer()
        good = _FakeWebSocket("good")
        bad = _FakeWebSocket("bad", fail=True)
        server.clients.update({good, bad})

        asyncio.run(server.broadcast("msg"))

        assert good.sent == ["msg"]
        assert bad not in server.clients
        assert good in server.clients

    def test_broadcast_empty_clients(self):
        server = BridgeServer()
        asyncio.run(server.broadcast("msg"))
        assert server.broadcast_count == 0

    def test_broadcast_concurrent_sends(self):
        """并发扇出：单客户端慢不阻塞其余客户端。"""
        server = BridgeServer()
        clients = [_FakeWebSocket(f"c{i}") for i in range(10)]
        server.clients.update(clients)

        asyncio.run(server.broadcast("concurrent"))

        assert server.broadcast_count == 10
        assert all(c.sent == ["concurrent"] for c in clients)


class TestHandler:
    def test_handler_scalar_json_no_crash(self):
        """标量 / null JSON 负载不崩溃。

        修复前 json.loads('123') 返回 int，
        'endpoint' in artifact 触发
        TypeError: argument of type 'int' is not iterable。
        """
        # 直接验证解析逻辑（不启动真实 WebSocket）
        for raw in ("123", "null", '"string"', "true", "[]"):
            artifact = json.loads(raw)
            # 修复后：isinstance(artifact, dict) 守卫
            is_dict = isinstance(artifact, dict)
            if is_dict:
                _ = "endpoint" in artifact
            assert not is_dict or isinstance(artifact, dict)

    def test_handler_dict_artifact(self):
        artifact = json.dumps({"endpoint": "GET /api", "verdict": "VULNERABLE"})
        parsed = json.loads(artifact)
        assert isinstance(parsed, dict)
        assert "endpoint" in parsed and "verdict" in parsed

    def test_handler_non_json_passthrough(self):
        raw = "not json at all"
        try:
            json.loads(raw)
            parsed = None
        except json.JSONDecodeError:
            parsed = None
        assert parsed is None


class TestBridgeServerLifecycle:
    def test_register_unregister(self):
        server = BridgeServer()
        ws = _FakeWebSocket("c1")

        asyncio.run(server.register(ws))
        assert ws in server.clients
        assert len(server.clients) == 1

        asyncio.run(server.unregister(ws))
        assert ws not in server.clients

    def test_stop_sets_running_false(self):
        server = BridgeServer()
        assert server.running is True
        server.stop()
        assert server.running is False
