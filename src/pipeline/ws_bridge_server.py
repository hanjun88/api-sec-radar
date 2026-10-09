#!/usr/bin/env python3
"""
WebSocket Bridge Gateway (CI/CD Automated Execution Spec v7.0-STRICT)
职责：在 ws://127.0.0.1:8765 上建立广播总线，
接收上游工件推流（feeder / artifact-emitter）并实时广播至所有前端态势感知客户端。
单一进程生命周期：mount -> accept -> broadcast -> dispose。
"""

import asyncio
import json
import os
import signal
import sys

try:
    import websockets
except ImportError:
    print("[ERROR] 缺失 websockets 依赖，请执行: pip install websockets", file=sys.stderr)
    sys.exit(1)

WS_HOST = os.environ.get("WS_HOST", "0.0.0.0")
WS_PORT = int(os.environ.get("WS_PORT", "8765"))


class BridgeServer:
    def __init__(self, host: str = WS_HOST, port: int = WS_PORT):
        self.host = host
        self.port = port
        self.clients: set[websockets.WebSocketServerProtocol] = set()
        self.running = True
        self.received_count = 0
        self.broadcast_count = 0
        self.server = None

    async def register(self, websocket: websockets.WebSocketServerProtocol) -> None:
        self.clients.add(websocket)
        print(f"[BRIDGE] 客户端接入 (当前: {len(self.clients)}) | remote={websocket.remote_address}")

    async def unregister(self, websocket: websockets.WebSocketServerProtocol) -> None:
        self.clients.discard(websocket)
        print(f"[BRIDGE] 客户端断开 (当前: {len(self.clients)}) | remote={websocket.remote_address}")

    async def broadcast(self, message: str) -> None:
        """广播消息至所有客户端。

        快照迭代：await send() 期间其他协程可能修改
        self.clients（register/unregister），直接迭代
        会触发 RuntimeError: Set changed size during iteration。
        并发扇出：单客户端失败不影响其余客户端。
        """
        if not self.clients:
            return
        snapshot = list(self.clients)
        disconnected: set[websockets.WebSocketServerProtocol] = set()
        results = await asyncio.gather(
            *(self._send_one(client, message, disconnected) for client in snapshot),
            return_exceptions=True,
        )
        for client, outcome in zip(snapshot, results, strict=False):
            if isinstance(outcome, Exception):
                disconnected.add(client)
            else:
                self.broadcast_count += 1
        for dc in disconnected:
            await self.unregister(dc)

    async def _send_one(
        self,
        client: websockets.WebSocketServerProtocol,
        message: str,
        disconnected: set[websockets.WebSocketServerProtocol],
    ) -> None:
        """向单个客户端发送消息，失败时记录断连。"""
        try:
            await client.send(message)
        except websockets.ConnectionClosed:
            disconnected.add(client)
        except Exception as e:
            print(f"[BRIDGE] 广播失败 remote={client.remote_address}: {e}",
                  file=sys.stderr)
            disconnected.add(client)

    async def handler(self, websocket: websockets.WebSocketServerProtocol) -> None:
        await self.register(websocket)
        try:
            async for message in websocket:
                self.received_count += 1
                # 解析并校验工件结构（标量 / null / 非 JSON 均不崩溃）
                raw = message if isinstance(message, str) else message.decode("utf-8")
                try:
                    artifact = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    artifact = None
                if isinstance(artifact, dict) and "endpoint" in artifact and "verdict" in artifact:
                    verdict = artifact.get("verdict", "UNKNOWN")
                    endpoint = artifact.get("endpoint", "?")
                    print(f"[BRIDGE] [#{self.received_count}] {verdict:12s} | {endpoint}")
                elif artifact is None:
                    print(f"[BRIDGE] [#{self.received_count}] 非 JSON 消息，原样透传 ({len(raw)} bytes)")
                else:
                    print(f"[BRIDGE] [#{self.received_count}] 非标准工件 (type: {type(artifact).__name__})")
                # 广播至所有其他客户端（不回发给发送者本身）
                await self.broadcast(raw)
        except websockets.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)

    async def start(self) -> None:
        print(f"[BRIDGE] WebSocket 网关启动: ws://{self.host}:{self.port}")
        print("[BRIDGE] 等待上游推流与前端客户端接入...")
        async with websockets.serve(self.handler, self.host, self.port):
            self.server = True
            while self.running:
                await asyncio.sleep(0.5)

    def stop(self) -> None:
        self.running = False
        print(f"\n[BRIDGE] 收到停止信号，累计接收: {self.received_count} | 累计广播: {self.broadcast_count}")


async def main() -> None:
    bridge = BridgeServer()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, bridge.stop)

    try:
        await bridge.start()
    finally:
        print("[BRIDGE] 网关已安全销毁。")


if __name__ == "__main__":
    asyncio.run(main())
