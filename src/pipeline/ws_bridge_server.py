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
from typing import Any, Dict, Optional, Set

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
        self.clients: Set[websockets.WebSocketServerProtocol] = set()
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

    async def broadcast(self, message: str, sender: Optional[websockets.WebSocketServerProtocol] = None) -> None:
        if not self.clients:
            return
        disconnected = set()
        for client in self.clients:
            # P2-⑪: 不回发给发送者本身（与 handler 注释一致）。
            if sender is not None and client is sender:
                continue
            try:
                await client.send(message)
                self.broadcast_count += 1
            except (websockets.ConnectionClosed, Exception):
                disconnected.add(client)
        for dc in disconnected:
            await self.unregister(dc)

    async def handler(self, websocket: websockets.WebSocketServerProtocol) -> None:
        await self.register(websocket)
        try:
            async for message in websocket:
                self.received_count += 1
                # 解析并校验工件结构
                try:
                    artifact = json.loads(message) if isinstance(message, str) else json.loads(message.decode("utf-8"))
                    if "endpoint" in artifact and "verdict" in artifact:
                        verdict = artifact.get("verdict", "UNKNOWN")
                        endpoint = artifact.get("endpoint", "?")
                        print(f"[BRIDGE] [#{self.received_count}] {verdict:12s} | {endpoint}")
                    else:
                        print(f"[BRIDGE] [#{self.received_count}] 非标准工件 (keys: {list(artifact.keys())})")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    print(f"[BRIDGE] [#{self.received_count}] 非 JSON 消息，原样透传 ({len(message)} bytes)")
                # 广播至所有其他客户端（不回发给发送者本身）
                await self.broadcast(message if isinstance(message, str) else message.decode("utf-8"), sender=websocket)
        except websockets.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)

    async def start(self) -> None:
        print(f"[BRIDGE] WebSocket 网关启动: ws://{self.host}:{self.port}")
        print(f"[BRIDGE] 等待上游推流与前端客户端接入...")
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
