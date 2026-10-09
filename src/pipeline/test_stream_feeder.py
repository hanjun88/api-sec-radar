#!/usr/bin/env python3
"""
端到端态势感知压测与工件推流发生器 (CI/CD Automated Execution Spec v7.0-STRICT)
职责：模拟 batch_differential_scan 与 artifact-emitter 高频输出，
通过 WebSocket (ws://127.0.0.1:8765) 持续灌入结构化工件，验证前端拓扑雷达与显存回收稳定性。
"""

import asyncio
import json
import os
import random
import signal
import sys
import time
from typing import Any

try:
    import websockets
except ImportError:
    print("[ERROR] 缺失 websockets 依赖，请执行: pip install websockets", file=sys.stderr)
    sys.exit(1)

TARGET_WS_URL = os.environ.get("WS_SERVER_URL", "ws://127.0.0.1:8765")
ENDPOINTS: list[str] = [
    "GET /api/v1/users/{id}",
    "GET /api/v1/orders/{id}",
    "GET /api/v1/accounts/{id}",
    "POST /api/v1/auth/login",
    "GET /api/v1/transactions/{id}",
    "GET /api/v1/profile",
    "PUT /api/v1/users/{id}/settings",
    "DELETE /api/v1/sessions/{id}",
    "GET /api/v1/wallet/{id}",
    "POST /api/v1/transfer",
    "GET /api/v1/documents/{id}",
    "PATCH /api/v1/profile",
    "GET /api/v1/admin/users",
    "POST /api/v1/admin/config",
    "GET /api/v1/payment/orders/{id}",
    "DELETE /api/v1/devices/{id}",
]

ROOT_CAUSES: dict[str, str] = {
    "VULNERABLE": "BOLA: Object-level reference parameter traversed without caller tenant boundary check.",
    "SAFE": "Authorization passed: Row-level security filter and principal ownership enforced.",
    "BLOCKED": "P0-INVARIANT-03: Non-idempotent write operation halted by safety circuit breaker.",
}


def build_synthetic_artifact() -> dict[str, Any]:
    endpoint = random.choice(ENDPOINTS)
    roll = random.random()

    if endpoint.startswith(("POST", "PUT", "DELETE", "PATCH")) and roll < 0.4:
        verdict = "BLOCKED"
        confidence = 1.0
        pri_status, sec_status, sim = 0, 0, 0.0
    elif roll < 0.45:
        verdict = "VULNERABLE"
        confidence = round(random.uniform(0.88, 0.99), 2)
        pri_status, sec_status = 200, 200
        sim = round(random.uniform(0.92, 1.0), 2)
    else:
        verdict = "SAFE"
        confidence = round(random.uniform(0.75, 0.95), 2)
        pri_status, sec_status = 200, 403
        sim = round(random.uniform(0.05, 0.25), 2)

    return {
        "endpoint": endpoint,
        "verdict": verdict,
        "confidence": confidence,
        "evidence": {
            "primary_status": pri_status,
            "secondary_status": sec_status,
            "response_similarity": sim,
            "elapsed_ms": random.randint(18, 140),
            "timestamp": int(time.time() * 1000),
        },
        "technical_root_cause": ROOT_CAUSES[verdict],
    }


class StreamFeeder:
    def __init__(self, uri: str = TARGET_WS_URL, interval_sec: float = 0.5):
        self.uri = uri
        self.interval_sec = interval_sec
        self.running = True
        self.sent_count = 0

    def stop(self) -> None:
        self.running = False

    async def run(self) -> None:
        print(f"[FEEDER] 尝试连接网关: {self.uri}")
        while self.running:
            try:
                async with websockets.connect(self.uri) as ws:
                    print("[FEEDER] WebSocket 链路已建立，开始注入测试工件流...")
                    while self.running:
                        artifact = build_synthetic_artifact()
                        payload = json.dumps(artifact)
                        await ws.send(payload)
                        self.sent_count += 1
                        print(
                            f"[FEEDER] [#{self.sent_count}] 推送: {artifact['verdict']} -> {artifact['endpoint']}"
                        )
                        await asyncio.sleep(self.interval_sec)
            except (websockets.ConnectionClosedError, ConnectionRefusedError) as e:
                if not self.running:
                    break
                print(f"[FEEDER] 网关尚未就绪或连接断开 ({e})，2 秒后重试...", file=sys.stderr)
                await asyncio.sleep(2.0)
            except Exception as e:
                print(f"[FEEDER] 未预期异常: {e}", file=sys.stderr)
                await asyncio.sleep(2.0)


async def main() -> None:
    feeder = StreamFeeder(TARGET_WS_URL, interval_sec=0.4)
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, feeder.stop)

    try:
        await feeder.run()
    finally:
        print(f"\n[FEEDER] 推流停止，累计推送工件数: {feeder.sent_count}")


if __name__ == "__main__":
    asyncio.run(main())
