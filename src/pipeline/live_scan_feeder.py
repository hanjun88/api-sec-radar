#!/usr/bin/env python3
"""
Live Scan Feeder (CI/CD Automated Execution Spec v7.0-STRICT)
职责：通过 MCP stdio 协议驱动 api-access-auditor 执行真实差分扫描，
将产出的漏洞证据转换为 VulnEvidencePayload 并实时推送至 WebSocket 广播网关。
这是态势感知流水线的最后一块拼图：真实审计数据 → 3D 拓扑渲染。
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

try:
    import websockets
except ImportError:
    print("[ERROR] 缺失 websockets 依赖，请执行: pip install websockets", file=sys.stderr)
    sys.exit(1)

WS_BRIDGE_URL = os.environ.get("WS_SERVER_URL", "ws://127.0.0.1:8765")
AUDITOR_MODULE = os.environ.get("AUDITOR_MODULE", "src.auditor.auditor_mcp_server")
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCAN_INTERVAL_SEC = float(os.environ.get("SCAN_INTERVAL_SEC", "5.0"))

DEFAULT_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Live Scan Target", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:18099"}],
    "paths": {
        "/api/v1/accounts/{id}": {
            "get": {
                "summary": "Get account by ID (BOLA candidate)",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/v1/users/{id}": {
            "get": {
                "summary": "Get user profile by ID (BOLA candidate)",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/v1/orders/{id}": {
            "get": {
                "summary": "Get order by ID (BOLA candidate)",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/v1/health": {
            "get": {"summary": "Health check (safe, no object ref)"}
        },
    },
}


class MCPClient:
    """轻量 MCP JSON-RPC over stdio 客户端，用于驱动 api-access-auditor。"""

    def __init__(self, module: str = AUDITOR_MODULE, cwd: str = PROJECT_ROOT):
        self.module = module
        self.cwd = cwd
        self.process: Optional[subprocess.Popen] = None
        self._req_id = 0
        self._initialized = False

    def is_alive(self) -> bool:
        """探测 MCP 子进程是否仍在运行（M6 存活检测）。"""
        return self.process is not None and self.process.poll() is None

    def start(self) -> None:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        self.process = subprocess.Popen(
            [sys.executable, "-m", self.module],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=self.cwd,
            env=env,
        )

    def _send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.process:
            raise RuntimeError("MCP process not started")
        self._req_id += 1
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        line = json.dumps(payload) + "\n"
        self.process.stdin.write(line)
        self.process.stdin.flush()

        response_line = self.process.stdout.readline()
        if not response_line:
            stderr = self.process.stderr.read()
            raise RuntimeError(f"MCP process exited. stderr: {stderr}")
        return json.loads(response_line)

    def _send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if not self.process:
            return
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def initialize(self) -> Dict[str, Any]:
        result = self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "live-scan-feeder", "version": "1.0.0"},
            },
        )
        self._send_notification("notifications/initialized")
        self._initialized = True
        return result

    def list_tools(self) -> List[str]:
        result = self._send_request("tools/list")
        tools = result.get("result", {}).get("tools", [])
        return [t["name"] for t in tools]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        result = self._send_request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        content = result.get("result", {}).get("content", [])
        if content and content[0].get("type") == "text":
            try:
                return json.loads(content[0]["text"])
            except json.JSONDecodeError:
                return {"raw": content[0]["text"]}
        return result

    def stop(self) -> None:
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None
        self._initialized = False


def normalize_verdict(raw: str) -> str:
    """将审计引擎的原始判定映射为前端三态枚举。

    引擎（``core._verdict``）产出 VULNERABLE / PRIV_ESCALATION / SUSPECT /
    LIKELY_SAFE / SAFE / INCONCLUSIVE，加上上层熔断的 BLOCKED 与 ERROR，
    共八类，此处须全部覆盖。PRIV_ESCALATION（属主被拒、攻击者通过）与
    SUSPECT（软越权嫌疑）都是引擎已判定的越权信号，不得降级为
    INCONCLUSIVE，否则高危信号会在态势雷达上静默消失。
    """
    upper = raw.upper()
    if "BLOCK" in upper or "SAFE_GUARD" in upper or "INVARIANT" in upper:
        return "BLOCKED"
    if "VULN" in upper or "BOLA" in upper or "BROKEN" in upper:
        return "VULNERABLE"
    # 权限提升与软越权嫌疑：引擎已判定的越权信号，归入 VULNERABLE
    if "PRIV_ESCALATION" in upper or "ESCALAT" in upper or "SUSPECT" in upper:
        return "VULNERABLE"
    # LIKELY_SAFE 含子串 SAFE，须先于 SAFE 分支判定
    if "LIKELY_SAFE" in upper:
        return "SAFE"
    if "SAFE" in upper or "SECURE" in upper or "OK" in upper:
        return "SAFE"
    return "INCONCLUSIVE"


def build_artifact_from_scan_result(scan_item: Dict[str, Any]) -> Dict[str, Any]:
    """将 batch_differential_scan 的单条结果转换为 VulnEvidencePayload。"""
    endpoint = scan_item.get("endpoint", scan_item.get("url", "UNKNOWN"))
    verdict_raw = scan_item.get("verdict", scan_item.get("vulnerability_detected", "UNKNOWN"))
    if isinstance(verdict_raw, bool):
        verdict_raw = "VULNERABLE" if verdict_raw else "SAFE"
    verdict = normalize_verdict(str(verdict_raw))

    evidence = scan_item.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    return {
        "endpoint": endpoint,
        "verdict": verdict,
        "confidence": float(scan_item.get("confidence_score", scan_item.get("confidence", 0.8))),
        "evidence": {
            "primary_status": int(evidence.get("primary_status", scan_item.get("primary_status", 0))),
            "secondary_status": int(evidence.get("secondary_status", scan_item.get("secondary_status", 0))),
            "response_similarity": float(
                evidence.get(
                    "response_similarity",
                    evidence.get("similarity", scan_item.get("response_similarity", scan_item.get("similarity", 0.0))),
                )
            ),
            "elapsed_ms": int(evidence.get("elapsed_ms", scan_item.get("elapsed_ms", 0))),
            "timestamp": int(time.time() * 1000),
        },
        "technical_root_cause": scan_item.get(
            "root_cause_analysis",
            scan_item.get("technical_root_cause", "Differential access scan completed."),
        ),
    }


class LiveScanFeeder:
    """真实扫描驱动的工件推流器：MCP 审计 → WebSocket 广播。"""

    def __init__(
        self,
        ws_url: str = WS_BRIDGE_URL,
        openapi_spec: Optional[Dict[str, Any]] = None,
        scan_interval_sec: float = SCAN_INTERVAL_SEC,
        primary_token: str = "Bearer token-alice",
        secondary_token: str = "Bearer token-bob",
        mcp_factory: Callable[[], "MCPClient"] = MCPClient,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
        ws_connect_fn: Callable[..., Any] = websockets.connect,
        max_reconnect_attempts: int = 5,
        base_reconnect_backoff_sec: float = 2.0,
    ):
        self.ws_url = ws_url
        self.openapi_spec = openapi_spec or DEFAULT_OPENAPI_SPEC
        self.scan_interval_sec = scan_interval_sec
        self.primary_token = primary_token
        self.secondary_token = secondary_token
        self.running = True
        self.scan_count = 0
        self.artifact_count = 0
        self.mcp: Optional[MCPClient] = None
        # 可注入的外部依赖：MCP 子进程工厂、异步 sleep、WebSocket 连接工厂。
        # 默认值等价于改造前的硬编码行为，CLI 用法不受影响。
        self._mcp_factory = mcp_factory
        self._sleep = sleep_fn
        self._ws_connect = ws_connect_fn
        # M6：MCP 子进程重连配置。连续重连失败超过上限则退出推流，
        # 避免进程崩溃后 feeder 静默空转、永远推不出数据也不退出。
        self.max_reconnect_attempts = max_reconnect_attempts
        self.base_reconnect_backoff_sec = base_reconnect_backoff_sec
        self._consecutive_failures = 0

    def stop(self) -> None:
        self.running = False

    async def _push_via_websocket(self, artifacts: List[Dict[str, Any]]) -> None:
        try:
            async with self._ws_connect(self.ws_url) as ws:
                for artifact in artifacts:
                    await ws.send(json.dumps(artifact))
                    self.artifact_count += 1
                    print(
                        f"[LIVE] [#{self.artifact_count}] {artifact['verdict']:12s} | {artifact['endpoint']}"
                    )
        except (websockets.ConnectionClosedError, ConnectionRefusedError) as e:
            print(f"[LIVE] WebSocket 网关不可用 ({e})，工件已生成但未推送。", file=sys.stderr)
        except Exception as e:
            print(f"[LIVE] WebSocket 推送异常: {e}", file=sys.stderr)

    def _run_single_scan_cycle(self) -> List[Dict[str, Any]]:
        """执行一次完整的 ingest_openapi → batch_differential_scan 循环。"""
        if not self.mcp:
            return []

        self.scan_count += 1
        print(f"\n[SCAN] === 第 {self.scan_count} 轮真实差分扫描 ===")

        # Phase 1: 白盒契约摄入
        try:
            ingest_result = self.mcp.call_tool(
                "ingest_openapi",
                {
                    "spec_content_or_path": json.dumps(self.openapi_spec),
                    "primary_headers_json": json.dumps({"Authorization": self.primary_token}),
                    "secondary_headers_json": json.dumps({"Authorization": self.secondary_token}),
                    # 只摄入含对象级引用参数的端点（BOLA/IDOR 高风险面）。
                    # 若不过滤，/api/v1/health 这类无对象引用的端点会被差分引擎按
                    # 「两个身份读到相同内容」判成 VULNERABLE，形成假阳性淹没真信号。
                    "only_auditable": True,
                },
            )
            target_matrix = ingest_result if isinstance(ingest_result, list) else ingest_result.get(
                "target_matrix", ingest_result.get("matrix", [])
            )
            print(f"[SCAN] ingest_openapi 产出待测矩阵: {len(target_matrix)} 条")
        except Exception as e:
            print(f"[SCAN] ingest_openapi 失败: {e}", file=sys.stderr)
            return []

        if not target_matrix:
            print("[SCAN] 待测矩阵为空，跳过本轮。")
            return []

        # Phase 2: 批量差分扫描
        try:
            scan_result = self.mcp.call_tool(
                "batch_differential_scan",
                {
                    "target_matrix": target_matrix,
                    "max_concurrency": 2,
                    "interval_ms": 100,
                    "allow_write": False,
                },
            )
        except Exception as e:
            print(f"[SCAN] batch_differential_scan 失败: {e}", file=sys.stderr)
            return []

        # Phase 3: 解析扫描结果
        results: List[Dict[str, Any]] = []
        if isinstance(scan_result, list):
            results = scan_result
        elif isinstance(scan_result, dict):
            results = (
                scan_result.get("all_results")
                or scan_result.get("results")
                or scan_result.get("scan_results")
                or scan_result.get("vulnerabilities")
                or []
            )
            if not results and "endpoint" in scan_result:
                results = [scan_result]

        print(f"[SCAN] batch_differential_scan 返回 {len(results)} 条结果")

        # Phase 4: 转换为 VulnEvidencePayload
        artifacts = []
        for item in results:
            if isinstance(item, dict):
                artifacts.append(build_artifact_from_scan_result(item))

        vuln_count = sum(1 for a in artifacts if a["verdict"] == "VULNERABLE")
        safe_count = sum(1 for a in artifacts if a["verdict"] == "SAFE")
        blocked_count = sum(1 for a in artifacts if a["verdict"] == "BLOCKED")
        print(f"[SCAN] 判定分布: VULNERABLE={vuln_count} | SAFE={safe_count} | BLOCKED={blocked_count}")

        return artifacts

    async def _ensure_mcp(self) -> bool:
        """探测 MCP 子进程存活；崩溃则退避重连，连续失败超限则退出（M6）。

        返回 True 表示当前可用（已存活或已成功重连），False 表示
        连续重连失败已达上限，调用方应停止推流。
        """
        if self.mcp is not None and self.mcp.is_alive():
            return True

        # 进程已死，进入重连流程
        self._consecutive_failures += 1
        if self._consecutive_failures > self.max_reconnect_attempts:
            print(
                f"[LIVE] MCP 子进程连续 {self._consecutive_failures} 次重连失败，停止推流。",
                file=sys.stderr,
            )
            self.running = False
            return False

        backoff = min(self.base_reconnect_backoff_sec * (2 ** (self._consecutive_failures - 1)), 30.0)
        print(
            f"[LIVE] MCP 子进程已异常退出，{backoff:.1f}s 后第 {self._consecutive_failures} 次重连...",
            file=sys.stderr,
        )
        await self._sleep(backoff)
        try:
            if self.mcp is not None:
                self.mcp.stop()
            self.mcp = self._mcp_factory()
            self.mcp.start()
            self.mcp.initialize()
            self.mcp.list_tools()
            self._consecutive_failures = 0
            print("[LIVE] MCP 审计引擎已重连并恢复。")
            return True
        except Exception as e:
            print(f"[LIVE] MCP 重连失败: {e}", file=sys.stderr)
            return False

    async def run(self) -> None:
        print(f"[LIVE] 启动真实扫描推流器 → {self.ws_url}")
        print(f"[LIVE] 审计模块: {AUDITOR_MODULE} | 扫描间隔: {self.scan_interval_sec}s")

        # 启动 MCP 审计引擎
        self.mcp = self._mcp_factory()
        try:
            self.mcp.start()
            self.mcp.initialize()
            tools = self.mcp.list_tools()
            print(f"[LIVE] MCP 审计引擎已就绪，注册工具: {tools}")
        except Exception as e:
            print(f"[LIVE] MCP 审计引擎启动失败: {e}", file=sys.stderr)
            print("[LIVE] 请确认 src.auditor 包可通过 python -m src.auditor.auditor_mcp_server 启动。", file=sys.stderr)
            return

        try:
            while self.running:
                # M6：每轮先探测 MCP 存活，崩溃则退避重连；重连失败超限则退出。
                if not await self._ensure_mcp():
                    break
                await self._run_one_iteration()
        finally:
            self.mcp.stop()
            print(f"\n[LIVE] 推流停止。扫描轮次: {self.scan_count} | 推送工件: {self.artifact_count}")

    async def _run_one_iteration(self) -> None:
        """单轮：扫描 → 推流 → 间隔等待。

        抽出独立方法后，测试可注入假 sleep（跑 N 轮后调用 stop()）确定性地
        驱动循环，无需真实等待或真实网络。

        M7：整轮包 try/except，Phase3/4（结果解析、build_artifact）任一畸形
        结果只跳过本轮，不再永久杀死推流。L4：同步子进程 I/O（MCPClient 的
        阻塞式 readline/write）经 to_thread 卸载到线程池，避免阻塞事件循环。
        """
        try:
            artifacts = await asyncio.to_thread(self._run_single_scan_cycle)
            if artifacts:
                await self._push_via_websocket(artifacts)
            await self._sleep(self.scan_interval_sec)
        except Exception as e:
            print(f"[LIVE] 单轮迭代异常（已忽略，继续推流）: {e}", file=sys.stderr)
            await self._sleep(self.scan_interval_sec)


async def main() -> None:
    # L3：统一读取 SCAN_INTERVAL_SEC 环境变量，避免 main() 写死间隔忽略配置。
    feeder = LiveScanFeeder(
        ws_url=WS_BRIDGE_URL,
        openapi_spec=DEFAULT_OPENAPI_SPEC,
        scan_interval_sec=SCAN_INTERVAL_SEC,
    )
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, feeder.stop)
    await feeder.run()


if __name__ == "__main__":
    asyncio.run(main())
