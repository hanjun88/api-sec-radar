#!/usr/bin/env python3
"""
Live Scan Feeder (CI/CD Automated Execution Spec v7.0-STRICT)
职责：通过 MCP stdio 协议驱动 api-access-auditor 执行真实差分扫描，
将产出的漏洞证据转换为 VulnEvidencePayload 并实时推送至 WebSocket 广播网关。
这是态势感知流水线的最后一块拼图：真实审计数据 → 3D 拓扑渲染。
"""

import asyncio
import copy
import json
import logging
import os
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

try:
    import websockets
except ImportError:
    print("[ERROR] 缺失 websockets 依赖，请执行: pip install websockets", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger("live-scan-feeder")

WS_BRIDGE_URL = os.environ.get("WS_SERVER_URL", "ws://127.0.0.1:8765")
AUDITOR_MODULE = os.environ.get("AUDITOR_MODULE", "src.auditor.auditor_mcp_server")
# P0-①: __file__ 位于 src/pipeline/，三级 dirname 才是仓库根；
# 子进程以仓库根为 cwd 才能 import src.auditor 包。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCAN_INTERVAL_SEC = float(os.environ.get("SCAN_INTERVAL_SEC", "5.0"))

# P2-⑩: 并发度从环境变量读取，默认 2。
CONCURRENCY_LIMIT = int(os.environ.get("CONCURRENCY_LIMIT", "2"))

# P1-⑥: 环境变量入口覆盖硬编码默认值。
_DEFAULT_TARGET_BASE_URL = "http://127.0.0.1:18099"
_DEFAULT_PRIMARY_TOKEN = "token-alice"
_DEFAULT_SECONDARY_TOKEN = "token-bob"
OPENAPI_SPEC_PATH = os.environ.get("OPENAPI_SPEC_PATH", "")
TARGET_BASE_URL = os.environ.get("TARGET_BASE_URL", "")
PRIMARY_TOKEN = os.environ.get("PRIMARY_TOKEN", _DEFAULT_PRIMARY_TOKEN)
SECONDARY_TOKEN = os.environ.get("SECONDARY_TOKEN", _DEFAULT_SECONDARY_TOKEN)
# 未指定任何目标相关环境变量时，即落在默认假目标上，必须在启动时警告。
USING_DEFAULT_TARGET = not OPENAPI_SPEC_PATH and not TARGET_BASE_URL

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


def _load_openapi_spec() -> Dict[str, Any]:
    """P1-⑥: 构造生效的扫描目标规范。

    - OPENAPI_SPEC_PATH 指向 JSON 规范文件时，从文件加载；
    - 否则使用内置 DEFAULT_OPENAPI_SPEC 的深拷贝；
    - TARGET_BASE_URL 非空时覆盖 servers[0].url。
    """
    if OPENAPI_SPEC_PATH:
        with open(OPENAPI_SPEC_PATH, "r", encoding="utf-8") as f:
            spec = json.load(f)
        if not isinstance(spec, dict):
            raise ValueError(f"OPENAPI_SPEC_PATH 文件内容不是 JSON 对象: {OPENAPI_SPEC_PATH}")
    else:
        spec = copy.deepcopy(DEFAULT_OPENAPI_SPEC)
    if TARGET_BASE_URL and isinstance(spec.get("servers"), list) and spec["servers"]:
        spec["servers"][0]["url"] = TARGET_BASE_URL
    return spec


class MCPClient:
    """轻量 MCP JSON-RPC over stdio 客户端，用于驱动 api-access-auditor。"""

    def __init__(self, module: str = AUDITOR_MODULE, cwd: str = PROJECT_ROOT):
        self.module = module
        self.cwd = cwd
        self.process: Optional[subprocess.Popen] = None
        self._req_id = 0
        self._initialized = False

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
    """将审计引擎的原始判定映射为前端三态枚举。"""
    upper = raw.upper()
    if "VULN" in upper or "BOLA" in upper or "BROKEN" in upper:
        return "VULNERABLE"
    # P1-⑤: 提权 / 软越权嫌疑是高价值信号，必须保留为 VULNERABLE，
    # 不得降级为 INCONCLUSIVE（大屏否则丢失提权信号）。
    if "PRIV_ESCALATION" in upper or "PRIVILEGE_ESCALATION" in upper or "SUSPECT" in upper:
        return "VULNERABLE"
    if "BLOCK" in upper or "SAFE_GUARD" in upper or "INVARIANT" in upper:
        return "BLOCKED"
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
                evidence.get("response_similarity", scan_item.get("response_similarity", 0.0))
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
        primary_token: str = PRIMARY_TOKEN,
        secondary_token: str = SECONDARY_TOKEN,
    ):
        self.ws_url = ws_url
        self.openapi_spec = openapi_spec or _load_openapi_spec()
        self.scan_interval_sec = scan_interval_sec
        # P0-④: 透传给 batch_differential_scan 的 token 必须是原始值
        # （hook 链会自行拼接 "Bearer " 前缀），剥离用户可能附带的 Bearer 前缀。
        self.primary_token = self._strip_bearer_prefix(primary_token)
        self.secondary_token = self._strip_bearer_prefix(secondary_token)
        self.running = True
        self.scan_count = 0
        self.artifact_count = 0
        self.mcp: Optional[MCPClient] = None

    @staticmethod
    def _strip_bearer_prefix(token: str) -> str:
        t = token.strip()
        if t.lower().startswith("bearer "):
            return t[len("bearer "):]
        return t

    def stop(self) -> None:
        self.running = False

    async def _push_via_websocket(self, artifacts: List[Dict[str, Any]]) -> None:
        try:
            async with websockets.connect(self.ws_url) as ws:
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
        # P0-②: 工具签名要求 *_headers_json: str（JSON 字符串），不是 dict。
        try:
            ingest_result = self.mcp.call_tool(
                "ingest_openapi",
                {
                    "spec_content_or_path": json.dumps(self.openapi_spec),
                    "secondary_headers_json": json.dumps(
                        {"Authorization": f"Bearer {self.secondary_token}"}
                    ),
                    "primary_headers_json": json.dumps(
                        {"Authorization": f"Bearer {self.primary_token}"}
                    ),
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
        # P2-⑩: max_concurrency 从环境变量 CONCURRENCY_LIMIT 读取（默认 2）；
        # P0-④: 透传 primary/secondary token，工具支持动态签名。
        try:
            scan_result = self.mcp.call_tool(
                "batch_differential_scan",
                {
                    "target_matrix": target_matrix,
                    "max_concurrency": CONCURRENCY_LIMIT,
                    "interval_ms": 100,
                    "allow_write": False,
                    "primary_token": self.primary_token,
                    "secondary_token": self.secondary_token,
                },
            )
        except Exception as e:
            print(f"[SCAN] batch_differential_scan 失败: {e}", file=sys.stderr)
            return []

        # [新增补丁] Phase 2.5: 自动触发报告双轨落盘（Markdown + JSON）
        try:
            report_res = self.mcp.call_tool(
                "emit_audit_report",
                {
                    "scan_result": scan_result,
                    "target": TARGET_BASE_URL or "http://127.0.0.1:18099",
                    "output_dir": "reports",
                },
            )
            if isinstance(report_res, dict) and report_res.get("status") == "DELIVERED":
                print(f"[SCAN] 审计报告已生成: {report_res.get('markdown_path')}")
            else:
                err = report_res.get("error") if isinstance(report_res, dict) else report_res
                print(f"[SCAN] 报告生成失败: {err}", file=sys.stderr)
        except Exception as e:
            print(f"[SCAN] 报告生成失败: {e}", file=sys.stderr)

        # Phase 3: 解析扫描结果
        # P0-③: 生产者实际返回键是 "all_results"，不是 "results"。
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

    async def run(self) -> None:
        print(f"[LIVE] 启动真实扫描推流器 → {self.ws_url}")
        print(f"[LIVE] 审计模块: {AUDITOR_MODULE} | 扫描间隔: {self.scan_interval_sec}s")
        # P1-⑥: 使用默认值（假目标/测试凭证）时必须打醒目警告。
        if USING_DEFAULT_TARGET:
            logger.warning(
                "⚠ 当前使用默认假目标 http://127.0.0.1:18099 与默认测试凭证 "
                "(PRIMARY_TOKEN/SECONDARY_TOKEN 未设置)，扫描结果仅供演示；"
                "指向真实目标请设置 OPENAPI_SPEC_PATH / TARGET_BASE_URL / "
                "PRIMARY_TOKEN / SECONDARY_TOKEN 环境变量。"
            )

        # 启动 MCP 审计引擎
        self.mcp = MCPClient()
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
                artifacts = self._run_single_scan_cycle()
                if artifacts:
                    await self._push_via_websocket(artifacts)
                await asyncio.sleep(self.scan_interval_sec)
        finally:
            self.mcp.stop()
            print(f"\n[LIVE] 推流停止。扫描轮次: {self.scan_count} | 推送工件: {self.artifact_count}")


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    feeder = LiveScanFeeder(
        ws_url=WS_BRIDGE_URL,
        scan_interval_sec=5.0,
    )
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, feeder.stop)
    await feeder.run()


if __name__ == "__main__":
    asyncio.run(main())
