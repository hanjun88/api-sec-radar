"""tests/conftest.py — 跨测试共享 fixture 与靶场。

提供：
  - mock_target_server: 内置多种漏洞类型的本地 HTTP 靶场
  - mock_openapi_spec: 10+ 端点的 OpenAPI 3.0 规范字符串
  - mock_har_content: 5+ 请求的 HAR JSON 字符串
  - sample_poc_report: 完整 PoCReport dict
  - sample_pipeline_result: 完整流水线结果 dict
  - MCPTestClient: MCP stdio 子进程客户端（E2E 测试复用）
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Generator, Optional

import pytest

# 项目根目录加入 sys.path 以便直接 import 被测包
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def pytest_addoption(parser: Any) -> None:
    """注册 --run-performance 命令行开关。"""
    parser.addoption(
        "--run-performance",
        action="store_true",
        default=False,
        help="运行标记为 performance 的基准测试（默认跳过）",
    )


def pytest_configure(config: Any) -> None:
    """注册 performance marker，避免未知标记警告。"""
    config.addinivalue_line("markers", "performance: 性能基准测试（默认跳过，加 --run-performance 运行）")


def pytest_collection_modifyitems(config: Any, items: list) -> None:
    """未传 --run-performance 时跳过所有 performance 标记的用例。"""
    if config.getoption("--run-performance"):
        return
    skip_perf = pytest.mark.skip(reason="需要 --run-performance 才运行性能基准测试")
    for item in items:
        if "performance" in item.keywords:
            item.add_marker(skip_perf)


# ── 靶场数据 ─────────────────────────────────────────────────

_MOCK_ACCOUNTS: Dict[str, Dict[str, Any]] = {
    "1001": {"id": "1001", "owner": "alice", "balance": 50000.0, "ssn": "111-22-1001"},
    "1002": {"id": "1002", "owner": "bob", "balance": 120.0, "ssn": "222-33-1002"},
    "1003": {"id": "1003", "owner": "charlie", "balance": 9999.0, "ssn": "333-44-1003"},
}

_RATE_LIMIT_COUNTS: Dict[str, int] = {}


class _MockTargetHandler(BaseHTTPRequestHandler):
    """内置 BOLA/IDOR、越权写入、功能级越权、安全端点与限速端点的靶场。"""

    def log_message(self, *args: Any) -> None:  # noqa: D401 - 静默访问日志
        """吞掉默认 stderr 访问日志，保持测试输出干净。"""
        return

    # ── 工具方法 ──────────────────────────────────────────
    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer "):]
        return ""

    def _json(self, status: int, body: Dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # ── GET ───────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 命名约定
        path = self.path.split("?")[0]
        token = self._bearer()
        if not token:
            self._json(401, {"error": "unauthorized"})
            return

        # BOLA/IDOR：不校验所有权，任意 token 可读任意账户
        if path.startswith("/api/v1/accounts/"):
            acc_id = path.rsplit("/", 1)[-1]
            if acc_id in _MOCK_ACCOUNTS:
                self._json(200, _MOCK_ACCOUNTS[acc_id])
                return
            self._json(404, {"error": "no such account"})
            return

        # 功能级越权：普通用户可访问 admin 端点（漏洞）
        if path == "/api/v1/admin/users":
            self._json(200, {"users": [{"id": "1001"}, {"id": "1002"}, {"id": "1003"}]})
            return

        # 安全端点：仅属主 alice 可读，其余 403（正确拒绝）
        if path.startswith("/api/v1/secure/"):
            owner_id = path.rsplit("/", 1)[-1]
            record = _MOCK_ACCOUNTS.get(owner_id)
            if record is None:
                self._json(404, {"error": "not found"})
                return
            expected_owner = record["owner"]
            # token 约定：token-<owner>
            if token == f"token-{expected_owner}":
                self._json(200, record)
            else:
                self._json(403, {"error": "forbidden: not owner"})
            return

        # 速率限制端点：第 3 次及以后返回 429
        if path == "/api/v1/rate-limited":
            key = f"get:{token}"
            count = _RATE_LIMIT_COUNTS.get(key, 0) + 1
            _RATE_LIMIT_COUNTS[key] = count
            if count >= 3:
                self._json(429, {"error": "too many requests", "attempt": count})
                return
            self._json(200, {"ok": True, "attempt": count})
            return

        # 健康检查
        if path == "/api/v1/health":
            self._json(200, {"status": "ok"})
            return

        self._json(404, {"error": "not found"})

    # ── PUT（越权写入）───────────────────────────────────
    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 命名约定
        path = self.path.split("?")[0]
        token = self._bearer()
        if not token:
            self._json(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b"{}"

        # 越权写入：不校验所有权，任意 token 均可更新任意账户
        if path.startswith("/api/v1/accounts/"):
            acc_id = path.rsplit("/", 1)[-1]
            if acc_id in _MOCK_ACCOUNTS:
                try:
                    update = json.loads(body.decode("utf-8") or "{}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    update = {}
                # 模块级账户表（非实例属性），此前误写 self._MOCK_ACCOUNTS 导致
                # PUT 端点 500，越权写入靶场不可用。
                _MOCK_ACCOUNTS[acc_id].update(
                    {k: v for k, v in update.items() if k in ("balance", "owner")}
                )
                self._json(200, {"updated": True, "account": _MOCK_ACCOUNTS[acc_id]})
                return
            self._json(404, {"error": "no such account"})
            return

        self._json(404, {"error": "not found"})


# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture(scope="module")
def mock_target_server() -> Generator[str, None, None]:
    """启动本地漏洞靶场 HTTP server，返回基址 http://127.0.0.1:<port>。

    模块级共享：同一测试文件内所有用例复用，结束后自动 shutdown。
    """
    server = HTTPServer(("127.0.0.1", 0), _MockTargetHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # 等待端口就绪
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def mock_openapi_spec() -> str:
    """返回包含 12 个端点的 OpenAPI 3.0 规范字符串。"""
    spec: Dict[str, Any] = {
        "openapi": "3.0.0",
        "info": {"title": "Acme API", "version": "1.0.0"},
        "servers": [{"url": "http://target.local"}],
        "paths": {
            "/api/v1/accounts/{accountId}": {
                "get": {"summary": "Get account by id"},
                "put": {"summary": "Update account by id"},
            },
            "/api/v1/accounts": {
                "get": {"summary": "List accounts"},
                "post": {
                    "summary": "Create account",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "example": {"owner": "new-user", "balance": 0}
                            }
                        }
                    },
                },
            },
            "/api/v1/users/{userId}": {"get": {"summary": "Get user"}},
            "/api/v1/orders/{orderId}": {
                "get": {"summary": "Get order"},
                "delete": {"summary": "Delete order"},
            },
            "/api/v1/products/{productId}": {"get": {"summary": "Get product"}},
            "/api/v1/admin/users": {"get": {"summary": "List admin users"}},
            "/api/v1/health": {"get": {"summary": "Health check"}},
        },
    }
    return json.dumps(spec)


@pytest.fixture(scope="session")
def mock_har_content() -> str:
    """返回包含 6 个请求的 HAR JSON 字符串。"""
    entries = []
    for acc_id in ("1001", "1002", "1003"):
        entries.append({
            "request": {
                "method": "GET",
                "url": f"http://target.local/api/v1/accounts/{acc_id}",
                "headers": [{"name": "Authorization", "value": "Bearer token-alice"}],
                "queryString": [],
            },
            "response": {"status": 200, "content": {"text": "{}"}},
        })
    entries.append({
        "request": {
            "method": "GET",
            "url": "http://target.local/api/v1/orders/ORD-9001",
            "headers": [{"name": "Authorization", "value": "Bearer token-alice"}],
            "queryString": [],
        },
        "response": {"status": 200, "content": {"text": "{}"}},
    })
    entries.append({
        "request": {
            "method": "POST",
            "url": "http://target.local/api/v1/accounts",
            "headers": [{"name": "Authorization", "value": "Bearer token-alice"}],
            "queryString": [],
            "postData": {"text": '{"owner":"x"}'},
        },
        "response": {"status": 201, "content": {"text": "{}"}},
    })
    entries.append({
        "request": {
            "method": "GET",
            "url": "http://target.local/api/v1/health",
            "headers": [{"name": "Authorization", "value": "Bearer token-alice"}],
            "queryString": [],
        },
        "response": {"status": 200, "content": {"text": "{}"}},
    })
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": entries}})


@pytest.fixture(scope="session")
def sample_poc_report() -> Dict[str, Any]:
    """返回一个完整的 PoCReport dict。"""
    return {
        "poc_id": "POC-TEST000001",
        "endpoint": "GET /api/v1/accounts/1001",
        "method": "GET",
        "url": "http://target.local/api/v1/accounts/1001",
        "vulnerability_type": "BOLA/IDOR",
        "severity": "critical",
        "confidence": 0.97,
        "similarity": 0.98,
        "primary_status": 200,
        "secondary_status": 200,
        "primary_request": {
            "method": "GET",
            "url": "http://target.local/api/v1/accounts/1001",
            "headers": {"Authorization": "***REDACTED***"},
            "expected_status": 200,
        },
        "secondary_request": {
            "method": "GET",
            "url": "http://target.local/api/v1/accounts/1001",
            "headers": {"Authorization": "***REDACTED***"},
            "expected_status": 200,
        },
        "evidence": {
            "status_match": True,
            "primary_status": 200,
            "secondary_status": 200,
            "similarity": 0.98,
            "threshold": 0.85,
            "content_length_delta": 0,
        },
        "root_cause": "Endpoint extracts account_id from URL without ownership check.",
        "remediation_hint": "Bind lookup to current_user.tenant_id and return 404.",
    }


@pytest.fixture(scope="session")
def sample_pipeline_result(sample_poc_report: Dict[str, Any]) -> Dict[str, Any]:
    """返回一个完整的流水线结果 dict。"""
    return {
        "pipeline_id": "PIPE-TEST000001",
        "program_id": "PROG-TEST000001",
        "program_name": "Test Program",
        "started_at": "2026-09-12T00:00:00+00:00",
        "finished_at": "2026-09-12T00:00:01+00:00",
        "elapsed_ms": 1234.5,
        "ingestion": {
            "total_ingested": 6,
            "in_scope": 6,
            "out_of_scope_filtered": 0,
            "auditable_count": 4,
            "safe_method_count": 5,
            "sources": ["har"],
        },
        "scan": {
            "scan_id": "SCAN-TEST000001",
            "status": "completed",
            "total_targets": 6,
            "scanned": 6,
            "vulnerable": 3,
            "safe": 1,
            "blocked": 1,
            "inconclusive": 1,
            "error": 0,
            "elapsed_ms": 1100.0,
        },
        "poc": {
            "total_vulnerabilities": 3,
            "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "informational": 0},
        },
        "target_matrix": [],
        "scan_result": None,
        "poc_reports": [sample_poc_report],
        "estimated_bounty": 9000.0,
        "bounty_breakdown": {"critical": 5000.0, "high": 4000.0},
        "status": "completed",
        "errors": [],
    }


# ── MCP stdio 客户端（E2E 复用）──────────────────────────────


class MCPTestClient:
    """最小 MCP stdio JSON-RPC 客户端，用于端到端测试 MCP server 子进程。"""

    def __init__(self, command: list[str]) -> None:
        import subprocess
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
        )
        self._req_id = 0

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._req_id += 1
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            assert self.proc.stderr is not None
            raise RuntimeError(f"MCP server exited: {self.proc.stderr.read()}")
        return json.loads(line)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        raw = self.call("tools/call", {"name": name, "arguments": arguments})
        return json.loads(raw["result"]["content"][0]["text"])

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture(scope="module")
def auditor_mcp_client(mock_target_server: str):
    """启动 src.auditor MCP 子进程并完成 initialize 握手。"""
    pytest.importorskip("mcp")
    import sys as _sys
    client = MCPTestClient([_sys.executable, "-m", "src.auditor.auditor_mcp_server"])
    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        })
        client.notify("notifications/initialized")
        yield client
    finally:
        client.close()


# 已移除 bounty_mcp_client：其依赖的 bounty_platform 包不随仓库分发，
# 也未在 requirements.txt 声明，使用该 fixture 必然失败（幽灵引用）。
