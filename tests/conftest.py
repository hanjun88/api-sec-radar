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
                self._MOCK_ACCOUNTS[acc_id].update(
                    {k: v for k, v in update.items() if k in ("balance", "owner")}
                )
                self._json(200, {"updated": True, "account": _MOCK_ACCOUNTS[acc_id]})
                return
            self._json(404, {"error": "no such account"})
            return

        self._json(404, {"error": "not found"})


# ── Fixtures ─────────────────────────────────────────────────


