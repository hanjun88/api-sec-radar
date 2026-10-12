"""tests/test_e2e_full_chain.py — 全链路端到端组（真实子进程 + 真实网关 + 真实靶场）

覆盖完整闭环：
    Mock 靶场 → run_pipeline/MCP/CLI → WebSocket 广播网关 → 大屏客户端接收工件
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

import pytest

from src.auditor.pipeline_orchestrator import (
    PipelineConfig,
    PipelineSource,
    run_pipeline,
)
from tests.conftest import MCPTestClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture()
def ws_bridge():
    """启动真实 ws_bridge_server 子进程，返回 ws:// URL。"""
    port = _free_port()
    env = dict(os.environ, WS_HOST="127.0.0.1", WS_PORT=str(port), PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(
        [sys.executable, "src/pipeline/ws_bridge_server.py"],
        cwd=PROJECT_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert _wait_port(port), "ws_bridge_server 未能在超时内就绪"
    try:
        yield f"ws://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _spec(base_url: str) -> str:
    return json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "E2E", "version": "1.0.0"},
        "servers": [{"url": base_url}],
        "paths": {
            "/api/v1/accounts/{id}": {"get": {"summary": "BOLA"}},
            "/api/v1/secure/{id}": {"get": {"summary": "Secure"}},
            "/api/v1/health": {"get": {"summary": "Health"}},
        },
    })


def _cfg(**overrides) -> PipelineConfig:
    defaults = dict(
        program_id="PROG-E2E",
        program_name="E2E Chain",
        primary_token="Bearer token-alice",
        secondary_token="Bearer token-bob",
    )
    defaults.update(overrides)
    return PipelineConfig(**defaults)


def _recv_artifacts(ws, expected: int, timeout: float = 10.0):
    """从大屏客户端连接收取 expected 条工件。"""
    received = []
    deadline = time.time() + timeout
    while len(received) < expected and time.time() < deadline:
        try:
            raw = ws.recv(timeout=max(0.1, deadline - time.time()))
        except TimeoutError:
            break
        received.append(json.loads(raw))
    return received


class TestPipelineToDashboard:
    def test_pipeline_pushes_artifacts_to_bridge(self, mock_target_server, ws_bridge):
        from websockets.sync.client import connect

        with connect(ws_bridge) as dashboard:
            result = run_pipeline(
                sources=[PipelineSource("openapi", _spec(mock_target_server))],
                config=_cfg(ws_bridge_url=ws_bridge),
            )
            assert result["scan"]["scanned"] == 3
            assert result["poc_reports"], "靶场应至少产出 1 条 PoC"
            assert result["pushed_artifacts"] == len(result["poc_reports"])

            received = _recv_artifacts(dashboard, result["pushed_artifacts"])
            assert len(received) == result["pushed_artifacts"]
            for artifact in received:
                assert set(artifact.keys()) >= {
                    "endpoint", "verdict", "confidence", "evidence", "technical_root_cause"
                }
                assert artifact["verdict"] in ("VULNERABLE", "SAFE", "BLOCKED", "INCONCLUSIVE")
            endpoints = {a["endpoint"] for a in received}
            assert any("accounts" in e for e in endpoints)

    def test_push_failure_recorded_not_fatal(self, mock_target_server):
        """网关不可达时流水线照常完成，错误记入 errors。"""
        dead_port = _free_port()
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))],
            config=_cfg(ws_bridge_url=f"ws://127.0.0.1:{dead_port}"),
        )
        assert result["status"] == "completed_with_errors"
        assert any(e["stage"] == "stream" for e in result["errors"])
        assert result["scan"]["vulnerable"] >= 1


class TestMcpServerE2E:
    @pytest.fixture(scope="class")
    def mcp_client(self):
        client = MCPTestClient(
            [sys.executable, "-m", "src.auditor.auditor_mcp_server"]
        )
        # MCP v2: initialize 需带 capabilities
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "pytest-e2e", "version": "1.0"},
        })
        client.notify("notifications/initialized")
        try:
            yield client
        finally:
            client.close()

    def test_tools_registry(self, mcp_client):
        tools = mcp_client.call("tools/list")["result"]["tools"]
        names = {t["name"] for t in tools}
        assert {
            "differential_access_test", "probe_endpoint", "ingest_openapi",
            "batch_differential_scan", "batch_differential_scan_fast",
            "emit_audit_report", "run_full_pipeline", "verify_remediation",
        } <= names

    def test_run_full_pipeline_tool(self, mcp_client, mock_target_server, ws_bridge):
        result = mcp_client.tool("run_full_pipeline", {
            "openapi_spec": _spec(mock_target_server),
            "program_id": "PROG-MCP",
            "primary_token": "Bearer token-alice",
            "secondary_token": "Bearer token-bob",
            "ws_bridge_url": ws_bridge,
        })
        assert result["status"] == "completed"
        assert result["scan"]["scanned"] == 3
        assert result["scan"]["vulnerable"] >= 1
        assert result["poc"]["total_vulnerabilities"] >= 1
        assert result["pushed_artifacts"] >= 1

    def test_emit_audit_report_tool(self, mcp_client, tmp_path):
        emitted = mcp_client.tool("emit_audit_report", {
            "scan_results": [
                {"endpoint": "GET /api/v1/x", "verdict": "VULNERABLE", "confidence": 0.9},
                {"endpoint": "GET /api/v1/y", "verdict": "SAFE"},
            ],
            "output_dir": str(tmp_path),
        })
        assert emitted["status"] == "DELIVERED"
        assert os.path.isfile(emitted["markdown_path"])
        assert os.path.isfile(emitted["json_path"])

    def test_run_full_pipeline_requires_source(self, mcp_client):
        result = mcp_client.tool("run_full_pipeline", {"program_id": "X"})
        assert result["status"] == "FAIL"
        assert "不能同时为空" in result["error"]

    def test_ingest_and_batch_tools(self, mcp_client, mock_target_server):
        ingest = mcp_client.tool("ingest_openapi", {
            "spec_content_or_path": _spec(mock_target_server),
        })
        assert ingest["status"] == "DELIVERED"
        matrix = ingest["target_matrix"]
        assert len(matrix) == 3

        scan = mcp_client.tool("batch_differential_scan", {
            "target_matrix": matrix,
            "primary_token": "token-alice",
            "secondary_token": "token-bob",
        })
        assert scan["status"] == "DELIVERED"
        assert scan["scan_summary"]["total"] == 3
        assert scan["scan_summary"]["vulnerable"] >= 1

    def test_batch_scan_only_auditable(self, mcp_client, mock_target_server):
        """only_auditable=True：非对象级引用端点（/api/v1/health）被预过滤。"""
        ingest = mcp_client.tool("ingest_openapi", {
            "spec_content_or_path": _spec(mock_target_server),
        })
        matrix = ingest["target_matrix"]
        assert len(matrix) == 3

        scan = mcp_client.tool("batch_differential_scan", {
            "target_matrix": matrix,
            "only_auditable": True,
            "primary_token": "token-alice",
            "secondary_token": "token-bob",
        })
        assert scan["status"] == "DELIVERED"
        assert scan["skipped_non_auditable"] == 1
        assert scan["scan_summary"]["total"] == 2
        assert all(r["is_auditable"] for r in scan["all_results"])
        assert scan["scan_summary"]["vulnerable"] >= 1

    def test_ingest_openapi_rejects_non_allowlisted_path(self, mcp_client, tmp_path):
        """H2：摄入通道拒绝白名单外的本地文件（任意文件读取面封闭）。"""
        secret = tmp_path / "creds"
        secret.write_text('{"openapi":"3.0.0"}', encoding="utf-8")
        result = mcp_client.tool("ingest_openapi", {
            "spec_content_or_path": str(secret),
        })
        assert result["status"] == "FAIL"
        assert "PATH_NOT_ALLOWED" in result["error"]

    def test_differential_access_test_tool(self, mcp_client, mock_target_server):
        result = mcp_client.tool("differential_access_test", {
            "url": f"{mock_target_server}/api/v1/accounts/1001",
            "primary_headers": {"Authorization": "Bearer token-alice"},
            "secondary_headers": {"Authorization": "Bearer token-bob"},
        })
        assert result["status"] == "DELIVERED"
        assert result["verdict"] == "VULNERABLE"
        assert result["evidence"]["primary_status"] == 200

    def test_write_blocked_via_gate(self, mcp_client, mock_target_server):
        result = mcp_client.tool("differential_access_test", {
            "url": f"{mock_target_server}/api/v1/accounts/1001",
            "method": "PUT",
            "primary_headers": {"Authorization": "Bearer token-alice"},
            "secondary_headers": {"Authorization": "Bearer token-bob"},
        })
        assert result["verdict"] == "BLOCKED"
        # 统一安全门禁（REQUEST_SECURITY_GATE）在 execute() 前置守卫中
        # 先于基础 P0-INVARIANT-03 熔断拦截写操作
        assert result["evidence"]["blocked_by"] == "REQUEST_SECURITY_GATE"
        assert "P0-INVARIANT-03" in result["evidence"]["reason"]


class TestArtifactEmitterCli:
    def test_cli_once_full_chain(self, mock_target_server, ws_bridge, tmp_path):
        from websockets.sync.client import connect

        spec_file = tmp_path / "e2e_spec.json"
        spec_file.write_text(_spec(mock_target_server), encoding="utf-8")

        with connect(ws_bridge) as dashboard:
            proc = subprocess.run(
                [
                    sys.executable, "src/pipeline/artifact_emitter.py",
                    "--openapi-spec", str(spec_file),
                    "--ws-url", ws_bridge,
                    "--once",
                    "--output-dir", str(tmp_path / "reports"),
                    "--primary-token", "Bearer token-alice",
                    "--secondary-token", "Bearer token-bob",
                ],
                cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120,
            )
            assert proc.returncode == 0, f"emitter 失败: {proc.stderr}"
            assert "[EMIT]" in proc.stdout
            assert "pushed=" in proc.stdout

            # CLI 推送条数未知（PoC 数），收取至少 1 条并校验结构
            received = _recv_artifacts(dashboard, 1, timeout=15)
            assert len(received) >= 1
            assert "endpoint" in received[0]
            assert received[0]["verdict"] in ("VULNERABLE", "SAFE", "BLOCKED", "INCONCLUSIVE")

        reports = list((tmp_path / "reports").glob("audit_*"))
        assert len(reports) == 2  # md + json
