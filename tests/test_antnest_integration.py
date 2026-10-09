"""tests/test_antnest_integration.py — AntNest MCP 集成组"""
from __future__ import annotations

import json
import subprocess

from src.auditor.auditor_mcp_server import (
    differential_access_test,
    ingest_openapi,
    probe_endpoint,
    run_full_pipeline,
    verify_remediation,
)

EXPECTED_TOOLS = {
    "differential_access_test",
    "probe_endpoint",
    "ingest_openapi",
    "batch_differential_scan",
    "batch_differential_scan_fast",
    "emit_audit_report",
    "run_full_pipeline",
    "verify_remediation",
}


class TestAntNestMcpConfig:
    def test_config_schema(self):
        """antnest-mcp.json 符合 AntNest McpHub 加载契约。"""
        with open("antnest-mcp.json", encoding="utf-8") as f:
            cfg = json.load(f)
        servers = cfg.get("servers")
        assert isinstance(servers, dict)
        radar = servers.get("api_sec_radar")
        assert isinstance(radar, dict)
        # AntNest _build_session: command → stdio
        assert radar.get("type") == "stdio"
        assert radar.get("command")
        assert isinstance(radar.get("args"), list)

    def test_config_loads_via_antnest_session(self):
        """配置可被 AntNest McpSession（stdio）加载并列出工具。"""
        with open("antnest-mcp.json", encoding="utf-8") as f:
            cfg = json.load(f)
        radar = cfg["servers"]["api_sec_radar"]
        proc = subprocess.Popen(
            [radar["command"]] + radar["args"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            def send(payload: dict) -> None:
                assert proc.stdin is not None
                proc.stdin.write(json.dumps(payload) + "\n")
                proc.stdin.flush()

            def recv() -> dict:
                assert proc.stdout is not None
                line = proc.stdout.readline()
                return json.loads(line) if line else {}

            send({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "AntNest", "version": "1.2.1"},
                },
            })
            init = recv()
            assert "result" in init

            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            tools = recv().get("result", {}).get("tools", [])
            tool_names = {t.get("name") for t in tools}
            assert EXPECTED_TOOLS.issubset(tool_names)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


class TestMcpToolsCallable:
    """工具函数可被 AntNest 通过 tools/call 调用。"""

    def test_probe_endpoint_returns_fingerprint(self):
        result = probe_endpoint(
            url="http://127.0.0.1:1/api/v1/health",
            method="GET",
            timeout=1.0,
        )
        assert result["status"] == "DELIVERED"
        assert "status_code" in result

    def test_differential_access_test_blocked_write(self):
        result = differential_access_test(
            url="http://127.0.0.1:1/api/v1/accounts/1001",
            method="PUT",
            primary_headers={"Authorization": "Bearer token-alice"},
            secondary_headers={"Authorization": "Bearer token-bob"},
        )
        assert result["verdict"] == "BLOCKED"
        assert result["evidence"]["blocked_by"] == "REQUEST_SECURITY_GATE"

    def test_ingest_openapi_returns_matrix(self, mock_openapi_spec):
        result = ingest_openapi(spec_content_or_path=mock_openapi_spec)
        assert result["status"] == "DELIVERED"
        assert result["total_endpoints"] >= 1

    def test_run_full_pipeline_requires_source(self):
        result = run_full_pipeline()
        assert result["status"] == "FAIL"

    def test_verify_remediation_static_only(self):
        result = verify_remediation(
            test_url="http://127.0.0.1:1/api/v1/accounts/1001",
            patch_code_snippet=(
                "if account.owner_id != current_user.id:\n"
                "    raise HTTPException(status_code=404)\n"
            ),
        )
        assert result["status"] == "DELIVERED"
        # 静态验证：verified_safe 仅表示 AST 特征命中
        assert "verified_safe" in result
