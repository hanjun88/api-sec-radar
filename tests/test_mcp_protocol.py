"""
test_mcp_protocol.py: MCP stdio 协议级端到端测试

直接启动 ``python -m src.auditor.auditor_mcp_server`` 子进程，完成
initialize → tools/list → tools/call 链路，验证工具函数不仅能被直接导入，
也能通过真实 MCP JSON-RPC 协议被外部编排层调用。
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp", reason="mcp 未安装，跳过 MCP 协议级测试")


GOOD_PATCH = """
def handler(account, current_user):
    if account.owner_id != current_user.user_id:
        raise HTTPException(status_code=404)
    return account
"""


EXPECTED_TOOLS = {
    "differential_access_test",
    "probe_endpoint",
    "ingest_openapi",
    "batch_differential_scan",
    "batch_differential_scan_fast",
    "verify_remediation",
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_mcp_tools_list_exposes_expected_tools(auditor_mcp_client) -> None:
    raw = auditor_mcp_client.call("tools/list")
    names = {tool["name"] for tool in raw["result"]["tools"]}
    assert EXPECTED_TOOLS.issubset(names)


def test_mcp_differential_access_test_detects_bola(
    auditor_mcp_client,
    mock_target_server: str,
) -> None:
    result = auditor_mcp_client.tool(
        "differential_access_test",
        {
            "url": f"{mock_target_server}/api/v1/accounts/1001",
            "method": "GET",
            "primary_headers": _auth("token-alice"),
            "secondary_headers": _auth("token-bob"),
        },
    )
    assert result["status"] == "DELIVERED"
    assert result["verdict"] == "VULNERABLE"
    assert result["primary"]["status_code"] == 200
    assert result["secondary"]["status_code"] == 200


def test_mcp_probe_endpoint_returns_response_fingerprint(
    auditor_mcp_client,
    mock_target_server: str,
) -> None:
    result = auditor_mcp_client.tool(
        "probe_endpoint",
        {
            "url": f"{mock_target_server}/api/v1/secure/1001",
            "headers": _auth("token-alice"),
        },
    )
    assert result["status"] == "DELIVERED"
    assert result["status_code"] == 200
    assert result["content_hash"]
    assert result["content_length"] > 0


def test_mcp_ingest_openapi_filters_to_safe_auditable_targets(
    auditor_mcp_client,
    mock_openapi_spec: str,
    mock_target_server: str,
) -> None:
    result = auditor_mcp_client.tool(
        "ingest_openapi",
        {
            "spec_content_or_path": mock_openapi_spec,
            "base_url_override": mock_target_server,
            "primary_headers_json": json.dumps(_auth("token-alice")),
            "secondary_headers_json": json.dumps(_auth("token-bob")),
            "only_auditable": True,
            "only_safe_methods": True,
        },
    )
    assert result["status"] == "DELIVERED"
    assert result["total_endpoints"] >= result["returned_endpoints"] > 0
    assert all(entry["is_auditable"] for entry in result["target_matrix"])
    assert all(entry["is_safe_method"] for entry in result["target_matrix"])
    assert all(entry["url"].startswith(mock_target_server) for entry in result["target_matrix"])


def test_mcp_batch_differential_scan_blocks_write_operations(
    auditor_mcp_client,
    mock_target_server: str,
) -> None:
    matrix = [
        {
            "method": "PUT",
            "url": f"{mock_target_server}/api/v1/accounts/1003",
            "path_template": "/api/v1/accounts/{id}",
            "json_body": '{"balance":1}',
            "primary_headers": _auth("token-alice"),
            "secondary_headers": _auth("token-bob"),
            "is_auditable": True,
            "is_safe_method": False,
        }
    ]
    result = auditor_mcp_client.tool(
        "batch_differential_scan",
        {"target_matrix": matrix, "interval_ms": 0, "allow_write": False},
    )
    assert result["status"] == "DELIVERED"
    assert result["scan_summary"]["blocked"] == 1
    assert result["all_results"][0]["verdict"] == "BLOCKED"


def test_mcp_fast_scan_filters_non_auditable(
    auditor_mcp_client,
    mock_target_server: str,
) -> None:
    """H3 纵深防御：MCP 工具入口过滤非可审计条目，不参与扫描。

    注：fast 模式的证据瘦身分支（_fast_mode）只作用于非可审计条目，
    而该分支位于入口过滤之后，故经 MCP 工具调用时恒不可达——可审计
    条目一律保留完整证据链。_run_batch_scan 层仍保留该分支（见
    tests/test_batch_scan.py::test_fast_mode_slims_non_auditable_evidence）。
    """
    auditable = {
        "method": "GET",
        "url": f"{mock_target_server}/api/v1/accounts/1003",
        "path_template": "/api/v1/accounts/{id}",
        "primary_headers": _auth("token-alice"),
        "secondary_headers": _auth("token-bob"),
        "is_auditable": True,
        "is_safe_method": True,
    }
    non_auditable = {
        "method": "GET",
        "url": f"{mock_target_server}/api/v1/health",
        "path_template": "/api/v1/health",
        "primary_headers": _auth("token-alice"),
        "secondary_headers": _auth("token-bob"),
        "is_auditable": False,
        "is_safe_method": True,
    }
    result = auditor_mcp_client.tool(
        "batch_differential_scan_fast",
        {"target_matrix": [auditable, non_auditable], "interval_ms": 0},
    )
    assert result["status"] == "DELIVERED"
    # H3：非可审计条目在入口被过滤，只剩可审计条目
    assert len(result["all_results"]) == 1
    assert result["all_results"][0]["endpoint"] == "GET /api/v1/accounts/{id}"
    assert result["all_results"][0]["is_auditable"] is True
    # 可审计条目保留完整证据链（fast 模式不对其瘦身）
    assert "_fast_mode" not in result["all_results"][0]["evidence"]
    assert result["scan_summary"]["total"] == 1


def test_mcp_verify_remediation_reports_static_ast_pass(auditor_mcp_client) -> None:
    result = auditor_mcp_client.tool(
        "verify_remediation",
        {
            "test_url": "http://target.local/api/v1/accounts/1001",
            "patch_code_snippet": GOOD_PATCH,
            "original_handler_snippet": "def handler(account): return account",
        },
    )
    assert result["status"] == "DELIVERED"
    assert result["patch_compiles"] is True
    assert result["remediation_status"] == "STATIC_AST_PASSED"
    assert result["verified_safe"] is False
