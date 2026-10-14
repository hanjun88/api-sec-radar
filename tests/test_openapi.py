"""
test_openapi.py: OpenAPI/Swagger 契约摄入解析测试

验证规范解析出的待测矩阵（Target Matrix）条目结构、对象级标识符识别
（BOLA 高风险面）、路径参数替换与身份头注入。

靶 spec（见 conftest.mock_openapi_spec）共 7 个 path / 10 个操作，
其中 6 个含对象级标识符（{accountId}/{userId}/{orderId}/{productId}）。
"""

from __future__ import annotations

import json

import pytest

from src.auditor.openapi import (
    OpenAPITargetEntry,
    filter_auditable,
    filter_safe_methods,
    parse_openapi_spec,
)

REQUIRED_KEYS = {
    "method",
    "url",
    "path_template",
    "primary_headers",
    "secondary_headers",
    "json_body",
    "is_auditable",
    "is_safe_method",
}


# --------------------------------------------------------------------------
# 矩阵结构
# --------------------------------------------------------------------------


def test_matrix_populated(mock_openapi_spec: str) -> None:
    matrix = parse_openapi_spec(mock_openapi_spec)
    assert len(matrix) == 10


def test_every_entry_has_required_keys(mock_openapi_spec: str) -> None:
    for entry in parse_openapi_spec(mock_openapi_spec):
        assert REQUIRED_KEYS <= set(entry)
    # 结构与 pydantic 模型一致
    OpenAPITargetEntry(**parse_openapi_spec(mock_openapi_spec)[0])


def test_non_http_keys_are_skipped(mock_openapi_spec: str) -> None:
    """path item 中的 summary/parameters 等非方法键不得解析为操作。"""
    methods = {e["method"] for e in parse_openapi_spec(mock_openapi_spec)}
    assert methods <= {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def test_path_parameters_substituted(mock_openapi_spec: str) -> None:
    """{accountId} 等占位符必须替换为探测值，不得出现在最终 URL。"""
    for entry in parse_openapi_spec(mock_openapi_spec):
        assert "{" not in entry["url"]


def test_mock_id_value_configurable(mock_openapi_spec: str) -> None:
    matrix = parse_openapi_spec(mock_openapi_spec, mock_id_value="9999")
    assert any(e["url"].endswith("9999") for e in matrix)


def test_url_joined_from_servers(mock_openapi_spec: str) -> None:
    matrix = parse_openapi_spec(mock_openapi_spec)
    assert all(e["url"].startswith("http://target.local/") for e in matrix)


def test_base_url_override(mock_openapi_spec: str) -> None:
    matrix = parse_openapi_spec(mock_openapi_spec, base_url_override="https://staging.local")
    assert all(e["url"].startswith("https://staging.local/") for e in matrix)


# --------------------------------------------------------------------------
# 对象级标识符识别（BOLA 高风险面）
# --------------------------------------------------------------------------


def test_auditable_entries_are_id_bearing(mock_openapi_spec: str) -> None:
    """含 {xxxId} 的 6 个操作被标记为可审计。"""
    auditable = filter_auditable(parse_openapi_spec(mock_openapi_spec))
    assert len(auditable) == 6
    assert all(e["is_auditable"] for e in auditable)


def test_admin_and_health_not_flagged_as_auditable(mock_openapi_spec: str) -> None:
    """/admin/users 与 /health 不含对象级占位符，不进入 BOLA 面。"""
    auditable_paths = {e["path_template"] for e in filter_auditable(parse_openapi_spec(mock_openapi_spec))}
    assert "/api/v1/admin/users" not in auditable_paths
    assert "/api/v1/health" not in auditable_paths


def test_filter_safe_methods(mock_openapi_spec: str) -> None:
    """7 个 GET 操作被标记为安全方法（可批量重放）。"""
    safe = filter_safe_methods(parse_openapi_spec(mock_openapi_spec))
    assert len(safe) == 7
    assert all(e["is_safe_method"] for e in safe)


def test_write_methods_present_but_not_safe(mock_openapi_spec: str) -> None:
    methods = {e["method"] for e in parse_openapi_spec(mock_openapi_spec)}
    assert {"PUT", "POST", "DELETE"} <= methods


# --------------------------------------------------------------------------
# 身份头注入
# --------------------------------------------------------------------------


def test_identity_headers_injected(mock_openapi_spec: str) -> None:
    matrix = parse_openapi_spec(
        mock_openapi_spec,
        primary_headers={"Authorization": "Bearer victim"},
        secondary_headers={"Authorization": "Bearer attacker"},
    )
    for entry in matrix:
        assert entry["primary_headers"]["Authorization"] == "Bearer victim"
        assert entry["secondary_headers"]["Authorization"] == "Bearer attacker"


def test_default_primary_headers(mock_openapi_spec: str) -> None:
    matrix = parse_openapi_spec(mock_openapi_spec)
    assert matrix[0]["primary_headers"] == {"Content-Type": "application/json"}


# --------------------------------------------------------------------------
# 边界与失败模式
# --------------------------------------------------------------------------


def test_empty_spec_yields_empty_matrix() -> None:
    assert parse_openapi_spec(json.dumps({"paths": {}})) == []


def test_spec_without_paths_key_yields_empty_matrix() -> None:
    assert parse_openapi_spec(json.dumps({"openapi": "3.0.0"})) == []


def test_malformed_json_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_openapi_spec("{not valid json")


def test_unsafe_path_item_type_skipped() -> None:
    """path 值为非 dict（如字符串）时跳过，不得崩溃。"""
    spec = json.dumps({"servers": [{"url": "http://t"}], "paths": {"/x": "oops"}})
    assert parse_openapi_spec(spec) == []


# --------------------------------------------------------------------------
# M3 补充：对象引用白名单扩展（slug/code/handle/email）
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path_template, expected_auditable",
    [
        ("/posts/{slug}", True),       # slug 间接对象引用
        ("/items/{code}", True),       # code 间接对象引用
        ("/users/{handle}", True),     # handle 间接对象引用
        ("/accounts/{email}", True),   # email 间接对象引用
        ("/admin/users", False),       # 非对象引用路径不得误标
        ("/health", False),            # 健康检查不得误标
    ],
)
def test_object_ref_keywords_detected(
    path_template: str, expected_auditable: bool
) -> None:
    """扩展白名单后，slug/code/handle/email 路径参数须标记为可审计。"""
    spec = json.dumps(
        {"servers": [{"url": "http://t"}], "paths": {path_template: {"get": {}}}}
    )
    matrix = parse_openapi_spec(spec)
    assert len(matrix) == 1
    assert matrix[0]["is_auditable"] is expected_auditable
    assert matrix[0]["path_template"] == path_template


def test_query_param_object_ref_detected() -> None:
    """?email= 等查询参数须触发可审计标记（声明式参数启发式）。"""
    spec = json.dumps(
        {
            "servers": [{"url": "http://t"}],
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [{"name": "email", "in": "query"}]
                    }
                }
            },
        }
    )
    matrix = parse_openapi_spec(spec)
    assert len(matrix) == 1
    assert matrix[0]["is_auditable"] is True


# --------------------------------------------------------------------------
# M12 补充：server override / mock body / 方法过滤 分支
# --------------------------------------------------------------------------


def test_swagger2_host_scheme_basepath() -> None:
    """Swagger 2.0 的 host/schemes/basePath 回退分支须正确拼装 base URL。"""
    spec = json.dumps(
        {
            "swagger": "2.0",
            "host": "api.example.com",
            "schemes": ["https"],
            "basePath": "/v2",
            "paths": {"/x/{id}": {"get": {}}},
        }
    )
    matrix = parse_openapi_spec(spec)
    assert all(e["url"].startswith("https://api.example.com/v2/") for e in matrix)


def test_mock_body_uses_request_example() -> None:
    """requestBody example 分支须被采纳为 mock body（openapi.py:72-90）。"""
    spec = json.dumps(
        {
            "servers": [{"url": "http://t"}],
            "paths": {
                "/accounts": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "example": {"owner": "alice", "balance": 5}
                                }
                            }
                        }
                    }
                }
            },
        }
    )
    matrix = parse_openapi_spec(spec)
    assert matrix[0]["json_body"] == json.dumps({"owner": "alice", "balance": 5})


def test_unsupported_method_skipped() -> None:
    """非标准 HTTP 方法（如 trace）须被方法过滤分支跳过（openapi.py:147）。"""
    spec = json.dumps(
        {"servers": [{"url": "http://t"}], "paths": {"/x": {"trace": {}, "get": {}}}}
    )
    methods = {e["method"] for e in parse_openapi_spec(spec)}
    assert methods == {"GET"}
