"""
test_auditor_mcp_server.py: MCP 服务层单元与批量调度测试

聚焦服务层的纯函数与批量调度策略（不依赖 MCP stdio 握手）：
- ``_coerce_headers``: headers 入参兼容（dict / JSON string / None）
- ``_batch_concurrency``: 分级并发度上限策略
- ``_compress_batch_results``: 大批量结果的负载压缩

导入模块本身即验证 mcp 依赖可用（该依赖缺失曾导致整层不可用）。
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp", reason="mcp 未安装，跳过 MCP 服务层测试")

from src.auditor.auditor_mcp_server import (  # noqa: E402
    _batch_concurrency,
    _coerce_headers,
    _compress_batch_results,
    _filter_auditable_entries,
    _validate_spec_input,
    mcp,
)


# --------------------------------------------------------------------------
# 服务句柄
# --------------------------------------------------------------------------


def test_mcp_server_instance_created() -> None:
    assert mcp is not None
    assert mcp.name == "api-access-auditor"


# --------------------------------------------------------------------------
# headers 入参兼容
# --------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_coerce_headers_empty_returns_empty_dict(raw: object) -> None:
    assert _coerce_headers(raw) == {}  # type: ignore[arg-type]


def test_coerce_headers_passthrough_dict() -> None:
    headers = {"Authorization": "Bearer x"}
    assert _coerce_headers(headers) == headers


def test_coerce_headers_parses_json_string() -> None:
    assert _coerce_headers('{"X-Api-Key": "k"}') == {"X-Api-Key": "k"}


def test_coerce_headers_invalid_json_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        _coerce_headers("{not json")


def test_coerce_headers_non_string_non_dict_returns_empty() -> None:
    """非预期类型（如 int）视为无头，不崩溃。"""
    assert _coerce_headers(123) == {}  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# ingest_openapi 本地文件读取防护（H2）
# --------------------------------------------------------------------------


def test_validate_spec_input_accepts_json_string() -> None:
    assert _validate_spec_input('{"openapi": "3.0"}') is None
    assert _validate_spec_input("  [1, 2, 3]") is None


def test_validate_spec_input_accepts_relative_path() -> None:
    assert _validate_spec_input("specs/foo.json") is None
    assert _validate_spec_input("openapi.yaml") is None


def test_validate_spec_input_rejects_absolute_path() -> None:
    assert _validate_spec_input("/etc/passwd") is not None
    # 类 Unix 绝对路径（Windows 盘符式在 POSIX 上 isabs 不识别，故仅校验 / 开头）
    assert _validate_spec_input("/abs/spec.json") is not None


def test_validate_spec_input_rejects_traversal() -> None:
    assert _validate_spec_input("../../etc/passwd") is not None
    assert _validate_spec_input("a/../b") is not None
    assert _validate_spec_input("..\\..\\secret") is not None


# --------------------------------------------------------------------------
# batch 入口 auditable 纵深防御（H3）
# --------------------------------------------------------------------------


def test_filter_auditable_entries_drops_non_auditable() -> None:
    """H3 纵深防御：MCP 入口丢弃 is_auditable 非真的条目（含缺失键），
    防止非对象引用端点复现 #9 假阳性。fast_mode 入口共用此过滤。"""
    matrix = [
        {"url": "/accounts/1", "is_auditable": True},
        {"url": "/health", "is_auditable": False},
        {"url": "/admin", "is_auditable": False},
        {"url": "/no-flag"},  # 缺键：fail-closed 视为非 auditable
    ]
    filtered = _filter_auditable_entries(matrix)
    assert len(filtered) == 1
    assert filtered[0]["url"] == "/accounts/1"


# --------------------------------------------------------------------------
# 分级并发度
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "max_concurrency, matrix_size, expected",
    [
        (3, 50, 3),      # 小矩阵：用请求值
        (20, 50, 10),    # 请求值超上限 → 截断到 10
        (0, 50, 1),      # 非正数 → 保底 1
        (8, 300, 5),     # 中矩阵：上限 5
        (8, 1000, 8),    # 大矩阵：上限 8
        (20, 3000, 10),  # 超大矩阵：上限 10
        (1, 100, 1),     # 边界：size == 100 属第一档
        (8, 101, 5),     # 边界：size == 101 进入第二档
    ],
)
def test_batch_concurrency_tiers(
    max_concurrency: int, matrix_size: int, expected: int
) -> None:
    assert _batch_concurrency(max_concurrency, matrix_size) == expected


def test_batch_concurrency_never_exceeds_ten() -> None:
    for size in (1, 100, 101, 500, 501, 2000, 2001, 100000):
        assert _batch_concurrency(999, size) <= 10


# --------------------------------------------------------------------------
# 批量结果压缩
# --------------------------------------------------------------------------


def test_compress_noop_when_at_threshold() -> None:
    """恰好 100 条不压缩（阈值为 >100）。"""
    results = [{"verdict": "SAFE", "evidence": {"a": 1}} for _ in range(100)]
    assert _compress_batch_results(results) is results


def test_compress_slims_non_vulnerable_above_threshold() -> None:
    results = [{"verdict": "SAFE", "evidence": {"heavy": "x" * 100}} for _ in range(101)]
    compressed = _compress_batch_results(results)
    assert len(compressed) == 101
    assert compressed[0]["evidence"]["_compressed"] is True


def test_compress_preserves_vulnerable_evidence() -> None:
    """VULNERABLE 条目保留完整证据链，不得精简。"""
    vulnerable = {"verdict": "VULNERABLE", "evidence": {"primary_status": 200, "detail": "full"}}
    results = [vulnerable] + [{"verdict": "SAFE", "evidence": {}} for _ in range(100)]
    compressed = _compress_batch_results(results)
    assert compressed[0] is vulnerable
    assert compressed[0]["evidence"]["detail"] == "full"


def test_compress_does_not_mutate_input() -> None:
    original = {"verdict": "SAFE", "evidence": {"keep": "me"}}
    results = [original] + [{"verdict": "SAFE", "evidence": {}} for _ in range(100)]
    compressed = _compress_batch_results(results)
    assert original["evidence"] == {"keep": "me"}
    assert compressed[0] is not original
