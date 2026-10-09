"""
openapi.py: OpenAPI / Swagger 规范解析器，提取对象级待测矩阵

白盒契约文档摄入适配器，输出与 HAR 摄入同构的 Target Matrix，
使下游 batch_differential_scan 可无缝接入。
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from pydantic import BaseModel

# Path 中潜在对象标识符正则（{id} / {userId} / {orderUuid} / {account_key} 等）
ID_PATH_REGEX = re.compile(
    r"\{[^{}]*(?:id|uuid|key|account|order|user|tenant|product|item|ref)[^{}]*\}",
    re.IGNORECASE,
)

# Query 参数中潜在对象标识符
ID_QUERY_REGEX = re.compile(
    r"(?:^|&)[^&=]*(?:id|uuid|key|account|order|user|tenant)[^&=]*=",
    re.IGNORECASE,
)

VALID_METHODS = {"get", "post", "put", "delete", "patch"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class OpenAPITargetEntry(BaseModel):
    """标准化待测矩阵条目（与 HAR 摄入同构）。"""
    method: str
    url: str
    path_template: str
    primary_headers: dict[str, str]
    secondary_headers: dict[str, str]
    json_body: str | None = None
    is_auditable: bool
    is_safe_method: bool


def _extract_base_url(spec: dict[str, Any], override: str | None) -> str:
    """从 OpenAPI 3.x servers 或 Swagger 2.0 host/schemes/basePath 提取 base URL。"""
    if override:
        return override.rstrip("/")
    if spec.get("servers"):
        return spec["servers"][0].get("url", "").rstrip("/")
    if "host" in spec:
        schemes = spec.get("schemes", ["https"])
        base_path = spec.get("basePath", "")
        return f"{schemes[0]}://{spec['host']}{base_path}".rstrip("/")
    return "http://localhost"


def _generate_mock_body(
    op_spec: dict[str, Any], method: str, mock_id_value: str
) -> str | None:
    """从 requestBody 生成最小 mock body；无 requestBody 时对写操作生成默认探针。"""
    if method not in {"POST", "PUT", "PATCH"}:
        return None

    # 尝试从 requestBody content 提取 example / schema 默认值
    request_body = op_spec.get("requestBody")
    if request_body:
        content = request_body.get("content", {})
        for media_type in content.values():
            if "example" in media_type:
                return json.dumps(media_type["example"])
            if media_type.get("examples"):
                first_key = next(iter(media_type["examples"]))
                ex = media_type["examples"][first_key]
                if isinstance(ex, dict) and "value" in ex:
                    return json.dumps(ex["value"])
            schema = media_type.get("schema", {})
            if "properties" in schema:
                mock: dict[str, Any] = {}
                for prop_name, prop_spec in schema["properties"].items():
                    if "example" in prop_spec:
                        mock[prop_name] = prop_spec["example"]
                    elif prop_spec.get("type") == "string":
                        mock[prop_name] = "test_probe"
                    elif prop_spec.get("type") in ("integer", "number"):
                        mock[prop_name] = 1
                    elif prop_spec.get("type") == "boolean":
                        mock[prop_name] = True
                if mock:
                    return json.dumps(mock)

    # 回退：默认探针 body
    return json.dumps({"test_probe": True, "id": mock_id_value})


def parse_openapi_spec(
    spec_content_or_path: str,
    base_url_override: str | None = None,
    secondary_headers: dict[str, str] | None = None,
    primary_headers: dict[str, str] | None = None,
    mock_id_value: str = "1001",
) -> list[dict[str, Any]]:
    """
    解析 OpenAPI 3.0 或 Swagger 2.0 文档，输出标准化待测矩阵。

    Args:
        spec_content_or_path: JSON 字符串或文件路径
        base_url_override: 覆盖 spec 中的 servers/host
        secondary_headers: 待测试身份的请求头（如攻击者 token）
        primary_headers: 基线身份请求头（如资源属主 token）
        mock_id_value: Path 参数 {id} 的替换探测值

    Returns:
        待测矩阵列表，每个条目为 OpenAPITargetEntry 的 dict 形式
    """
    # 1. 载入规范文档
    stripped = spec_content_or_path.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        spec = json.loads(stripped)
    else:
        with open(spec_content_or_path, encoding="utf-8") as f:
            spec = json.load(f)

    # 2. 提取 Base URL
    server_url = _extract_base_url(spec, base_url_override)

    target_matrix: list[dict[str, Any]] = []
    paths: dict[str, Any] = spec.get("paths", {})

    # 3. 遍历接口定义
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Path 级参数（所有方法共享）
        path_params = path_item.get("parameters", [])

        # 检查 Path 是否包含潜在对象标识符
        is_path_auditable = bool(ID_PATH_REGEX.search(path_str))

        # 将路径参数替换为实际测试探测值
        concrete_path = ID_PATH_REGEX.sub(mock_id_value, path_str)
        target_url = urljoin(server_url + "/", concrete_path.lstrip("/"))

        for method, op_spec in path_item.items():
            if method.lower() not in VALID_METHODS:
                continue

            method_upper = method.upper()
            is_safe = method_upper in SAFE_METHODS

            # 合并操作级参数
            op_params = op_spec.get("parameters", []) if isinstance(op_spec, dict) else []
            all_params = path_params + op_params

            # 检查 Query 参数是否包含对象标识符
            has_id_query = any(
                p.get("in") == "query" and ID_QUERY_REGEX.search(p.get("name", "") + "=")
                for p in all_params
                if isinstance(p, dict)
            )

            is_auditable = is_path_auditable or has_id_query

            # 生成 mock body
            mock_body = _generate_mock_body(
                op_spec if isinstance(op_spec, dict) else {}, method_upper, mock_id_value
            )

            entry = OpenAPITargetEntry(
                method=method_upper,
                url=target_url,
                path_template=path_str,
                primary_headers=primary_headers or {"Content-Type": "application/json"},
                secondary_headers=secondary_headers or {},
                json_body=mock_body,
                is_auditable=is_auditable,
                is_safe_method=is_safe,
            )
            target_matrix.append(entry.model_dump())

    return target_matrix


def filter_auditable(matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """过滤出包含对象级引用参数的待测条目（BOLA/IDOR 高风险面）。"""
    return [e for e in matrix if e.get("is_auditable", False)]


def filter_safe_methods(matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """过滤出只读方法（GET/HEAD/OPTIONS），可安全批量重放。"""
    return [e for e in matrix if e.get("is_safe_method", False)]
