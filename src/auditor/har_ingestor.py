"""
har_ingestor.py: HAR 黑盒流量摄入适配器

将浏览器/代理录制的 HAR（HTTP Archive）流量转换为与 OpenAPI 摄入
**同构** 的标准化待测矩阵，使下游 ``run_batch_scan`` 可无缝接入：

- OpenAPI（白盒契约）与 HAR（黑盒流量）双通道汇合至同一 Target Matrix；
- 自动识别路径 / query 中的对象级引用参数（BOLA/IDOR 高风险面）；
- 保留录制请求的原始 headers（可被 primary/secondary 身份覆盖）。
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel

# 复用 OpenAPI 摄入的对象标识符识别正则（双通道判定标准一致）
from .openapi import ID_PATH_REGEX, ID_QUERY_REGEX

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class HarTargetEntry(BaseModel):
    """标准化待测矩阵条目（与 OpenAPITargetEntry 同构）。"""
    method: str
    url: str
    path_template: str
    primary_headers: dict[str, str]
    secondary_headers: dict[str, str]
    json_body: str | None = None
    is_auditable: bool
    is_safe_method: bool


# 对象级引用段关键词：段名命中且后跟取值段 → 对象级引用（BOLA/IDOR 高风险面）
_ID_SEGMENT_RE = re.compile(
    r"(?:^|[^a-z])(?:id|uuid|guid|key|account|order|user|tenant|product|item|ref|"
    r"doc|file|session|device|wallet|transaction|payment|invoice|ticket|profile)s?"
    r"(?:$|[^a-z])",
    re.IGNORECASE,
)


def _is_object_ref_path(path: str) -> bool:
    """
    识别录制 URL 中的对象级引用：关键词段 + 后跟取值段。

    ``/api/v1/accounts/1001`` → True（accounts 段后跟对象 id）
    ``/api/v1/users/42``      → True
    ``/api/v1/admin/users``   → False（集合列举，末段无对象值）
    ``/api/v1/health``        → False
    """
    segments = [seg for seg in (path or "").split("/") if seg]
    return any(_ID_SEGMENT_RE.search(segment) for segment in segments[:-1])


def _load_har(content_or_path: str) -> dict[str, Any]:
    """载入 HAR JSON（字符串或文件路径）。"""
    stripped = content_or_path.strip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    with open(content_or_path, encoding="utf-8") as f:
        return json.load(f)


def _headers_to_dict(headers: Any) -> dict[str, str]:
    """HAR headers 列表 → dict（后者覆盖前者，大小写原样保留）。"""
    result: dict[str, str] = {}
    if not isinstance(headers, list):
        return result
    for h in headers:
        if isinstance(h, dict) and h.get("name"):
            result[str(h["name"])] = str(h.get("value", ""))
    return result


def _path_template(url: str) -> str:
    """提取 URL 的 path 部分作为模板标识（无 query）。"""
    parsed = urlparse(url)
    return parsed.path or "/"


def _strip_query(url: str) -> str:
    """移除 query string，保留 scheme/host/path。"""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def parse_har(
    content_or_path: str,
    primary_headers: dict[str, str] | None = None,
    secondary_headers: dict[str, str] | None = None,
    max_entries: int = 2000,
) -> list[dict[str, Any]]:
    """
    解析 HAR 流量，输出标准化待测矩阵。

    Args:
        content_or_path: HAR JSON 字符串或文件路径。
        primary_headers: 基线身份请求头（覆盖录制值）。
        secondary_headers: 待测试身份请求头（覆盖录制值）。
        max_entries: 最大摄入条目数（防御性上限，防超大 HAR 耗尽内存）。

    Returns:
        待测矩阵列表，每个条目为 HarTargetEntry 的 dict 形式。
    """
    har = _load_har(content_or_path)
    log = har.get("log", {}) if isinstance(har, dict) else {}
    entries = log.get("entries", []) if isinstance(log, dict) else []

    target_matrix: list[dict[str, Any]] = []
    for entry in entries[:max_entries]:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request", {})
        if not isinstance(request, dict):
            continue

        method = str(request.get("method", "GET")).upper()
        url = str(request.get("url", ""))
        if method not in VALID_METHODS or not url:
            continue

        path = _path_template(url)
        query = urlparse(url).query
        recorded_headers = _headers_to_dict(request.get("headers", []))

        # 对象级引用识别：path 段（关键词段+取值段）或 query 参数含 id/uuid/key 等语义
        is_path_auditable = bool(ID_PATH_REGEX.search(path)) or _is_object_ref_path(path)
        has_id_query = bool(ID_QUERY_REGEX.search(query))
        is_auditable = is_path_auditable or has_id_query

        # body：postData.text（优先 mimeType 为 json 的录制体）
        json_body: str | None = None
        post_data = request.get("postData")
        if isinstance(post_data, dict):
            text = post_data.get("text")
            if text:
                json_body = str(text)

        # primary 身份默认沿用录制头，secondary 默认空（由调用方注入攻击者身份）
        p_headers = dict(recorded_headers)
        if primary_headers:
            p_headers.update(primary_headers)
        s_headers: dict[str, str] = dict(recorded_headers)
        s_headers.pop("Authorization", None)
        s_headers.pop("Cookie", None)
        if secondary_headers:
            s_headers.update(secondary_headers)

        target_matrix.append(HarTargetEntry(
            method=method,
            url=_strip_query(url),
            path_template=path,
            primary_headers=p_headers,
            secondary_headers=s_headers,
            json_body=json_body,
            is_auditable=is_auditable,
            is_safe_method=method in SAFE_METHODS,
        ).model_dump())

    return target_matrix


def filter_auditable(matrix: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """过滤出包含对象级引用参数的待测条目（BOLA/IDOR 高风险面）。"""
    return [e for e in matrix if e.get("is_auditable", False)]
