"""
safety.py: API 差分审计安全守则与写操作物理熔断门禁

P0-INVARIANT-03: 非只读方法默认零网络流量阻断（fail-closed 白名单模型）。
仅 GET/HEAD/OPTIONS 默认放行，其余所有方法必须显式 allow_write=True。
安全方法携带非空 body 且 Content-Type 为表单/JSON 时升级为可疑写绕过。

强化项：
- ``validate_method_safety`` 为 P0-INVARIANT-03 物理门禁判定（白名单 fail-closed 模型）。
- HTTP 方法覆盖（header/query）解析与 Content-Type 变体/body 编码探测
  由 ``_detect_actual_method`` / ``_detect_body_encoding`` / ``_canonical_content_type``
  等内部工具函数承载，供上层按需组合。
- ``validate_method_safety`` 签名保持向后兼容，行为不变。
"""

from __future__ import annotations

import base64
import binascii
import gzip
from typing import Dict, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

# RFC 7231 / 9110 定义的安全方法（白名单，fail-closed）
SAFE_HTTP_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS"}

# 写操作 Content-Type 特征（用于 GET+body 绕过检测）
_WRITE_CONTENT_TYPES = ("form-urlencoded", "json", "multipart", "xml")

# 明确视为「写语义 JSON」的 Content-Type 变体（大小写/参数无关）
_WRITE_JSON_CT_VARIANTS = ("application/json", "text/json", "application/javascript")

# HTTP 方法覆盖 header（大小写不敏感）
_METHOD_OVERRIDE_HEADERS = {
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-method",
}

# 方法覆盖 query 参数
_METHOD_OVERRIDE_QUERY_KEYS = {"_method", "x-http-method", "method"}


def _canonical_content_type(content_type: str) -> str:
    """
    规范化 Content-Type：小写、剥离 ``; charset=...`` 等参数后比较。

    处理 ``Application/JSON``、``application/json; charset=utf-8``、``text/json`` 等变体。
    """
    if not content_type:
        return ""
    ct = content_type.lower().strip()
    # 剥离参数部分（; 之后）
    if ";" in ct:
        ct = ct.split(";", 1)[0].strip()
    return ct


def _is_write_content_type(content_type: str) -> bool:
    """判断 Content-Type 是否具备写操作特征（大小写/参数/变体鲁棒）。"""
    ct = _canonical_content_type(content_type)
    if not ct:
        return False
    if ct in _WRITE_JSON_CT_VARIANTS:
        return True
    return any(wct in ct for wct in _WRITE_CONTENT_TYPES)


def _detect_actual_method(
    method: str,
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, str]] = None,
) -> Tuple[str, bool, str]:
    """
    解析 HTTP 方法覆盖。

    Returns:
        ``(effective_method, overridden, reason)``。
        当 header / query 参数将方法覆盖为非安全写方法时，
        effective_method 返回覆盖后方法，overridden=True。
    """
    norm = (method or "").upper().strip()
    low_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for hname in _METHOD_OVERRIDE_HEADERS:
        if hname in low_headers:
            override = low_headers[hname].upper().strip()
            if override:
                return override, True, f"HEADER_OVERRIDE:{hname}={override}"

    qp_lower = {str(k).lower(): str(v) for k, v in (query_params or {}).items()}
    for qkey in _METHOD_OVERRIDE_QUERY_KEYS:
        if qkey in qp_lower:
            override = qp_lower[qkey].upper().strip()
            if override:
                return override, True, f"QUERY_OVERRIDE:{qkey}={override}"
    return norm, False, ""


def _detect_body_encoding(body: Optional[str]) -> str:
    """
    探测 body 编码形态。返回标识串：
    ``plain`` / ``base64_json`` / ``gzip`` / ``empty``。
    """
    if not body or not body.strip():
        return "empty"
    sample = body.strip()
    # gzip 魔数 0x1f 0x8b
    if body.startswith("\x1f\x8b"):
        return "gzip"
    # 尝试 gzip 解压（防御性：二进制字面量在 str 中少见，这里仅识别魔数）
    try:
        gzip.decompress(body.encode("latin-1"))
        return "gzip"
    except (OSError, binascii.Error, UnicodeEncodeError):
        pass
    # base64 编码的 JSON：纯 base64 字符集且长度合理，解码后以 { 或 [ 开头
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if len(sample) >= 16 and set(sample) <= b64_chars and len(sample) % 4 == 0:
        try:
            decoded = base64.b64decode(sample, validate=True)
            head = decoded[:1]
            if head in (b"{", b"["):
                return "base64_json"
        except (binascii.Error, ValueError):
            pass
    return "plain"


def validate_method_safety(
    method: str,
    allow_write: bool,
    body: Optional[str] = None,
    content_type: str = "",
) -> Tuple[bool, Optional[str]]:
    """
    P0-INVARIANT-03 物理门禁判定（白名单 fail-closed 模型）。

    1. 安全方法（GET/HEAD/OPTIONS）默认放行，但携带非空 body 且
       Content-Type 为表单/JSON/multipart/XML 时判定为可疑写绕过。
    2. 非安全方法（POST/PUT/PATCH/DELETE/CONNECT/TRACE/WebDAV 等）
       在 allow_write=False 时零网络流量阻断。

    Note:
        本函数签名保持向后兼容。HTTP 方法覆盖（header/query）与对抗绕过
        检测请由上层用 ``_detect_actual_method`` 等工具函数按需组合。
    """
    norm_method = method.upper().strip()

    if norm_method in SAFE_HTTP_METHODS:
        # 安全方法携带非空 body 且 Content-Type 为写特征 → 可疑写绕过
        if body and body.strip():
            if _is_write_content_type(content_type):
                return (
                    False,
                    f"SAFE_METHOD_WITH_BODY: 安全方法 [{norm_method}] 携带 "
                    f"[{_canonical_content_type(content_type)}] 请求体，"
                    f"疑似写操作绕过，需显式 allow_write=True",
                )
        return True, None

    if not allow_write:
        return (
            False,
            f"P0-INVARIANT-03_VIOLATION: 非只读方法 [{norm_method}] 默认物理熔断。"
            "需在调用参数中显式设置 allow_write=True 方可执行差分重放。",
        )
    return True, None
