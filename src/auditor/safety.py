"""
safety.py: API 差分审计安全守则与写操作物理熔断门禁

P0-INVARIANT-03: 非只读方法默认零网络流量阻断（fail-closed 白名单模型）。
仅 GET/HEAD/OPTIONS 默认放行，其余所有方法必须显式 allow_write=True。
安全方法携带非空 body 且 Content-Type 为表单/JSON 时升级为可疑写绕过。

强化项：
- ``validate_request_security`` 整合写熔断 + HTTP 方法覆盖 + Content-Type 变体
  + body 编码探测 + 对抗绕过检测。
- ``validate_method_safety`` 签名保持向后兼容，行为不变。
"""

from __future__ import annotations

import base64
import binascii
import gzip

# RFC 7231 / 9110 定义的安全方法（白名单，fail-closed）
SAFE_HTTP_METHODS: set[str] = {"GET", "HEAD", "OPTIONS"}

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
    headers: dict[str, str] | None = None,
    query_params: dict[str, str] | None = None,
) -> tuple[str, bool, str]:
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


def _detect_body_encoding(body: str | None) -> str:
    """
    探测 body 编码形态。返回标识串：
    ``plain`` / ``base64_json`` / ``gzip`` / ``empty``。

    兼容 str 与 bytes 输入；bytes 输入时直接按字节匹配 gzip 魔数。
    """
    if not body or (isinstance(body, str) and not body.strip()):
        return "empty"
    if isinstance(body, (bytes, bytearray)):
        if not body:
            return "empty"
        # gzip 魔数 0x1f 0x8b
        if body[:2] == b"\x1f\x8b":
            return "gzip"
        try:
            gzip.decompress(bytes(body))
            return "gzip"
        except (OSError, binascii.Error):
            pass
        # base64 编码的 JSON：纯 base64 字符集且长度合理
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError:
            return "plain"
        return _detect_body_encoding(text)
    sample = body.strip()
    # gzip 魔数 0x1f 0x8b
    if body.startswith("\x1f\x8b"):
        return "gzip"
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
    body: str | None = None,
    content_type: str = "",
) -> tuple[bool, str | None]:
    """
    P0-INVARIANT-03 物理门禁判定（白名单 fail-closed 模型）。

    1. 安全方法（GET/HEAD/OPTIONS）默认放行，但携带非空 body 且
       Content-Type 为表单/JSON/multipart/XML 时判定为可疑写绕过。
    2. 非安全方法（POST/PUT/PATCH/DELETE/CONNECT/TRACE/WebDAV 等）
       在 allow_write=False 时零网络流量阻断。

    Note:
        本函数签名保持向后兼容。HTTP 方法覆盖（header/query）与对抗绕过
        检测请使用 :func:`validate_request_security`。
    """
    norm_method = method.upper().strip()

    if norm_method in SAFE_HTTP_METHODS:
        # 安全方法携带非空 body 且 Content-Type 为写特征 → 可疑写绕过
        if body and body.strip() and _is_write_content_type(content_type):
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


def validate_request_security(
    url: str,
    method: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    query_params: dict[str, str] | None = None,
    allow_write: bool = False,
) -> tuple[bool, str | None, list]:
    """
    整合写熔断 + 对抗检测的统一请求安全门禁。

    本函数为薄委托：单一事实来源位于 :mod:`src.auditor.adversarial_guard`
    （URL → Header → 方法覆盖 → 写熔断 → 对抗检测），此处保留既有调用签名，
    消除历史上对 ``bounty_platform.adversarial_guard`` 的外部依赖。

    Returns:
        ``(is_allowed, block_reason, findings)``。
    """
    # 延迟导入避免循环依赖（adversarial_guard 模块级引用本模块的熔断原语）
    from .adversarial_guard import (
        validate_request_security as _validate_request_security,
    )

    return _validate_request_security(
        url=url,
        method=method,
        headers=headers,
        body=body,
        query_params=query_params,
        allow_write=allow_write,
    )
