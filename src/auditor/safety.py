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
        检测请使用 :func:`validate_request_security`。
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


def validate_request_security(
    url: str,
    method: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    query_params: Optional[Dict[str, str]] = None,
    allow_write: bool = False,
) -> Tuple[bool, Optional[str], list]:
    """
    整合写熔断 + 对抗检测的统一请求安全门禁。

    校验顺序（短路返回）：
    1. URL 合法性（scheme/host/控制字符）。
    2. HTTP 方法覆盖解析（X-HTTP-Method-Override header / _method query）。
    3. Content-Type 变体鲁棒判定 + body 编码探测。
    4. P0-INVARIANT-03 写熔断（基于解析后的有效方法）。
    5. 对抗绕过检测（BypassDetector 聚合）。

    Args:
        url: 请求 URL。
        method: 原始 HTTP 方法。
        headers: 请求头。
        body: 请求体。
        query_params: 解析后的 query 参数。
        allow_write: 是否显式允许写操作。

    Returns:
        ``(is_allowed, block_reason, findings)``：
        ``findings`` 为对抗检测命中项列表（即便放行也可能含 info 级提示）。
    """
    headers = headers or {}
    query_params = query_params or {}

    # 延迟导入避免循环依赖（adversarial_guard 不依赖 safety）
    # 原先依赖外部私有包 bounty_platform；该包未随仓库分发且不在
    # requirements.txt 中，导致本函数必崩。改为仓内本地实现（同契约）。
    from .adversarial_guard import (
        BypassDetector,
        validate_headers,
        validate_url,
    )

    # 1. URL 合法性
    url_ok, url_reason = validate_url(url)
    if not url_ok:
        return False, f"URL_REJECTED: {url_reason}", []

    # 2. Header 校验
    header_problems = validate_headers(headers)
    if header_problems:
        return False, f"HEADER_REJECTED: {'; '.join(header_problems)}", []

    # 3. 方法覆盖解析
    effective_method, overridden, override_reason = _detect_actual_method(
        method, headers, query_params
    )

    # 4. 方法覆盖升级为写操作：先于通用写熔断判定，使本分支可达。
    #    即便原始方法是 GET，只要被 header/query 覆盖为非安全写方法且未显式
    #    allow_write，立即以「方法覆盖」专属原因 fail-closed 阻断。
    if overridden and effective_method not in SAFE_HTTP_METHODS and not allow_write:
        return (
            False,
            f"P0-INVARIANT-03_VIOLATION: 方法覆盖 {override_reason} 将安全方法 "
            f"升级为写操作 [{effective_method}]，需显式 allow_write=True",
            [],
        )

    # 5. Content-Type 变体 + body 编码探测
    content_type = ""
    low_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    content_type = low_headers.get("content-type", "")
    body_encoding = _detect_body_encoding(body)

    # 6. 通用写熔断（基于解析后的有效方法）
    is_allowed, block_reason = validate_method_safety(
        effective_method,
        allow_write,
        body=body,
        content_type=content_type,
    )

    if not is_allowed:
        return False, block_reason, []

    # 7. 对抗绕过检测
    detector = BypassDetector()
    findings = detector.check_request(url, method, headers, query_params, body)
    blocking = [f for f in findings if f["blocked"]]
    if blocking:
        reasons = "; ".join(f["reason"] for f in blocking)
        return False, f"ADVERSARIAL_BLOCK: {reasons}", findings

    # body 编码为 base64/gzip 时附加提示（不阻断，供上层解码重放）
    if body_encoding in ("base64_json", "gzip"):
        findings.append({
            "type": "body_encoding",
            "blocked": False,
            "reason": f"BODY_ENCODING: 检测到 {body_encoding} body，重放前需解码",
        })

    return True, None, findings
