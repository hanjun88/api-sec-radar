"""
adversarial_guard.py: 对抗绕过检测与统一请求安全门禁

本模块是 P0-INVARIANT-03 写熔断之上的一体化请求安全守门员，提供：

- ``validate_url`` / ``validate_headers``: URL 与 Header 合法性硬校验；
- ``BypassDetector``: XSS / SQLi / 路径遍历 / 代码注入 / 方法覆盖检测器；
- ``validate_request_security``: 整合门禁（URL → Header → 方法覆盖 →
  写熔断 → 对抗检测），返回 ``(is_allowed, block_reason, findings)``。

设计约束：
- 本模块不依赖 MCP / 网络栈，可被 auditor、pipeline、bounty 平台复用；
- 对 ``safety.py`` 仅做只读引用（SAFE_HTTP_METHODS / validate_method_safety），
  ``safety.validate_request_security`` 以薄委托方式复用本实现，避免循环导入。
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlparse

from .safety import (
    SAFE_HTTP_METHODS,
    _detect_body_encoding,
    validate_method_safety,
)

# ── 常量 ──────────────────────────────────────────────────────

MAX_URL_LENGTH = 2048
MAX_HEADERS = 64
ALLOWED_SCHEMES = {"http", "https"}

# HTTP 方法覆盖 header（大小写不敏感）
METHOD_OVERRIDE_HEADERS = {
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-method",
}

# 方法覆盖 query 参数
METHOD_OVERRIDE_QUERY_KEYS = {"_method", "x-http-method", "method"}

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# 路径遍历编码形态（%2e / ..%2f / %252e 等，单/双跳编码）
_PATH_TRAVERSAL_ENCODED_RE = re.compile(
    r"(?:%2e%2e|\.\.(?:%2f|%5c)|(?:%2f|%5c)\.\.)", re.IGNORECASE
)
# 路径遍历明文形态
_PATH_TRAVERSAL_PLAIN_RE = re.compile(r"\.\.[/\\]")

# XSS / SQLi / 代码注入特征（大小写不敏感）
_XSS_SCRIPT_RE = re.compile(r"<\s*script", re.IGNORECASE)
_XSS_JS_PROTOCOL_RE = re.compile(r"javascript\s*:", re.IGNORECASE)
_XSS_EVENT_HANDLER_RE = re.compile(r"\bon[a-z]{3,}\s*=", re.IGNORECASE)
_SQLI_UNION_RE = re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)
_SQLI_TAUTOLOGY_RE = re.compile(
    r"\bor\b\s+['\"`]?[\w.]+['\"`]?\s*=\s*['\"`]?[\w.]+['\"`]?", re.IGNORECASE
)
_CODE_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("code_injection_exec", re.compile(r"\bexec\s*\(", re.IGNORECASE)),
    ("code_injection_eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("code_injection_system", re.compile(r"\b(?:system|shell_exec|popen)\s*\(", re.IGNORECASE)),
)

# 阻断型 finding（命中即拒绝请求）
BLOCKING_FINDING_TYPES = {
    "xss_script_tag",
    "xss_javascript_protocol",
    "xss_event_handler",
    "sqli_union_select",
    "sqli_tautology",
    "path_traversal",
    "path_traversal_encoded",
    "code_injection_exec",
    "code_injection_eval",
    "code_injection_system",
}


# ── URL / Header 校验 ─────────────────────────────────────────


def validate_url(url: str) -> tuple[bool, str]:
    """
    URL 合法性硬校验。

    Returns:
        ``(ok, reason)``；reason 为空串表示通过。
    """
    if not url or not url.strip():
        return False, "EMPTY_URL: URL 为空"
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL_TOO_LONG: {len(url)} > {MAX_URL_LENGTH}"
    if _CONTROL_CHARS_RE.search(url):
        return False, "CONTROL_CHARS: URL 含控制字符"
    try:
        parsed = urlparse(url)
    except ValueError as e:
        return False, f"MALFORMED_URL: 解析失败 ({e})"
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"BAD_SCHEME: 仅允许 http/https，得到 {parsed.scheme!r}"
    if not parsed.netloc:
        return False, "NO_HOST: 缺少 host"
    if not parsed.hostname:
        return False, "NO_HOSTNAME: host 解析失败"
    return True, ""


def validate_headers(headers: dict[str, str] | None) -> list[str]:
    """
    Header 集合合法性校验，返回问题描述列表（空列表 = 通过）。

    规则：
    - Header 数量超过 ``MAX_HEADERS``（64）→ TOO_MANY_HEADERS；
    - Header 名含 ``:`` / 控制字符 → INVALID_HEADER_NAME；
    - Header 值含 CR / LF / NUL → HEADER_CRLF_INJECTION（CRLF 注入）。
    """
    problems: list[str] = []
    if not headers:
        return problems
    if len(headers) > MAX_HEADERS:
        problems.append(f"TOO_MANY_HEADERS: {len(headers)} > {MAX_HEADERS}")
    for raw_name, raw_value in headers.items():
        name = str(raw_name)
        value = str(raw_value)
        if not name or ":" in name or _CONTROL_CHARS_RE.search(name):
            problems.append(f"INVALID_HEADER_NAME: {name!r}")
        if "\r" in value or "\n" in value or "\x00" in value:
            problems.append(f"HEADER_CRLF_INJECTION: {name}")
    return problems


# ── 方法覆盖解析 ──────────────────────────────────────────────


def detect_actual_method(
    method: str,
    headers: dict[str, str] | None = None,
    query_params: dict[str, str] | None = None,
) -> tuple[str, bool, str]:
    """
    解析 HTTP 方法覆盖（header / query）。

    Returns:
        ``(effective_method, overridden, reason)``。
    """
    norm = (method or "").upper().strip()
    low_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for hname in METHOD_OVERRIDE_HEADERS:
        if hname in low_headers:
            override = low_headers[hname].upper().strip()
            if override:
                return override, True, f"HEADER_OVERRIDE:{hname}={override}"

    qp_lower = {str(k).lower(): str(v) for k, v in (query_params or {}).items()}
    for qkey in METHOD_OVERRIDE_QUERY_KEYS:
        if qkey in qp_lower:
            override = qp_lower[qkey].upper().strip()
            if override:
                return override, True, f"QUERY_OVERRIDE:{qkey}={override}"
    return norm, False, ""


# ── 对抗检测器 ────────────────────────────────────────────────


class BypassDetector:
    """
    请求对抗载荷检测器。

    ``check_request`` 扫描 URL（含内嵌 query）、query 参数与 body，
    并对方法覆盖 header / query 输出 info 级 finding。
    返回 finding 列表（干净请求返回 ``[]``），每项结构::

        {"type": str, "blocked": bool, "reason": str, "location": str}

    阻断语义：仅 ``BLOCKING_FINDING_TYPES`` 内的类型 blocked=True；
    方法覆盖为 info 级（其写语义由 P0-INVARIANT-03 门禁单独裁决）。
    """

    def check_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        query_params: dict[str, str] | None = None,
        body: str | None = None,
    ) -> list[dict[str, Any]]:
        headers = headers or {}
        query_params = query_params or {}
        findings: list[dict[str, Any]] = []
        seen: set = set()

        def _add(ftype: str, location: str, detail: str) -> None:
            key = (ftype, location)
            if key in seen:
                return
            seen.add(key)
            findings.append({
                "type": ftype,
                "blocked": ftype in BLOCKING_FINDING_TYPES,
                "reason": f"{ftype.upper()} @ {location}: {detail}",
                "location": location,
            })

        # 1. URL 自身（含内嵌 query string）
        if url:
            self._scan_payload(url, "url", _add)

        # 2. 显式 query 参数（key + value）
        for key, value in query_params.items():
            self._scan_payload(f"{key}={value}", f"query[{key}]", _add)

        # 3. 请求体
        if body:
            self._scan_payload(str(body), "body", _add)

        # 4. 方法覆盖（info 级）
        low_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        for hname in METHOD_OVERRIDE_HEADERS:
            if hname in low_headers and low_headers[hname].strip():
                _add(
                    "method_override_header",
                    f"header[{hname}]",
                    f"方法覆盖 header 指向 {low_headers[hname].upper()}",
                )
                break
        qp_lower = {str(k).lower(): str(v) for k, v in query_params.items()}
        for qkey in METHOD_OVERRIDE_QUERY_KEYS:
            if qkey in qp_lower and qp_lower[qkey].strip():
                _add(
                    "method_override_query",
                    f"query[{qkey}]",
                    f"方法覆盖参数指向 {qp_lower[qkey].upper()}",
                )
                break

        return findings

    def _scan_payload(self, raw: str, location: str, _add: Any) -> None:
        """对单个扫描串执行全部载荷特征匹配（raw + 单次 URL 解码变体）。"""
        variants = [raw]
        try:
            decoded = unquote(raw)
        except Exception:
            decoded = raw
        if decoded != raw:
            variants.append(decoded)

        # 路径遍历（编码形态优先，避免重复上报）
        enc_hit = any(_PATH_TRAVERSAL_ENCODED_RE.search(v) for v in variants)
        plain_hit = any(_PATH_TRAVERSAL_PLAIN_RE.search(v) for v in variants)
        if enc_hit:
            _add("path_traversal_encoded", location, "检测到编码路径遍历序列（%2e%2e 等）")
        elif plain_hit:
            _add("path_traversal", location, "检测到明文路径遍历序列（../）")

        checks: tuple[tuple[str, Any], ...] = (
            ("xss_script_tag", _XSS_SCRIPT_RE),
            ("xss_javascript_protocol", _XSS_JS_PROTOCOL_RE),
            ("xss_event_handler", _XSS_EVENT_HANDLER_RE),
            ("sqli_union_select", _SQLI_UNION_RE),
            ("sqli_tautology", _SQLI_TAUTOLOGY_RE),
        )
        for ftype, pattern in checks:
            if any(pattern.search(v) for v in variants):
                _add(ftype, location, f"命中特征 {pattern.pattern}")

        for ftype, pattern in _CODE_INJECTION_PATTERNS:
            if any(pattern.search(v) for v in variants):
                _add(ftype, location, f"命中特征 {pattern.pattern}")


# ── 统一请求安全门禁 ──────────────────────────────────────────


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

    校验顺序（短路返回）：
    1. URL 合法性（scheme/host/控制字符/长度）；
    2. Header 合法性（数量/名称/CRLF 注入）；
    3. HTTP 方法覆盖解析（X-HTTP-Method-Override header / _method query）；
    4. P0-INVARIANT-03 写熔断（基于解析后的有效方法，含 GET+body 写绕过检测）；
    5. 对抗绕过检测（BypassDetector 聚合，仅阻断型 finding 拒绝）。

    Args:
        url: 请求 URL。
        method: 原始 HTTP 方法。
        headers: 请求头。
        body: 请求体。
        query_params: 解析后的 query 参数。
        allow_write: 是否显式允许写操作。

    Returns:
        ``(is_allowed, block_reason, findings)``：findings 为检测命中项列表
        （即便放行也可能含 info 级提示，如方法覆盖 / body 编码）。
    """
    headers = headers or {}
    query_params = query_params or {}

    # 1. URL 合法性
    url_ok, url_reason = validate_url(url)
    if not url_ok:
        return False, f"URL_REJECTED: {url_reason}", []

    # 2. Header 合法性
    header_problems = validate_headers(headers)
    if header_problems:
        return False, f"HEADER_REJECTED: {'; '.join(header_problems)}", []

    # 3. 方法覆盖解析
    effective_method, overridden, override_reason = detect_actual_method(
        method, headers, query_params
    )

    # 4. 方法覆盖升级为写操作：先于通用写熔断判定，使本分支可达
    if overridden and effective_method not in SAFE_HTTP_METHODS and not allow_write:
        return (
            False,
            f"P0-INVARIANT-03_VIOLATION: 方法覆盖 {override_reason} 将安全方法 "
            f"升级为写操作 [{effective_method}]，需显式 allow_write=True",
            [],
        )

    # 5. 通用写熔断（含安全方法携带写特征 body 的绕过检测）
    content_type = {
        str(k).lower(): str(v) for k, v in headers.items()
    }.get("content-type", "")
    body_encoding = _detect_body_encoding(body)
    is_allowed, block_reason = validate_method_safety(
        effective_method,
        allow_write,
        body=body,
        content_type=content_type,
    )
    if not is_allowed:
        return False, block_reason, []

    # 6. 对抗绕过检测
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
            "location": "body",
        })

    return True, None, findings
