"""
adversarial_guard.py: 对抗绕过检测与基础校验内聚模块

从 bounty_platform 内聚而来，消除外部依赖。
提供：BypassDetector / validate_url / validate_headers / validate_method_safety / validate_request_security
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# URL 校验规则
_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_URL_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_MAX_URL_LENGTH = 2048

# Header 校验规则
_HEADER_NAME_RE = re.compile(r"^[a-zA-Z0-9!#$%&'*+\-.^_`|~]+$")
_HEADER_VALUE_MAX_LEN = 8192
_MAX_HEADERS = 100

# 方法覆盖 header（大小写不敏感）
_METHOD_OVERRIDE_HEADERS = {
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-method",
}

# 方法覆盖 query 参数
_METHOD_OVERRIDE_QUERY_KEYS = {"_method", "x-http-method", "method"}

# 常见绕过载荷特征
_BYPASS_PATTERNS = [
    (re.compile(r"(?i)<\s*script\s*>"), "XSS_SCRIPT_TAG"),
    (re.compile(r"(?i)javascript\s*:"), "XSS_JAVASCRIPT_PROTOCOL"),
    (re.compile(r"(?i)on\w+\s*="), "XSS_EVENT_HANDLER"),
    (re.compile(r"(?i)union\s+select"), "SQLI_UNION_SELECT"),
    (re.compile(r"(?i)or\s+1\s*=\s*1"), "SQLI_TAUTOLOGY"),
    (re.compile(r"(?i)\.\./"), "PATH_TRAVERSAL"),
    (re.compile(r"(?i)%2e%2e%2f"), "PATH_TRAVERSAL_ENCODED"),
    (re.compile(r"(?i)exec\s*\("), "CODE_INJECTION_EXEC"),
    (re.compile(r"(?i)eval\s*\("), "CODE_INJECTION_EVAL"),
]


class BypassDetector:
    """对抗绕过检测器"""

    def check_request(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> List[Dict[str, any]]:
        findings: List[Dict[str, any]] = []

        findings.extend(self._scan_string(url, "URL", blocked=True))

        if query_params:
            for k, v in query_params.items():
                findings.extend(self._scan_string(k, f"QUERY_KEY:{k}", blocked=True))
                findings.extend(self._scan_string(v, f"QUERY_VALUE:{k}", blocked=True))

        if headers:
            for k, v in headers.items():
                findings.extend(self._scan_string(k, f"HEADER_NAME:{k}", blocked=True))
                findings.extend(self._scan_string(v, f"HEADER_VALUE:{k}", blocked=True))

        if body:
            findings.extend(self._scan_string(body, "BODY", blocked=True))

        if headers:
            low_headers = {str(k).lower(): str(v) for k, v in headers.items()}
            for hname in _METHOD_OVERRIDE_HEADERS:
                if hname in low_headers:
                    findings.append({
                        "type": "method_override_header",
                        "blocked": False,
                        "reason": f"检测到方法覆盖 Header: {hname}={low_headers[hname]}",
                        "location": f"HEADER:{hname}",
                    })

        if query_params:
            for qkey in _METHOD_OVERRIDE_QUERY_KEYS:
                if qkey in query_params:
                    findings.append({
                        "type": "method_override_query",
                        "blocked": False,
                        "reason": f"检测到方法覆盖 Query 参数: {qkey}={query_params[qkey]}",
                        "location": f"QUERY:{qkey}",
                    })

        return findings

    def _scan_string(self, s: str, location: str, blocked: bool) -> List[Dict[str, any]]:
        results: List[Dict[str, any]] = []
        if not s:
            return results
        for pattern, name in _BYPASS_PATTERNS:
            if pattern.search(s):
                results.append({
                    "type": name.lower(),
                    "blocked": blocked,
                    "reason": f"检测到 {name} 载荷",
                    "location": location,
                })
        return results


def validate_url(url: str) -> Tuple[bool, str]:
    if not url:
        return False, "URL 为空"
    if len(url) > _MAX_URL_LENGTH:
        return False, f"URL 长度超过限制 ({_MAX_URL_LENGTH})"
    if _URL_CONTROL_CHARS.search(url):
        return False, "URL 包含控制字符"
    if not _URL_SCHEME_RE.match(url):
        return False, "URL 必须以 http:// 或 https:// 开头"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "URL 缺少 host"
    except Exception as e:
        return False, f"URL 解析失败: {e}"
    return True, "ok"


def validate_headers(headers: Optional[Dict[str, str]]) -> List[str]:
    problems: List[str] = []
    if not headers:
        return problems
    if len(headers) > _MAX_HEADERS:
        problems.append(f"Header 数量超过限制 ({_MAX_HEADERS})")
    for name, value in headers.items():
        if not _HEADER_NAME_RE.match(str(name)):
            problems.append(f"非法 Header 名: {name}")
        if len(str(value)) > _HEADER_VALUE_MAX_LEN:
            problems.append(f"Header 值过长: {name} (>{_HEADER_VALUE_MAX_LEN})")
    return problems


def _detect_actual_method(
    method: str,
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, str]] = None,
) -> Tuple[str, bool, str]:
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


def _canonical_content_type(content_type: str) -> str:
    if not content_type:
        return ""
    ct = content_type.lower().strip()
    if ";" in ct:
        ct = ct.split(";", 1)[0].strip()
    return ct


def _is_write_content_type(content_type: str) -> bool:
    ct = _canonical_content_type(content_type)
    if not ct:
        return False
    write_variants = ("application/json", "text/json", "application/javascript")
    if ct in write_variants:
        return True
    return any(wct in ct for wct in ("form-urlencoded", "json", "multipart", "xml"))


SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}


def validate_method_safety(
    method: str,
    allow_write: bool,
    body: Optional[str] = None,
    content_type: str = "",
) -> Tuple[bool, Optional[str]]:
    norm_method = method.upper().strip()

    if norm_method in SAFE_HTTP_METHODS:
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
) -> Tuple[bool, Optional[str], List[Dict[str, any]]]:
    headers = headers or {}
    query_params = query_params or {}

    url_ok, url_reason = validate_url(url)
    if not url_ok:
        return False, f"URL_REJECTED: {url_reason}", []

    header_problems = validate_headers(headers)
    if header_problems:
        return False, f"HEADER_REJECTED: {'; '.join(header_problems)}", []

    effective_method, overridden, override_reason = _detect_actual_method(
        method, headers, query_params
    )

    if overridden and effective_method not in SAFE_HTTP_METHODS and not allow_write:
        return (
            False,
            f"P0-INVARIANT-03_VIOLATION: 方法覆盖 {override_reason} 将安全方法 "
            f"升级为写操作 [{effective_method}]，需显式 allow_write=True",
            [],
        )

    content_type = ""
    low_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    content_type = low_headers.get("content-type", "")

    is_allowed, block_reason = validate_method_safety(
        effective_method,
        allow_write,
        body=body,
        content_type=content_type,
    )

    if not is_allowed:
        return False, block_reason, []

    detector = BypassDetector()
    findings = detector.check_request(url, method, headers, query_params, body)
    blocking = [f for f in findings if f["blocked"]]
    if blocking:
        reasons = "; ".join(f["reason"] for f in blocking)
        return False, f"ADVERSARIAL_BLOCK: {reasons}", findings

    return True, None, findings
