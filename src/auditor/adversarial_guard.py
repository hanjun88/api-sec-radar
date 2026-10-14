"""
adversarial_guard.py: 请求对抗绕过检测守卫

本模块是 ``bounty_platform.adversarial_guard`` 的本地等价实现，供
:func:`safety.validate_request_security` 消费。仅暴露三个符号：

- :func:`validate_url` —— URL 语法与 scheme 合法性
- :func:`validate_headers` —— 请求头注入检测
- :class:`BypassDetector` —— 对抗绕过聚合检测

设计基线：**fail-closed，但区分「确凿阻断」与「可疑标记」**。
校验失败一律拒绝；可疑但不确凿的模式置 ``blocked=False`` 由上层决策，
避免审计工具因误报而无法扫描合法目标。

Notation:
    finding = {"type": str, "blocked": bool, "reason": str}
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# 差分审计只走 HTTP(S)；file://、gopher://、dict:// 等一律拒绝
_ALLOWED_SCHEMES = ("http", "https")

# 路径穿越特征（含大小写与双重编码变体）
_PATH_TRAVERSAL_TOKENS = (
    "../",
    "..\\",
    "..%2f",
    "..%5c",
    "%2e%2e",
    "%252e%252e",
)

# 危险请求头：可改变服务端路由语义，审计重放时须拒绝
_FORBIDDEN_HEADERS = (
    "x-forwarded-for",
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
)


def _has_control_chars(value: str) -> bool:
    """检测控制字符（含 CRLF），用于阻断请求/响应走私。"""
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def validate_url(url: str) -> Tuple[bool, str]:
    """
    校验 URL 合法性。

    Returns:
        ``(ok, reason)``；``ok=True`` 时 ``reason`` 为空串，
        失败时 ``reason`` 供上层拼接 ``URL_REJECTED: {reason}``。

    拒绝项：空值 / 非字符串、控制字符（CRLF 走私）、非 http(s) scheme、
    缺失 host、端口越界。
    """
    if not isinstance(url, str) or not url.strip():
        return False, "URL 为空或非字符串"

    if _has_control_chars(url):
        return False, "URL 含控制字符（疑似 CRLF 请求走私）"

    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        return False, f"URL 解析失败: {exc}"

    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, f"不支持的 scheme [{scheme or '空'}]，仅允许 http/https"

    if not parts.hostname:
        return False, "URL 缺少 host"

    try:
        port = parts.port
    except ValueError:
        return False, "URL 端口非法（非数字）"

    if port is not None and not (0 < port <= 65535):
        return False, f"URL 端口越界 [{port}]"

    # SSRF 加固：拒绝指向内网/保留/链路本地地址的主机（如 169.254.169.254
    # 云元数据、10/172.16-31/192.168 私有段、组播等）。回环地址（127.0.0.1 /
    # ::1 / localhost）放行，以便本地靶场差分审计仍可执行。仅对 IP 字面量做
    # 此判定（DNS 名无法静态安全解析，交由上层网络层控制）。
    if parts.hostname:
        try:
            ip = ipaddress.ip_address(parts.hostname)
        except ValueError:
            ip = None
        if ip is not None and not ip.is_loopback:
            if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False, (
                    f"URL 指向内网/保留地址 [{parts.hostname}]，疑似 SSRF，已拒绝"
                )

    return True, ""


def validate_headers(headers: Optional[Dict[str, str]]) -> List[str]:
    """
    校验请求头安全性。

    Returns:
        问题字符串列表；**空列表表示通过**，非空供上层拼接
        ``HEADER_REJECTED: {'; '.join(problems)}``。

    拒绝项：header 名/值含控制字符（响应拆分）、NUL 字节、
    可改写服务端路由的危险转发头。
    """
    if headers is None:
        return []

    if not isinstance(headers, dict):
        return ["headers 必须为 dict"]

    problems: List[str] = []
    for raw_name, raw_value in headers.items():
        name = str(raw_name)
        value = str(raw_value)

        if _has_control_chars(name):
            problems.append(f"header 名含控制字符: {name!r}")

        if _has_control_chars(value):
            problems.append(f"header [{name}] 值含 CRLF（响应拆分/请求走私）")

        if "\x00" in value:
            problems.append(f"header [{name}] 值含 NUL 字节")

        if name.lower().strip() in _FORBIDDEN_HEADERS:
            problems.append(
                f"危险转发头 [{name}] 可改写服务端路由，审计重放须移除"
            )

    return problems


class BypassDetector:
    """
    对抗绕过聚合检测器。

    :meth:`check_request` 返回 finding 列表，每项含 ``type`` / ``blocked`` /
    ``reason`` 三键。``blocked=True`` 者会被
    :func:`safety.validate_request_security` 汇总为阻断原因。
    """

    def check_request(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        对一次请求做对抗绕过检测。

        Args:
            url: 目标 URL。
            method: 原始 HTTP 方法。
            headers: 请求头。
            query_params: query 参数字典。
            body: 请求体。

        Returns:
            finding 列表（可为空）。
        """
        findings: List[Dict[str, Any]] = []
        headers = headers or {}
        query_params = query_params or {}

        findings.extend(self._scan_traversal(url, query_params))
        findings.extend(self._scan_null_byte(url, body))
        findings.extend(self._scan_userinfo(url))
        findings.extend(self._scan_method_override(headers, query_params))

        return findings

    def _scan_traversal(
        self, url: str, query_params: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """路径穿越：含 `../` 及其大小写/双重编码变体。"""
        haystacks = [(url or "").lower()]
        haystacks.extend(str(v).lower() for v in query_params.values())

        for source in haystacks:
            for token in _PATH_TRAVERSAL_TOKENS:
                if token in source:
                    return [{
                        "type": "path_traversal",
                        "blocked": True,
                        "reason": f"检测到路径穿越特征 [{token}]",
                    }]
        return []

    def _scan_null_byte(
        self, url: str, body: Optional[str]
    ) -> List[Dict[str, Any]]:
        """NUL 字节截断绕过（C 风格字符串截断）。"""
        for label, value in (("URL", url or ""), ("body", body or "")):
            if "\x00" in value:
                return [{
                    "type": "null_byte",
                    "blocked": True,
                    "reason": f"{label} 含 NUL 字节（截断绕过特征）",
                }]
        return []

    def _scan_userinfo(self, url: str) -> List[Dict[str, Any]]:
        """
        URL userinfo 混淆（``http://expected@evil/`` 式解析差异）。

        仅标记不阻断：可能是已废弃但仍合法的 basic-auth 写法。
        """
        if not url:
            return []
        try:
            if urlsplit(url).username is not None:
                return [{
                    "type": "url_userinfo",
                    "blocked": False,
                    "reason": "URL 含 userinfo，注意 host 解析差异（SSRF 混淆特征）",
                }]
        except ValueError:
            return []
        return []

    def _scan_method_override(
        self, headers: Dict[str, str], query_params: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        方法覆盖痕迹标记。

        safety 模块已先行阻断未授权的覆盖升级；此处仅在放行路径上留痕，
        便于回溯审计记录。
        """
        low_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        if any(h in low_headers for h in ("x-http-method-override", "x-http-method", "x-method-override")):
            return [{
                "type": "method_override",
                "blocked": False,
                "reason": "检测到方法覆盖头，实际语义以服务端解析为准",
            }]

        low_query = {str(k).lower(): str(v) for k, v in query_params.items()}
        if any(q in low_query for q in ("_method", "x-http-method", "method")):
            return [{
                "type": "method_override",
                "blocked": False,
                "reason": "检测到方法覆盖 query 参数，实际语义以服务端解析为准",
            }]

        return []
