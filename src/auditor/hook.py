"""
hook.py: 请求预处理 Hook 引擎

解决现代 API 防御重放失效问题：动态时间戳、Nonce、HMAC 签名
在发包前毫秒级重新计算，避免静态 Header 被网关拒绝。

强化项：
- 时间戳容差验证 ``verify_timestamp``（默认 ±300s）。
- Nonce 重放检测 ``NonceCache``（带 TTL 的线程安全字典）。
- 签名基串纳入 body 的 SHA-256 摘要，防止 body 被篡改。
- path 部分先 URL 解码再编码规范化，消除编码差异导致的签名不一致。
- ``verify_signature`` 校验收到的请求签名是否合法。
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import uuid
from collections.abc import Callable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse

# ---------------------------------------------------------------------------
# 签名规范化工具
# ---------------------------------------------------------------------------

def _normalize_path(path: str) -> str:
    """
    规范化 URL path：先 unquote 解码，再 quote 编码（safe='/'）。

    消除 ``%2f`` / ``%5c`` 等编码差异导致同一逻辑 path 签名不一致的问题。
    """
    if not path:
        return "/"
    decoded = unquote(path)
    return quote(decoded, safe="/")


def _canonical_query(query: str) -> str:
    """规范化 query string：排序后重新编码，防止参数顺序差异。"""
    return urlencode(sorted(parse_qsl(query or "")), doseq=True)


def _body_hash(body: str | None) -> str:
    """
    计算 body 的 SHA-256 摘要（hex）。body 为空时返回空串，
    保证「无 body」与「空 body」签名基串一致。
    """
    if not body:
        return ""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _build_signing_base(
    method: str,
    url: str,
    timestamp: str,
    nonce: str,
    body: str | None,
) -> str:
    """
    构造签名基串：``METHOD|norm_path|canon_query|ts|nonce|body_sha256``。

    path 经解码-编码规范化，body 以 SHA-256 摘要拼入。
    """
    parsed = urlparse(url)
    norm_path = _normalize_path(parsed.path or "/")
    canon_query = _canonical_query(parsed.query or "")
    bhash = _body_hash(body)
    return f"{method.upper()}|{norm_path}|{canon_query}|{timestamp}|{nonce}|{bhash}"


def _compute_signature(secret: str, sign_base: str) -> str:
    """以 HMAC-SHA256 计算签名 hex。"""
    return hmac.new(
        secret.encode("utf-8"),
        sign_base.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# 时间戳 / Nonce 重放防护
# ---------------------------------------------------------------------------

def verify_timestamp(ts: str, max_skew_seconds: int = 300) -> bool:
    """
    验证时间戳是否在容差窗口内。

    Args:
        ts: 十进制 Unix 时间戳字符串（如 ``"1730000000"``）。
        max_skew_seconds: 允许的时钟偏移（秒），默认 300（5 分钟）。

    Returns:
        在容差内返回 True；无法解析或超出窗口返回 False。
    """
    try:
        ts_int = int(str(ts).strip())
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    return abs(now - ts_int) <= max_skew_seconds


class NonceCache:
    """
    带 TTL 的 Nonce 重放缓存（线程安全）。

    已使用的 nonce 在 TTL 窗口内拒绝再次出现，超过 TTL 自动淘汰。
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        """
        Args:
            ttl_seconds: Nonce 保留时长（秒），默认 300。
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds 必须为正数")
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._seen: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        """淘汰过期 nonce（调用方持锁）。"""
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for k in expired:
            self._seen.pop(k, None)

    def check_and_store(self, nonce: str) -> bool:
        """
        检查 nonce 是否首次出现；若是则记录并返回 True，否则（重放）返回 False。
        """
        if not nonce:
            return False
        now = time.time()
        with self._lock:
            self._prune(now)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + self.ttl_seconds
            return True

    def is_replay(self, nonce: str) -> bool:
        """仅查询 nonce 是否已被使用，不记录。"""
        with self._lock:
            self._prune(time.time())
            return nonce in self._seen

    def clear(self) -> None:
        """清空所有 nonce。"""
        with self._lock:
            self._seen.clear()


# ---------------------------------------------------------------------------
# Hook 引擎
# ---------------------------------------------------------------------------

class RequestHook:
    """请求预处理 Hook 集合。所有方法为纯函数，返回新 headers dict，不修改入参。"""

    # 模块级共享 Nonce 缓存，用于 verify_signature 重放检测
    _default_nonce_cache = NonceCache(ttl_seconds=300)

    @staticmethod
    def verify_timestamp(ts: str, max_skew_seconds: int = 300) -> bool:
        """时间戳容差验证（实例/类访问入口，等价于模块级 ``verify_timestamp``）。"""
        return verify_timestamp(ts, max_skew_seconds)

    @staticmethod
    def apply_standard_auth(
        headers: dict[str, str],
        method: str,
        url: str,
        body: str | None = None,
        secret: str | None = None,
        timestamp_header: str = "X-Timestamp",
        nonce_header: str = "X-Nonce",
        signature_header: str = "X-Signature",
    ) -> dict[str, str]:
        """
        常见企业网关签名补齐：动态写入 Timestamp、Nonce 及可选 HMAC-SHA256。

        签名拼接范式: METHOD|norm_path|canon_query|timestamp|nonce|sha256(body)

        其中 path 经解码-编码规范化，body 非空时以 SHA-256 摘要拼入，
        防止 body 篡改与编码差异导致签名不一致。
        """
        updated = dict(headers)
        ts = str(int(time.time()))
        nonce = uuid.uuid4().hex[:16]

        updated[timestamp_header] = ts
        updated[nonce_header] = nonce

        if secret:
            sign_base = _build_signing_base(method, url, ts, nonce, body)
            sign = _compute_signature(secret, sign_base)
            updated[signature_header] = sign

        return updated

    @staticmethod
    def verify_signature_with_details(
        headers: dict[str, str],
        method: str,
        url: str,
        body: str | None = None,
        secret: str | None = None,
        timestamp_header: str = "X-Timestamp",
        nonce_header: str = "X-Nonce",
        signature_header: str = "X-Signature",
        max_skew_seconds: int = 300,
        nonce_cache: NonceCache | None = None,
    ) -> dict[str, object]:
        """
        校验收到的请求签名是否合法，并返回详细失败原因。

        校验顺序（关键：先验签，通过后才消耗 nonce，签名失败不污染 nonce 缓存）：
        1. timestamp / nonce / signature 三个 header 均存在；
        2. 时间戳在容差窗口内（默认 ±300s）；
        3. HMAC-SHA256 常数时间比较；签名不通过直接返回，**不记录 nonce**；
        4. 签名通过后才 ``check_and_store(nonce)``，拒绝重放。

        Returns:
            ``{"valid": bool, "reason": str}``，reason 取值：
            ``ok`` / ``missing_secret`` / ``missing_headers`` /
            ``stale_timestamp`` / ``bad_signature`` / ``nonce_replayed``。
        """
        if not secret:
            return {"valid": False, "reason": "missing_secret"}
        # 大小写不敏感取 header
        low_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        ts = low_map.get(timestamp_header.lower())
        nonce = low_map.get(nonce_header.lower())
        received = low_map.get(signature_header.lower())
        if not ts or not nonce or not received:
            return {"valid": False, "reason": "missing_headers"}

        if not verify_timestamp(ts, max_skew_seconds):
            return {"valid": False, "reason": "stale_timestamp"}

        # 先验签：签名错误时绝不消耗/占用 nonce
        sign_base = _build_signing_base(method, url, ts, nonce, body)
        expected = _compute_signature(secret, sign_base)
        if not hmac.compare_digest(expected, received):
            return {"valid": False, "reason": "bad_signature"}

        # 签名通过后才记录 nonce，防重放
        cache = nonce_cache if nonce_cache is not None else RequestHook._default_nonce_cache
        if not cache.check_and_store(nonce):
            return {"valid": False, "reason": "nonce_replayed"}

        return {"valid": True, "reason": "ok"}

    @staticmethod
    def verify_signature(
        headers: dict[str, str],
        method: str,
        url: str,
        body: str | None = None,
        secret: str | None = None,
        timestamp_header: str = "X-Timestamp",
        nonce_header: str = "X-Nonce",
        signature_header: str = "X-Signature",
        max_skew_seconds: int = 300,
        nonce_cache: NonceCache | None = None,
    ) -> bool:
        """
        校验收到的请求签名是否合法（便捷布尔包装）。

        等价于 ``verify_signature_with_details(...)["valid"]``。

        校验项：
        1. timestamp / nonce / signature 三个 header 均存在；
        2. 时间戳在容差窗口内（默认 ±300s）；
        3. 签名以 HMAC-SHA256 常数时间比较通过；
        4. nonce 未被重放（签名通过后才记录 nonce）。

        Args:
            headers: 收到的请求头。
            method: HTTP 方法。
            url: 请求 URL。
            body: 请求体。
            secret: 共享密钥；为空时直接返回 False。
            timestamp_header: 时间戳 header 名。
            nonce_header: nonce header 名。
            signature_header: 签名 header 名。
            max_skew_seconds: 时间戳容差（秒）。
            nonce_cache: 自定义 nonce 缓存；缺省用模块默认缓存。

        Returns:
            全部校验通过返回 True，否则 False。
        """
        return bool(
            RequestHook.verify_signature_with_details(
                headers, method, url, body, secret,
                timestamp_header, nonce_header, signature_header,
                max_skew_seconds, nonce_cache,
            )["valid"]
        )

    @staticmethod
    def apply_bearer_token(
        headers: dict[str, str],
        token: str,
        header_name: str = "Authorization",
    ) -> dict[str, str]:
        """注入 Bearer Token。"""
        updated = dict(headers)
        updated[header_name] = f"Bearer {token}"
        return updated

    @staticmethod
    def apply_api_key(
        headers: dict[str, str],
        api_key: str,
        header_name: str = "X-API-Key",
    ) -> dict[str, str]:
        """注入 API Key。"""
        updated = dict(headers)
        updated[header_name] = api_key
        return updated

    @staticmethod
    def apply_content_type(
        headers: dict[str, str],
        content_type: str = "application/json",
    ) -> dict[str, str]:
        """确保 Content-Type 存在。"""
        updated = dict(headers)
        if "content-type" not in {k.lower() for k in updated}:
            updated["Content-Type"] = content_type
        return updated

    @staticmethod
    def compose(
        headers: dict[str, str],
        hooks: list[Callable[[dict[str, str]], dict[str, str]]],
    ) -> dict[str, str]:
        """
        组合多个 Hook 顺序执行。
        每个 Hook 接收当前 headers，返回新 headers。
        """
        current = dict(headers)
        for hook in hooks:
            current = hook(current)
        return current


def build_hook_chain(
    method: str,
    url: str,
    body: str | None = None,
    secret: str | None = None,
    primary_token: str | None = None,
    secondary_token: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """
    构建 primary / secondary 双身份的 Hook 链。
    返回 (primary_headers, secondary_headers)。
    """
    base: dict[str, str] = {}

    def _with_signature(h: dict[str, str]) -> dict[str, str]:
        return RequestHook.apply_standard_auth(h, method, url, body, secret)

    def _with_primary_token(h: dict[str, str]) -> dict[str, str]:
        if primary_token:
            return RequestHook.apply_bearer_token(h, primary_token)
        return h

    def _with_secondary_token(h: dict[str, str]) -> dict[str, str]:
        if secondary_token:
            return RequestHook.apply_bearer_token(h, secondary_token)
        return h

    primary_headers = RequestHook.compose(base, [_with_primary_token, _with_signature])
    secondary_headers = RequestHook.compose(base, [_with_secondary_token, _with_signature])

    return primary_headers, secondary_headers
