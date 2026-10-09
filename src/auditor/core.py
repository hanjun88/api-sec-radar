"""
api_access_auditor/core.py — API 访问控制差分审计引擎

符合 SystemSkill<TInput, TOutput> 契约：
  - validate_inputs: 入参硬约束
  - execute: 确定性差分测试，输出证据链
  - cleanup: 连接释放

核心机制：
  对同一端点发送两个不同身份的请求（primary / secondary），
  对比状态码、响应体长度、结构化相似度，判定是否存在越权（IDOR / BOLA）。
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

from .adversarial_guard import validate_request_security
from .safety import validate_method_safety

logger = logging.getLogger(__name__)


# ── 模块级共享 httpx 连接池（线程安全单例）──────────────────
_shared_client: httpx.Client | None = None
_client_lock = threading.Lock()

_BODY_SIM_MAX_BYTES = 100 * 1024  # 100KB，超过则截断后再算相似度
_FLATTEN_MAX_DEPTH = 10  # 防止恶意深层 JSON 递归导致栈溢出

# 连接池可配置参数（运行时可通过 configure_shared_client 调整）
_pool_config: dict[str, float] = {
    "max_connections": 100,
    "max_keepalive_connections": 50,
    "keepalive_expiry": 30.0,
    "timeout": 10.0,       # 总超时
    "connect_timeout": 5.0,  # 连接超时
}

# 连接池监控计数器（线程安全）
_stats_lock = threading.Lock()
_total_requests: int = 0
_inflight_requests: int = 0


def _record_request_start() -> None:
    """记录一次请求开始（用于连接池监控）。"""
    global _total_requests, _inflight_requests
    with _stats_lock:
        _total_requests += 1
        _inflight_requests += 1


def _record_request_end() -> None:
    """记录一次请求结束（用于连接池监控）。"""
    global _inflight_requests
    with _stats_lock:
        if _inflight_requests > 0:
            _inflight_requests -= 1


def configure_shared_client(
    max_connections: int | None = None,
    max_keepalive: int | None = None,
    timeout: float | None = None,
) -> None:
    """运行时调优共享连接池参数。

    下一次获取/重建共享 Client 时生效（当前已存在的 Client 会被关闭重建）。

    Args:
        max_connections: 最大总连接数，默认 100。
        max_keepalive: 最大空闲 keep-alive 连接数，默认 50。
        timeout: 单次请求总超时（秒），默认 10.0；连接超时固定为其一半且不超过 5s。
    """
    if max_connections is not None:
        _pool_config["max_connections"] = int(max_connections)
    if max_keepalive is not None:
        _pool_config["max_keepalive_connections"] = int(max_keepalive)
    if timeout is not None:
        _pool_config["timeout"] = float(timeout)
        _pool_config["connect_timeout"] = min(5.0, float(timeout))
    # 参数变化后强制重建连接池，使新配置立即生效
    close_shared_client()


def get_pool_stats() -> dict[str, Any]:
    """返回共享连接池监控指标。

    Returns:
        包含活跃连接数、空闲连接数、总请求数、在途请求数及池配置的字典。
        若底层 httpcore 内部结构变化导致自省失败，对应字段退化为 0，
        但总请求数与在途请求数始终由本模块计数器保证准确。
    """
    active: int = 0
    idle: int = 0
    pool: Any = None
    with _stats_lock:
        total = _total_requests
        inflight = _inflight_requests

    client = _shared_client
    if client is not None and not client.is_closed:
        try:
            pool = client._transport._pool  # type: ignore[attr-defined]
            for conn in getattr(pool, "_connections", []) or []:
                try:
                    if conn.is_idle():
                        idle += 1
                    else:
                        active += 1
                except Exception:
                    idle += 1
        except Exception:
            pool = None

    return {
        "total_requests": total,
        "inflight_requests": inflight,
        "active_connections": active,
        "idle_connections": idle,
        "max_connections": int(_pool_config["max_connections"]),
        "max_keepalive_connections": int(_pool_config["max_keepalive_connections"]),
        "keepalive_expiry": float(_pool_config["keepalive_expiry"]),
        "timeout": float(_pool_config["timeout"]),
    }


def execute_with_timeout(func: Callable[..., Any], timeout_seconds: float) -> Any:
    """使用 threading.Timer 实现的硬超时守卫。

    在独立线程中运行 func，超过 timeout_seconds 未返回则抛出 TimeoutError。
    注意：底层工作线程无法被真正强杀，仅用于避免调用方无限阻塞；
    工作线程作为守护线程继续运行直至自然结束。

    Args:
        func: 要执行的可调用对象。
        timeout_seconds: 硬超时秒数。

    Returns:
        func 的返回值。

    Raises:
        TimeoutError: 超过 timeout_seconds 仍未完成。
        Exception: func 执行过程中抛出的原始异常。
    """
    result_box: dict[str, Any] = {}

    def _runner() -> None:
        try:
            result_box["value"] = func()
        except BaseException as exc:
            result_box["error"] = exc

    worker = threading.Thread(target=_runner, daemon=True)
    worker.start()
    worker.join(timeout=timeout_seconds)

    if worker.is_alive():
        raise TimeoutError(
            f"execute_with_timeout: 操作超过 {timeout_seconds}s 仍未完成"
        )
    if "error" in result_box:
        raise result_box["error"]
    return result_box.get("value")


def _get_shared_client() -> httpx.Client:
    """获取模块级共享 httpx.Client（带连接池复用）。线程安全。"""
    global _shared_client
    with _client_lock:
        if _shared_client is None or _shared_client.is_closed:
            timeout = httpx.Timeout(
                _pool_config["timeout"],
                connect=_pool_config["connect_timeout"],
            )
            _shared_client = httpx.Client(
                http2=False,
                follow_redirects=False,
                timeout=timeout,
                limits=httpx.Limits(
                    max_connections=int(_pool_config["max_connections"]),
                    max_keepalive_connections=int(
                        _pool_config["max_keepalive_connections"]
                    ),
                    keepalive_expiry=float(_pool_config["keepalive_expiry"]),
                ),
            )
        return _shared_client


def close_shared_client() -> None:
    """真正关闭共享连接池（供测试/进程退出调用）。"""
    global _shared_client
    with _client_lock:
        if _shared_client is not None and not _shared_client.is_closed:
            _shared_client.close()
        _shared_client = None


# ── 输入 / 输出模型 ──────────────────────────────────────────


class RequestIdentity(BaseModel):
    """单次请求的身份凭证与载荷。"""
    label: str = Field(description="身份标签，如 'victim' / 'attacker' / 'user_a'")
    method: str = Field(default="GET", description="HTTP 方法")
    url: str = Field(description="目标端点 URL")
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = Field(default=None, description="请求体（JSON 字符串或原始文本）")
    timeout: float = Field(default=10.0, ge=0.5, le=60.0)

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, v: str) -> str:
        return v.upper()

    @field_validator("url")
    @classmethod
    def valid_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("INVALID_URL: 必须包含 scheme 和 host")
        return v


class DifferentialTestInput(BaseModel):
    """差分测试入参。"""
    primary: RequestIdentity = Field(description="第一身份请求（通常为资源属主）")
    secondary: RequestIdentity = Field(description="第二身份请求（通常为越权尝试者）")
    similarity_threshold: float = Field(
        default=0.85, ge=0.0, le=1.0,
        description="响应体相似度阈值，超过则判定为越权",
    )
    follow_redirects: bool = Field(default=False)
    allow_write: bool = Field(
        default=False,
        description="P0-INVARIANT-03: 非幂等写操作默认熔断，必须显式设为 True",
    )


class ResponseFingerprint(BaseModel):
    """单次响应的结构化指纹（证据链）。"""
    label: str
    status_code: int
    content_length: int
    content_hash: str = Field(description="响应体 SHA-256 前 16 位")
    content_type: str
    elapsed_ms: float
    body_preview: str = Field(default="", description="响应体前 200 字符截断")


class DifferentialTestOutput(BaseModel):
    """差分测试输出（确定性证据链）。"""
    verdict: str = Field(description="VULNERABLE / SAFE / INCONCLUSIVE / ERROR")
    confidence: float = Field(ge=0.0, le=1.0)
    similarity: float = Field(ge=0.0, le=1.0, description="响应体结构化相似度")
    primary: ResponseFingerprint
    secondary: ResponseFingerprint
    evidence: dict[str, Any] = Field(description="判定依据的结构化证据")


# ── 相似度计算 ───────────────────────────────────────────────


def _body_similarity(a: str, b: str) -> float:
    """基于 token 集合 Jaccard + 长度比的结构化相似度。

    性能优化：
      1. 对超过 100KB 的响应体只取前 100KB 计算。
      2. 快速路径：两响应体长度差异 > 50%（较短者不足较长者一半）时，
         直接返回长度比作为相似度，跳过昂贵的 JSON 解析与分词。
      3. JSON key 集合缓存：对内容相同的响应体（按 SHA-1 摘要去重）
         复用其扁平 key 集合，避免对同 URL 重复响应反复 flatten。
      4. 使用 ``str.split()`` 做空白分词，避免引入更复杂的分词器。
    """
    if len(a) > _BODY_SIM_MAX_BYTES:
        a = a[:_BODY_SIM_MAX_BYTES]
    if len(b) > _BODY_SIM_MAX_BYTES:
        b = b[:_BODY_SIM_MAX_BYTES]

    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    # 长度比（较短 / 较长）
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))

    # 快速路径：长度差异 > 50% 直接返回长度比，跳过 token 计算
    if len_ratio < 0.5:
        return round(len_ratio, 4)

    ta = _token_set(a)
    tb = _token_set(b)
    if not ta and not tb:
        return 1.0
    intersection = len(ta & tb)
    union = len(ta | tb)
    jaccard = intersection / union if union > 0 else 0.0

    return round(jaccard * 0.7 + len_ratio * 0.3, 4)


# JSON key 集合缓存：body 摘要 -> 扁平 key/token 集合
# 限制最大条目数，防止长时间运行内存无限增长
_TOKEN_SET_CACHE_MAX = 4096
_token_set_cache: OrderedDict[str, set[str]] = OrderedDict()
_token_set_lock = threading.Lock()


def _token_set(s: str) -> set[str]:
    """返回响应体的 token 集合（JSON key 集合或空白分词集合），带缓存。"""
    digest = hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()
    with _token_set_lock:
        cached = _token_set_cache.get(digest)
        if cached is not None:
            _token_set_cache.move_to_end(digest)
            return set(cached)

    # 尝试 JSON 解析后取 key 集合；失败则按空白分词（str.split 快速路径）
    try:
        obj = json.loads(s)
        result: set[str] = set(_flatten_keys(obj))
    except (json.JSONDecodeError, TypeError):
        result = set(s.lower().split())

    with _token_set_lock:
        _token_set_cache[digest] = result
        if len(_token_set_cache) > _TOKEN_SET_CACHE_MAX:
            _token_set_cache.popitem(last=False)
    return set(result)


# 动态字段黑名单：这些字段值随请求变化，不应纳入相似度计算
_DYNAMIC_FIELDS = {
    "timestamp", "ts", "nonce", "csrf_token", "request_id", "trace_id",
    "created_at", "updated_at", "expires", "expires_at", "server_time",
    "access_token", "refresh_token", "session_id", "jti",
}


def _flatten_keys(
    obj: Any, prefix: str = "", depth: int = 0
) -> list[str]:
    """
    递归展平 JSON 对象的 key 路径。

    修复：
    - 动态字段（timestamp/trace_id 等）不纳入计算，避免抬高噪声
    - 列表全量展开（上限 20 项），不再只看 [0]，防止空列表软越权漏报
    - 递归深度上限 ``_FLATTEN_MAX_DEPTH``（默认 10 层），
      防止恶意深层 JSON 导致栈溢出
    """
    if depth > _FLATTEN_MAX_DEPTH:
        return []
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _DYNAMIC_FIELDS:
                continue
            path = f"{prefix}.{k}" if prefix else k
            keys.append(path)
            keys.extend(_flatten_keys(v, path, depth + 1))
    elif isinstance(obj, list) and obj:
        # 全量展开（上限 20 防大列表），不只 [0]
        for i, item in enumerate(obj[:20]):
            keys.extend(_flatten_keys(item, f"{prefix}[{i}]", depth + 1))
    return keys


# ── 审计引擎（SystemSkill 契约）──────────────────────────────


class ApiAccessAuditor:
    """
    API 访问控制差分审计引擎。
    id: skill:audit:api-access-differential
    domain: api-security
    """

    id = "skill:audit:api-access-differential"
    domain = "api-security"
    version = "1.0.0"

    def __init__(self) -> None:
        self._client: httpx.Client | None = None

    def validate_inputs(self, params: DifferentialTestInput) -> None:
        """入参硬约束，违规立即 raise ValueError。"""
        if params.primary.url != params.secondary.url:
            raise ValueError(
                "ENDPOINT_MISMATCH: 差分测试要求 primary 与 secondary 指向同一 URL"
            )
        if params.primary.method != params.secondary.method:
            raise ValueError(
                "METHOD_MISMATCH: 差分测试要求相同 HTTP 方法"
            )

    def execute(self, params: DifferentialTestInput) -> DifferentialTestOutput:
        """执行确定性差分测试，输出证据链。"""
        self.validate_inputs(params)

        # 统一请求安全门禁（P0-INVARIANT-03 前置守卫）：
        # URL 合法性 / Header 合法性（CRLF 注入）/ 方法覆盖解析 /
        # 写熔断 / 对抗绕过检测。primary 与 secondary 两个身份均须通过，
        # 否则任一身份携带的覆盖头或注入载荷都会在核心路径上绕过基础门禁。
        for identity in (params.primary, params.secondary):
            gate_ok, gate_reason, _gate_findings = validate_request_security(
                url=identity.url,
                method=identity.method,
                headers=identity.headers,
                body=identity.body,
                allow_write=params.allow_write,
            )
            if not gate_ok:
                return DifferentialTestOutput(
                    verdict="BLOCKED",
                    confidence=1.0,
                    similarity=0.0,
                    primary=ResponseFingerprint(
                        label=params.primary.label, status_code=0,
                        content_length=0, content_hash="", content_type="",
                        elapsed_ms=0, body_preview="",
                    ),
                    secondary=ResponseFingerprint(
                        label=params.secondary.label, status_code=0,
                        content_length=0, content_hash="", content_type="",
                        elapsed_ms=0, body_preview="",
                    ),
                    evidence={
                        "blocked_by": "REQUEST_SECURITY_GATE",
                        "blocked_identity": identity.label,
                        "method": identity.method.upper(),
                        "allow_write": params.allow_write,
                        "reason": gate_reason,
                    },
                )

        # P0-INVARIANT-03: 写操作物理熔断（在任何网络连接之前）
        # 传入 body 和 content_type 以检测 GET+body 写绕过
        is_allowed, block_reason = validate_method_safety(
            params.primary.method,
            params.allow_write,
            body=params.primary.body,
            content_type=params.primary.headers.get("content-type", ""),
        )
        if not is_allowed:
            return DifferentialTestOutput(
                verdict="BLOCKED",
                confidence=1.0,
                similarity=0.0,
                primary=ResponseFingerprint(
                    label=params.primary.label, status_code=0,
                    content_length=0, content_hash="", content_type="",
                    elapsed_ms=0, body_preview="",
                ),
                secondary=ResponseFingerprint(
                    label=params.secondary.label, status_code=0,
                    content_length=0, content_hash="", content_type="",
                    elapsed_ms=0, body_preview="",
                ),
                evidence={
                    "blocked_by": "P0-INVARIANT-03",
                    "method": params.primary.method.upper(),
                    "allow_write": params.allow_write,
                    "reason": block_reason,
                },
            )

        self._ensure_client()
        assert self._client is not None

        try:
            primary_resp = self._send(params.primary, params.follow_redirects)
            secondary_resp = self._send(params.secondary, params.follow_redirects)
        except httpx.HTTPError as e:
            return DifferentialTestOutput(
                verdict="ERROR",
                confidence=1.0,
                similarity=0.0,
                primary=ResponseFingerprint(
                    label=params.primary.label, status_code=0,
                    content_length=0, content_hash="", content_type="",
                    elapsed_ms=0, body_preview=str(e),
                ),
                secondary=ResponseFingerprint(
                    label=params.secondary.label, status_code=0,
                    content_length=0, content_hash="", content_type="",
                    elapsed_ms=0, body_preview="",
                ),
                evidence={"error": str(e), "type": type(e).__name__},
            )

        sim = _body_similarity(primary_resp.text, secondary_resp.text)

        # 判定逻辑（传入响应体长度用于软越权检测）
        verdict, confidence = self._verdict(
            primary_resp.status_code,
            secondary_resp.status_code,
            sim,
            params.similarity_threshold,
            primary_len=len(primary_resp.content),
            secondary_len=len(secondary_resp.content),
        )

        return DifferentialTestOutput(
            verdict=verdict,
            confidence=confidence,
            similarity=sim,
            primary=self._fingerprint(params.primary.label, primary_resp),
            secondary=self._fingerprint(params.secondary.label, secondary_resp),
            evidence={
                "status_match": primary_resp.status_code == secondary_resp.status_code,
                "primary_status": primary_resp.status_code,
                "secondary_status": secondary_resp.status_code,
                "similarity": sim,
                "threshold": params.similarity_threshold,
                "content_length_delta": abs(
                    len(primary_resp.content) - len(secondary_resp.content)
                ),
            },
        )

    def cleanup(self) -> None:
        """释放实例对客户端的引用（共享连接池不关闭，避免影响其他实例）。"""
        self._client = None

    # ── 内部 ──────────────────────────────────────────────────

    def _ensure_client(self) -> None:
        """复用模块级共享 httpx 连接池。"""
        self._client = _get_shared_client()

    def _send(
        self, identity: RequestIdentity, follow_redirects: bool
    ) -> httpx.Response:
        # per-request timeout 覆盖：identity.timeout 显式传给单次请求，
        # 若未指定则使用共享 Client 的全局默认超时（None）。
        # 当 identity.timeout 超过 30s 时，再套一层 threading 硬超时兜底，
        # 防止 httpx 因网络层挂起而长时间卡死工作线程。
        _record_request_start()
        try:
            request_kwargs = dict(
                method=identity.method,
                url=identity.url,
                headers=identity.headers,
                content=identity.body,
                follow_redirects=follow_redirects,
                timeout=identity.timeout,
            )
            if identity.timeout > 30.0:
                return execute_with_timeout(
                    lambda: self._client.request(**request_kwargs),
                    timeout_seconds=identity.timeout,
                )
            return self._client.request(**request_kwargs)  # type: ignore[union-attr]
        finally:
            _record_request_end()

    @staticmethod
    def _fingerprint(label: str, resp: httpx.Response) -> ResponseFingerprint:
        body = resp.text
        content_hash = hashlib.sha256(resp.content).hexdigest()[:16]
        return ResponseFingerprint(
            label=label,
            status_code=resp.status_code,
            content_length=len(resp.content),
            content_hash=content_hash,
            content_type=resp.headers.get("content-type", ""),
            elapsed_ms=round(resp.elapsed.total_seconds() * 1000, 2),
            body_preview=body[:200],
        )

    @staticmethod
    def _verdict(
        primary_status: int,
        secondary_status: int,
        similarity: float,
        threshold: float,
        primary_len: int = 0,
        secondary_len: int = 0,
    ) -> tuple[str, float]:
        """
        差分判定逻辑（修复软越权漏报）。

        新增分类：
        - SUSPECT: 双方 2xx 但响应体塌缩（<30%），软越权嫌疑
        - PRIV_ESCALATION: primary 4xx + secondary 2xx，权限提升
        - LIKELY_SAFE: primary 2xx + secondary 3xx，可能被重定向拒绝
        """
        # 双方都 2xx
        if 200 <= primary_status < 300 and 200 <= secondary_status < 300:
            if similarity >= threshold:
                return "VULNERABLE", round(min(similarity, 0.99), 4)
            # 新增：同 2xx 但响应体塌缩（secondary < primary 的 30%）→ 软越权嫌疑
            if primary_len > 0 and secondary_len < primary_len * 0.3:
                return "SUSPECT", 0.55
            # 相似度在阈值 70% 以上 → 可能越权（降置信度）
            if similarity >= threshold * 0.7:
                return "VULNERABLE", round(similarity * 0.8, 4)
            return "INCONCLUSIVE", 0.4

        # primary 2xx + secondary 4xx → 安全（正确拒绝）
        if 200 <= primary_status < 300 and 400 <= secondary_status < 500:
            return "SAFE", 0.95

        # 新增：primary 4xx + secondary 2xx → 权限提升（属主被拒但攻击者通过）
        if primary_status >= 400 and 200 <= secondary_status < 300:
            return "PRIV_ESCALATION", 0.75

        # 新增：primary 2xx + secondary 3xx → 可能被重定向到登录页（大概率安全）
        if 200 <= primary_status < 300 and 300 <= secondary_status < 400:
            return "LIKELY_SAFE", 0.7

        # 双方都 4xx/5xx → 无法判定
        if primary_status >= 400 and secondary_status >= 400:
            return "INCONCLUSIVE", 0.5

        return "INCONCLUSIVE", 0.4
