"""
test_hook.py: 动态签名 Hook 与重放防护测试

覆盖 RequestHook 的签名生成/校验、时间戳容差、Nonce 重放缓存，
以及文档声明的关键安全性质：**签名校验失败时不消耗 nonce**
（否则攻击者可用错误签名占满/污染 nonce 缓存）。
"""

from __future__ import annotations

import time
import uuid

import pytest

from src.auditor.hook import (
    NonceCache,
    RequestHook,
    _build_signing_base,
    _compute_signature,
    verify_timestamp,
)

SECRET = "s3cr3t-signing-key"
URL = "http://127.0.0.1:8080/api/v1/accounts/1001?fields=balance"


def _sign(
    method: str = "GET",
    url: str = URL,
    body: str | None = None,
    ts: str | None = None,
    nonce: str | None = None,
) -> tuple[dict[str, str], str, str]:
    """构造一组合法签名头，返回 (headers, ts, nonce) 便于后续篡改。"""
    ts = ts or str(int(time.time()))
    nonce = nonce or uuid.uuid4().hex[:16]
    signature = _compute_signature(SECRET, _build_signing_base(method, url, ts, nonce, body))
    return {"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": signature}, ts, nonce


# --------------------------------------------------------------------------
# 时间戳容差
# --------------------------------------------------------------------------


def test_timestamp_within_window() -> None:
    assert verify_timestamp(str(int(time.time()))) is True


def test_timestamp_stale_rejected() -> None:
    assert verify_timestamp(str(int(time.time()) - 3600)) is False


def test_timestamp_in_future_beyond_window_rejected() -> None:
    assert verify_timestamp(str(int(time.time()) + 3600)) is False


@pytest.mark.parametrize("bad", ["", "not-a-number", "12.5", None])
def test_timestamp_unparseable_rejected(bad: object) -> None:
    assert verify_timestamp(str(bad)) is False


# --------------------------------------------------------------------------
# Nonce 缓存
# --------------------------------------------------------------------------


def test_nonce_first_use_accepted_then_replayed() -> None:
    cache = NonceCache(ttl_seconds=60)
    assert cache.check_and_store("n1") is True
    assert cache.check_and_store("n1") is False


def test_nonce_empty_rejected() -> None:
    assert NonceCache().check_and_store("") is False


def test_nonce_ttl_must_be_positive() -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        NonceCache(ttl_seconds=0)


def test_nonce_is_replay_query_does_not_consume() -> None:
    """is_replay 只查询不记录。"""
    cache = NonceCache(ttl_seconds=60)
    cache.check_and_store("n1")
    assert cache.is_replay("n1") is True
    assert cache.is_replay("n2") is False
    assert cache.check_and_store("n2") is True


def test_nonce_clear_resets() -> None:
    cache = NonceCache(ttl_seconds=60)
    cache.check_and_store("n1")
    cache.clear()
    assert cache.check_and_store("n1") is True


# --------------------------------------------------------------------------
# 签名校验
# --------------------------------------------------------------------------


def test_valid_signature_accepted() -> None:
    headers, _, _ = _sign()
    result = RequestHook.verify_signature_with_details(headers, "GET", URL, secret=SECRET)
    assert result == {"valid": True, "reason": "ok"}


def test_missing_secret_rejected() -> None:
    headers, _, _ = _sign()
    result = RequestHook.verify_signature_with_details(headers, "GET", URL, secret=None)
    assert result["reason"] == "missing_secret"


def test_missing_headers_rejected() -> None:
    result = RequestHook.verify_signature_with_details({}, "GET", URL, secret=SECRET)
    assert result["reason"] == "missing_headers"


def test_stale_timestamp_rejected() -> None:
    headers, _, _ = _sign(ts=str(int(time.time()) - 3600))
    result = RequestHook.verify_signature_with_details(headers, "GET", URL, secret=SECRET)
    assert result["reason"] == "stale_timestamp"


def test_tampered_signature_rejected() -> None:
    headers, _, _ = _sign()
    headers["X-Signature"] = "0" * 64
    result = RequestHook.verify_signature_with_details(headers, "GET", URL, secret=SECRET)
    assert result["reason"] == "bad_signature"


def test_body_tampering_detected() -> None:
    """签名绑定 body：body 被改后校验失败。"""
    headers, _, _ = _sign(method="POST", body='{"balance":1}')
    result = RequestHook.verify_signature_with_details(
        headers, "POST", URL, body='{"balance":99999}', secret=SECRET
    )
    assert result["reason"] == "bad_signature"


def test_url_tampering_detected() -> None:
    headers, _, _ = _sign()
    result = RequestHook.verify_signature_with_details(
        headers, "GET", "http://127.0.0.1:8080/api/v1/admin/users", secret=SECRET
    )
    assert result["reason"] == "bad_signature"


def test_replay_rejected() -> None:
    """同一 nonce 二次出现被拒绝（签名正确也算重放）。"""
    cache = NonceCache(ttl_seconds=60)
    headers, _, _ = _sign()
    first = RequestHook.verify_signature_with_details(
        headers, "GET", URL, secret=SECRET, nonce_cache=cache
    )
    second = RequestHook.verify_signature_with_details(
        headers, "GET", URL, secret=SECRET, nonce_cache=cache
    )
    assert first["valid"] is True
    assert second["reason"] == "nonce_replayed"


def test_failed_signature_does_not_consume_nonce() -> None:
    """
    关键安全性质：签名失败不占用 nonce，否则错误签名会污染缓存，
    导致合法请求后续被误判为重放（DoS 面）。
    """
    cache = NonceCache(ttl_seconds=60)
    headers, _, _ = _sign()
    tampered = dict(headers, **{"X-Signature": "f" * 64})

    bad = RequestHook.verify_signature_with_details(
        tampered, "GET", URL, secret=SECRET, nonce_cache=cache
    )
    assert bad["reason"] == "bad_signature"
    assert cache.is_replay(headers["X-Nonce"]) is False

    good = RequestHook.verify_signature_with_details(
        headers, "GET", URL, secret=SECRET, nonce_cache=cache
    )
    assert good["valid"] is True


def test_header_names_case_insensitive() -> None:
    """HTTP header 名大小写不敏感。"""
    headers, _, _ = _sign()
    lowered = {k.lower(): v for k, v in headers.items()}
    assert RequestHook.verify_signature(lowered, "GET", URL, secret=SECRET) is True


def test_apply_standard_auth_produces_verifiable_headers() -> None:
    """apply_standard_auth 生成的头可被自身校验链路接受。"""
    cache = NonceCache(ttl_seconds=60)
    headers = RequestHook.apply_standard_auth({}, "GET", URL, secret=SECRET)
    assert headers["X-Timestamp"] and headers["X-Nonce"] and headers["X-Signature"]
    assert RequestHook.verify_signature(
        headers, "GET", URL, secret=SECRET, nonce_cache=cache
    ) is True


def test_apply_standard_auth_without_secret_skips_signature() -> None:
    headers = RequestHook.apply_standard_auth({}, "GET", URL)
    assert "X-Signature" not in headers


# --------------------------------------------------------------------------
# 头部注入辅助方法
# --------------------------------------------------------------------------


def test_apply_bearer_token() -> None:
    headers = RequestHook.apply_bearer_token({}, "abc123")
    assert headers["Authorization"] == "Bearer abc123"


def test_apply_api_key() -> None:
    assert RequestHook.apply_api_key({}, "mykey")["X-API-Key"] == "mykey"
    assert RequestHook.apply_api_key({}, "mykey", "X-Token")["X-Token"] == "mykey"


def test_apply_content_type() -> None:
    assert RequestHook.apply_content_type({}, "application/json") == {
        "Content-Type": "application/json"
    }


def test_apply_content_type_preserves_existing() -> None:
    """已存在 Content-Type（任意大小写）时不覆盖调用方设定。"""
    existing = RequestHook.apply_content_type({"content-type": "text/plain"})
    assert list(existing.values()) == ["text/plain"]


def test_compose_applies_hooks_in_order() -> None:
    """compose 顺序执行，后者可覆盖前者。"""
    composed = RequestHook.compose(
        {},
        [
            lambda h: RequestHook.apply_bearer_token(h, "t"),
            lambda h: RequestHook.apply_content_type(h, "application/json"),
        ],
    )
    assert composed["Authorization"] == "Bearer t"
    assert composed["Content-Type"] == "application/json"


def test_helpers_do_not_mutate_input() -> None:
    """所有 Hook 方法为纯函数，返回新 dict。"""
    original: dict[str, str] = {}
    RequestHook.apply_bearer_token(original, "abc123")
    RequestHook.apply_content_type(original)
    assert original == {}
