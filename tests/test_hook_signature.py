"""tests/test_hook_signature.py — 签名 Hook 组 (A)"""
from __future__ import annotations
import time
import uuid
import pytest
from src.auditor.hook import RequestHook, build_hook_chain, _build_signing_base, _compute_signature, NonceCache


class TestSignatureRoundTrip:
    def test_build_hook_chain_then_verify_passes(self):
        secret = "test-secret-key-123"
        method = "GET"
        url = "http://example.com/api/v1/users/1001"
        body = '{"test": "data"}'
        primary_headers, secondary_headers = build_hook_chain(
            method=method, url=url, body=body, secret=secret,
            primary_token="token-alice", secondary_token="token-bob",
        )
        result = RequestHook.verify_signature_with_details(
            headers=primary_headers, method=method, url=url, body=body, secret=secret,
        )
        assert result["valid"] is True
        result = RequestHook.verify_signature_with_details(
            headers=secondary_headers, method=method, url=url, body=body, secret=secret,
        )
        assert result["valid"] is True

    def test_verify_signature_rejects_tampered_body(self):
        secret = "test-secret-key-123"
        method = "POST"
        url = "http://example.com/api/v1/orders"
        body = '{"amount": 100}'
        primary_headers, _ = build_hook_chain(
            method=method, url=url, body=body, secret=secret,
            primary_token="token-alice", secondary_token="token-bob",
        )
        tampered_body = '{"amount": 999}'
        result = RequestHook.verify_signature_with_details(
            headers=primary_headers, method=method, url=url, body=tampered_body, secret=secret,
        )
        assert result["valid"] is False
        assert result["reason"] == "bad_signature"


class TestNonceInSigningBase:
    """变异防护：签名基串必须包含 nonce，否则不同 nonce 产生相同签名"""

    def test_nonce_in_base_produces_different_signatures(self):
        secret = "s"
        base1 = _build_signing_base("GET", "http://x/api", "1000", "nonce-aaa", None)
        base2 = _build_signing_base("GET", "http://x/api", "1000", "nonce-bbb", None)
        assert base1 != base2
        sig1 = _compute_signature(secret, base1)
        sig2 = _compute_signature(secret, base2)
        assert sig1 != sig2

    def test_nonce_appears_in_base_string(self):
        base = _build_signing_base("GET", "http://x/api", "1000", "my-nonce-123", None)
        assert "my-nonce-123" in base


class TestTimestampVerify:
    def test_current_timestamp_valid(self):
        from src.auditor.hook import verify_timestamp
        ts = str(int(time.time()))
        assert verify_timestamp(ts) is True

    def test_stale_timestamp_rejected(self):
        from src.auditor.hook import verify_timestamp
        ts = str(int(time.time()) - 9999)
        assert verify_timestamp(ts) is False

    def test_garbage_timestamp_rejected(self):
        from src.auditor.hook import verify_timestamp
        assert verify_timestamp("not-a-number") is False


class TestNonceCache:
    def test_first_use_returns_true(self):
        cache = NonceCache(ttl_seconds=60)
        assert cache.check_and_store("n1") is True

    def test_replay_returns_false(self):
        cache = NonceCache(ttl_seconds=60)
        cache.check_and_store("n2")
        assert cache.check_and_store("n2") is False

    def test_empty_nonce_rejected(self):
        cache = NonceCache()
        assert cache.check_and_store("") is False

    def test_invalid_ttl_raises(self):
        with pytest.raises(ValueError):
            NonceCache(ttl_seconds=0)


class TestVerifySignatureEdgeCases:
    def test_missing_secret_rejected(self):
        r = RequestHook.verify_signature_with_details(
            headers={"X-Timestamp": "1", "X-Nonce": "n", "X-Signature": "s"},
            method="GET", url="http://x", body=None, secret="",
        )
        assert r["valid"] is False
        assert r["reason"] == "missing_secret"

    def test_missing_headers_rejected(self):
        r = RequestHook.verify_signature_with_details(
            headers={}, method="GET", url="http://x", body=None, secret="k",
        )
        assert r["valid"] is False
        assert r["reason"] == "missing_headers"

    def test_bad_signature_rejected(self):
        r = RequestHook.verify_signature_with_details(
            headers={"X-Timestamp": str(int(time.time())), "X-Nonce": "n", "X-Signature": "bad"},
            method="GET", url="http://x", body=None, secret="k",
        )
        assert r["valid"] is False
        assert r["reason"] == "bad_signature"

    def test_nonce_replay_rejected(self):
        cache = NonceCache()
        secret = "k"
        ts = str(int(time.time()))
        nonce = "replay-nonce"
        base = _build_signing_base("GET", "http://x", ts, nonce, None)
        sig = _compute_signature(secret, base)
        headers = {"X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig}
        r1 = RequestHook.verify_signature_with_details(headers=headers, method="GET", url="http://x", body=None, secret=secret, nonce_cache=cache)
        assert r1["valid"] is True
        r2 = RequestHook.verify_signature_with_details(headers=headers, method="GET", url="http://x", body=None, secret=secret, nonce_cache=cache)
        assert r2["valid"] is False
        assert r2["reason"] == "nonce_replayed"


class TestPathNormalization:
    def test_encoded_path_normalizes(self):
        from src.auditor.hook import _normalize_path
        assert _normalize_path("/api%2fusers") == "/api/users"

    def test_empty_path_defaults_to_root(self):
        from src.auditor.hook import _normalize_path
        assert _normalize_path("") == "/"


class TestBodyHash:
    def test_empty_body_hash_is_empty(self):
        from src.auditor.hook import _body_hash
        assert _body_hash(None) == ""
        assert _body_hash("") == ""

    def test_body_hash_is_deterministic(self):
        from src.auditor.hook import _body_hash
        assert _body_hash("abc") == _body_hash("abc")