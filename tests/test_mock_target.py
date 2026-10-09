"""tests/test_mock_target.py — Mock 靶机组 (F)"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def _get(base_url: str, path: str, token: str | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(base_url + path)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class TestMockTargetServer:
    def test_unauthorized_without_token(self, mock_target_server: str):
        status, body = _get(mock_target_server, "/api/v1/accounts/1001")
        assert status == 401

    def test_bola_returns_any_account(self, mock_target_server: str):
        _, body_alice = _get(mock_target_server, "/api/v1/accounts/1001", "token-alice")
        _, body_bob = _get(mock_target_server, "/api/v1/accounts/1002", "token-alice")
        assert body_alice["owner"] == "alice"
        assert body_bob["owner"] == "bob"

    def test_secure_endpoint_rejects_non_owner(self, mock_target_server: str):
        status, _ = _get(mock_target_server, "/api/v1/secure/sec-1001", "token-bob")
        assert status in (403, 404)

    def test_secure_endpoint_allows_owner(self, mock_target_server: str):
        status, body = _get(mock_target_server, "/api/v1/secure/sec-1001", "token-alice")
        assert status == 200
        assert body["owner"] == "alice"

    def test_health_endpoint(self, mock_target_server: str):
        status, body = _get(mock_target_server, "/api/v1/health", "token-alice")
        assert status == 200

    def test_not_found(self, mock_target_server: str):
        status, _ = _get(mock_target_server, "/api/v1/nonexistent", "token-alice")
        assert status == 404

    def test_rate_limited_after_threshold(self, mock_target_server: str):
        for _ in range(2):
            _get(mock_target_server, "/api/v1/rate-limited", "token-ratelimit")
        status, _ = _get(mock_target_server, "/api/v1/rate-limited", "token-ratelimit")
        assert status == 429
