"""tests/test_token_handling.py — token scheme 处理组"""
from __future__ import annotations

from src.auditor.pipeline_orchestrator import _identity_headers, _raw_token


class TestIdentityHeaders:
    def test_bearer_token(self):
        assert _identity_headers("Bearer abc") == {"Authorization": "Bearer abc"}

    def test_basic_token_preserved(self):
        """Basic 凭证原样透传，不被 Bearer 前缀破坏。"""
        assert _identity_headers("Basic dXNlcjpwYXNz") == {
            "Authorization": "Basic dXNlcjpwYXNz"
        }

    def test_token_scheme_preserved(self):
        assert _identity_headers("Token xyz") == {"Authorization": "Token xyz"}

    def test_raw_token_gets_bearer_prefix(self):
        assert _identity_headers("raw-token") == {"Authorization": "Bearer raw-token"}

    def test_empty_token_none(self):
        assert _identity_headers("") is None
        assert _identity_headers("   ") is None


class TestRawToken:
    def test_bearer_stripped(self):
        assert _raw_token("Bearer abc") == "abc"

    def test_token_scheme_stripped(self):
        assert _raw_token("Token xyz") == "xyz"

    def test_basic_returns_empty(self):
        """Basic 凭证不参与 bearer hook（headers 已透传）。"""
        assert _raw_token("Basic dXNlcjpwYXNz") == ""

    def test_raw_token_unchanged(self):
        assert _raw_token("raw-token") == "raw-token"

    def test_empty_token(self):
        assert _raw_token("") == ""
