"""tests/test_hook_signature.py"""
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
