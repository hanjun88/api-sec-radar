"""tests/test_safety_gate.py"""
from __future__ import annotations
import pytest
from src.auditor.safety import validate_method_safety, validate_request_security, SAFE_HTTP_METHODS

class TestValidateMethodSafety:
    def test_safe_methods_allowed_by_default(self):
        for method in SAFE_HTTP_METHODS:
            allowed, reason = validate_method_safety(method, allow_write=False)
            assert allowed is True
            assert reason is None

    def test_unsafe_methods_blocked_by_default(self):
        unsafe_methods = ["POST", "PUT", "PATCH", "DELETE"]
        for method in unsafe_methods:
            allowed, reason = validate_method_safety(method, allow_write=False)
            assert allowed is False
            assert "P0-INVARIANT-03_VIOLATION" in reason

    def test_unsafe_methods_allowed_when_explicit(self):
        for method in ["POST", "PUT", "PATCH", "DELETE"]:
            allowed, reason = validate_method_safety(method, allow_write=True)
            assert allowed is True
            assert reason is None
