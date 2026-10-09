"""tests/test_safety_gate.py — 写熔断门禁组 (B)"""
from __future__ import annotations

from src.auditor.adversarial_guard import validate_request_security
from src.auditor.core import (
    ApiAccessAuditor,
    DifferentialTestInput,
    RequestIdentity,
)
from src.auditor.safety import SAFE_HTTP_METHODS, validate_method_safety


class TestCoreExecuteSecurityGate:
    """核心 execute() 路径的统一安全门禁回归（审查更正：核心路径
    此前只走基础 validate_method_safety，方法覆盖 / CRLF / URL 校验
    在核心路径上不可达）。"""

    def _input(self, method="GET", url="http://127.0.0.1/api/v1/health",
               headers=None, body=None):
        return DifferentialTestInput(
            primary=RequestIdentity(
                label="primary", method=method, url=url,
                headers=headers or {}, body=body,
            ),
            secondary=RequestIdentity(
                label="secondary", method=method, url=url,
                headers={}, body=body,
            ),
        )

    def test_method_override_header_blocked_in_core(self):
        params = self._input(
            headers={"X-Http-Method-Override": "DELETE"},
        )
        result = ApiAccessAuditor().execute(params)
        assert result.verdict == "BLOCKED"
        assert result.evidence["blocked_by"] == "REQUEST_SECURITY_GATE"
        assert "P0-INVARIANT-03" in result.evidence["reason"]

    def test_method_override_query_blocked_in_core(self):
        params = self._input(
            url="http://127.0.0.1/api/v1/health?_method=DELETE",
        )
        result = ApiAccessAuditor().execute(params)
        assert result.verdict == "BLOCKED"
        assert result.evidence["blocked_by"] == "REQUEST_SECURITY_GATE"

    def test_crlf_header_blocked_in_core(self):
        params = self._input(
            headers={"X-Custom": "value\r\nInjected: true"},
        )
        result = ApiAccessAuditor().execute(params)
        assert result.verdict == "BLOCKED"
        assert "HEADER_CRLF_INJECTION" in result.evidence["reason"]

    def test_secondary_identity_override_blocked_in_core(self):
        params = DifferentialTestInput(
            primary=RequestIdentity(
                label="primary", method="GET",
                url="http://127.0.0.1/api/v1/health",
            ),
            secondary=RequestIdentity(
                label="secondary", method="GET",
                url="http://127.0.0.1/api/v1/health",
                headers={"X-Http-Method-Override": "PUT"},
            ),
        )
        result = ApiAccessAuditor().execute(params)
        assert result.verdict == "BLOCKED"
        assert result.evidence["blocked_identity"] == "secondary"

    def test_write_method_blocked_in_core(self):
        params = self._input(method="PUT")
        result = ApiAccessAuditor().execute(params)
        assert result.verdict == "BLOCKED"
        assert result.evidence["blocked_by"] == "REQUEST_SECURITY_GATE"

    def test_clean_get_passes_core_gate(self):
        params = self._input()
        result = ApiAccessAuditor().execute(params)
        assert result.verdict in ("VULNERABLE", "SAFE", "INCONCLUSIVE", "ERROR")


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

    def test_safe_method_with_json_body_blocked(self):
        allowed, reason = validate_method_safety(
            "GET", allow_write=False, body='{"x":1}', content_type="application/json"
        )
        assert allowed is False
        assert "SAFE_METHOD_WITH_BODY" in reason

    def test_safe_method_with_empty_body_allowed(self):
        allowed, reason = validate_method_safety("GET", allow_write=False, body="", content_type="")
        assert allowed is True

    def test_case_insensitive_method(self):
        allowed, _ = validate_method_safety("post", allow_write=False)
        assert allowed is False
        allowed, _ = validate_method_safety("get", allow_write=False)
        assert allowed is True


class TestValidateRequestSecurity:
    def test_url_rejected_when_empty(self):
        ok, reason, _ = validate_request_security("", "GET")
        assert ok is False
        assert "URL" in reason

    def test_url_rejected_without_scheme(self):
        ok, reason, _ = validate_request_security("example.com/api", "GET")
        assert ok is False

    def test_url_rejected_with_control_chars(self):
        ok, reason, _ = validate_request_security("http://x/api\x00", "GET")
        assert ok is False

    def test_url_rejected_too_long(self):
        ok, reason, _ = validate_request_security("http://x/" + "a" * 3000, "GET")
        assert ok is False

    def test_write_method_blocked_by_default(self):
        ok, reason, _ = validate_request_security("http://x/api", "POST")
        assert ok is False
        assert "P0-INVARIANT-03" in reason

    def test_write_method_allowed_when_explicit(self):
        ok, reason, _ = validate_request_security("http://x/api", "POST", allow_write=True)
        assert ok is True

    def test_method_override_header_detected(self):
        ok, reason, _ = validate_request_security(
            "http://x/api", "GET",
            headers={"X-Http-Method-Override": "DELETE"},
        )
        assert ok is False
        assert "P0-INVARIANT-03" in reason

    def test_method_override_inline_query_detected(self):
        ok, reason, _ = validate_request_security(
            "http://x/api?_method=DELETE", "GET",
        )
        assert ok is False
        assert "P0-INVARIANT-03" in reason

    def test_method_override_inline_query_lowercase(self):
        ok, reason, _ = validate_request_security(
            "http://x/api?_method=delete", "GET",
        )
        assert ok is False

    def test_normal_query_string_allowed(self):
        ok, reason, _ = validate_request_security(
            "http://x/api/v1/health?attempt=1", "GET",
        )
        assert ok is True

    def test_explicit_query_overrides_inline(self):
        ok, reason, _ = validate_request_security(
            "http://x/api?_method=DELETE", "GET",
            query_params={"_method": "GET"},
        )
        assert ok is True

    def test_adversarial_payload_blocked(self):
        ok, reason, _ = validate_request_security(
            "http://x/api", "GET",
            query_params={"q": "<script>alert(1)</script>"},
        )
        assert ok is False
        assert "ADVERSARIAL_BLOCK" in reason

    def test_clean_request_passes(self):
        ok, reason, _ = validate_request_security(
            "http://x/api/v1/health", "GET",
            headers={"Authorization": "***"},
        )
        assert ok is True

    def test_too_many_headers_rejected(self):
        headers = {f"X-H-{i}": "v" for i in range(200)}
        ok, reason, _ = validate_request_security("http://x/api", "GET", headers=headers)
        assert ok is False
