"""tests/test_safety_adversarial.py — 对抗检测组 (C)"""
from __future__ import annotations

from src.auditor.adversarial_guard import BypassDetector


class TestBypassDetector:
    def test_detects_xss_script_tag(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?q=<script>alert(1)</script>",
            method="GET",
        )
        assert any(f["type"] == "xss_script_tag" for f in findings)

    def test_detects_javascript_protocol(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?next=javascript:alert(1)",
            method="GET",
        )
        assert any(f["type"] == "xss_javascript_protocol" for f in findings)

    def test_detects_event_handler(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?name=<img src=x onerror=alert(1)>",
            method="GET",
        )
        assert any(f["type"] == "xss_event_handler" for f in findings)

    def test_detects_sql_injection_union(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?id=1 union select password from users",
            method="GET",
        )
        assert any(f["type"] == "sqli_union_select" for f in findings)

    def test_detects_sql_injection_tautology(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?id=1 or 1=1",
            method="GET",
        )
        assert any(f["type"] == "sqli_tautology" for f in findings)

    def test_detects_path_traversal(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?file=../../../etc/passwd",
            method="GET",
        )
        assert any(f["type"] == "path_traversal" for f in findings)

    def test_detects_path_traversal_encoded(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?file=%2e%2e%2fetc%2fpasswd",
            method="GET",
        )
        assert any(f["type"] == "path_traversal_encoded" for f in findings)

    def test_detects_code_injection_exec(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?cmd=exec('rm -rf /')",
            method="GET",
        )
        assert any(f["type"] == "code_injection_exec" for f in findings)

    def test_detects_code_injection_eval(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?cmd=eval('1+1')",
            method="GET",
        )
        assert any(f["type"] == "code_injection_eval" for f in findings)

    def test_clean_url_no_findings(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api/v1/health",
            method="GET",
        )
        assert findings == []

    def test_method_override_header_detected(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api",
            method="GET",
            headers={"X-Http-Method-Override": "DELETE"},
        )
        assert any(f["type"] == "method_override_header" for f in findings)

    def test_method_override_query_detected(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api",
            method="GET",
            query_params={"_method": "DELETE"},
        )
        assert any(f["type"] == "method_override_query" for f in findings)

    def test_scan_string_includes_location(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?q=<script>alert(1)</script>",
            method="GET",
        )
        assert all("location" in f for f in findings)
