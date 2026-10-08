"""tests/test_safety_adversarial.py"""
from __future__ import annotations
import pytest
from src.auditor.adversarial_guard import BypassDetector, validate_request_security

class TestBypassDetector:
    def test_detects_xss_script_tag(self):
        detector = BypassDetector()
        findings = detector.check_request(
            url="http://example.com/api?q=<script>alert(1)</script>",
            method="GET",
        )
        assert any(f["type"] == "xss_script_tag" for f in findings)
