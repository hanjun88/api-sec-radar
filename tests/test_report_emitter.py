"""tests/test_report_emitter.py"""
from __future__ import annotations
import os
import json
import tempfile
import shutil
from src.auditor.report_emitter import emit_audit_report

class TestEmitAuditReport:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp(prefix="audit_test_")
    def teardown_method(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    def test_emit_creates_both_markdown_and_json(self):
        scan_results = [
            {"endpoint": "GET /api/v1/users/1001", "verdict": "VULNERABLE", "confidence": 0.95, "similarity": 0.98, "primary_status": 200, "secondary_status": 200, "evidence": {"technical_root_cause": "BOLA"}},
            {"endpoint": "GET /api/v1/health", "verdict": "SAFE"},
        ]
        result = emit_audit_report(scan_results=scan_results, output_dir=self.temp_dir)
        assert result["status"] == "DELIVERED"
        assert os.path.exists(result["markdown_path"])
        assert os.path.exists(result["json_path"])
