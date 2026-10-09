"""tests/test_report_emitter.py — 报告落盘组 (E)"""
from __future__ import annotations
import os
import json
import tempfile
import shutil
import re
from src.auditor.report_emitter import emit_audit_report


class TestEmitAuditReport:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp(prefix="audit_test_")

    def teardown_method(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_emit_creates_both_markdown_and_json(self):
        scan_results = [
            {"endpoint": "GET /api/v1/users/1001", "verdict": "VULNERABLE", "confidence": 0.95,
             "similarity": 0.98, "primary_status": 200, "secondary_status": 200,
             "evidence": {"technical_root_cause": "BOLA"}},
            {"endpoint": "GET /api/v1/health", "verdict": "SAFE"},
        ]
        result = emit_audit_report(scan_results=scan_results, output_dir=self.temp_dir)
        assert result["status"] == "DELIVERED"
        assert os.path.exists(result["markdown_path"])
        assert os.path.exists(result["json_path"])

    def test_filename_pattern(self):
        result = emit_audit_report(scan_results=[], output_dir=self.temp_dir)
        md_name = os.path.basename(result["markdown_path"])
        json_name = os.path.basename(result["json_path"])
        assert re.match(r"audit_\d{8}_\d{6}\.md", md_name), f"bad md name: {md_name}"
        assert re.match(r"audit_\d{8}_\d{6}\.json", json_name), f"bad json name: {json_name}"
        assert md_name.replace(".md", "") == json_name.replace(".json", "")

    def test_json_contains_verdict_distribution(self):
        scan_results = [
            {"endpoint": "GET /api/v1/users/1001", "verdict": "VULNERABLE", "confidence": 0.95},
            {"endpoint": "GET /api/v1/health", "verdict": "SAFE"},
        ]
        result = emit_audit_report(scan_results=scan_results, output_dir=self.temp_dir)
        doc = json.load(open(result["json_path"], encoding="utf-8"))
        assert "verdict_distribution" in doc
        assert doc["verdict_distribution"]["VULNERABLE"] == 1
        assert doc["verdict_distribution"]["SAFE"] == 1

    def test_md_contains_verdict_table(self):
        scan_results = [
            {"endpoint": "GET /api/v1/users/1001", "verdict": "VULNERABLE", "confidence": 0.95},
        ]
        result = emit_audit_report(scan_results=scan_results, output_dir=self.temp_dir)
        md = open(result["markdown_path"], encoding="utf-8").read()
        assert "VULNERABLE" in md
        assert "SAFE" in md

    def test_creates_output_dir_if_missing(self):
        nested = os.path.join(self.temp_dir, "nested", "deep")
        result = emit_audit_report(scan_results=[], output_dir=nested)
        assert os.path.isdir(nested)
        assert os.path.isfile(result["markdown_path"])

    def test_empty_results_still_emits(self):
        result = emit_audit_report(scan_results=[], output_dir=self.temp_dir)
        assert result["status"] == "DELIVERED"
        md = open(result["markdown_path"], encoding="utf-8").read()
        assert len(md) > 0