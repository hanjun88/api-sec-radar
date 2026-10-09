"""tests/test_pipeline_contract.py — 流水线契约组 (D)"""
from __future__ import annotations

import json


class TestPipelineResultContract:
    def test_required_top_level_keys(self, sample_pipeline_result):
        for key in ("pipeline_id", "program_id", "program_name", "started_at",
                     "finished_at", "elapsed_ms", "ingestion", "scan", "poc",
                     "target_matrix", "scan_result", "poc_reports",
                     "estimated_bounty", "bounty_breakdown", "status", "errors"):
            assert key in sample_pipeline_result, f"missing key: {key}"

    def test_status_is_completed(self, sample_pipeline_result):
        assert sample_pipeline_result["status"] == "completed"

    def test_ingestion_structure(self, sample_pipeline_result):
        ing = sample_pipeline_result["ingestion"]
        for key in ("total_ingested", "in_scope", "out_of_scope_filtered",
                     "auditable_count", "safe_method_count", "sources"):
            assert key in ing

    def test_scan_structure(self, sample_pipeline_result):
        scan = sample_pipeline_result["scan"]
        for key in ("scan_id", "status", "total_targets", "scanned",
                     "vulnerable", "safe", "blocked", "inconclusive", "error", "elapsed_ms"):
            assert key in scan

    def test_poc_structure(self, sample_pipeline_result):
        poc = sample_pipeline_result["poc"]
        assert "total_vulnerabilities" in poc
        assert "by_severity" in poc

    def test_bounty_breakdown_sums_to_estimated(self, sample_pipeline_result):
        bd = sample_pipeline_result["bounty_breakdown"]
        total = sum(bd.values())
        assert total == sample_pipeline_result["estimated_bounty"]


class TestPoCReportContract:
    def test_required_fields(self, sample_poc_report):
        for key in ("poc_id", "endpoint", "method", "url", "vulnerability_type",
                     "severity", "confidence", "similarity", "primary_status",
                     "secondary_status", "primary_request", "secondary_request",
                     "evidence", "root_cause", "remediation_hint"):
            assert key in sample_poc_report

    def test_confidence_in_range(self, sample_poc_report):
        assert 0.0 <= sample_poc_report["confidence"] <= 1.0

    def test_similarity_in_range(self, sample_poc_report):
        assert 0.0 <= sample_poc_report["similarity"] <= 1.0

    def test_evidence_has_status_match(self, sample_poc_report):
        assert "status_match" in sample_poc_report["evidence"]


class TestOpenApiSpecContract:
    def test_spec_has_openapi_version(self, mock_openapi_spec):
        spec = json.loads(mock_openapi_spec)
        assert spec["openapi"] == "3.0.0"

    def test_spec_has_paths(self, mock_openapi_spec):
        spec = json.loads(mock_openapi_spec)
        assert len(spec["paths"]) >= 5

    def test_spec_has_servers(self, mock_openapi_spec):
        spec = json.loads(mock_openapi_spec)
        assert "servers" in spec
        assert len(spec["servers"]) >= 1


class TestHarContentContract:
    def test_har_has_entries(self, mock_har_content):
        har = json.loads(mock_har_content)
        assert "log" in har
        assert len(har["log"]["entries"]) >= 5

    def test_har_entries_have_request(self, mock_har_content):
        har = json.loads(mock_har_content)
        for entry in har["log"]["entries"]:
            assert "request" in entry
            assert "method" in entry["request"]
            assert "url" in entry["request"]
