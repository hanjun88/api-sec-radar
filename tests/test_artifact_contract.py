"""tests/test_artifact_contract.py — 工件契约组"""
from __future__ import annotations

import time

import pytest

from src.auditor.artifact_contract import (
    build_artifact_from_poc,
    build_artifact_from_scan_result,
    build_artifacts,
    normalize_verdict,
)

_SCAN_ITEM = {
    "endpoint": "GET /api/v1/accounts/1001",
    "method": "GET",
    "url": "http://t/api/v1/accounts/1001",
    "verdict": "VULNERABLE",
    "confidence": 0.97,
    "similarity": 0.98,
    "primary_status": 200,
    "secondary_status": 200,
    "evidence": {"primary_status": 200, "secondary_status": 200},
}

_POC = {
    "poc_id": "POC-ABC",
    "endpoint": "GET /api/v1/accounts/1001",
    "severity": "critical",
    "confidence": 0.98,
    "similarity": 0.99,
    "primary_status": 200,
    "secondary_status": 200,
    "root_cause": "missing ownership check",
}


class TestNormalizeVerdict:
    @pytest.mark.parametrize("raw,expected", [
        ("VULNERABLE", "VULNERABLE"),
        ("BOLA_DETECTED", "VULNERABLE"),
        ("BROKEN_AUTH", "VULNERABLE"),
        ("BLOCKED", "BLOCKED"),
        ("P0-INVARIANT-03", "BLOCKED"),
        ("SAFE", "SAFE"),
        ("SECURE", "SAFE"),
        ("OK", "SAFE"),
        ("INCONCLUSIVE", "INCONCLUSIVE"),
        ("WEIRD", "INCONCLUSIVE"),
    ])
    def test_mapping(self, raw, expected):
        assert normalize_verdict(raw) == expected

    def test_bool_verdict(self):
        item = dict(_SCAN_ITEM, verdict=True)
        artifact = build_artifact_from_scan_result(item)
        assert artifact["verdict"] == "VULNERABLE"


class TestBuildArtifact:
    def test_payload_shape(self):
        artifact = build_artifact_from_scan_result(_SCAN_ITEM)
        assert set(artifact.keys()) == {
            "endpoint", "verdict", "confidence", "evidence", "technical_root_cause"
        }
        evidence = artifact["evidence"]
        for key in ("primary_status", "secondary_status", "response_similarity",
                    "elapsed_ms", "timestamp"):
            assert key in evidence
        assert evidence["primary_status"] == 200
        assert evidence["timestamp"] <= int(time.time() * 1000)

    def test_evidence_fallback_to_top_level(self):
        artifact = build_artifact_from_scan_result(dict(_SCAN_ITEM, evidence=None))
        assert artifact["evidence"]["primary_status"] == 200

    def test_similarity_key_from_producer(self):
        """生产者发 'similarity'，dashboard 读 'response_similarity'。

        修复前 _evidence_block 只读 response_similarity，
        导致相似度恒为 0.0（审查缺陷 B）。
        """
        item = dict(_SCAN_ITEM, evidence={
            "primary_status": 200, "secondary_status": 200,
            "similarity": 0.98,
        })
        artifact = build_artifact_from_scan_result(item)
        assert artifact["evidence"]["response_similarity"] == 0.98

    def test_similarity_legacy_key_still_supported(self):
        item = dict(_SCAN_ITEM, evidence={
            "primary_status": 200, "secondary_status": 200,
            "response_similarity": 0.87,
        })
        artifact = build_artifact_from_scan_result(item)
        assert artifact["evidence"]["response_similarity"] == 0.87

    def test_root_cause_passthrough(self):
        artifact = build_artifact_from_scan_result(
            dict(_SCAN_ITEM, technical_root_cause="BOLA")
        )
        assert artifact["technical_root_cause"] == "BOLA"

    def test_default_root_cause(self):
        artifact = build_artifact_from_scan_result(_SCAN_ITEM)
        assert artifact["technical_root_cause"] == "Differential access scan completed."

    def test_poc_artifact_severity_mapping(self):
        critical = build_artifact_from_poc(_POC)
        assert critical["verdict"] == "VULNERABLE"
        assert critical["technical_root_cause"] == "missing ownership check"
        low = build_artifact_from_poc(dict(_POC, severity="low"))
        assert low["verdict"] == "INCONCLUSIVE"
        info = build_artifact_from_poc(dict(_POC, severity="informational"))
        assert info["verdict"] == "SAFE"


class TestBuildArtifacts:
    def test_poc_priority(self):
        artifacts = build_artifacts(poc_reports=[_POC], scan_results=[_SCAN_ITEM])
        assert len(artifacts) == 1
        assert artifacts[0]["confidence"] == 0.98

    def test_scan_fallback(self):
        artifacts = build_artifacts(poc_reports=[], scan_results=[_SCAN_ITEM, _SCAN_ITEM])
        assert len(artifacts) == 2
        assert artifacts[0]["endpoint"] == _SCAN_ITEM["endpoint"]

    def test_empty(self):
        assert build_artifacts() == []
        assert build_artifacts(poc_reports=[], scan_results=[]) == []

    def test_non_dict_skipped(self):
        artifacts = build_artifacts(poc_reports=["junk", _POC])
        assert len(artifacts) == 1
