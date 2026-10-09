"""tests/test_poc_builder.py — PoC 构建与赏金估算组"""
from __future__ import annotations

import re

from src.auditor.poc_builder import (
    BOUNTY_TABLE,
    build_poc_report,
    build_poc_reports,
    classify_severity,
    estimate_bounty,
    severity_distribution,
)

_VULN_AUDITABLE = {
    "endpoint": "GET /api/v1/accounts/1001",
    "method": "GET",
    "url": "http://t/api/v1/accounts/1001",
    "verdict": "VULNERABLE",
    "confidence": 0.98,
    "similarity": 0.99,
    "is_auditable": True,
    "primary_status": 200,
    "secondary_status": 200,
    "evidence": {"status_match": True, "content_length_delta": 0},
}

_VULN_FUNCTIONAL = {
    "endpoint": "GET /api/v1/admin/users",
    "method": "GET",
    "url": "http://t/api/v1/admin/users",
    "verdict": "VULNERABLE",
    "confidence": 0.9,
    "similarity": 1.0,
    "is_auditable": False,
    "primary_status": 200,
    "secondary_status": 200,
}

_PRIV_ESC = {
    "endpoint": "GET /api/v1/secret",
    "method": "GET",
    "url": "http://t/api/v1/secret",
    "verdict": "PRIV_ESCALATION",
    "confidence": 0.75,
    "similarity": 0.5,
    "is_auditable": True,
    "primary_status": 403,
    "secondary_status": 200,
}

_SUSPECT = {
    "endpoint": "GET /api/v1/reports/1",
    "method": "GET",
    "url": "http://t/api/v1/reports/1",
    "verdict": "SUSPECT",
    "confidence": 0.55,
    "similarity": 0.3,
    "is_auditable": True,
    "primary_status": 200,
    "secondary_status": 200,
}

_SAFE = {
    "endpoint": "GET /api/v1/health",
    "method": "GET",
    "url": "http://t/api/v1/health",
    "verdict": "SAFE",
    "confidence": 0.95,
    "similarity": 0.1,
    "is_auditable": False,
    "primary_status": 200,
    "secondary_status": 403,
}


class TestSeverity:
    def test_auditable_high_similarity_is_critical(self):
        assert classify_severity(_VULN_AUDITABLE) == "critical"

    def test_functional_vuln_is_high(self):
        assert classify_severity(_VULN_FUNCTIONAL) == "high"

    def test_priv_escalation_is_high(self):
        assert classify_severity(_PRIV_ESC) == "high"

    def test_suspect_is_medium(self):
        assert classify_severity(_SUSPECT) == "medium"

    def test_low_similarity_auditable_is_high_not_critical(self):
        item = dict(_VULN_AUDITABLE, similarity=0.9)
        assert classify_severity(item) == "high"


class TestBuildPocReport:
    def test_required_contract_fields(self):
        report = build_poc_report(_VULN_AUDITABLE)
        for key in ("poc_id", "endpoint", "method", "url", "vulnerability_type",
                    "severity", "confidence", "similarity", "primary_status",
                    "secondary_status", "primary_request", "secondary_request",
                    "evidence", "root_cause", "remediation_hint"):
            assert key in report, f"missing key: {key}"

    def test_poc_id_format(self):
        report = build_poc_report(_VULN_AUDITABLE)
        assert re.fullmatch(r"POC-[0-9A-F]{12}", report["poc_id"])

    def test_bola_type_for_auditable(self):
        assert build_poc_report(_VULN_AUDITABLE)["vulnerability_type"] == "BOLA/IDOR"

    def test_bfla_type_for_functional(self):
        assert build_poc_report(_VULN_FUNCTIONAL)["vulnerability_type"] == "BFLA"

    def test_priv_escalation_type(self):
        assert build_poc_report(_PRIV_ESC)["vulnerability_type"] == "PRIV_ESCALATION"

    def test_headers_redacted(self):
        report = build_poc_report(_VULN_AUDITABLE)
        for side in ("primary_request", "secondary_request"):
            assert report[side]["headers"] == {"Authorization": "***REDACTED***"}

    def test_evidence_status_match(self):
        report = build_poc_report(_VULN_AUDITABLE)
        assert report["evidence"]["status_match"] is True
        assert report["evidence"]["primary_status"] == 200
        assert report["evidence"]["secondary_status"] == 200
        assert report["evidence"]["content_length_delta"] == 0

    def test_confidence_and_similarity_in_range(self):
        report = build_poc_report(_VULN_AUDITABLE)
        assert 0.0 <= report["confidence"] <= 1.0
        assert 0.0 <= report["similarity"] <= 1.0

    def test_root_cause_from_evidence(self):
        report = build_poc_report(dict(_VULN_AUDITABLE, technical_root_cause="missing owner check"))
        assert report["root_cause"] == "missing owner check"

    def test_remediation_hint_mentions_ownership(self):
        report = build_poc_report(_VULN_AUDITABLE)
        assert "404" in report["remediation_hint"] or "owner" in report["remediation_hint"]

    def test_non_poc_verdicts_return_empty(self):
        for item in (_SAFE, {"verdict": "BLOCKED"}, {"verdict": "ERROR"},
                     {"verdict": "INCONCLUSIVE"}):
            assert build_poc_report(item) == {}


class TestBatchAndBounty:
    def test_build_poc_reports_filters_and_sorts(self):
        reports = build_poc_reports([_SAFE, _VULN_FUNCTIONAL, _VULN_AUDITABLE])
        assert len(reports) == 2
        assert reports[0]["confidence"] >= reports[1]["confidence"]

    def test_empty_input(self):
        assert build_poc_reports([]) == []
        assert build_poc_reports(None) == []

    def test_non_dict_items_skipped(self):
        assert build_poc_reports(["junk", 42, _VULN_AUDITABLE]) != []

    def test_severity_distribution_keys(self):
        reports = build_poc_reports([_VULN_AUDITABLE, _VULN_FUNCTIONAL])
        dist = severity_distribution(reports)
        assert dist == {"critical": 1, "high": 1, "medium": 0, "low": 0, "informational": 0}

    def test_bounty_breakdown_sums_to_total(self):
        reports = build_poc_reports([_VULN_AUDITABLE, _VULN_FUNCTIONAL, _PRIV_ESC, _SUSPECT])
        total, breakdown = estimate_bounty(reports)
        assert round(sum(breakdown.values()), 2) == total
        assert total == BOUNTY_TABLE["critical"] + 2 * BOUNTY_TABLE["high"] + BOUNTY_TABLE["medium"]

    def test_bounty_empty(self):
        assert estimate_bounty([]) == (0.0, {})
