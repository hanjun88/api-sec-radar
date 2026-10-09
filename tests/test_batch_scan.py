"""tests/test_batch_scan.py — 批量扫描引擎组"""
from __future__ import annotations

from src.auditor.batch_scan import (
    RICH_EVIDENCE_VERDICTS,
    batch_concurrency,
    compress_batch_results,
)


def _result(verdict: str, similarity: float = 0.9) -> dict:
    return {
        "endpoint": f"GET /api/v1/{verdict}",
        "method": "GET",
        "verdict": verdict,
        "confidence": 0.9,
        "similarity": similarity,
        "primary_status": 200,
        "secondary_status": 200,
        "evidence": {
            "primary_status": 200,
            "secondary_status": 200,
            "similarity": similarity,
            "root_cause": "missing ownership check",
        },
    }


class TestCompressBatchResults:
    def test_small_batch_untouched(self):
        results = [_result("VULNERABLE"), _result("SAFE")]
        assert compress_batch_results(results) is results

    def test_vulnerable_evidence_preserved(self):
        results = [_result("VULNERABLE") for _ in range(101)]
        compressed = compress_batch_results(results)
        assert all("_compressed" not in r["evidence"] for r in compressed)
        assert all(r["evidence"].get("root_cause") for r in compressed)

    def test_rich_evidence_verdicts_preserved(self):
        """PRIV_ESCALATION / SUSPECT 保留完整证据（PoC 依赖）。"""
        for verdict in ("PRIV_ESCALATION", "SUSPECT"):
            results = [_result(verdict) for _ in range(101)]
            compressed = compress_batch_results(results)
            assert all("_compressed" not in r["evidence"] for r in compressed)
            assert all(r["evidence"].get("root_cause") for r in compressed)

    def test_safe_evidence_compressed(self):
        results = [_result("SAFE") for _ in range(101)]
        compressed = compress_batch_results(results)
        assert all(r["evidence"].get("_compressed") for r in compressed)
        assert all("root_cause" not in r["evidence"] for r in compressed)

    def test_mixed_batch_preserves_rich_only(self):
        results = (
            [_result("VULNERABLE")] * 50
            + [_result("PRIV_ESCALATION")] * 30
            + [_result("SUSPECT")] * 20
            + [_result("SAFE")] * 10
        )
        compressed = compress_batch_results(results)
        rich = [r for r in compressed if r["verdict"] in RICH_EVIDENCE_VERDICTS]
        safe = [r for r in compressed if r["verdict"] == "SAFE"]
        assert len(rich) == 100
        assert all(r["evidence"].get("root_cause") for r in rich)
        assert all(r["evidence"].get("_compressed") for r in safe)


class TestBatchConcurrency:
    def test_small_matrix(self):
        assert batch_concurrency(5, 50) == 5

    def test_medium_matrix_capped(self):
        assert batch_concurrency(10, 200) == 5

    def test_large_matrix_capped(self):
        assert batch_concurrency(10, 1000) == 8

    def test_huge_matrix_capped(self):
        assert batch_concurrency(20, 3000) == 10

    def test_minimum_one(self):
        assert batch_concurrency(0, 50) == 1
