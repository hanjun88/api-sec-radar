"""tests/test_batch_scan.py — 批量扫描引擎组"""
from __future__ import annotations

from src.auditor.batch_scan import (
    RICH_EVIDENCE_VERDICTS,
    batch_concurrency,
    compress_batch_results,
    run_batch_scan,
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


class TestOnlyAuditableFilter:
    """only_auditable 预过滤（H3：直接传裸矩阵时的纵深防御）。"""

    @staticmethod
    def _matrix(base_url: str) -> list[dict]:
        return [
            {
                "method": "GET",
                "url": f"{base_url}/api/v1/health",
                "is_auditable": False,
                "is_safe_method": True,
            },
            {
                "method": "GET",
                "url": f"{base_url}/api/v1/accounts/1001",
                "is_auditable": True,
                "is_safe_method": True,
            },
        ]

    def test_filter_skips_non_auditable(self, mock_target_server):
        result = run_batch_scan(
            target_matrix=self._matrix(mock_target_server),
            interval_ms=0,
            only_auditable=True,
        )
        assert result["skipped_non_auditable"] == 1
        assert result["scan_summary"]["total"] == 1
        assert all(r["is_auditable"] for r in result["all_results"])

    def test_default_scans_all(self, mock_target_server):
        result = run_batch_scan(
            target_matrix=self._matrix(mock_target_server),
            interval_ms=0,
        )
        assert result["skipped_non_auditable"] == 0
        assert result["scan_summary"]["total"] == 2

    def test_all_auditable_matrix_unchanged(self, mock_target_server):
        matrix = [e for e in self._matrix(mock_target_server) if e["is_auditable"]]
        result = run_batch_scan(
            target_matrix=matrix, interval_ms=0, only_auditable=True,
        )
        assert result["skipped_non_auditable"] == 0
        assert result["scan_summary"]["total"] == 1
