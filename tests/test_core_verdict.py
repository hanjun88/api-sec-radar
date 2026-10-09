"""tests/test_core_verdict.py — 差分判定逻辑组"""
from __future__ import annotations

import pytest

from src.auditor.core import ApiAccessAuditor


class TestVerdict:
    """_verdict 边界回归（回合2：PRIV_ESCALATION 仅认 401/403）。"""

    @pytest.mark.parametrize("primary,secondary,expected", [
        (401, 200, "PRIV_ESCALATION"),
        (403, 200, "PRIV_ESCALATION"),
        (500, 200, "INCONCLUSIVE"),
        (404, 200, "INCONCLUSIVE"),
        (301, 200, "INCONCLUSIVE"),
        (200, 403, "SAFE"),
        (200, 404, "SAFE"),
        (200, 302, "LIKELY_SAFE"),
        (403, 403, "INCONCLUSIVE"),
        (500, 500, "INCONCLUSIVE"),
    ])
    def test_status_combinations(self, primary, secondary, expected):
        verdict, _confidence = ApiAccessAuditor._verdict(
            primary, secondary, 0.95, 0.85
        )
        assert verdict == expected

    def test_high_similarity_vulnerable(self):
        verdict, confidence = ApiAccessAuditor._verdict(
            200, 200, 0.98, 0.85
        )
        assert verdict == "VULNERABLE"
        assert confidence == 0.98

    def test_similarity_capped_at_099(self):
        verdict, confidence = ApiAccessAuditor._verdict(
            200, 200, 1.0, 0.85
        )
        assert verdict == "VULNERABLE"
        assert confidence == 0.99

    def test_body_collapse_suspect(self):
        verdict, confidence = ApiAccessAuditor._verdict(
            200, 200, 0.5, 0.85, primary_len=1000, secondary_len=100
        )
        assert verdict == "SUSPECT"
        assert confidence == 0.55

    def test_marginal_similarity_vulnerable_low_confidence(self):
        verdict, confidence = ApiAccessAuditor._verdict(
            200, 200, 0.7, 0.85
        )
        assert verdict == "VULNERABLE"
        assert confidence == 0.56

    def test_low_similarity_inconclusive(self):
        verdict, _ = ApiAccessAuditor._verdict(200, 200, 0.3, 0.85)
        assert verdict == "INCONCLUSIVE"
