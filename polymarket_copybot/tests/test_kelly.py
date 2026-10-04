"""必测 1/3：Kelly 边界（p=0/1、b 极端值、除零保护、半 Kelly 与单笔封顶）。"""

import math

import pytest

from copybot.kelly import kelly_fraction, odds, size_position


class TestOdds:
    def test_even_money(self):
        assert odds(0.5) == pytest.approx(1.0)

    def test_longshot_has_large_b(self):
        assert odds(0.01) == pytest.approx(99.0)

    @pytest.mark.parametrize("price", [0.0, 1.0, -0.1, 1.5, math.nan, math.inf])
    def test_invalid_price_gives_zero_b(self, price):
        assert odds(price) == 0.0


class TestKellyFraction:
    def test_textbook_value(self):
        # p=0.6, price=0.5 → b=1 → f* = (0.6·1 − 0.4)/1 = 0.2
        assert kelly_fraction(0.6, 0.5) == pytest.approx(0.2)

    def test_p_zero_never_bets(self):
        assert kelly_fraction(0.0, 0.5) == 0.0

    def test_p_one_bets_everything(self):
        assert kelly_fraction(1.0, 0.5) == pytest.approx(1.0)

    def test_p_one_with_tiny_edge_price(self):
        assert kelly_fraction(1.0, 0.999) == pytest.approx(1.0)

    def test_no_edge_returns_zero(self):
        assert kelly_fraction(0.5, 0.5) == 0.0

    def test_negative_edge_clipped_to_zero(self):
        assert kelly_fraction(0.4, 0.6) == 0.0

    def test_price_at_or_above_one_is_skipped_not_divided(self):
        # b = 0 → 除零保护，直接跳过
        assert kelly_fraction(0.99, 1.0) == 0.0
        assert kelly_fraction(0.99, 1.2) == 0.0

    def test_price_zero_or_negative_is_skipped(self):
        assert kelly_fraction(0.9, 0.0) == 0.0
        assert kelly_fraction(0.9, -0.5) == 0.0

    def test_extreme_b_huge(self):
        # price=0.001 → b=999；f* ≈ p − q/b，必须落在 [0,1] 且有限
        f = kelly_fraction(0.01, 0.001)
        assert 0.0 <= f <= 1.0 and math.isfinite(f)
        assert f == pytest.approx(0.01 - 0.99 / 999)

    def test_extreme_b_tiny(self):
        # price=0.999 → b≈0.001；p=0.99 时 f* 为负 → 0
        assert kelly_fraction(0.99, 0.999) == 0.0

    @pytest.mark.parametrize("p", [-0.01, 1.01, math.nan, math.inf])
    def test_invalid_p_raises(self, p):
        with pytest.raises(ValueError):
            kelly_fraction(p, 0.5)

    def test_monotonic_in_p(self):
        fs = [kelly_fraction(p / 100, 0.4) for p in range(0, 101, 5)]
        assert fs == sorted(fs)


class TestSizePosition:
    def test_half_kelly(self):
        r = size_position(100.0, 0.6, 0.5, multiplier=0.5, max_position_pct=50)
        assert r.full_kelly == pytest.approx(0.2)
        assert r.fraction == pytest.approx(0.1)
        assert r.usd == pytest.approx(10.0)
        assert not r.capped

    def test_capped_by_single_trade_limit(self):
        # 半 Kelly = 0.5，但单笔上限 5%
        r = size_position(20.0, 1.0, 0.5, multiplier=0.5, max_position_pct=5.0)
        assert r.fraction == pytest.approx(0.05)
        assert r.usd == pytest.approx(1.0)
        assert r.capped

    def test_no_edge_zero_size(self):
        r = size_position(20.0, 0.5, 0.6)
        assert r.usd == 0.0 and r.fraction == 0.0

    def test_zero_or_negative_equity(self):
        assert size_position(0.0, 0.9, 0.5).usd == 0.0
        assert size_position(-5.0, 0.9, 0.5).usd == 0.0

    def test_price_one_skips(self):
        assert size_position(20.0, 0.9, 1.0).usd == 0.0
