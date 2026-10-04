"""必测 2/3：贝叶斯更新（公式、拉普拉斯平滑、持久化、不重复计数）。"""

import pytest

from copybot.bayes import BayesianTracker, posterior_mean
from copybot.db import Database
from tests.conftest import add_closed_trade


class TestPosteriorMean:
    def test_no_data_is_one_half_with_laplace(self):
        assert posterior_mean(0, 0, 1, 1) == pytest.approx(0.5)

    def test_formula(self):
        # (wins + α) / (total + α + β)
        assert posterior_mean(7, 10, 1, 1) == pytest.approx(8 / 12)
        assert posterior_mean(7, 10, 2, 3) == pytest.approx(9 / 15)

    def test_never_exactly_zero_or_one(self):
        assert 0.0 < posterior_mean(0, 100, 1, 1) < 0.01
        assert 0.99 < posterior_mean(100, 100, 1, 1) < 1.0

    def test_converges_to_empirical_rate(self):
        assert posterior_mean(6000, 10000) == pytest.approx(0.6, abs=1e-3)

    @pytest.mark.parametrize("wins,total", [(-1, 5), (6, 5), (0, -1)])
    def test_rejects_impossible_counts(self, wins, total):
        with pytest.raises(ValueError):
            posterior_mean(wins, total)

    @pytest.mark.parametrize("a,b", [(0, 1), (1, 0), (-1, 1)])
    def test_rejects_non_positive_prior(self, a, b):
        with pytest.raises(ValueError):
            posterior_mean(1, 2, a, b)
        with pytest.raises(ValueError):
            BayesianTracker(Database(":memory:"), a, b)


class TestTracker:
    def test_updates_from_settled_trades(self, db, clock):
        tr = BayesianTracker(db)
        assert tr.p("BTC_HOURLY") == pytest.approx(0.5)
        add_closed_trade(db, clock, pnl=0.8, idx=1)
        add_closed_trade(db, clock, pnl=0.7, idx=2)
        add_closed_trade(db, clock, pnl=-1.0, idx=3)
        assert tr.counts("BTC_HOURLY") == (2, 3)
        assert tr.p("BTC_HOURLY") == pytest.approx(3 / 5)

    def test_market_types_are_independent(self, db, clock):
        tr = BayesianTracker(db)
        add_closed_trade(db, clock, pnl=1.0, market_type="BTC_HOURLY")
        assert tr.counts("BTC_OTHER") == (0, 0)

    def test_break_even_counts_as_loss(self, db, clock):
        add_closed_trade(db, clock, pnl=0.0)
        assert BayesianTracker(db).counts("BTC_HOURLY") == (0, 1)

    def test_settling_twice_does_not_double_count(self, db, clock):
        tid = add_closed_trade(db, clock, pnl=1.0)
        again = db.settle_trade(tid, exit_price=1.0, pnl_usd=1.0, extra_fee_usd=0, closed_at=clock.now)
        assert again is False
        assert BayesianTracker(db).counts("BTC_HOURLY") == (1, 1)

    def test_persists_across_restart(self, tmp_path, clock):
        path = str(tmp_path / "state.db")
        db1 = Database(path)
        add_closed_trade(db1, clock, pnl=1.0, idx=1)
        add_closed_trade(db1, clock, pnl=-1.0, idx=2)
        db1.close()

        db2 = Database(path)  # 模拟进程重启
        tr = BayesianTracker(db2)
        assert tr.counts("BTC_HOURLY") == (1, 2)
        assert tr.p("BTC_HOURLY") == pytest.approx(2 / 4)
        db2.close()
