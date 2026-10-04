"""必测 3/3：风控熔断（日亏损、总回撤、API 连续失败、锁存持久化、模式隔离）。"""

from datetime import timedelta

import pytest

from copybot.config import Mode
from copybot.db import Database
from copybot.risk import RiskControl
from tests.conftest import FakeClock, add_closed_trade, make_settings


class Spy:
    def __init__(self):
        self.messages: list[str] = []

    def send(self, text: str) -> None:
        self.messages.append(text)


def make_risk(db, clock, notifier=None, **env):
    return RiskControl(db, make_settings(**env), clock=clock, notifier=notifier)


class TestEquityAndEntryChecks:
    def test_equity_is_bankroll_plus_realized(self, db, clock):
        r = make_risk(db, clock)
        assert r.equity() == pytest.approx(20.0)
        add_closed_trade(db, clock, pnl=-1.5)
        assert r.equity() == pytest.approx(18.5)

    def test_position_cap_is_5pct_of_equity(self, db, clock):
        r = make_risk(db, clock)
        assert r.check_new_entry(1.0).allowed
        v = r.check_new_entry(1.01)
        assert not v.allowed and v.code == "position_cap"

    def test_zero_size_rejected(self, db, clock):
        assert make_risk(db, clock).check_new_entry(0.0).code == "size_zero"

    def test_exposure_cannot_exceed_equity(self, db, clock):
        r = make_risk(db, clock, BANKROLL_USD="20", MAX_POSITION_PCT="100")
        from copybot.models import CopySignal, Side, Trade, TradeStatus
        sig = CopySignal("s", "t", Side.BUY, 0.5, 1, 1, "0x", clock.now, clock.now)
        db.insert_signal(sig)
        db.open_trade(Trade("tr", "s", Mode.DRY_RUN, "m", "t", "BTC_HOURLY", TradeStatus.OPEN,
                            0.5, 36.0, 18.0, clock.now, 12))
        assert r.cash_available() == pytest.approx(2.0)
        assert not r.check_new_entry(3.0).allowed
        assert r.check_new_entry(3.0).code == "exposure_cap"
        assert r.check_new_entry(2.0).allowed


class TestDailyLossLimit:
    def test_below_limit_keeps_trading(self, db, clock):
        r = make_risk(db, clock)
        add_closed_trade(db, clock, pnl=-1.9)  # 1.9 < 10% × 20
        assert not r.halt_status().halted

    def test_hitting_10pct_halts_new_entries(self, db, clock):
        spy = Spy()
        r = make_risk(db, clock, spy)
        add_closed_trade(db, clock, pnl=-2.0)  # = 10% × 20
        status = r.evaluate_after_close()
        assert status.halted and status.code == "daily_loss_limit" and not status.latched
        assert r.check_new_entry(0.5).code == "risk_halted"
        assert len(spy.messages) == 1

    def test_alert_sent_once_per_day(self, db, clock):
        spy = Spy()
        r = make_risk(db, clock, spy)
        add_closed_trade(db, clock, pnl=-2.5, idx=1)
        r.evaluate_after_close()
        r.evaluate_after_close()
        assert len(spy.messages) == 1

    def test_auto_resumes_next_utc_day(self, db, clock):
        r = make_risk(db, clock)
        add_closed_trade(db, clock, pnl=-2.5)
        r.evaluate_after_close()
        assert r.halt_status().halted
        clock.advance(days=1)
        assert not r.halt_status().halted

    def test_yesterdays_loss_does_not_count_today(self, db, clock):
        r = make_risk(db, clock)
        add_closed_trade(db, clock, pnl=-1.5, idx=1, closed_at=clock.now - timedelta(days=1))
        add_closed_trade(db, clock, pnl=-1.0, idx=2)
        assert not r.halt_status().halted  # 今日仅亏 1.0

    def test_gains_offset_losses_within_day(self, db, clock):
        r = make_risk(db, clock)
        add_closed_trade(db, clock, pnl=-2.5, idx=1)
        add_closed_trade(db, clock, pnl=+1.0, idx=2)
        assert not r.halt_status().halted


class TestTotalDrawdownBreaker:
    def _lose_across_days(self, db, clock, amounts):
        for i, a in enumerate(amounts):
            add_closed_trade(db, clock, pnl=a, idx=i, closed_at=clock.now - timedelta(days=len(amounts) - i))

    def test_20pct_drawdown_latches(self, db, clock):
        spy = Spy()
        r = make_risk(db, clock, spy)
        self._lose_across_days(db, clock, [-1.5, -1.5, -1.0])  # 20 → 16，回撤 20%
        status = r.evaluate_after_close()
        assert status.halted and status.latched and status.code == "total_drawdown"
        assert any("total_drawdown" in m for m in spy.messages)

    def test_below_limit_not_latched(self, db, clock):
        r = make_risk(db, clock)
        self._lose_across_days(db, clock, [-1.5, -1.5, -0.9])  # 回撤 19.5%
        assert not r.evaluate_after_close().halted

    def test_drawdown_measured_from_peak_not_start(self, db, clock):
        r = make_risk(db, clock)
        self._lose_across_days(db, clock, [+10.0])
        r.evaluate_after_close()  # 峰值 30
        add_closed_trade(db, clock, pnl=-6.0, idx=9)  # 30 → 24，回撤 20%
        assert r.evaluate_after_close().code == "total_drawdown"

    def test_latch_survives_restart(self, tmp_path, clock):
        path = str(tmp_path / "risk.db")
        db1 = Database(path)
        self._lose_across_days(db1, clock, [-2.0, -2.0])
        make_risk(db1, clock).evaluate_after_close()
        db1.close()

        db2 = Database(path)  # 模拟 Docker 自动重启
        r2 = make_risk(db2, clock)
        assert r2.halt_status().halted and r2.halt_status().latched
        assert r2.check_new_entry(0.5).code == "risk_halted"
        db2.close()

    def test_latch_does_not_clear_next_day(self, db, clock):
        r = make_risk(db, clock)
        self._lose_across_days(db, clock, [-2.0, -2.0])
        r.evaluate_after_close()
        clock.advance(days=3)
        assert r.halt_status().halted

    def test_reset_requires_explicit_call_and_rebases_peak(self, db, clock):
        r = make_risk(db, clock)
        self._lose_across_days(db, clock, [-2.0, -2.0])
        r.evaluate_after_close()
        assert r.reset_halt() is True
        assert not r.halt_status().halted
        assert not r.evaluate_after_close().halted  # 峰值已重置，不会立刻再触发


class TestApiFailureBreaker:
    def test_five_consecutive_failures_latch(self, db, clock):
        spy = Spy()
        r = make_risk(db, clock, spy)
        for _ in range(4):
            r.record_api_result("clob", False)
        assert not r.halt_status().halted
        r.record_api_result("clob", False)
        s = r.halt_status()
        assert s.halted and s.latched and s.code == "api_failures"
        assert "clob" in s.detail
        assert len(spy.messages) == 1

    def test_success_resets_counter(self, db, clock):
        r = make_risk(db, clock)
        for _ in range(4):
            r.record_api_result("clob", False)
        r.record_api_result("clob", True)
        for _ in range(4):
            r.record_api_result("clob", False)
        assert not r.halt_status().halted

    def test_services_counted_independently(self, db, clock):
        r = make_risk(db, clock)
        for _ in range(4):
            r.record_api_result("clob", False)
            r.record_api_result("gamma", False)
        assert not r.halt_status().halted

    def test_limit_is_configurable(self, db, clock):
        r = make_risk(db, clock, API_FAILURE_LIMIT="2")
        r.record_api_result("gamma", False)
        r.record_api_result("gamma", False)
        assert r.halt_status().halted

    def test_first_latch_reason_is_preserved(self, db, clock):
        r = make_risk(db, clock)
        for _ in range(5):
            r.record_api_result("clob", False)
        for _ in range(5):
            r.record_api_result("gamma", False)
        assert "clob" in r.halt_status().detail


class TestModeIsolation:
    def test_dry_run_losses_do_not_affect_live_risk(self, db, clock):
        add_closed_trade(db, clock, pnl=-5.0, mode=Mode.DRY_RUN)
        live_env = dict(MODE="LIVE", PRIVATE_KEY="0x" + "11" * 32, REQUIRE_APPROVAL="false")
        r = make_risk(db, clock, **live_env)
        assert r.equity() == pytest.approx(20.0)
        assert not r.evaluate_after_close().halted
