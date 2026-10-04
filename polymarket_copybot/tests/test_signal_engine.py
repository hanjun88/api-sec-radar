"""信号引擎：四条规则 + 每次过滤都有原因码。"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest

from copybot.bayes import BayesianTracker
from copybot.btc import CoinbasePriceFeed
from copybot.config import Mode
from copybot.db import Database
from copybot.kelly import kelly_fraction
from copybot.market_data import MarketDataService
from copybot.models import CopySignal, Side, SignalStatus, Trade, TradeStatus
from copybot.risk import RiskControl
from copybot.signal_engine import SignalEngine
from tests.conftest import FakeClock, add_closed_trade, make_settings
from tests.fakes import TOKEN_UP, FakeWorld, candles, gamma_market, raw_book


def build(**env) -> SimpleNamespace:
    s = make_settings(**env)
    clock, db, world = FakeClock(), Database(":memory:"), None
    world = FakeWorld(s)
    http = world.client()
    risk = RiskControl(db, s, clock=clock)
    md = MarketDataService(http, s, report=risk.record_api_result)
    feed = CoinbasePriceFeed(http, s.price_feed_url, risk.record_api_result)
    bayes = BayesianTracker(db, s.bayes_alpha, s.bayes_beta)
    engine = SignalEngine(s, db, md, feed, bayes, risk, clock=clock)
    return SimpleNamespace(s=s, clock=clock, db=db, world=world, risk=risk, md=md, bayes=bayes, engine=engine)


def sig(env, *, side=Side.BUY, price=0.50, token=TOKEN_UP, age=10, sid="sig-1") -> CopySignal:
    return CopySignal(sid, token, side, price, 20.0, price * 20, "0xtx",
                      env.clock.now - timedelta(seconds=age), env.clock.now)


def hold(env, shares=20.0, price=0.5, token=TOKEN_UP):
    env.db.insert_signal(sig(env, sid="entry"))
    env.db.open_trade(Trade("pos-1", "entry", Mode.DRY_RUN, "m", token, "BTC_HOURLY", TradeStatus.OPEN,
                            price, shares, shares * price, env.clock.now, 12))


def seed_history(env, wins: int, losses: int, hour_clock=None):
    for i in range(wins):
        add_closed_trade(env.db, hour_clock or env.clock, pnl=0.001, idx=i, amount=0.01)
    for i in range(losses):
        add_closed_trade(env.db, hour_clock or env.clock, pnl=-0.001, idx=1000 + i, amount=0.01)


# $1000 本金让 1% 兜底仓位（$10）足以满足交易所最小 5 份
BIG = dict(BANKROLL_USD="1000")


class TestFiltersAndReasons:
    def test_non_btc_market_is_filtered(self):
        e = build(**BIG)
        e.world.markets_by_token[TOKEN_UP] = gamma_market(question="Will the Fed cut rates in November?", slug="fed-cut")
        d = e.engine.evaluate(sig(e))
        assert not d.accepted and d.reason_code == "not_btc_market" and d.status is SignalStatus.FILTERED

    def test_disabled_market_type_is_filtered(self):
        e = build(MARKET_TYPES="BTC_SHORT", **BIG)
        assert e.engine.evaluate(sig(e)).reason_code == "market_type_disabled"

    def test_expired_signal(self):
        e = build(**BIG)
        d = e.engine.evaluate(sig(e, age=200))
        assert d.status is SignalStatus.EXPIRED and d.reason_code == "signal_expired"

    def test_already_holding_blocks_add(self):
        e = build(**BIG)
        hold(e)
        assert e.engine.evaluate(sig(e)).reason_code == "already_holding"

    def test_slippage_exceeded(self):
        e = build(**BIG)
        e.world.books[TOKEN_UP] = raw_book(asks=((0.60, 100.0),))
        d = e.engine.evaluate(sig(e, price=0.50))
        assert d.reason_code == "slippage_exceeded"

    def test_empty_ask_side(self):
        e = build(**BIG)
        e.world.books[TOKEN_UP] = raw_book(asks=())
        assert e.engine.evaluate(sig(e)).reason_code == "no_liquidity"

    def test_missing_market_metadata_is_data_unavailable(self):
        e = build(**BIG)
        e.world.markets_by_token.pop(TOKEN_UP)
        assert e.engine.evaluate(sig(e)).reason_code == "data_unavailable"

    def test_missing_orderbook_is_data_unavailable(self):
        e = build(**BIG)
        e.world.books.pop(TOKEN_UP)
        assert e.engine.evaluate(sig(e)).reason_code == "data_unavailable"


class TestRule1TimeWindow:
    def test_cold_start_passes(self):
        e = build(**BIG)
        d = e.engine.evaluate(sig(e))
        assert d.accepted
        assert any(r.name == "time_window" and r.code == "window_cold_start" for r in d.rules)

    def test_low_historical_winrate_in_this_hour_is_dropped(self):
        e = build(**BIG)
        seed_history(e, wins=4, losses=8)  # 33% < 65%，同一 UTC 小时
        d = e.engine.evaluate(sig(e))
        assert d.reason_code == "window_winrate_low"

    def test_other_hours_do_not_matter(self):
        e = build(**BIG)
        other = FakeClock(e.clock.now - timedelta(hours=5))
        seed_history(e, wins=2, losses=10, hour_clock=other)  # 5 小时前的差时段
        assert e.engine.evaluate(sig(e)).accepted

    def test_good_hour_passes(self):
        e = build(**BIG, WINDOW_MIN_SAMPLES="10")
        seed_history(e, wins=9, losses=3)  # 75% ≥ 65%
        e.world.books[TOKEN_UP] = raw_book(asks=((0.45, 100.0),))
        d = e.engine.evaluate(sig(e, price=0.45))
        assert d.accepted
        assert any(r.code == "window_ok" for r in d.rules)


class TestRule2Volatility:
    def test_high_volatility_skips(self):
        e = build(**BIG)
        e.world.candle_rows = candles(wiggle=3000)  # CV ≈ 3% > 2%
        assert e.engine.evaluate(sig(e)).reason_code == "volatility_high"

    def test_threshold_is_configurable(self):
        e = build(VOLATILITY_THRESHOLD_PCT="0.001", **BIG)
        e.world.candle_rows = candles(wiggle=50)  # CV ≈ 0.05%
        assert e.engine.evaluate(sig(e)).reason_code == "volatility_high"

    def test_price_feed_down_fails_closed(self):
        e = build(**BIG)
        e.world.fail["coinbase"] = 500
        assert e.engine.evaluate(sig(e)).reason_code == "volatility_unavailable"

    def test_too_few_candles_fails_closed(self):
        e = build(**BIG)
        e.world.candle_rows = candles(n=3)
        assert e.engine.evaluate(sig(e)).reason_code == "volatility_unavailable"


class TestRule3BayesKelly:
    def test_bootstrap_lets_cold_start_through_with_small_fixed_stake(self):
        e = build(**BIG)
        d = e.engine.evaluate(sig(e))  # p=0.5 < 价格 0.51，本无边际
        assert d.accepted
        assert d.order.reason.startswith("bootstrap")
        assert d.order.size_usd == pytest.approx(10.0, abs=0.6)  # 1% × $1000
        assert d.order.limit_price == pytest.approx(0.51)         # 0.50×1.02 向下取整到 tick

    def test_without_bootstrap_no_edge_is_rejected(self):
        e = build(ENABLE_BOOTSTRAP="false", **BIG)
        d = e.engine.evaluate(sig(e))
        assert d.reason_code == "no_edge"

    def test_bootstrap_ends_after_enough_samples(self):
        e = build(BOOTSTRAP_TRADES="12", WINDOW_MIN_SAMPLES="100", **BIG)
        seed_history(e, wins=6, losses=6)  # p=7/14=0.5，价格 0.51 → 无边际；样本已够 → 不再探索
        assert e.engine.evaluate(sig(e)).reason_code == "no_edge"

    def test_positive_edge_uses_half_kelly(self):
        e = build(MAX_POSITION_PCT="50", WINDOW_MIN_SAMPLES="100", **BIG)
        seed_history(e, wins=30, losses=10)  # p = 31/42
        e.world.books[TOKEN_UP] = raw_book(asks=((0.40, 500.0),))
        d = e.engine.evaluate(sig(e, price=0.40))
        assert d.accepted and d.order.reason.startswith("kelly")
        f = kelly_fraction(31 / 42, 0.40) * 0.5
        equity = e.risk.equity()
        assert d.order.size_usd == pytest.approx(f * equity, rel=0.02)

    def test_position_cap_binds(self):
        e = build(WINDOW_MIN_SAMPLES="100", **BIG)  # 单笔上限 5%
        seed_history(e, wins=38, losses=2)
        e.world.books[TOKEN_UP] = raw_book(asks=((0.40, 5000.0),))
        d = e.engine.evaluate(sig(e, price=0.40))
        assert d.order.size_usd <= e.risk.equity() * 0.05 + 1e-6


class TestMinimumOrderSize:
    def test_default_20_dollar_bankroll_cannot_meet_5_share_minimum(self):
        """$20 × 5% = $1：价格 0.51 时只能买 ~1.9 份，低于交易所 5 份下限。"""
        e = build()  # 默认 $20
        d = e.engine.evaluate(sig(e))
        assert d.reason_code == "below_min_order_size"
        assert "至少需要" in d.reason_detail

    def test_can_be_disabled_for_pure_simulation(self):
        e = build(ENFORCE_MIN_ORDER_SIZE="false")
        assert e.engine.evaluate(sig(e)).accepted

    def test_cheap_outcome_fits_within_cap(self):
        e = build(ENABLE_BOOTSTRAP="true", MAX_POSITION_PCT="25")  # $5 / 0.18 ≈ 27 份
        e.world.books[TOKEN_UP] = raw_book(asks=((0.17, 500.0),))
        assert e.engine.evaluate(sig(e, price=0.17)).accepted


class TestCopyOnlyMode:
    def test_skips_own_rules_and_edge_test(self):
        e = build(CONFIRM_MODE="COPY_ONLY", ENABLE_BOOTSTRAP="false", **BIG)
        e.world.candle_rows = candles(wiggle=3000)  # CONFIRM 下会被波动率拦截
        seed_history(e, wins=2, losses=10)          # CONFIRM 下会被时间窗口拦截
        d = e.engine.evaluate(sig(e))
        assert d.accepted and d.order.reason.startswith("copy_only_fallback")
        assert {r.name for r in d.rules} == {"btc_only", "risk"}

    def test_still_respects_risk_halt(self):
        e = build(CONFIRM_MODE="COPY_ONLY", **BIG)
        for i in range(5):
            e.risk.record_api_result("clob", False)
        assert e.engine.evaluate(sig(e)).reason_code == "risk_halted"

    def test_still_respects_slippage_protection(self):
        e = build(CONFIRM_MODE="COPY_ONLY", **BIG)
        e.world.books[TOKEN_UP] = raw_book(asks=((0.70, 100.0),))
        assert e.engine.evaluate(sig(e)).reason_code == "slippage_exceeded"


class TestSellMirroring:
    def test_sell_without_position_is_ignored(self):
        e = build(**BIG)
        assert e.engine.evaluate(sig(e, side=Side.SELL)).reason_code == "no_position_to_sell"

    def test_sell_with_position_closes_entire_position(self):
        e = build(**BIG)
        hold(e, shares=20.0)
        d = e.engine.evaluate(sig(e, side=Side.SELL, price=0.60))
        assert d.accepted and d.order.side is Side.SELL
        assert d.order.shares == pytest.approx(20.0)
        assert d.order.limit_price == pytest.approx(0.59)  # 0.60×0.98=0.588 向上取整到 tick

    def test_exit_is_never_blocked_by_halt_or_entry_rules(self):
        e = build(**BIG)
        hold(e)
        e.world.candle_rows = candles(wiggle=3000)
        for _ in range(5):
            e.risk.record_api_result("gamma", False)  # 锁存熔断
        assert e.risk.halt_status().halted
        assert e.engine.evaluate(sig(e, side=Side.SELL)).accepted

    def test_dust_position_below_min_size_is_held_to_settlement(self):
        e = build(**BIG)
        hold(e, shares=3.0)
        assert e.engine.evaluate(sig(e, side=Side.SELL)).reason_code == "position_below_min_order_size"


class TestHaltBlocksEntries:
    def test_latched_halt_blocks_buy(self):
        e = build(**BIG)
        for _ in range(5):
            e.risk.record_api_result("clob", False)
        d = e.engine.evaluate(sig(e))
        assert d.reason_code == "risk_halted" and "api_failures" in d.reason_detail

    def test_halted_bot_does_not_hit_the_orderbook_api(self):
        """熔断期间不应再打 CLOB（避免在已知故障/风控停机时继续制造请求与失败计数）。"""
        e = build(**BIG)
        for _ in range(5):
            e.risk.record_api_result("gamma", False)
        e.world.requests.clear()
        assert e.engine.evaluate(sig(e)).reason_code == "risk_halted"
        assert not any(r[2] == "/book" for r in e.world.requests)
