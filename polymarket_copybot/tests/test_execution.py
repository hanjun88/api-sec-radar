"""DRY_RUN 执行器、结算器、LIVE 执行器（用假 CLOB 客户端；未触达真实 API）。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from copybot.bayes import BayesianTracker
from copybot.config import Mode
from copybot.db import Database
from copybot.executor import DryRunExecutor
from copybot.live_executor import LiveExecutor
from copybot.market_data import MarketDataService
from copybot.models import CopySignal, ExecutionResult, Side, Trade, TradeOrder, TradeStatus
from copybot.risk import RiskControl
from copybot.settlement import Settler
from tests.conftest import FakeClock, make_settings
from tests.fakes import COND, TOKEN_UP, FakeWorld, gamma_market, raw_book

LIVE_ENV = dict(MODE="LIVE", PRIVATE_KEY="0x" + "11" * 32, REQUIRE_APPROVAL="false")


def order(side=Side.BUY, shares=20.0, limit=0.52, sid="s1") -> TradeOrder:
    return TradeOrder(sid, COND, TOKEN_UP, "BTC_HOURLY", side, limit, shares, round(shares * limit, 4), 0.01, "test")


def seed_signal(db, clock, sid="s1"):
    db.insert_signal(CopySignal(sid, TOKEN_UP, Side.BUY, 0.5, 1, 1, "0xtx", clock.now, clock.now))


def dry_env(**env):
    s = make_settings(**env)
    clock, db, w = FakeClock(), Database(":memory:"), None
    w = FakeWorld(s)
    md = MarketDataService(w.client(), s)
    ex = DryRunExecutor(s, db, md, clock=clock, new_id=iter(f"t{i}" for i in range(100)).__next__)
    return SimpleNamespace(s=s, clock=clock, db=db, w=w, md=md, ex=ex)


class TestDryRunBuy:
    def test_fills_at_book_vwap_not_at_signal_price(self):
        e = dry_env()
        seed_signal(e.db, e.clock)
        e.w.books[TOKEN_UP] = raw_book(asks=((0.50, 10.0), (0.52, 100.0)))
        r = e.ex.execute(order(shares=20, limit=0.52), None)
        assert r.filled
        assert r.executed_price == pytest.approx((10 * 0.50 + 10 * 0.52) / 20)
        t = e.db.open_trade_for_token(Mode.DRY_RUN, TOKEN_UP)
        assert t.shares == 20 and t.amount_usd == pytest.approx(10.2) and t.mode is Mode.DRY_RUN
        assert t.hour_utc == e.clock.now.hour

    def test_unfilled_when_depth_within_limit_is_insufficient(self):
        e = dry_env()
        seed_signal(e.db, e.clock)
        e.w.books[TOKEN_UP] = raw_book(asks=((0.50, 5.0), (0.60, 100.0)))
        r = e.ex.execute(order(shares=20, limit=0.52), None)
        assert not r.filled and "not_filled" in r.reason
        assert e.db.open_trades(Mode.DRY_RUN) == []

    def test_simulated_fee(self):
        e = dry_env(SIM_FEE_BPS="100")
        seed_signal(e.db, e.clock)
        r = e.ex.execute(order(shares=10, limit=0.52), None)
        assert r.trade.fee_usd == pytest.approx(r.trade.amount_usd * 0.01)

    def test_book_unavailable(self):
        e = dry_env()
        e.w.books.clear()
        r = e.ex.execute(order(), None)
        assert not r.filled and r.reason.startswith("book_unavailable")


class TestDryRunSell:
    def _open(self, e, shares=20.0, price=0.50):
        seed_signal(e.db, e.clock)
        e.db.open_trade(Trade("pos", "s1", Mode.DRY_RUN, COND, TOKEN_UP, "BTC_HOURLY", TradeStatus.OPEN,
                              price, shares, shares * price, e.clock.now, 12))

    def test_exit_realizes_pnl_and_updates_bayes(self):
        e = dry_env()
        self._open(e)
        e.w.books[TOKEN_UP] = raw_book(bids=((0.60, 100.0),))
        r = e.ex.execute(order(Side.SELL, shares=20, limit=0.58), None)
        assert r.filled
        t = e.db.closed_trades(Mode.DRY_RUN)[0]
        assert t.pnl_usd == pytest.approx(20 * 0.60 - 10.0)
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (1, 1)

    def test_losing_exit_counts_as_loss(self):
        e = dry_env()
        self._open(e)
        e.w.books[TOKEN_UP] = raw_book(bids=((0.40, 100.0),))
        e.ex.execute(order(Side.SELL, shares=20, limit=0.39), None)
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (0, 1)

    def test_not_filled_leaves_position_open(self):
        e = dry_env()
        self._open(e)
        e.w.books[TOKEN_UP] = raw_book(bids=((0.30, 100.0),))
        r = e.ex.execute(order(Side.SELL, limit=0.58), None)
        assert not r.filled and len(e.db.open_trades(Mode.DRY_RUN)) == 1

    def test_no_position(self):
        e = dry_env()
        assert e.ex.execute(order(Side.SELL), None).reason == "no_position"


class TestDryRunNeverPostsAnything:
    def test_only_get_requests_during_fills(self):
        e = dry_env()
        seed_signal(e.db, e.clock)
        e.ex.execute(order(), None)
        assert e.w.non_get_requests() == []


class TestSettler:
    def make(self, **env):
        e = dry_env(**env)
        e.risk = RiskControl(e.db, e.s, clock=e.clock)
        e.settler = Settler(e.s, e.db, e.md, e.risk, clock=e.clock)
        seed_signal(e.db, e.clock)
        e.db.open_trade(Trade("pos", "s1", Mode.DRY_RUN, COND, TOKEN_UP, "BTC_HOURLY", TradeStatus.OPEN,
                              0.5, 2.0, 1.0, e.clock.now, 12))
        return e

    def test_unresolved_stays_open(self):
        e = self.make()
        assert e.settler.run_once() == 0 and len(e.db.open_trades(Mode.DRY_RUN)) == 1

    def test_win_pays_one_per_share(self):
        e = self.make()
        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("1", "0"))
        assert e.settler.run_once() == 1
        t = e.db.closed_trades(Mode.DRY_RUN)[0]
        assert t.pnl_usd == pytest.approx(1.0) and t.exit_price == 1.0
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (1, 1)
        assert e.db.hourly_state("BTC_HOURLY", 12).total == 1

    def test_loss_loses_the_stake(self):
        e = self.make()
        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("0", "1"))
        e.settler.run_once()
        assert e.db.closed_trades(Mode.DRY_RUN)[0].pnl_usd == pytest.approx(-1.0)
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (0, 1)

    def test_settling_is_idempotent(self):
        e = self.make()
        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("1", "0"))
        e.settler.run_once()
        assert e.settler.run_once() == 0
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (1, 1)

    def test_api_failure_leaves_trade_open(self):
        e = self.make()
        e.w.fail["gamma-api"] = 500
        assert e.settler.run_once() == 0 and len(e.db.open_trades(Mode.DRY_RUN)) == 1

    def test_big_loss_triggers_risk_review(self):
        e = self.make(BANKROLL_USD="5")  # 亏 $1 = 20% 回撤
        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("0", "1"))
        e.settler.run_once()
        assert e.risk.halt_status().halted


# ───────────────────────── LIVE（假客户端） ─────────────────────────
class FakeClob:
    def __init__(self, post_resp=None, states=None):
        self.post_resp = post_resp if post_resp is not None else {"success": True, "orderID": "oid-1"}
        self.states = states or [{"size_matched": "0"}]
        self.created, self.posted, self.cancelled, self.polls = [], [], [], 0
        self.raise_on_post = None

    def create_order(self, args, opts):
        self.created.append((args, opts))
        return {"signed": True}

    def post_order(self, signed, order_type):
        if self.raise_on_post:
            raise self.raise_on_post
        self.posted.append(order_type)
        return self.post_resp

    def get_order(self, oid):
        i = min(self.polls, len(self.states) - 1)
        self.polls += 1
        return self.states[i]

    def cancel(self, oid):
        self.cancelled.append(oid)


SDK = SimpleNamespace(
    OrderArgs=lambda **kw: SimpleNamespace(**kw), PartialCreateOrderOptions=lambda **kw: SimpleNamespace(**kw),
    OrderType=SimpleNamespace(GTC="GTC"), BUY="BUY", SELL="SELL")


def live_env(client, **env):
    s = make_settings(**{**LIVE_ENV, **env})
    clock, db = FakeClock(), Database(":memory:")
    w = FakeWorld(s)
    md = MarketDataService(w.client(), s)
    t = [0.0]

    def sleep(sec):
        t[0] += sec

    ex = LiveExecutor(s, db, md, client=client, sdk=SDK, clock=clock, sleep=sleep, monotonic=lambda: t[0],
                      new_id=iter(f"lt{i}" for i in range(100)).__next__)
    seed_signal(db, clock)
    return SimpleNamespace(s=s, clock=clock, db=db, w=w, ex=ex, client=client)


class TestLiveExecutor:
    def test_refuses_to_exist_in_dry_run(self):
        s = make_settings()
        with pytest.raises(RuntimeError):
            LiveExecutor(s, Database(":memory:"), None, client=FakeClob(), sdk=SDK)

    def test_full_fill_records_live_trade_with_actual_average(self):
        c = FakeClob({"success": True, "orderID": "oid-1", "makingAmount": "10.2", "takingAmount": "20"},
                     [{"size_matched": "20"}])
        e = live_env(c)
        r = e.ex.execute(order(shares=20, limit=0.52), None)
        assert r.filled and r.shares == 20 and r.executed_price == pytest.approx(0.51)
        t = e.db.open_trade_for_token(Mode.LIVE, TOKEN_UP)
        assert t.mode is Mode.LIVE and t.order_id == "oid-1"
        assert c.cancelled == []

    def test_uses_gtc_limit_order_with_exact_args(self):
        c = FakeClob(states=[{"size_matched": "20"}])
        e = live_env(c)
        e.ex.execute(order(shares=20, limit=0.52), None)
        args, opts = c.created[0]
        assert (args.token_id, args.price, args.size, args.side) == (TOKEN_UP, 0.52, 20, "BUY")
        assert opts.tick_size == "0.01" and opts.neg_risk is False
        assert c.posted == ["GTC"]

    def test_no_fill_before_timeout_cancels_and_records_nothing(self):
        c = FakeClob(states=[{"size_matched": "0"}])
        e = live_env(c, ORDER_TIMEOUT_SEC="30")
        r = e.ex.execute(order(), None)
        assert not r.filled and "timeout" in r.reason
        assert c.cancelled == ["oid-1"]
        assert e.db.open_trades(Mode.LIVE) == []
        assert c.polls >= 30  # 确实等满了超时窗口再撤

    def test_partial_fill_is_recorded_and_remainder_cancelled(self):
        c = FakeClob(states=[{"size_matched": "0"}, {"size_matched": "8"}])
        e = live_env(c, ORDER_TIMEOUT_SEC="5")
        r = e.ex.execute(order(shares=20, limit=0.52), None)
        assert r.filled and r.shares == 8
        assert c.cancelled == ["oid-1"]
        assert e.db.open_trade_for_token(Mode.LIVE, TOKEN_UP).shares == 8

    def test_post_exception_is_not_filled_and_leaks_nothing(self):
        c = FakeClob()
        c.raise_on_post = RuntimeError("bad key 0x" + "11" * 32)
        e = live_env(c)
        r = e.ex.execute(order(), None)
        assert not r.filled and "11" * 32 not in r.reason
        assert e.db.open_trades(Mode.LIVE) == []

    @pytest.mark.parametrize("resp", [{"success": False, "errorMsg": "not enough balance"},
                                      {"success": True}, None])
    def test_rejected_orders(self, resp):
        c = FakeClob(post_resp=resp if resp is not None else "garbage")
        e = live_env(c)
        assert not e.ex.execute(order(), None).filled

    def _open_live(self, e, shares=20.0):
        e.db.open_trade(Trade("pos", "s1", Mode.LIVE, COND, TOKEN_UP, "BTC_HOURLY", TradeStatus.OPEN,
                              0.5, shares, shares * 0.5, e.clock.now, 12))

    def test_full_exit_settles_position(self):
        c = FakeClob({"success": True, "orderID": "o2", "makingAmount": "20", "takingAmount": "12"},
                     [{"size_matched": "20"}])
        e = live_env(c)
        self._open_live(e)
        r = e.ex.execute(order(Side.SELL, shares=20, limit=0.58), None)
        assert r.filled
        t = e.db.closed_trades(Mode.LIVE)[0]
        assert t.pnl_usd == pytest.approx(12.0 - 10.0)

    def test_partial_exit_splits_position(self):
        c = FakeClob({"success": True, "orderID": "o2"}, [{"size_matched": "5"}])
        e = live_env(c, ORDER_TIMEOUT_SEC="2")
        self._open_live(e)
        r = e.ex.execute(order(Side.SELL, shares=20, limit=0.60), None)
        assert r.filled and r.shares == 5
        remaining = e.db.open_trade_for_token(Mode.LIVE, TOKEN_UP)
        assert remaining.id == "pos" and remaining.shares == pytest.approx(15) and remaining.amount_usd == pytest.approx(7.5)
        closed = e.db.closed_trades(Mode.LIVE)[0]
        assert closed.shares == 5 and closed.amount_usd == pytest.approx(2.5)
        assert closed.pnl_usd == pytest.approx(5 * 0.60 - 2.5)

    def test_sell_without_position(self):
        e = live_env(FakeClob())
        assert e.ex.execute(order(Side.SELL), None).reason == "no_position"


class TestRealSdkCompatibility:
    """离线核对：我传给官方 SDK 的参数名/类型与已安装版本的签名一致（不联网）。"""

    def test_sdk_symbols_and_kwargs_exist(self):
        pytest.importorskip("py_clob_client")
        from copybot.live_executor import load_sdk

        sdk = load_sdk()
        a = sdk.OrderArgs(token_id="1", price=0.5, size=10.0, side=sdk.BUY)
        o = sdk.PartialCreateOrderOptions(tick_size="0.01", neg_risk=False)
        assert a.token_id == "1" and o.tick_size == "0.01"
        assert sdk.BUY == "BUY" and sdk.SELL == "SELL" and sdk.OrderType.GTC == "GTC"

    def test_client_exposes_methods_we_call(self):
        pytest.importorskip("py_clob_client")
        from py_clob_client.client import ClobClient

        for m in ("create_order", "post_order", "cancel", "get_order", "create_or_derive_api_creds", "set_api_creds"):
            assert callable(getattr(ClobClient, m))
