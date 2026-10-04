"""端到端：目标钱包成交 → 监控 → 引擎 → 虚拟成交 → 市场结算 → 贝叶斯/报表。"""

from __future__ import annotations

import threading
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest

from copybot.app import build_bot
from copybot.bayes import BayesianTracker
from copybot.config import Mode
from copybot.db import Database
from copybot.models import CopySignal, Side
from copybot.notifier import TelegramNotifier
from copybot.report import export_equity_csv, render, summarize
from tests.conftest import FakeClock, make_settings
from tests.fakes import COND, TOKEN_UP, FakeWorld, gamma_market, raw_book

TX1, TX2 = "0x" + "a1" * 32, "0x" + "b2" * 32


def make_bot(**env):
    env = {"BANKROLL_USD": "1000", **env}
    s = make_settings(**env)
    clock, w = FakeClock(), None
    w = FakeWorld(s)
    bot = build_bot(s, http=w.client(), db=Database(":memory:"), clock=clock)
    return SimpleNamespace(s=s, clock=clock, w=w, bot=bot, db=bot.db)


def ts(e, ago=10):
    return (e.clock.now - timedelta(seconds=ago)).timestamp()


def drive(e):
    """监控拉取一次 + 主循环处理队列里全部信号。"""
    n = e.bot.monitor.poll_once()
    for _ in range(n):
        e.bot.step()
    return n


class TestFullDryRunCycle:
    def test_buy_then_settle_win(self):
        e = make_bot()
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), price=0.50, size=20, tx=TX1)]
        assert drive(e) == 1

        row = e.db.get_signal(next(iter(e.db._conn.execute("SELECT id FROM signals").fetchone())))
        assert row["status"] == "EXECUTED" and row["market_type"] == "BTC_HOURLY"
        pos = e.db.open_trade_for_token(Mode.DRY_RUN, TOKEN_UP)
        assert pos is not None and pos.mode is Mode.DRY_RUN
        assert pos.executed_price == pytest.approx(0.51) and pos.shares == pytest.approx(19.6)

        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("1", "0"))
        assert e.bot.settler.run_once() == 1
        closed = e.db.closed_trades(Mode.DRY_RUN)[0]
        assert closed.pnl_usd == pytest.approx(19.6 - 19.6 * 0.51)
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (1, 1)

        text = render(e.db, e.s)
        assert "BTC_HOURLY" in text and "EXECUTED" in text and "胜率 100.0%" in text
        assert summarize(e.db, e.s).total_pnl == pytest.approx(closed.pnl_usd)

    def test_settle_loss_updates_state_against_us(self):
        e = make_bot()
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), price=0.50, tx=TX1)]
        drive(e)
        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("0", "1"))
        e.bot.settler.run_once()
        assert BayesianTracker(e.db).counts("BTC_HOURLY") == (0, 1)
        assert e.bot.risk.equity() < 1000

    def test_mirrored_exit(self):
        e = make_bot()
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e, 30), price=0.50, tx=TX1)]
        drive(e)
        e.w.books[TOKEN_UP] = raw_book(bids=((0.60, 100.0),))
        e.w.data_api_rows.append(e.w.target_trade(side="SELL", ts=ts(e, 5), price=0.60, tx=TX2))
        assert drive(e) == 1
        assert e.db.open_trades(Mode.DRY_RUN) == []
        assert e.db.closed_trades(Mode.DRY_RUN)[0].pnl_usd == pytest.approx(19.6 * 0.60 - 19.6 * 0.51)

    def test_same_fills_are_not_processed_twice(self):
        e = make_bot()
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), tx=TX1)]
        assert drive(e) == 1 and drive(e) == 0
        assert len(e.db.open_trades(Mode.DRY_RUN)) == 1

    def test_stale_trade_is_expired_not_copied(self):
        e = make_bot()
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e, 300), tx=TX1)]
        drive(e)
        row = e.db._conn.execute("SELECT status, reason_code FROM signals").fetchone()
        assert (row["status"], row["reason_code"]) == ("EXPIRED", "signal_expired")
        assert e.db.open_trades(Mode.DRY_RUN) == []

    def test_non_btc_trade_filtered_with_reason_in_db(self):
        e = make_bot()
        e.w.markets_by_token[TOKEN_UP] = gamma_market(question="Will it rain in Paris?", slug="rain")
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), tx=TX1)]
        drive(e)
        assert e.db.signal_funnel() == [("FILTERED", "not_btc_market", 1)]

    def test_halt_blocks_new_entries_but_is_recorded(self):
        e = make_bot()
        for _ in range(5):
            e.bot.risk.record_api_result("clob", False)
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), tx=TX1)]
        drive(e)
        assert e.db.signal_funnel() == [("FILTERED", "risk_halted", 1)]

    def test_engine_crash_on_one_signal_does_not_kill_the_loop(self):
        e = make_bot()
        e.bot.engine.evaluate = lambda sig: (_ for _ in ()).throw(RuntimeError("bug"))
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), tx=TX1)]
        drive(e)
        assert e.db.signal_funnel() == [("FILTERED", "internal_error", 1)]

    def test_startup_expires_orphaned_pending_signals(self):
        e = make_bot()
        old = CopySignal("orphan", TOKEN_UP, Side.BUY, 0.5, 1, 1, "0x", e.clock.now, e.clock.now - timedelta(minutes=10))
        e.db.insert_signal(old)
        e.bot.startup()
        assert e.db.get_signal("orphan")["status"] == "EXPIRED"

    def test_equity_curve_csv(self, tmp_path):
        e = make_bot()
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), tx=TX1)]
        drive(e)
        e.w.markets_by_condition[COND] = gamma_market(closed=True, prices=("1", "0"))
        e.bot.settler.run_once()
        path = tmp_path / "curve.csv"
        assert export_equity_csv(e.db, e.s, str(path)) == 1
        lines = path.read_text().splitlines()
        assert lines[0] == "closed_at_utc,pnl_usd,equity_usd" and len(lines) == 2

    def test_default_20_dollar_bankroll_yields_no_executable_trades(self):
        """文档默认值（$20、单笔 5%）在 0.51 价位买不到交易所最小 5 份——模拟盘必须如实暴露这点。"""
        e = make_bot(BANKROLL_USD="20")
        e.w.data_api_rows = [e.w.target_trade(ts=ts(e), tx=TX1)]
        drive(e)
        assert e.db.signal_funnel() == [("FILTERED", "below_min_order_size", 1)]


class TestThreadedRun:
    def test_run_loop_processes_a_trade_end_to_end(self):
        e = make_bot(POLL_INTERVAL_SEC="1")
        e.w.data_api_rows = [e.w.target_trade(ts=time.time() - 5, tx=TX1)]
        # 线程里的时钟用真实时间：信号 TTL 以 bot 的 clock 判断
        e.bot._clock = lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        e.bot.engine._clock = e.bot._clock
        t = threading.Thread(target=e.bot.run, daemon=True)
        t.start()
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    if e.db.open_trades(Mode.DRY_RUN):
                        break
                except Exception:
                    pass
                time.sleep(0.1)
            assert e.db.open_trades(Mode.DRY_RUN), "10 秒内应完成 抓取→过滤→虚拟成交"
        finally:
            e.bot.stop()
            t.join(timeout=10)
        assert not t.is_alive()


class TestLiveApprovalFlow:
    def test_order_waits_for_telegram_approval_before_executing(self):
        s = make_settings(MODE="LIVE", PRIVATE_KEY="0x" + "11" * 32, BANKROLL_USD="20", MAX_POSITION_PCT="100",
                          TELEGRAM_BOT_TOKEN="123456:ABCDEF", TELEGRAM_CHAT_ID="42", ENFORCE_MIN_ORDER_SIZE="false",
                          CONFIRM_MODE="COPY_ONLY")  # LIVE 不做冷启动探索；CONFIRM 需先有正边际
        clock, w = FakeClock(), None
        w = FakeWorld(s)
        calls = []

        class RecordingExecutor:
            def execute(self, order, sig):
                calls.append(order)
                from copybot.models import ExecutionResult
                return ExecutionResult(False, "stub")

        bot = build_bot(s, http=w.client(), db=Database(":memory:"), clock=clock, executor=RecordingExecutor())
        assert isinstance(bot.notifier, TelegramNotifier) and bot.approvals is not None
        w.data_api_rows = [w.target_trade(ts=ts(SimpleNamespace(clock=clock)), tx=TX1)]
        bot.monitor.poll_once()
        bot.step()
        assert calls == [], "未经 /approve 不得下单"
        assert any("/approve" in m for m in w.tg_sent)
        aid = next(iter(bot.approvals.pending))
        w.tg_updates.append({"update_id": 1, "message": {"chat": {"id": 42}, "text": f"/approve {aid}"}})
        bot._poll_approvals()
        assert len(calls) == 1

    def test_approved_order_is_rechecked_against_halt(self):
        s = make_settings(MODE="LIVE", PRIVATE_KEY="0x" + "11" * 32, BANKROLL_USD="20", MAX_POSITION_PCT="100",
                          TELEGRAM_BOT_TOKEN="123456:ABCDEF", TELEGRAM_CHAT_ID="42", ENFORCE_MIN_ORDER_SIZE="false",
                          CONFIRM_MODE="COPY_ONLY")  # LIVE 不做冷启动探索；CONFIRM 需先有正边际
        clock, w = FakeClock(), None
        w = FakeWorld(s)
        calls = []
        bot = build_bot(s, http=w.client(), db=Database(":memory:"), clock=clock,
                        executor=SimpleNamespace(execute=lambda o, g: calls.append(o)))
        w.data_api_rows = [w.target_trade(ts=ts(SimpleNamespace(clock=clock)), tx=TX1)]
        bot.monitor.poll_once()
        bot.step()
        aid = next(iter(bot.approvals.pending))
        for _ in range(5):                       # 等待确认期间发生熔断
            bot.risk.record_api_result("clob", False)
        w.tg_updates.append({"update_id": 1, "message": {"chat": {"id": 42}, "text": f"/approve {aid}"}})
        bot._poll_approvals()
        assert calls == []
