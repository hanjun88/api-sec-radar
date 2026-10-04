"""装配与主循环。

线程模型：
  - 监控线程：每 POLL_INTERVAL_SEC 轮询数据源 → 去重入库 → 入内存队列（queue.Queue）
  - 主线程：消费队列 → 信号引擎 → 执行器；并定时结算、轮询 Telegram 确认
熔断后进程**不退出**：继续记录信号并标注 risk_halted。若退出，Docker/systemd 的自动重启会绕过熔断。
"""

from __future__ import annotations

import logging
import queue
import signal as os_signal
import threading
import time
from datetime import timedelta
from typing import Any, Callable, Optional

import httpx

from .bayes import BayesianTracker
from .btc import CoinbasePriceFeed, PriceFeed
from .config import Settings
from .db import Database
from .executor import DryRunExecutor
from .logging_setup import LOGGER_NAME, log_event
from .market_data import MarketDataService
from .models import CopySignal, ExecutionResult, Side, SignalStatus, TradeOrder
from .notifier import ApprovalGate, NullNotifier, TelegramNotifier
from .risk import RiskControl
from .settlement import Settler
from .signal_engine import SignalEngine
from .util import utcnow
from .wallet_monitor import (DataApiTradeSource, TradeSource, WalletMonitor, build_chain_source)

log = logging.getLogger(f"{LOGGER_NAME}.app")
APPROVAL_POLL_SEC = 3.0


def build_executor(settings: Settings, db: Database, md: MarketDataService, clock: Callable = utcnow) -> Any:
    if settings.is_live:
        # 延迟导入：DRY_RUN 下 live_executor（及 py-clob-client）永远不会被加载
        from .live_executor import LiveExecutor
        return LiveExecutor(settings, db, md, clock=clock)
    return DryRunExecutor(settings, db, md, clock=clock)


class Bot:
    def __init__(self, settings: Settings, *, db: Database, http: httpx.Client, risk: RiskControl,
                 market_data: MarketDataService, engine: SignalEngine, executor: Any, settler: Settler,
                 monitor: WalletMonitor, signals: "queue.Queue[CopySignal]", notifier: Any,
                 approvals: Optional[ApprovalGate] = None, clock: Callable = utcnow,
                 monotonic: Callable[[], float] = time.monotonic):
        self.settings, self.db, self.http, self.risk = settings, db, http, risk
        self.market_data, self.engine, self.executor, self.settler = market_data, engine, executor, settler
        self.monitor, self.signals, self.notifier, self.approvals = monitor, signals, notifier, approvals
        self._clock, self._mono = clock, monotonic
        self._stop = threading.Event()
        self._next_settle = 0.0
        self._next_approval_poll = 0.0

    # ── 单个信号 ─────────────────────────────────────
    def process_signal(self, sig: CopySignal) -> None:
        decision = self.engine.evaluate(sig)
        if not decision.accepted:
            self.db.set_signal(sig.signal_id, decision.status, reason_code=decision.reason_code,
                               reason_detail=decision.reason_detail, market_id=decision.market_id,
                               market_type=decision.market_type)
            return
        order = decision.order
        assert order is not None
        self.db.set_signal(sig.signal_id, SignalStatus.PENDING, reason_code="accepted", reason_detail=order.reason,
                           kelly_fraction=order.kelly_fraction, market_id=order.market_id,
                           market_type=order.market_type)
        if self.approvals is not None:
            aid = self.approvals.submit(order, sig)
            self.db.set_signal(sig.signal_id, SignalStatus.PENDING, reason_code="awaiting_approval",
                               reason_detail=f"等待 Telegram /approve {aid}")
            return
        self._execute(order, sig)

    def _execute(self, order: TradeOrder, sig: CopySignal) -> None:
        try:
            result: ExecutionResult = self.executor.execute(order, sig)
        except Exception as e:  # noqa: BLE001
            log.exception("execution_error")
            self.db.set_signal(sig.signal_id, SignalStatus.FILTERED, reason_code="execution_error",
                               reason_detail=type(e).__name__)
            return
        if result.filled:
            self.db.set_signal(sig.signal_id, SignalStatus.EXECUTED, reason_code="executed",
                               reason_detail=order.reason)
            self._notify(f"{'🟢' if order.side is Side.BUY else '🔴'} {self.settings.mode.value} "
                         f"{order.side.value} {result.shares:g} 份 @ {result.executed_price:.4f}（{order.market_type}）")
            if order.side is Side.SELL:
                self.risk.evaluate_after_close()
        else:
            self.db.set_signal(sig.signal_id, SignalStatus.FILTERED, reason_code="not_filled",
                               reason_detail=result.reason)
            log_event(log, logging.INFO, "order_not_filled", signal_id=sig.signal_id, reason=result.reason)

    def _poll_approvals(self) -> None:
        assert self.approvals is not None
        approved, dropped = self.approvals.poll()
        for item in dropped:
            p, why = item
            self.db.set_signal(p.signal.signal_id, SignalStatus.FILTERED, reason_code=why,
                               reason_detail="未获人工确认，订单作废")
        for p in approved:
            if p.order.side is Side.BUY:  # 等待确认期间可能触发了熔断/占用了资金，下单前再核一次
                v = self.risk.check_new_entry(p.order.size_usd)
                if not v.allowed:
                    self.db.set_signal(p.signal.signal_id, SignalStatus.FILTERED, reason_code=v.code,
                                       reason_detail=v.detail)
                    continue
            self._execute(p.order, p.signal)

    # ── 主循环 ───────────────────────────────────────
    def step(self, timeout: float = 0.0) -> None:
        """处理一个队列项并执行到期的周期任务。公开以便测试单步驱动。"""
        try:
            sig = self.signals.get(timeout=timeout) if timeout > 0 else self.signals.get_nowait()
        except queue.Empty:
            sig = None
        if sig is not None:
            try:
                self.process_signal(sig)
            except Exception as e:  # noqa: BLE001 - 单个信号的任何异常都不应让主循环退出
                log.exception("process_signal_error")
                self.db.set_signal(sig.signal_id, SignalStatus.FILTERED, reason_code="internal_error",
                                   reason_detail=type(e).__name__)
        now = self._mono()
        if now >= self._next_settle:
            self._next_settle = now + self.settings.settle_interval_sec
            try:
                self.settler.run_once()
            except Exception:  # noqa: BLE001
                log.exception("settle_error")
        if self.approvals is not None and now >= self._next_approval_poll:
            self._next_approval_poll = now + APPROVAL_POLL_SEC
            try:
                self._poll_approvals()
            except Exception:  # noqa: BLE001
                log.exception("approval_poll_error")

    def _monitor_loop(self) -> None:
        while not self._stop.is_set():
            self.monitor.poll_safely()
            self._stop.wait(self.settings.poll_interval_sec)

    def startup(self) -> None:
        s = self.settings
        n = self.db.expire_stale_pending(self._clock() - timedelta(seconds=s.signal_ttl_sec))
        log_event(log, logging.INFO, "bot_starting", expired_orphans=n, **s.public_summary())
        if s.is_live:
            log_event(log, logging.WARNING, "LIVE_MODE_ENABLED", note="将提交真实订单", cap_usd=s.bankroll_usd,
                      require_approval=s.require_approval)
        else:
            log_event(log, logging.INFO, "DRY_RUN_MODE", note="模拟盘：不会提交任何真实订单")
        halt = self.risk.halt_status()
        if halt.halted:
            log_event(log, logging.CRITICAL, "started_in_halted_state", code=halt.code, detail=halt.detail)
        self._notify(f"🤖 copybot 启动 mode={s.mode.value} confirm={s.confirm_mode.value}"
                     + (f"\n⚠️ 当前处于熔断状态: {halt.code}" if halt.halted else ""))

    def run(self) -> None:
        if threading.current_thread() is threading.main_thread():
            for sig in (os_signal.SIGINT, os_signal.SIGTERM):
                os_signal.signal(sig, lambda *_: self.stop())
        self.startup()
        t = threading.Thread(target=self._monitor_loop, name="wallet-monitor", daemon=True)
        t.start()
        try:
            while not self._stop.is_set():
                self.step(timeout=1.0)
        finally:
            self._stop.set()
            t.join(timeout=5)
            self.db.close()
            log_event(log, logging.INFO, "bot_stopped")

    def stop(self) -> None:
        self._stop.set()

    def _notify(self, text: str) -> None:
        try:
            self.notifier.send(text)
        except Exception:  # noqa: BLE001
            log.exception("notify_failed")


def build_bot(
    settings: Settings, *, http: Optional[httpx.Client] = None, db: Optional[Database] = None,
    price_feed: Optional[PriceFeed] = None, source: Optional[TradeSource] = None,
    notifier: Any = None, executor: Any = None, clock: Callable = utcnow,
) -> Bot:
    http = http or httpx.Client(timeout=settings.http_timeout_sec, headers={"User-Agent": "polymarket-copybot/0.1"})
    db = db or Database(settings.db_path)
    if notifier is None:
        notifier = (TelegramNotifier(settings.telegram_bot_token, settings.telegram_chat_id, http)
                    if settings.telegram_bot_token and settings.telegram_chat_id else NullNotifier())
    risk = RiskControl(db, settings, clock=clock, notifier=notifier)
    md = MarketDataService(http, settings, report=risk.record_api_result)
    feed = price_feed or CoinbasePriceFeed(http, settings.price_feed_url, risk.record_api_result)
    bayes = BayesianTracker(db, settings.bayes_alpha, settings.bayes_beta)
    engine = SignalEngine(settings, db, md, feed, bayes, risk, clock=clock)
    executor = executor or build_executor(settings, db, md, clock)
    if source is None:
        source = (build_chain_source(settings, db, risk.record_api_result) if settings.monitor_source == "chain"
                  else DataApiTradeSource(http, settings, risk.record_api_result))
    signals: "queue.Queue[CopySignal]" = queue.Queue()
    monitor = WalletMonitor(source, db, signals, clock=clock)
    settler = Settler(settings, db, md, risk, notifier, clock=clock)
    approvals = None
    if settings.is_live and settings.require_approval:
        assert isinstance(notifier, TelegramNotifier), "LIVE + REQUIRE_APPROVAL 需要 Telegram"
        approvals = ApprovalGate(notifier, db, settings.approval_timeout_sec, clock=clock)
    return Bot(settings, db=db, http=http, risk=risk, market_data=md, engine=engine, executor=executor,
               settler=settler, monitor=monitor, signals=signals, notifier=notifier, approvals=approvals,
               clock=clock)
