"""DRY_RUN 执行器：完整走"指令 → 虚拟成交 → 记账"，**绝不下真实订单**。

隔离保证（由 tests/test_dry_run_isolation.py 做静态 + 运行时审计）：
  - 本模块不导入 py_clob_client，不含任何下单/签名调用，也不持有私钥。
  - 真实下单代码全部在 live_executor.py，且只在 MODE=LIVE 时才被延迟导入。

成交模拟：把限价单与**订单簿快照**撮合（吃单 VWAP，只吃限价以内的档位）。
这比"假设按信号价成交"更真实，能在 Phase 1 就暴露出跟单滞后造成的滑点。
简化：全部成交或不成交（不模拟部分成交与 30 秒挂单等待）。
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable

from .config import Mode, Settings
from .db import Database
from .logging_setup import LOGGER_NAME, log_event
from .market_data import ApiError, MarketDataService
from .models import CopySignal, ExecutionResult, Side, Trade, TradeOrder, TradeStatus
from .util import utcnow

log = logging.getLogger(f"{LOGGER_NAME}.executor")


class DryRunExecutor:
    mode = Mode.DRY_RUN

    def __init__(self, settings: Settings, db: Database, market_data: MarketDataService, *, clock=utcnow,
                 new_id: Callable[[], str] = lambda: str(uuid.uuid4())):
        self._s, self._db, self._md, self._clock, self._new_id = settings, db, market_data, clock, new_id

    def execute(self, order: TradeOrder, sig: CopySignal) -> ExecutionResult:
        try:
            book = self._md.get_book(order.token_id, fresh=True)  # 撮合用最新盘口，不用 5 秒缓存
        except ApiError as e:
            return ExecutionResult(False, f"book_unavailable: {e}")
        if order.side is Side.BUY:
            return self._buy(order, book)
        return self._sell(order, book)

    def _buy(self, order: TradeOrder, book) -> ExecutionResult:
        filled, avg = book.fill_buy(order.shares, order.limit_price)
        if filled + 1e-9 < order.shares:
            return ExecutionResult(
                False, f"not_filled: 限价 {order.limit_price:.4f} 内只有 {filled:g}/{order.shares:g} 份")
        amount = filled * avg
        fee = amount * self._s.sim_fee_bps / 10_000
        now = self._clock()
        trade = Trade(
            id=self._new_id(), signal_id=order.signal_id, mode=Mode.DRY_RUN, market_id=order.market_id,
            token_id=order.token_id, market_type=order.market_type, status=TradeStatus.OPEN,
            executed_price=avg, shares=filled, amount_usd=amount, opened_at=now, hour_utc=now.hour, fee_usd=fee)
        self._db.open_trade(trade)
        log_event(log, logging.INFO, "dry_run_fill", side="BUY", trade_id=trade.id, signal_id=order.signal_id,
                  price=round(avg, 4), shares=filled, amount_usd=round(amount, 4),
                  slippage_vs_limit=round(order.limit_price - avg, 4), mode="DRY_RUN")
        return ExecutionResult(True, trade=trade, executed_price=avg, shares=filled)

    def _sell(self, order: TradeOrder, book) -> ExecutionResult:
        pos = self._db.open_trade_for_token(Mode.DRY_RUN, order.token_id)
        if pos is None:
            return ExecutionResult(False, "no_position")
        filled, avg = book.fill_sell(pos.shares, order.limit_price)
        if filled + 1e-9 < pos.shares:
            return ExecutionResult(
                False, f"not_filled: 限价 {order.limit_price:.4f} 以上的买盘只有 {filled:g}/{pos.shares:g} 份")
        proceeds = filled * avg
        fee = proceeds * self._s.sim_fee_bps / 10_000
        pnl = proceeds - fee - pos.amount_usd - pos.fee_usd
        self._db.settle_trade(pos.id, exit_price=avg, pnl_usd=pnl, extra_fee_usd=fee, closed_at=self._clock())
        log_event(log, logging.INFO, "dry_run_fill", side="SELL", trade_id=pos.id, signal_id=order.signal_id,
                  price=round(avg, 4), shares=filled, pnl_usd=round(pnl, 4), mode="DRY_RUN")
        return ExecutionResult(True, trade=pos, executed_price=avg, shares=filled)
