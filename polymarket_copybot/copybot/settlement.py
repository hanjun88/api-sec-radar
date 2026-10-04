"""结算：查询持仓所属市场是否已结算，按兑付价记账 → 更新贝叶斯/小时胜率 → 触发风控复核。"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from .config import Settings
from .db import Database
from .logging_setup import LOGGER_NAME, log_event
from .market_data import ApiError, MarketDataService
from .risk import Notifier, RiskControl
from .util import utcnow

log = logging.getLogger(f"{LOGGER_NAME}.settle")


class Settler:
    def __init__(self, settings: Settings, db: Database, market_data: MarketDataService, risk: RiskControl,
                 notifier: Optional[Notifier] = None, *, clock=utcnow):
        self._s, self._db, self._md, self._risk, self._n, self._clock = (
            settings, db, market_data, risk, notifier, clock)

    def run_once(self) -> int:
        closed = 0
        for t in self._db.open_trades(self._s.mode):
            try:
                payoff = self._md.resolution_payoff(t.market_id, t.token_id)
            except ApiError:
                continue  # 失败已计入风控的连续失败计数；下个周期重试
            if payoff is None:
                continue
            pnl = t.shares * payoff - t.amount_usd - t.fee_usd
            if self._db.settle_trade(t.id, exit_price=payoff, pnl_usd=pnl, extra_fee_usd=0.0,
                                     closed_at=self._clock()):
                closed += 1
                log_event(log, logging.INFO, "trade_settled", trade_id=t.id, market_type=t.market_type,
                          payoff=payoff, pnl_usd=round(pnl, 4), mode=self._s.mode.value)
                self._notify(f"{'✅' if pnl > 0 else '❌'} 结算 {t.market_type} 盈亏 ${pnl:+.2f}（{self._s.mode.value}）")
        if closed:
            self._risk.evaluate_after_close()
        return closed

    def _notify(self, text: str) -> None:
        if self._n is not None:
            try:
                self._n.send(text)
            except Exception:  # noqa: BLE001
                log.exception("notify_failed")
