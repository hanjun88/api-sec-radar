"""LIVE 执行器：通过官方 py-clob-client 提交真实限价单。

⚠️ 这是整个项目里**唯一**会下真实订单的文件。
  - 只在 MODE=LIVE 时由 app.build_executor 延迟导入；DRY_RUN 镜像里甚至不安装 py-clob-client。
  - 不自己拼签名——EIP-712 签名、API 凭证派生全部交给官方客户端。
  - 只用限价单（GTC），超时（默认 30 秒）未成交则撤单；部分成交按已成交份额记账。
  - 本文件**未对真实 API 联调过**（开发环境无法访问 Polymarket）。Phase 2 首周强制 Telegram 逐单确认，
    正是为了在真金白银上线前先小额验证这条路径。
"""

from __future__ import annotations

import logging
import time
import uuid
from types import SimpleNamespace
from typing import Any, Callable, Optional

from .config import Mode, Settings
from .db import Database
from .logging_setup import LOGGER_NAME, log_event
from .market_data import ApiError, MarketDataService
from .models import CopySignal, ExecutionResult, Side, Trade, TradeOrder, TradeStatus
from .util import utcnow

log = logging.getLogger(f"{LOGGER_NAME}.live")
POLYGON_CHAIN_ID = 137


def load_sdk() -> SimpleNamespace:
    """延迟导入官方 SDK，便于测试时注入替身。"""
    from py_clob_client.clob_types import OrderArgs, OrderType, PartialCreateOrderOptions
    from py_clob_client.order_builder.constants import BUY, SELL

    return SimpleNamespace(OrderArgs=OrderArgs, OrderType=OrderType,
                           PartialCreateOrderOptions=PartialCreateOrderOptions, BUY=BUY, SELL=SELL)


def build_client(s: Settings) -> Any:
    from py_clob_client.client import ClobClient
    from py_clob_client.clob_types import ApiCreds

    client = ClobClient(s.clob_url, key=s.private_key, chain_id=POLYGON_CHAIN_ID,
                        signature_type=s.clob_signature_type, funder=s.clob_funder)
    if s.clob_api_key and s.clob_api_secret and s.clob_api_passphrase:
        creds = ApiCreds(api_key=s.clob_api_key, api_secret=s.clob_api_secret,
                         api_passphrase=s.clob_api_passphrase)
    else:
        creds = client.create_or_derive_api_creds()  # 由私钥派生，无需单独保管 API Key
    client.set_api_creds(creds)
    return client


class LiveExecutor:
    mode = Mode.LIVE

    def __init__(self, settings: Settings, db: Database, market_data: MarketDataService, *,
                 client: Any = None, sdk: Any = None, clock=utcnow,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic,
                 new_id: Callable[[], str] = lambda: str(uuid.uuid4())):
        if not settings.is_live:
            raise RuntimeError("LiveExecutor 只能在 MODE=LIVE 下构造")
        self._s, self._db, self._md = settings, db, market_data
        self._client = client if client is not None else build_client(settings)
        self._sdk = sdk if sdk is not None else load_sdk()
        self._clock, self._sleep, self._mono, self._new_id = clock, sleep, monotonic, new_id

    def execute(self, order: TradeOrder, sig: CopySignal) -> ExecutionResult:
        try:
            book = self._md.get_book(order.token_id, fresh=True)
        except ApiError as e:
            return ExecutionResult(False, f"book_unavailable: {e}")

        pos: Optional[Trade] = None
        if order.side is Side.SELL:
            pos = self._db.open_trade_for_token(Mode.LIVE, order.token_id)
            if pos is None:
                return ExecutionResult(False, "no_position")
            shares = pos.shares
        else:
            shares = order.shares

        try:
            signed = self._client.create_order(
                self._sdk.OrderArgs(token_id=order.token_id, price=order.limit_price, size=shares,
                                    side=self._sdk.BUY if order.side is Side.BUY else self._sdk.SELL),
                self._sdk.PartialCreateOrderOptions(tick_size=str(book.tick_size), neg_risk=book.neg_risk))
            resp = self._client.post_order(signed, self._sdk.OrderType.GTC)
        except Exception as e:  # noqa: BLE001 - SDK 抛出的异常类型不统一；消息可能含敏感头，只记类型
            log_event(log, logging.ERROR, "live_order_post_error", error=type(e).__name__, signal_id=order.signal_id)
            return ExecutionResult(False, f"post_error: {type(e).__name__}")

        order_id = resp.get("orderID") if isinstance(resp, dict) else None
        if not isinstance(resp, dict) or not resp.get("success", False) or not order_id:
            err = resp.get("errorMsg", "") if isinstance(resp, dict) else ""
            log_event(log, logging.ERROR, "live_order_rejected", signal_id=order.signal_id, error=str(err)[:200])
            return ExecutionResult(False, f"order_rejected: {str(err)[:100]}")
        log_event(log, logging.WARNING, "live_order_posted", order_id=order_id, side=order.side.value,
                  price=order.limit_price, shares=shares, signal_id=order.signal_id)

        matched = self._wait_for_fill(order_id, shares)
        if matched <= 1e-9:
            return ExecutionResult(False, f"timeout_no_fill ({self._s.order_timeout_sec}s)")

        avg = self._avg_price(resp, order, matched)
        if order.side is Side.BUY:
            return self._record_buy(order, order_id, matched, avg)
        return self._record_sell(order, pos, order_id, matched, avg)

    # ── 等待成交 / 超时撤单 ──────────────────────────
    def _wait_for_fill(self, order_id: str, shares: float) -> float:
        deadline = self._mono() + self._s.order_timeout_sec
        matched = 0.0
        while True:
            matched = self._matched(order_id)
            if matched >= shares - 1e-9 or self._mono() >= deadline:
                break
            self._sleep(1.0)
        if matched < shares - 1e-9:
            try:
                self._client.cancel(order_id)
                log_event(log, logging.WARNING, "live_order_cancelled_on_timeout", order_id=order_id)
            except Exception as e:  # noqa: BLE001
                log_event(log, logging.ERROR, "live_cancel_failed", order_id=order_id, error=type(e).__name__)
            matched = self._matched(order_id)  # 撤单期间可能又成交了一部分，以最终状态为准
        return matched

    def _matched(self, order_id: str) -> float:
        try:
            o = self._client.get_order(order_id)
            return float(o.get("size_matched", 0) or 0)
        except Exception as e:  # noqa: BLE001
            log_event(log, logging.ERROR, "live_get_order_failed", order_id=order_id, error=type(e).__name__)
            return 0.0

    @staticmethod
    def _avg_price(resp: dict, order: TradeOrder, matched: float) -> float:
        """尽力还原均价：下单响应里即时成交会带 makingAmount/takingAmount（USDC 与份额）。
        拿不到时回退到限价——对买单这是成本上界、对卖单是收入下界，即偏保守。"""
        try:
            making, taking = float(resp.get("makingAmount") or 0), float(resp.get("takingAmount") or 0)
            if making > 0 and taking > 0:
                usdc, sh = (making, taking) if order.side is Side.BUY else (taking, making)
                return usdc / sh
        except (TypeError, ValueError):
            pass
        return order.limit_price

    # ── 记账 ────────────────────────────────────────
    def _record_buy(self, order: TradeOrder, order_id: str, matched: float, avg: float) -> ExecutionResult:
        now = self._clock()
        trade = Trade(
            id=self._new_id(), signal_id=order.signal_id, mode=Mode.LIVE, market_id=order.market_id,
            token_id=order.token_id, market_type=order.market_type, status=TradeStatus.OPEN,
            executed_price=avg, shares=matched, amount_usd=matched * avg, opened_at=now, hour_utc=now.hour,
            order_id=order_id)
        self._db.open_trade(trade)
        log_event(log, logging.WARNING, "live_fill", side="BUY", trade_id=trade.id, order_id=order_id,
                  price=round(avg, 4), shares=matched, partial=matched < order.shares - 1e-9)
        return ExecutionResult(True, trade=trade, executed_price=avg, shares=matched)

    def _record_sell(self, order: TradeOrder, pos: Trade, order_id: str, matched: float, avg: float) -> ExecutionResult:
        target = pos
        if matched < pos.shares - 1e-9:  # 部分卖出：拆出已卖部分单独结算，剩余仍持有
            target = self._db.split_open_trade(pos.id, matched, self._new_id())
        pnl = matched * avg - target.amount_usd - target.fee_usd
        self._db.settle_trade(target.id, exit_price=avg, pnl_usd=pnl, extra_fee_usd=0.0, closed_at=self._clock())
        log_event(log, logging.WARNING, "live_fill", side="SELL", trade_id=target.id, order_id=order_id,
                  price=round(avg, 4), shares=matched, pnl_usd=round(pnl, 4), partial=target.id != pos.id)
        return ExecutionResult(True, trade=target, executed_price=avg, shares=matched)
