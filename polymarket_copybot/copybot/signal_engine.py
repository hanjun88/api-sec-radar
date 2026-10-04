"""信号引擎：把目标钱包的跟单信号与自有策略规则结合，决定是否下单。

BUY 的判定顺序（任一环节失败即短路，并记录稳定的原因码，供漏斗复盘）：
  0. 信号时效（TTL）
  1. 仅 BTC 市场 + 允许的市场类型
  2. 同一 token 已有持仓则不加仓
  3. [CONFIRM] 规则 1 时间窗口  →  规则 2 波动率
  4. 熔断状态
  5. 订单簿：滑点保护（最优卖价不得高于限价）
  6. [CONFIRM] 规则 3 贝叶斯 + Kelly 边际检验（后验胜率须高于市场价格隐含概率）
  7. 仓位 = 半 Kelly，受单笔上限 / 可用资金封顶
  8. 交易所最小下单量
  9. 风控放行

COPY_ONLY 模式跳过 3 与 6：目标钱包信号"直接触发（仅过风控）"。无 Kelly 边际时用固定小仓位。

SELL：目标钱包卖出我们持有的 token 时平掉整笔持仓（无持仓则忽略——Polymarket 无法裸卖空）。
退出永远不被入场规则或熔断拦截——降低风险的动作不该被风控挡住。
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from .bayes import BayesianTracker
from .btc import PriceFeed, classify_market, volatility
from .config import ConfirmMode, Settings
from .db import Database
from .kelly import size_position
from .logging_setup import LOGGER_NAME, log_event
from .market_data import ApiError, MarketDataService
from .models import (CopySignal, Decision, MarketInfo, RuleResult, Side, SignalStatus,
                     TradeOrder)
from .risk import RiskControl
from .time_window import TimeWindowFilter
from .util import floor_shares, round_to_tick, utcnow

log = logging.getLogger(f"{LOGGER_NAME}.engine")


class SignalEngine:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        market_data: MarketDataService,
        price_feed: PriceFeed,
        bayes: BayesianTracker,
        risk: RiskControl,
        *,
        clock=utcnow,
    ):
        self._s = settings
        self._db = db
        self._md = market_data
        self._feed = price_feed
        self._bayes = bayes
        self._risk = risk
        self._clock = clock
        self._window = TimeWindowFilter(db, settings.min_window_winrate_pct, settings.window_min_samples)

    # ── 入口 ────────────────────────────────────────
    def evaluate(self, sig: CopySignal) -> Decision:
        rules: list[RuleResult] = []
        now = self._clock()
        age = (now - sig.trade_time).total_seconds()
        if age > self._s.signal_ttl_sec:
            return self._reject(sig, rules, "signal_expired",
                                f"信号已过期 {age:.0f}s > TTL {self._s.signal_ttl_sec}s",
                                status=SignalStatus.EXPIRED)
        try:
            info = self._md.get_market_info(sig.token_id)
        except ApiError as e:
            return self._reject(sig, rules, "data_unavailable", f"市场元数据不可用: {e}")
        if not info.condition_id:
            return self._reject(sig, rules, "data_unavailable", "市场元数据缺少 conditionId，无法结算")
        try:
            if sig.side is Side.SELL:
                return self._evaluate_sell(sig, info, rules)
            return self._evaluate_buy(sig, info, rules, now)
        except ApiError as e:
            return self._reject(sig, rules, "data_unavailable", str(e), market_id=info.condition_id)

    # ── BUY ─────────────────────────────────────────
    def _evaluate_buy(self, sig: CopySignal, info: MarketInfo, rules: list[RuleResult], now: datetime) -> Decision:
        s = self._s
        mid = info.condition_id

        mtype = classify_market(info)
        if mtype is None:
            return self._reject(sig, rules, "not_btc_market", f"非 BTC 市场: {info.question!r}", market_id=mid)
        rules.append(RuleResult("btc_only", True, f"{mtype}: {info.question!r}", code="btc_ok"))
        if mtype not in s.market_types:
            return self._reject(sig, rules, "market_type_disabled",
                                f"{mtype} 不在允许列表 {list(s.market_types)}", market_id=mid, market_type=mtype)
        if self._db.open_trade_for_token(s.mode, sig.token_id):
            return self._reject(sig, rules, "already_holding", "该 token 已有持仓，不加仓",
                                market_id=mid, market_type=mtype)

        if s.confirm_mode is ConfirmMode.CONFIRM:
            r1 = self._window.check(mtype, now)
            rules.append(r1)
            if not r1.passed:
                return self._reject(sig, rules, r1.code, r1.detail, market_id=mid, market_type=mtype)
            r2 = self._volatility_rule()
            rules.append(r2)
            if not r2.passed:
                return self._reject(sig, rules, r2.code, r2.detail, market_id=mid, market_type=mtype)

        halt = self._risk.halt_status(now)
        if halt.halted:
            return self._reject(sig, rules, "risk_halted", f"{halt.code}: {halt.detail}",
                                market_id=mid, market_type=mtype)

        book = self._md.get_book(sig.token_id)
        tick = book.tick_size
        limit = min(round_to_tick(sig.price * (1 + s.max_slippage_pct / 100), tick, up=False), 1 - tick)
        ask = book.best_ask
        if ask is None:
            return self._reject(sig, rules, "no_liquidity", "卖盘为空", market_id=mid, market_type=mtype)
        if ask > limit + 1e-9:
            return self._reject(
                sig, rules, "slippage_exceeded",
                f"最优卖价 {ask:.4f} > 限价 {limit:.4f}（信号价 {sig.price:.4f} +{s.max_slippage_pct:g}%）",
                market_id=mid, market_type=mtype)

        wins, total = self._bayes.counts(mtype)
        p = self._bayes.p(mtype)
        equity = self._risk.equity()
        sized = size_position(equity, p, ask, multiplier=s.kelly_multiplier, max_position_pct=s.max_position_pct)
        has_edge = sized.full_kelly > 0
        bootstrap = s.bootstrap_active and total < s.bootstrap_trades

        if s.confirm_mode is ConfirmMode.CONFIRM:
            ok = has_edge or bootstrap
            rules.append(RuleResult(
                "bayes_kelly", ok,
                f"后验胜率 p={p:.3f}（{wins}/{total}）vs 价格 {ask:.3f}，f*={sized.full_kelly:.3f}"
                + ("；冷启动探索放行" if (bootstrap and not has_edge) else ""),
                code="" if ok else "no_edge"))
            if not ok:
                return self._reject(sig, rules, "no_edge", rules[-1].detail, market_id=mid, market_type=mtype)

        if has_edge:
            size_usd, basis = sized.usd, "kelly"
        else:
            frac = min(s.fallback_stake_pct, s.max_position_pct) / 100.0
            size_usd = equity * frac
            basis = "bootstrap" if s.confirm_mode is ConfirmMode.CONFIRM else "copy_only_fallback"
        size_usd = min(size_usd, self._risk.max_position_usd(), self._risk.cash_available())

        shares = floor_shares(size_usd / limit)
        if shares <= 0:
            return self._reject(sig, rules, "size_zero", f"仓位 {size_usd:.2f}$ 不足 1 份", market_id=mid, market_type=mtype)
        order_usd = round(shares * limit, 4)
        if s.enforce_min_order_size and book.min_order_size and shares < book.min_order_size:
            need = book.min_order_size * limit
            return self._reject(
                sig, rules, "below_min_order_size",
                f"{shares:g} 份 < 交易所最小 {book.min_order_size:g} 份（至少需要约 ${need:.2f}，当前仓位 ${order_usd:.2f}）",
                market_id=mid, market_type=mtype)

        verdict = self._risk.check_new_entry(order_usd)
        rules.append(RuleResult("risk", verdict.allowed, verdict.detail, code=verdict.code))
        if not verdict.allowed:
            return self._reject(sig, rules, verdict.code, verdict.detail, market_id=mid, market_type=mtype)

        reason = (f"{basis}: p={p:.3f} 价={ask:.3f} f*={sized.full_kelly:.3f} "
                  f"仓位=${order_usd:.2f}({order_usd / equity:.2%} of ${equity:.2f})")
        order = TradeOrder(
            signal_id=sig.signal_id, market_id=mid, token_id=sig.token_id, market_type=mtype, side=Side.BUY,
            limit_price=limit, shares=shares, size_usd=order_usd, kelly_fraction=order_usd / equity,
            reason=reason, p_win=p)
        log_event(log, logging.INFO, "signal_accepted", signal_id=sig.signal_id, market=info.question,
                  market_type=mtype, side="BUY", limit=limit, shares=shares, size_usd=order_usd,
                  p=round(p, 4), full_kelly=round(sized.full_kelly, 4), basis=basis,
                  rules=[(r.name, r.passed, r.detail) for r in rules])
        return Decision(sig.signal_id, SignalStatus.PENDING, rules, order, market_type=mtype, market_id=mid)

    # ── SELL ────────────────────────────────────────
    def _evaluate_sell(self, sig: CopySignal, info: MarketInfo, rules: list[RuleResult]) -> Decision:
        s, mid = self._s, info.condition_id
        pos = self._db.open_trade_for_token(s.mode, sig.token_id)
        if pos is None:
            return self._reject(sig, rules, "no_position_to_sell", "目标钱包卖出，但我们没有该 token 的持仓",
                                market_id=mid)
        book = self._md.get_book(sig.token_id)
        tick = book.tick_size
        limit = max(round_to_tick(sig.price * (1 - s.max_slippage_pct / 100), tick, up=True), tick)
        if s.enforce_min_order_size and book.min_order_size and pos.shares < book.min_order_size:
            return self._reject(
                sig, rules, "position_below_min_order_size",
                f"持仓 {pos.shares:g} 份 < 交易所最小 {book.min_order_size:g} 份，无法卖出，持有至结算",
                market_id=mid, market_type=pos.market_type)
        order = TradeOrder(
            signal_id=sig.signal_id, market_id=mid, token_id=sig.token_id, market_type=pos.market_type,
            side=Side.SELL, limit_price=limit, shares=pos.shares, size_usd=round(pos.shares * limit, 4),
            kelly_fraction=0.0, reason="mirror_exit: 目标钱包卖出，平掉整笔持仓")
        log_event(log, logging.INFO, "signal_accepted", signal_id=sig.signal_id, market=info.question,
                  market_type=pos.market_type, side="SELL", limit=limit, shares=pos.shares)
        return Decision(sig.signal_id, SignalStatus.PENDING, rules, order,
                        market_type=pos.market_type, market_id=mid)

    # ── 规则 2：波动率 ───────────────────────────────
    def _volatility_rule(self) -> RuleResult:
        thr = self._s.volatility_threshold_pct / 100.0
        try:
            vol = volatility(self._feed.closes_last_hour())
        except ApiError as e:
            # 取不到行情时保守处理：不下单
            return RuleResult("volatility", False, f"波动率数据不可用: {e}", code="volatility_unavailable")
        if vol > thr:
            return RuleResult("volatility", False, f"1h 波动率 {vol:.3%} > 阈值 {thr:.2%}", code="volatility_high")
        return RuleResult("volatility", True, f"1h 波动率 {vol:.3%} ≤ 阈值 {thr:.2%}", code="volatility_ok")

    # ── 工具 ────────────────────────────────────────
    def _reject(
        self, sig: CopySignal, rules: list[RuleResult], code: str, detail: str, *,
        status: SignalStatus = SignalStatus.FILTERED, market_id: Optional[str] = None,
        market_type: Optional[str] = None,
    ) -> Decision:
        log_event(log, logging.INFO, "signal_filtered", signal_id=sig.signal_id, token_id=sig.token_id,
                  side=sig.side.value, code=code, detail=detail,
                  rules=[(r.name, r.passed, r.detail) for r in rules])
        return Decision(sig.signal_id, status, rules, None, code, detail, market_type, market_id)
