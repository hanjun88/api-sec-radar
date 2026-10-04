"""领域模型：纯数据，无 I/O。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .config import Mode


class Side(str, Enum):
    BUY = "BUY"
    SELL = "SELL"


class SignalStatus(str, Enum):
    PENDING = "PENDING"
    FILTERED = "FILTERED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


class TradeStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class Fill:
    """目标钱包的一笔原始成交（链上日志或 Data API 解析而来）。"""
    tx_hash: str
    token_id: str
    side: Side
    price: float
    shares: float
    trade_time: datetime
    market_id: Optional[str] = None  # conditionId；链上来源拿不到，后续由 Gamma 补全

    @property
    def usd(self) -> float:
        return self.price * self.shares


@dataclass(frozen=True)
class CopySignal:
    """跟单信号：同一笔交易内同 token 同方向的成交聚合后的结果。"""
    signal_id: str
    token_id: str
    side: Side
    price: float          # 目标钱包的加权成交价
    shares: float
    amount_usd: float     # 目标钱包的成交金额（仅记录，不决定我们的仓位）
    tx_hash: str
    trade_time: datetime  # 链上成交时间（UTC）
    detected_at: datetime
    market_id: Optional[str] = None


@dataclass(frozen=True)
class MarketInfo:
    condition_id: str
    token_id: str
    question: str
    slug: str
    outcome: str
    end_date: Optional[datetime] = None
    closed: bool = False


@dataclass(frozen=True)
class Level:
    price: float
    size: float


@dataclass(frozen=True)
class OrderBook:
    token_id: str
    bids: tuple[Level, ...]  # 价格从高到低
    asks: tuple[Level, ...]  # 价格从低到高
    tick_size: float = 0.01
    min_order_size: Optional[float] = None
    neg_risk: bool = False

    @property
    def best_bid(self) -> Optional[float]:
        return self.bids[0].price if self.bids else None

    @property
    def best_ask(self) -> Optional[float]:
        return self.asks[0].price if self.asks else None

    def fill_buy(self, shares: float, limit: float) -> tuple[float, float]:
        """按卖盘从低到高吃单，只吃 ≤ limit 的档位。返回 (成交份额, 加权均价)。"""
        return _walk(self.asks, shares, lambda p: p <= limit + 1e-12)

    def fill_sell(self, shares: float, limit: float) -> tuple[float, float]:
        """按买盘从高到低吃单，只吃 ≥ limit 的档位。返回 (成交份额, 加权均价)。"""
        return _walk(self.bids, shares, lambda p: p >= limit - 1e-12)


def _walk(levels: tuple[Level, ...], shares: float, ok) -> tuple[float, float]:
    remaining, cost = shares, 0.0
    for lv in levels:
        if remaining <= 1e-9 or not ok(lv.price):
            break
        take = min(remaining, lv.size)
        cost += take * lv.price
        remaining -= take
    filled = shares - remaining
    return filled, (cost / filled if filled > 0 else 0.0)


@dataclass(frozen=True)
class RuleResult:
    name: str
    passed: bool
    detail: str = ""
    code: str = ""  # 稳定的机器可读原因码，用于漏斗统计


@dataclass(frozen=True)
class TradeOrder:
    """信号引擎输出的交易指令。"""
    signal_id: str
    market_id: str
    token_id: str
    market_type: str
    side: Side
    limit_price: float
    shares: float
    size_usd: float
    kelly_fraction: float  # 实际使用的仓位比例（半 Kelly 之后、封顶之前的原始值见 reason）
    reason: str
    p_win: Optional[float] = None


@dataclass
class Decision:
    signal_id: str
    status: SignalStatus
    rules: list[RuleResult] = field(default_factory=list)
    order: Optional[TradeOrder] = None
    reason_code: str = ""
    reason_detail: str = ""
    market_type: Optional[str] = None
    market_id: Optional[str] = None

    @property
    def accepted(self) -> bool:
        return self.order is not None


@dataclass
class Trade:
    id: str
    signal_id: str
    mode: Mode
    market_id: str
    token_id: str
    market_type: str
    status: TradeStatus
    executed_price: float
    shares: float
    amount_usd: float
    opened_at: datetime
    hour_utc: int
    fee_usd: float = 0.0
    exit_price: Optional[float] = None
    pnl_usd: Optional[float] = None
    closed_at: Optional[datetime] = None
    order_id: Optional[str] = None


@dataclass(frozen=True)
class ExecutionResult:
    filled: bool
    reason: str = ""
    trade: Optional[Trade] = None
    executed_price: float = 0.0
    shares: float = 0.0
