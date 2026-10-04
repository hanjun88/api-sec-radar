"""Kelly 仓位计算（纯函数）。

f* = (p·b − q) / b，b = 1/price − 1（买入价为 price 的二元合约，赢则每份赔 1），q = 1 − p。
实际使用半 Kelly，并受单笔上限封顶。
"""

from __future__ import annotations

import math
from dataclasses import dataclass

_MIN_B = 1e-9


def odds(price: float) -> float:
    """赔率 b = 1/price − 1。价格不在 (0,1) 开区间内时返回 0（视为不可交易，调用方跳过）。"""
    if not math.isfinite(price) or price <= 0.0 or price >= 1.0:
        return 0.0
    return 1.0 / price - 1.0


def kelly_fraction(p: float, price: float) -> float:
    """完整 Kelly 比例，范围 [0, 1]。无优势（f*≤0）、b≈0 或价格非法时返回 0.0。

    - p 必须是 [0,1] 内的有限数，否则抛 ValueError（这是调用方的 bug，不应被静默吞掉）。
    - b=0（价格≥1 或≤0）时除零保护：直接返回 0.0。
    """
    if not math.isfinite(p) or not 0.0 <= p <= 1.0:
        raise ValueError(f"p 必须在 [0,1] 内，收到 {p!r}")
    b = odds(price)
    if b <= _MIN_B:
        return 0.0
    q = 1.0 - p
    f = (p * b - q) / b
    return min(max(f, 0.0), 1.0)


@dataclass(frozen=True)
class SizeResult:
    full_kelly: float     # f*
    fraction: float       # 实际使用的比例 = min(f*·multiplier, 单笔上限)
    usd: float
    capped: bool          # 是否被单笔上限截断


def size_position(
    equity: float, p: float, price: float, *, multiplier: float = 0.5, max_position_pct: float = 5.0,
) -> SizeResult:
    """半 Kelly 仓位，单笔不超过总资金的 max_position_pct%。"""
    if equity <= 0:
        return SizeResult(0.0, 0.0, 0.0, False)
    f_star = kelly_fraction(p, price)
    raw = f_star * multiplier
    cap = max_position_pct / 100.0
    fraction = min(raw, cap)
    return SizeResult(f_star, fraction, equity * fraction, raw > cap)
