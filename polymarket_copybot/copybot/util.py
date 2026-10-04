"""通用小工具：UTC 时间与价格/数量取整。所有时间一律 UTC。"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """序列化为带时区的 ISO-8601（UTC）。"""
    if dt.tzinfo is None:
        raise ValueError("naive datetime 不允许入库，必须带时区")
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError(f"缺少时区: {s!r}")
    return dt.astimezone(timezone.utc)


def from_unix(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, timezone.utc)


def round_to_tick(price: float, tick: float, *, up: bool) -> float:
    """把价格对齐到 tick 的整数倍（Decimal 避免浮点误差）。

    买单限价向下取整（不超过滑点上限），卖单限价向上取整（不低于滑点下限）。
    """
    if tick <= 0:
        raise ValueError("tick 必须为正")
    d_tick = Decimal(str(tick))
    steps = (Decimal(str(price)) / d_tick).to_integral_value(
        rounding=ROUND_CEILING if up else ROUND_FLOOR
    )
    return float(steps * d_tick)


def floor_shares(shares: float, decimals: int = 2) -> float:
    """份额向下取整到 decimals 位（CLOB 的 size 精度），保证花费不超预算。"""
    q = Decimal(1).scaleb(-decimals)
    return float(Decimal(str(shares)).quantize(q, rounding=ROUND_FLOOR))
