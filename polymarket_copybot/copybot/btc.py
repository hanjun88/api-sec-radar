"""BTC 市场识别 + BTC 价格源 + 波动率。

市场类型（用于贝叶斯与小时胜率分桶）：
  BTC_HOURLY  "Bitcoin Up or Down - October 4, 3PM ET" 这类按小时结算的涨跌市场
  BTC_SHORT   5/15 分钟级别的涨跌市场（题目含 "3:15PM-3:30PM" 区间或 slug 含 15m）
  BTC_OTHER   其余与 BTC 相关的市场（"价格是否高于 X" 等）
识别基于 question/slug 的关键词启发式，**未对真实线上命名做过联调**；
每条信号的日志都会带上 question 与识别结果，便于人工核对后用 MARKET_TYPES 收窄。
"""

from __future__ import annotations

import re
import statistics
import time
from typing import Callable, Optional, Protocol

import httpx

from .market_data import ApiError, ApiReporter, get_json
from .models import MarketInfo

_BTC_RE = re.compile(r"\b(bitcoin|btc)\b", re.I)
_UPDOWN_RE = re.compile(r"up\s*or\s*down|updown", re.I)
_RANGE_RE = re.compile(r"\d{1,2}(?::\d{2})?\s*[ap]m\s*[-–—]\s*\d{1,2}(?::\d{2})?\s*[ap]m", re.I)
_HOUR_RE = re.compile(r"\b\d{1,2}\s*[ap]m\b", re.I)
_SHORT_SLUG_RE = re.compile(r"\b(5|15)m\b", re.I)


def classify_market(info: MarketInfo) -> Optional[str]:
    """非 BTC 市场返回 None。"""
    slug = info.slug.replace("-", " ")
    text = f"{info.question} {slug}"
    if not _BTC_RE.search(text):
        return None
    if _RANGE_RE.search(info.question) or _SHORT_SLUG_RE.search(slug):
        return "BTC_SHORT"
    if _UPDOWN_RE.search(text) and _HOUR_RE.search(text):
        return "BTC_HOURLY"
    return "BTC_OTHER"


class InsufficientData(ApiError):
    pass


def volatility(closes: list[float], *, min_points: int = 10) -> float:
    """波动率 = 标准差 / 均值（文档口径，对价格水平而非收益率）。

    注意：对 BTC 而言 1 小时内价格水平的变异系数通常只有零点几个百分点，
    默认 2% 阈值很宽松，实际更像"极端行情熔断"；如需更敏感请调低 VOLATILITY_THRESHOLD_PCT。
    """
    if len(closes) < min_points:
        raise InsufficientData(f"price_feed: K 线不足 {len(closes)}<{min_points}")
    mean = statistics.fmean(closes)
    if mean <= 0:
        raise InsufficientData("price_feed: 均价非正")
    return statistics.pstdev(closes) / mean


class PriceFeed(Protocol):
    def closes_last_hour(self) -> list[float]: ...


class CoinbasePriceFeed:
    """Coinbase Exchange 公开 1 分钟 K 线（美国 IP 可用；Binance 对美国 IP 返回 451，故不用）。"""

    def __init__(
        self,
        http: httpx.Client,
        base_url: str,
        report: Optional[ApiReporter] = None,
        *,
        ttl_sec: float = 30.0,
        monotonic: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ):
        self._http, self._base, self._report = http, base_url.rstrip("/"), report
        self._ttl, self._mono, self._wall = ttl_sec, monotonic, wall
        self._cache: Optional[tuple[float, list[float]]] = None

    def closes_last_hour(self) -> list[float]:
        now = self._mono()
        if self._cache and now - self._cache[0] < self._ttl:
            return self._cache[1]
        raw = get_json(self._http, "price_feed", f"{self._base}/products/BTC-USD/candles",
                       {"granularity": 60}, self._report)
        if not isinstance(raw, list):
            raise ApiError("price_feed: K 线响应结构异常")
        cutoff = self._wall() - 3600
        rows = []
        for c in raw:  # [time, low, high, open, close, volume]，新→旧
            try:
                if float(c[0]) >= cutoff:
                    rows.append((float(c[0]), float(c[4])))
            except (IndexError, TypeError, ValueError):
                continue
        rows.sort()
        closes = [c for _, c in rows]
        self._cache = (now, closes)
        return closes
