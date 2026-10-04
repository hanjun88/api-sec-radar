"""规则 1：时间窗口过滤。

按（市场类型, UTC 小时）统计**本系统已结算交易**的历史胜率；胜率低于阈值（默认 65%）的时段丢弃信号。
冷启动：该时段样本数不足 `min_samples` 时放行（否则永远没有数据可统计），并在日志里标明。
"""

from __future__ import annotations

from datetime import datetime

from .db import Database
from .models import RuleResult


class TimeWindowFilter:
    def __init__(self, db: Database, min_winrate_pct: float, min_samples: int):
        self._db = db
        self._min = min_winrate_pct / 100.0
        self._min_samples = min_samples

    def check(self, market_type: str, now: datetime) -> RuleResult:
        hour = now.hour
        s = self._db.hourly_state(market_type, hour)
        if s.total < self._min_samples:
            return RuleResult(
                "time_window", True,
                f"{market_type} {hour:02d}:00 UTC 样本 {s.total}<{self._min_samples}，冷启动放行",
                code="window_cold_start")
        rate = s.wins / s.total
        if rate < self._min:
            return RuleResult(
                "time_window", False,
                f"{market_type} {hour:02d}:00 UTC 历史胜率 {rate:.1%}（{s.wins}/{s.total}）< {self._min:.0%}",
                code="window_winrate_low")
        return RuleResult(
            "time_window", True,
            f"{market_type} {hour:02d}:00 UTC 历史胜率 {rate:.1%}（{s.wins}/{s.total}）≥ {self._min:.0%}",
            code="window_ok")
