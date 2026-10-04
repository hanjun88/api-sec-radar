"""贝叶斯胜率更新：Beta(α, β) 先验 + 二项观测，后验均值 p = (wins + α) / (total + α + β)。

α=β=1 即拉普拉斯平滑（无数据时 p=0.5）。状态持久化在 SQLite，重启不丢。
写入由 `Database.settle_trade` 在结算事务里完成（保证不重复计数），本模块只负责读取与计算。
"""

from __future__ import annotations

from .db import Database


def posterior_mean(wins: int, total: int, alpha: float = 1.0, beta: float = 1.0) -> float:
    if alpha <= 0 or beta <= 0:
        raise ValueError("alpha/beta 必须为正")
    if total < 0 or not 0 <= wins <= total:
        raise ValueError(f"非法的胜负计数 wins={wins}, total={total}")
    return (wins + alpha) / (total + alpha + beta)


class BayesianTracker:
    def __init__(self, db: Database, alpha: float = 1.0, beta: float = 1.0):
        if alpha <= 0 or beta <= 0:
            raise ValueError("alpha/beta 必须为正")
        self._db = db
        self.alpha = alpha
        self.beta = beta

    def counts(self, market_type: str) -> tuple[int, int]:
        s = self._db.bayes_state(market_type)
        return s.wins, s.total

    def p(self, market_type: str) -> float:
        wins, total = self.counts(market_type)
        return posterior_mean(wins, total, self.alpha, self.beta)
