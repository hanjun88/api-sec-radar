"""Phase 1 验收所需的复盘报表：模拟盈亏、胜率、最大回撤、信号漏斗、各时段统计、权益曲线 CSV。"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from typing import Optional

from .bayes import posterior_mean
from .config import Mode, Settings
from .db import Database
from .models import Trade


@dataclass(frozen=True)
class Summary:
    mode: str
    trades: int
    wins: int
    win_rate: Optional[float]
    total_pnl: float
    avg_pnl: Optional[float]
    start_equity: float
    end_equity: float
    max_drawdown_pct: float
    open_positions: int


def equity_curve(trades: list[Trade], bankroll: float) -> list[tuple[str, float, float]]:
    """[(平仓时间, 本笔盈亏, 累计权益)]，按平仓时间排序。"""
    eq, out = bankroll, []
    for t in trades:
        eq += t.pnl_usd or 0.0
        out.append((t.closed_at.isoformat(timespec="seconds"), t.pnl_usd or 0.0, eq))
    return out


def max_drawdown_pct(curve: list[tuple[str, float, float]], bankroll: float) -> float:
    peak, worst = bankroll, 0.0
    for _, _, eq in curve:
        peak = max(peak, eq)
        if peak > 0:
            worst = max(worst, (peak - eq) / peak)
    return worst * 100.0


def summarize(db: Database, settings: Settings, mode: Optional[Mode] = None) -> Summary:
    mode = mode or settings.mode
    trades = db.closed_trades(mode)
    curve = equity_curve(trades, settings.bankroll_usd)
    wins = sum(1 for t in trades if (t.pnl_usd or 0) > 0)
    total = sum(t.pnl_usd or 0.0 for t in trades)
    return Summary(
        mode=mode.value, trades=len(trades), wins=wins, win_rate=(wins / len(trades)) if trades else None,
        total_pnl=total, avg_pnl=(total / len(trades)) if trades else None, start_equity=settings.bankroll_usd,
        end_equity=settings.bankroll_usd + total, max_drawdown_pct=max_drawdown_pct(curve, settings.bankroll_usd),
        open_positions=len(db.open_trades(mode)))


def export_equity_csv(db: Database, settings: Settings, path: str, mode: Optional[Mode] = None) -> int:
    curve = equity_curve(db.closed_trades(mode or settings.mode), settings.bankroll_usd)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["closed_at_utc", "pnl_usd", "equity_usd"])
        w.writerows([(ts, f"{pnl:.4f}", f"{eq:.4f}") for ts, pnl, eq in curve])
    return len(curve)


def render(db: Database, settings: Settings) -> str:
    s = summarize(db, settings)
    lines = [f"=== 复盘报表（{s.mode}）===",
             f"已平仓交易 {s.trades} 笔，胜 {s.wins}，胜率 " + (f"{s.win_rate:.1%}" if s.win_rate is not None else "n/a"),
             f"累计盈亏 ${s.total_pnl:+.2f}，资金 ${s.start_equity:.2f} → ${s.end_equity:.2f}，"
             f"最大回撤 {s.max_drawdown_pct:.1f}%，当前持仓 {s.open_positions} 笔",
             "", "— 贝叶斯后验胜率（按市场类型）—"]
    rows = db.all_bayes()
    if not rows:
        lines.append("  （暂无已结算交易）")
    for r in rows:
        p = posterior_mean(r["wins"], r["total"], settings.bayes_alpha, settings.bayes_beta)
        lines.append(f"  {r['market_type']:<11} {r['wins']}/{r['total']}  p={p:.3f}")
    lines += ["", "— 各 UTC 小时胜率 —"]
    hourly = db.all_hourly()
    if not hourly:
        lines.append("  （暂无数据）")
    for r in hourly:
        lines.append(f"  {r['market_type']:<11} {r['hour_utc']:02d}:00  {r['wins']}/{r['total']}"
                     f"  ({r['wins'] / r['total']:.0%})")
    lines += ["", "— 信号漏斗（状态 / 原因码 / 数量）—"]
    funnel = db.signal_funnel()
    if not funnel:
        lines.append("  （暂无信号）")
    for status, code, n in funnel:
        lines.append(f"  {status:<9} {code or '-':<28} {n}")
    return "\n".join(lines)
