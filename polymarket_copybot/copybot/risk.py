"""风控：日亏损熔断、总回撤熔断、API 连续失败停机、单笔/总敞口上限。

两类熔断：
  - 日亏损：不锁存。按 UTC 日历日重算，次日 00:00 UTC 自动解除（"当天停机"）。
  - 总回撤 / API 连续失败：**锁存进数据库**，需人工 `reset-halt` 才能恢复。
    锁存必须落库：Docker/systemd 的自动重启会让进程"重新满血"，只放内存等于熔断形同虚设。

口径（文档未明确处的取舍）：
  - 总资金 equity = BANKROLL_USD + 已实现盈亏（按 mode 隔离，DRY 的盈亏不会影响 LIVE 的熔断）。
  - 总回撤 = (峰值 equity − 当前 equity) / 峰值 equity。
  - 日亏损 = 当日(UTC)平仓交易的已实现亏损 / 当日开盘 equity。
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Protocol

from .config import Settings
from .db import Database
from .logging_setup import LOGGER_NAME, log_event
from .util import iso, utcnow

log = logging.getLogger(f"{LOGGER_NAME}.risk")

HALT_KEY = "risk:halt"
PEAK_KEY = "risk:peak_equity"
_EPS = 1e-9


class Notifier(Protocol):
    def send(self, text: str) -> None: ...


@dataclass(frozen=True)
class HaltStatus:
    halted: bool
    code: str = ""
    detail: str = ""
    latched: bool = False  # True = 需人工 reset-halt


@dataclass(frozen=True)
class RiskVerdict:
    allowed: bool
    code: str = ""
    detail: str = ""


class RiskControl:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        *,
        clock: Callable[[], datetime] = utcnow,
        notifier: Optional[Notifier] = None,
    ):
        self._db = db
        self._s = settings
        self._clock = clock
        self._notifier = notifier
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._daily_alerted: Optional[str] = None

    # ── 资金口径 ────────────────────────────────────
    def equity(self) -> float:
        return self._s.bankroll_usd + self._db.realized_pnl(self._s.mode)

    def peak_equity(self) -> float:
        # 没有记录时以初始资金为峰值；reset-halt 会把峰值重置为当时的资金（可能低于初始资金）
        stored = self._db.kv_get(PEAK_KEY)
        return float(stored) if stored else self._s.bankroll_usd

    def daily_pnl(self, now: Optional[datetime] = None) -> float:
        day = (now or self._clock()).date().isoformat()
        return self._db.realized_pnl(self._s.mode, day=day)

    def cash_available(self) -> float:
        return max(self.equity() - self._db.open_exposure(self._s.mode), 0.0)

    def max_position_usd(self) -> float:
        return self.equity() * self._s.max_position_pct / 100.0

    # ── 熔断状态 ────────────────────────────────────
    def halt_status(self, now: Optional[datetime] = None) -> HaltStatus:
        raw = self._db.kv_get(HALT_KEY)
        if raw:
            d = json.loads(raw)
            return HaltStatus(True, d["code"], d["detail"], latched=True)
        now = now or self._clock()
        pnl = self.daily_pnl(now)
        if pnl < 0:
            start_equity = self.equity() - pnl
            limit = self._s.max_daily_loss_pct / 100.0 * start_equity
            if -pnl >= limit - _EPS:
                return HaltStatus(
                    True, "daily_loss_limit",
                    f"当日亏损 {-pnl:.2f} ≥ 上限 {limit:.2f}（{self._s.max_daily_loss_pct:g}% × 开盘资金 {start_equity:.2f}）",
                )
        return HaltStatus(False)

    def _latch(self, code: str, detail: str) -> None:
        if self._db.kv_get(HALT_KEY):
            return  # 已锁存，保留最先触发的原因
        self._db.kv_set(HALT_KEY, json.dumps({"code": code, "detail": detail, "at": iso(self._clock())}))
        log_event(log, logging.CRITICAL, "risk_halt_latched", code=code, detail=detail)
        self._alert(f"🛑 熔断停机：{code}\n{detail}\n需人工执行 reset-halt 后才会恢复。")

    def reset_halt(self) -> bool:
        had = self._db.kv_get(HALT_KEY) is not None
        self._db.kv_delete(HALT_KEY)
        with self._lock:
            self._failures.clear()
        # 回撤熔断复位后，把峰值重置为当前资金，否则会立刻再次触发
        self._db.kv_set(PEAK_KEY, repr(self.equity()))
        if had:
            log_event(log, logging.WARNING, "risk_halt_reset", equity=self.equity())
        return had

    # ── 事件入口 ────────────────────────────────────
    def record_api_result(self, service: str, ok: bool) -> None:
        """每次外部 API 调用后上报。同一服务连续失败达上限 → 锁存停机。"""
        with self._lock:
            if ok:
                self._failures[service] = 0
                return
            n = self._failures.get(service, 0) + 1
            self._failures[service] = n
        if n >= self._s.api_failure_limit:
            self._latch("api_failures", f"{service} 连续失败 {n} 次（上限 {self._s.api_failure_limit}）")

    def evaluate_after_close(self) -> HaltStatus:
        """每笔交易平仓后调用：刷新峰值、检查总回撤与日亏损。"""
        equity = self.equity()
        peak = max(self.peak_equity(), equity)
        self._db.kv_set(PEAK_KEY, repr(peak))
        drawdown = (peak - equity) / peak if peak > 0 else 0.0
        limit = self._s.max_total_drawdown_pct / 100.0
        if drawdown >= limit - _EPS:
            self._latch(
                "total_drawdown",
                f"总回撤 {drawdown:.1%} ≥ 上限 {limit:.0%}（峰值 {peak:.2f} → 当前 {equity:.2f}）")
        status = self.halt_status()
        if status.halted and not status.latched:
            day = self._clock().date().isoformat()
            if self._daily_alerted != day:
                self._daily_alerted = day
                log_event(log, logging.WARNING, "risk_daily_halt", detail=status.detail)
                self._alert(f"⚠️ 日亏损熔断：{status.detail}\n今日(UTC)停止开新仓，明日自动恢复。")
        return status

    # ── 开仓前检查 ──────────────────────────────────
    def check_new_entry(self, size_usd: float) -> RiskVerdict:
        status = self.halt_status()
        if status.halted:
            return RiskVerdict(False, "risk_halted", f"{status.code}: {status.detail}")
        if size_usd <= 0:
            return RiskVerdict(False, "size_zero", "仓位为 0")
        cap = self.max_position_usd()
        if size_usd > cap + 1e-6:
            return RiskVerdict(False, "position_cap", f"{size_usd:.2f} > 单笔上限 {cap:.2f}")
        cash = self.cash_available()
        if size_usd > cash + 1e-6:
            return RiskVerdict(False, "exposure_cap", f"{size_usd:.2f} > 可用资金 {cash:.2f}（已有持仓占用）")
        return RiskVerdict(True)

    def _alert(self, text: str) -> None:
        if self._notifier is not None:
            try:
                self._notifier.send(text)
            except Exception:  # 告警失败绝不能影响风控本身
                log.exception("alert_failed")
