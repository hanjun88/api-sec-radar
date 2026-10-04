"""SQLite 持久化：信号、交易、贝叶斯状态、小时胜率、键值（游标/熔断锁存）。

线程模型：监控线程与主线程共用一个连接，所有访问经 RLock 串行化。
事务：写操作用 `with self._lock, self._conn:`，异常自动回滚。
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from .config import Mode
from .models import CopySignal, SignalStatus, Trade, TradeStatus
from .util import iso, parse_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
    id              TEXT PRIMARY KEY,
    market_id       TEXT,
    token_id        TEXT NOT NULL,
    side            TEXT NOT NULL,
    source          TEXT NOT NULL,
    suggested_price REAL NOT NULL,
    kelly_fraction  REAL,
    status          TEXT NOT NULL,
    reason_code     TEXT,
    reason_detail   TEXT,
    market_type     TEXT,
    tx_hash         TEXT,
    target_usd      REAL,
    trade_time      TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_status ON signals(status);

CREATE TABLE IF NOT EXISTS trades (
    id             TEXT PRIMARY KEY,
    signal_id      TEXT NOT NULL REFERENCES signals(id),
    mode           TEXT NOT NULL,
    market_id      TEXT NOT NULL,
    token_id       TEXT NOT NULL,
    market_type    TEXT NOT NULL,
    status         TEXT NOT NULL,
    executed_price REAL NOT NULL,
    shares         REAL NOT NULL,
    amount_usd     REAL NOT NULL,
    fee_usd        REAL NOT NULL DEFAULT 0,
    exit_price     REAL,
    pnl_usd        REAL,
    opened_at      TEXT NOT NULL,
    closed_at      TEXT,
    order_id       TEXT,
    hour_utc       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trades_open ON trades(mode, status);

CREATE TABLE IF NOT EXISTS bayesian_state (
    market_type TEXT PRIMARY KEY,
    wins        INTEGER NOT NULL,
    total       INTEGER NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hourly_stats (
    market_type TEXT NOT NULL,
    hour_utc    INTEGER NOT NULL,
    wins        INTEGER NOT NULL,
    total       INTEGER NOT NULL,
    PRIMARY KEY (market_type, hour_utc)
);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class WinLoss:
    wins: int
    total: int


class Database:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── 信号 ──────────────────────────────────────────
    def insert_signal(self, sig: CopySignal, *, source: str = "COPY") -> bool:
        """幂等写入。返回 True 表示是新信号；False 表示已存在（重复检测，调用方不应再入队）。"""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO signals (id, market_id, token_id, side, source, suggested_price,"
                " status, tx_hash, target_usd, trade_time, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (sig.signal_id, sig.market_id, sig.token_id, sig.side.value, source, sig.price,
                 SignalStatus.PENDING.value, sig.tx_hash, sig.amount_usd, iso(sig.trade_time),
                 iso(sig.detected_at)),
            )
            return cur.rowcount == 1

    def set_signal(
        self, signal_id: str, status: SignalStatus, *, reason_code: str = "", reason_detail: str = "",
        kelly_fraction: Optional[float] = None, market_id: Optional[str] = None,
        market_type: Optional[str] = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE signals SET status=?, reason_code=?, reason_detail=?,"
                " kelly_fraction=COALESCE(?, kelly_fraction), market_id=COALESCE(?, market_id),"
                " market_type=COALESCE(?, market_type) WHERE id=?",
                (status.value, reason_code, reason_detail, kelly_fraction, market_id, market_type, signal_id),
            )

    def expire_stale_pending(self, cutoff: datetime) -> int:
        """崩溃/重启后，内存队列已丢失：把早于 cutoff 仍为 PENDING 的信号标记为 EXPIRED。"""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE signals SET status=?, reason_code='restart_orphan',"
                " reason_detail='进程重启时仍在队列中，已作废' WHERE status=? AND created_at<?",
                (SignalStatus.EXPIRED.value, SignalStatus.PENDING.value, iso(cutoff)))
            return cur.rowcount

    def get_signal(self, signal_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM signals WHERE id=?", (signal_id,)).fetchone()

    def signal_funnel(self) -> list[tuple[str, str, int]]:
        """(status, reason_code, count)，用于复盘"每次过滤原因"。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COALESCE(reason_code,''), COUNT(*) FROM signals"
                " GROUP BY 1,2 ORDER BY 3 DESC").fetchall()
        return [(r[0], r[1], r[2]) for r in rows]

    # ── 交易 ──────────────────────────────────────────
    def open_trade(self, t: Trade) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO trades (id, signal_id, mode, market_id, token_id, market_type, status,"
                " executed_price, shares, amount_usd, fee_usd, opened_at, order_id, hour_utc)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (t.id, t.signal_id, t.mode.value, t.market_id, t.token_id, t.market_type,
                 TradeStatus.OPEN.value, t.executed_price, t.shares, t.amount_usd, t.fee_usd,
                 iso(t.opened_at), t.order_id, t.hour_utc),
            )

    def open_trades(self, mode: Mode) -> list[Trade]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM trades WHERE mode=? AND status=? ORDER BY opened_at",
                (mode.value, TradeStatus.OPEN.value)).fetchall()
        return [_trade(r) for r in rows]

    def open_trade_for_token(self, mode: Mode, token_id: str) -> Optional[Trade]:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM trades WHERE mode=? AND status=? AND token_id=? LIMIT 1",
                (mode.value, TradeStatus.OPEN.value, token_id)).fetchone()
        return _trade(r) if r else None

    def closed_trades(self, mode: Optional[Mode] = None) -> list[Trade]:
        with self._lock:
            if mode is None:
                rows = self._conn.execute(
                    "SELECT * FROM trades WHERE status=? ORDER BY closed_at, rowid",
                    (TradeStatus.CLOSED.value,)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM trades WHERE status=? AND mode=? ORDER BY closed_at, rowid",
                    (TradeStatus.CLOSED.value, mode.value)).fetchall()
        return [_trade(r) for r in rows]

    def split_open_trade(self, trade_id: str, sold_shares: float, child_id: str) -> Trade:
        """部分平仓：把 sold_shares 份拆成一笔新的 OPEN 子交易（成本/手续费按份额比例），原交易缩减。

        随后由调用方对子交易调用 settle_trade 记账。仅 LIVE 的部分成交会用到。
        """
        with self._lock, self._conn:
            r = self._conn.execute(
                "SELECT * FROM trades WHERE id=? AND status=?", (trade_id, TradeStatus.OPEN.value)).fetchone()
            if r is None or not 0 < sold_shares < r["shares"]:
                raise ValueError("非法的部分平仓请求")
            ratio = sold_shares / r["shares"]
            cost, fee = r["amount_usd"] * ratio, r["fee_usd"] * ratio
            self._conn.execute(
                "UPDATE trades SET shares=shares-?, amount_usd=amount_usd-?, fee_usd=fee_usd-? WHERE id=?",
                (sold_shares, cost, fee, trade_id))
            self._conn.execute(
                "INSERT INTO trades (id, signal_id, mode, market_id, token_id, market_type, status,"
                " executed_price, shares, amount_usd, fee_usd, opened_at, order_id, hour_utc)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (child_id, r["signal_id"], r["mode"], r["market_id"], r["token_id"], r["market_type"],
                 TradeStatus.OPEN.value, r["executed_price"], sold_shares, cost, fee, r["opened_at"],
                 r["order_id"], r["hour_utc"]))
            child = self._conn.execute("SELECT * FROM trades WHERE id=?", (child_id,)).fetchone()
        return _trade(child)

    def settle_trade(
        self, trade_id: str, *, exit_price: float, pnl_usd: float, extra_fee_usd: float,
        closed_at: datetime,
    ) -> bool:
        """平仓/结算，并在**同一事务**里更新贝叶斯与小时胜率。

        只有成功把 OPEN→CLOSED 才会更新统计，因此重复调用不会重复计数。
        win 的定义：扣费后盈亏 > 0。
        """
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT market_type, hour_utc FROM trades WHERE id=? AND status=?",
                (trade_id, TradeStatus.OPEN.value)).fetchone()
            if row is None:
                return False
            self._conn.execute(
                "UPDATE trades SET status=?, exit_price=?, pnl_usd=?, fee_usd=fee_usd+?, closed_at=?"
                " WHERE id=?",
                (TradeStatus.CLOSED.value, exit_price, pnl_usd, extra_fee_usd, iso(closed_at), trade_id))
            win = 1 if pnl_usd > 0 else 0
            now = iso(closed_at)
            self._conn.execute(
                "INSERT INTO bayesian_state (market_type, wins, total, updated_at) VALUES (?,?,1,?)"
                " ON CONFLICT(market_type) DO UPDATE SET wins=wins+excluded.wins, total=total+1,"
                " updated_at=excluded.updated_at", (row["market_type"], win, now))
            self._conn.execute(
                "INSERT INTO hourly_stats (market_type, hour_utc, wins, total) VALUES (?,?,?,1)"
                " ON CONFLICT(market_type, hour_utc) DO UPDATE SET wins=wins+excluded.wins,"
                " total=total+1", (row["market_type"], row["hour_utc"], win))
            return True

    # ── 资金统计（按 mode 隔离：DRY 的盈亏绝不污染 LIVE 的熔断计算）──
    def realized_pnl(self, mode: Mode, *, day: Optional[str] = None) -> float:
        """已实现盈亏。day='YYYY-MM-DD'（UTC）时只统计当天平仓的交易。"""
        sql = "SELECT COALESCE(SUM(pnl_usd),0) FROM trades WHERE mode=? AND status=?"
        args: list = [mode.value, TradeStatus.CLOSED.value]
        if day is not None:
            sql += " AND substr(closed_at,1,10)=?"
            args.append(day)
        with self._lock:
            return float(self._conn.execute(sql, args).fetchone()[0])

    def open_exposure(self, mode: Mode) -> float:
        with self._lock:
            return float(self._conn.execute(
                "SELECT COALESCE(SUM(amount_usd),0) FROM trades WHERE mode=? AND status=?",
                (mode.value, TradeStatus.OPEN.value)).fetchone()[0])

    # ── 贝叶斯 / 小时胜率 ──────────────────────────────
    def bayes_state(self, market_type: str) -> WinLoss:
        with self._lock:
            r = self._conn.execute(
                "SELECT wins, total FROM bayesian_state WHERE market_type=?", (market_type,)).fetchone()
        return WinLoss(r["wins"], r["total"]) if r else WinLoss(0, 0)

    def hourly_state(self, market_type: str, hour_utc: int) -> WinLoss:
        with self._lock:
            r = self._conn.execute(
                "SELECT wins, total FROM hourly_stats WHERE market_type=? AND hour_utc=?",
                (market_type, hour_utc)).fetchone()
        return WinLoss(r["wins"], r["total"]) if r else WinLoss(0, 0)

    def all_bayes(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM bayesian_state ORDER BY market_type").fetchall()

    def all_hourly(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM hourly_stats ORDER BY market_type, hour_utc").fetchall()

    # ── 键值 ──────────────────────────────────────────
    def kv_get(self, key: str) -> Optional[str]:
        with self._lock:
            r = self._conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def kv_set(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def kv_delete(self, key: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM kv WHERE key=?", (key,))

    def kv_prefix(self, prefix: str) -> Iterable[tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, value FROM kv WHERE key LIKE ?", (prefix + "%",)).fetchall()
        return [(r["key"], r["value"]) for r in rows]


def _trade(r: sqlite3.Row) -> Trade:
    return Trade(
        id=r["id"], signal_id=r["signal_id"], mode=Mode(r["mode"]), market_id=r["market_id"],
        token_id=r["token_id"], market_type=r["market_type"], status=TradeStatus(r["status"]),
        executed_price=r["executed_price"], shares=r["shares"], amount_usd=r["amount_usd"],
        opened_at=parse_iso(r["opened_at"]), hour_utc=r["hour_utc"], fee_usd=r["fee_usd"],
        exit_price=r["exit_price"], pnl_usd=r["pnl_usd"],
        closed_at=parse_iso(r["closed_at"]) if r["closed_at"] else None, order_id=r["order_id"],
    )
