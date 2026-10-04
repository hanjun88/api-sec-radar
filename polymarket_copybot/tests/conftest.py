"""共享 fixture：配置工厂、内存数据库、可控时钟。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from copybot.config import Mode, Settings
from copybot.db import Database
from copybot.models import Trade, TradeStatus

TARGET = "0x" + "ab" * 20
BASE_ENV = {"MODE": "DRY_RUN", "TARGET_WALLET": TARGET, "MONITOR_SOURCE": "dataapi"}


def make_settings(**env_overrides: str) -> Settings:
    env = dict(BASE_ENV)
    env.update({k: str(v) for k, v in env_overrides.items()})
    return Settings.from_env(env)


class FakeClock:
    def __init__(self, start: datetime | None = None):
        self.now = start or datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def db() -> Database:
    d = Database(":memory:")
    yield d
    d.close()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


def add_closed_trade(
    db: Database, clock: FakeClock, *, pnl: float, amount: float = 1.0, market_type: str = "BTC_HOURLY",
    mode: Mode = Mode.DRY_RUN, token: str = "tok", idx: int = 0, closed_at: datetime | None = None,
) -> str:
    """直接造一笔已平仓交易（含贝叶斯/小时统计），供风控与统计测试使用。"""
    from copybot.models import CopySignal, Side

    sid = f"sig-{token}-{idx}-{pnl}"
    sig = CopySignal(sid, token, Side.BUY, 0.5, 2.0, 1.0, "0xtx", clock.now, clock.now)
    db.insert_signal(sig)
    t = Trade(
        id=f"trade-{sid}", signal_id=sid, mode=mode, market_id="m", token_id=token, market_type=market_type,
        status=TradeStatus.OPEN, executed_price=0.5, shares=amount / 0.5, amount_usd=amount,
        opened_at=clock.now, hour_utc=clock.now.hour,
    )
    db.open_trade(t)
    db.settle_trade(t.id, exit_price=1.0 if pnl > 0 else 0.0, pnl_usd=pnl, extra_fee_usd=0.0,
                    closed_at=closed_at or clock.now)
    return t.id


@pytest.fixture
def log_stream():
    """把 copybot 日志捕获到内存，并在用例结束后恢复全局 logger 状态。"""
    import io
    import logging

    from copybot.logging_setup import LOGGER_NAME, setup_logging

    stream = io.StringIO()
    setup_logging(None, "DEBUG", [], stream=stream)
    yield stream
    lg = logging.getLogger(LOGGER_NAME)
    for h in list(lg.handlers):
        lg.removeHandler(h)
    lg.propagate = True
