"""命令行：check-config / report / reset-halt（真实走一遍 main()）。"""

from __future__ import annotations

import json
import logging
import os

import pytest

from copybot.__main__ import main
from copybot.config import Mode
from copybot.db import Database
from copybot.logging_setup import LOGGER_NAME
from tests.conftest import FakeClock, TARGET, add_closed_trade

KEY = "0x" + "11" * 32


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """隔离 os.environ，并写一份指向临时目录的 .env。"""
    monkeypatch.setattr(os, "environ", {})
    p = tmp_path / ".env"
    p.write_text(f"MODE=DRY_RUN\nTARGET_WALLET={TARGET}\nMONITOR_SOURCE=dataapi\n"
                 f"DB_PATH={tmp_path / 'cb.db'}\nLOG_DIR={tmp_path / 'logs'}\n")
    os.chmod(p, 0o600)
    yield p
    lg = logging.getLogger(LOGGER_NAME)
    for h in list(lg.handlers):
        h.close()
        lg.removeHandler(h)
    lg.propagate = True


def test_check_config_prints_summary_without_secrets(env_file, capsys):
    env_file.write_text(env_file.read_text() + f"PRIVATE_KEY={KEY}\nPOLYGON_RPC_URL=https://rpc.example/RPCSECRET\n")
    assert main(["--env-file", str(env_file), "check-config"]) == 0
    out = capsys.readouterr().out
    summary = json.loads(out)
    assert summary["mode"] == "DRY_RUN" and summary["private_key_loaded"] is False  # DRY_RUN 不读私钥
    assert summary["polygon_rpc_configured"] is True
    assert KEY not in out and "RPCSECRET" not in out


def test_bad_config_exits_2_with_message(env_file, capsys):
    env_file.write_text("MODE=DRY_RUN\nTARGET_WALLET=0xb27b...b82\n")
    assert main(["--env-file", str(env_file), "check-config"]) == 2
    assert "TARGET_WALLET" in capsys.readouterr().err


def test_live_refuses_world_readable_env_file(env_file, capsys):
    env_file.write_text(f"MODE=LIVE\nTARGET_WALLET={TARGET}\nPRIVATE_KEY={KEY}\nREQUIRE_APPROVAL=false\n")
    os.chmod(env_file, 0o644)
    assert main(["--env-file", str(env_file), "check-config"]) == 2
    err = capsys.readouterr().err
    assert "chmod 600" in err and KEY not in err


def test_report_on_empty_db_and_csv_export(env_file, tmp_path, capsys):
    csv_path = tmp_path / "curve.csv"
    assert main(["--env-file", str(env_file), "report", "--csv", str(csv_path)]) == 0
    out = capsys.readouterr().out
    assert "复盘报表" in out and "暂无" in out
    assert csv_path.read_text().splitlines() == ["closed_at_utc,pnl_usd,equity_usd"]


def test_report_shows_recorded_trades(env_file, tmp_path, capsys):
    db = Database(str(tmp_path / "cb.db"))
    clock = FakeClock()
    add_closed_trade(db, clock, pnl=1.0, idx=1)
    add_closed_trade(db, clock, pnl=-0.5, idx=2)
    db.close()
    assert main(["--env-file", str(env_file), "report"]) == 0
    out = capsys.readouterr().out
    assert "已平仓交易 2 笔" in out and "胜率 50.0%" in out and "BTC_HOURLY" in out


def test_reset_halt_requires_confirmation_and_clears_latch(env_file, tmp_path, capsys, monkeypatch):
    from copybot.config import Settings
    from copybot.risk import RiskControl

    settings = Settings.from_env({"MODE": "DRY_RUN", "TARGET_WALLET": TARGET, "DB_PATH": str(tmp_path / "cb.db")})
    db = Database(settings.db_path)
    risk = RiskControl(db, settings)
    for _ in range(5):
        risk.record_api_result("clob", False)
    assert risk.halt_status().halted
    db.close()

    monkeypatch.setattr("builtins.input", lambda *_: "no")
    assert main(["--env-file", str(env_file), "reset-halt"]) == 1
    assert Database(settings.db_path).kv_get("risk:halt") is not None  # 未确认 → 仍熔断

    assert main(["--env-file", str(env_file), "reset-halt", "--yes"]) == 0
    assert Database(settings.db_path).kv_get("risk:halt") is None
    assert "已解除" in capsys.readouterr().out


def test_reset_halt_when_nothing_halted(env_file, capsys):
    assert main(["--env-file", str(env_file), "reset-halt", "--yes"]) == 0
    assert "没有熔断" in capsys.readouterr().out
