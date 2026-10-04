"""命令行入口：python -m copybot {run,report,reset-halt,check-config}"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .config import ConfigError, Settings, load_env_file


def _peek_is_live(env_file: str) -> bool:
    mode = os.environ.get("MODE")
    if mode is None and os.path.exists(env_file):
        from dotenv import dotenv_values
        mode = dotenv_values(env_file).get("MODE")
    return (mode or "DRY_RUN").strip().upper() == "LIVE"


def load_settings(env_file: str) -> Settings:
    # LIVE 下 .env 必须是 0600，否则拒绝启动（里面有私钥）
    load_env_file(env_file, strict_permissions=_peek_is_live(env_file))
    return Settings.from_env()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="copybot", description="Polymarket 跟单机器人（默认 DRY_RUN 模拟盘）")
    ap.add_argument("--env-file", default=".env")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run", help="启动机器人（默认）")
    rp = sub.add_parser("report", help="打印复盘报表")
    rp.add_argument("--csv", help="同时导出权益曲线 CSV 到该路径")
    rs = sub.add_parser("reset-halt", help="人工解除锁存的熔断（总回撤 / API 连续失败）")
    rs.add_argument("--yes", action="store_true", help="跳过交互确认")
    sub.add_parser("check-config", help="校验并打印配置摘要（不含机密）")
    args = ap.parse_args(argv)
    cmd = args.cmd or "run"

    try:
        settings = load_settings(args.env_file)
    except ConfigError as e:
        print(e, file=sys.stderr)
        return 2

    from .logging_setup import setup_logging

    setup_logging(settings.log_dir, settings.log_level, settings.secret_values())

    if cmd == "check-config":
        print(json.dumps(settings.public_summary(), ensure_ascii=False, indent=2))
        return 0

    from .db import Database

    if cmd == "report":
        from .report import export_equity_csv, render

        db = Database(settings.db_path)
        print(render(db, settings))
        if args.csv:
            n = export_equity_csv(db, settings, args.csv)
            print(f"\n权益曲线已导出：{args.csv}（{n} 个点）")
        return 0

    if cmd == "reset-halt":
        from .risk import RiskControl

        db = Database(settings.db_path)
        risk = RiskControl(db, settings)
        status = risk.halt_status()
        if not status.halted:
            print("当前没有熔断。")
            return 0
        print(f"当前熔断：{status.code} — {status.detail}")
        if not args.yes and input("确认已复盘并解除？输入 yes 继续: ").strip().lower() != "yes":
            print("已取消。")
            return 1
        risk.reset_halt()
        print("已解除。峰值资金已重置为当前资金。" if status.latched else "日亏损熔断无需手动解除，将在次日 UTC 自动恢复。")
        return 0

    from .app import build_bot

    build_bot(settings).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
