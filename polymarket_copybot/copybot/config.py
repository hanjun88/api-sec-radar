"""配置：全部来自环境变量，启动时一次性校验。

安全约束：
  - 私钥只在 MODE=LIVE 时才读取；DRY_RUN 下即便环境里有 PRIVATE_KEY 也被忽略（settings.private_key=None）。
  - 机密字段 repr=False，不会出现在日志/异常里；`secret_values()` 供日志脱敏使用。
  - 校验错误信息从不回显机密字段的值。
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional
from urllib.parse import parse_qs, urlsplit

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_PRIVKEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# Polymarket 官方 py-clob-client 配置里的 Polygon 主网交易所合约（可用环境变量覆盖）
CTF_EXCHANGE = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
NEG_RISK_CTF_EXCHANGE = "0xC5d563A36AE78145C45a50134d48A1215220f80a"


class ConfigError(ValueError):
    """配置非法。消息中不包含任何机密值。"""


class Mode(str, Enum):
    DRY_RUN = "DRY_RUN"
    LIVE = "LIVE"


class ConfirmMode(str, Enum):
    COPY_ONLY = "COPY_ONLY"
    CONFIRM = "CONFIRM"


@dataclass(frozen=True)
class Settings:
    mode: Mode
    confirm_mode: ConfirmMode
    target_wallet: str

    # ── 资金与仓位（百分比参数沿用文档的"百分数"写法，如 10 表示 10%）──
    bankroll_usd: float = 20.0
    max_position_pct: float = 5.0
    kelly_multiplier: float = 0.5
    max_daily_loss_pct: float = 10.0
    max_total_drawdown_pct: float = 20.0
    api_failure_limit: int = 5

    # ── 策略规则 ──
    market_types: tuple[str, ...] = ("BTC_HOURLY", "BTC_SHORT", "BTC_OTHER")
    min_window_winrate_pct: float = 65.0
    window_min_samples: int = 10
    volatility_threshold_pct: float = 2.0
    bayes_alpha: float = 1.0
    bayes_beta: float = 1.0
    enable_bootstrap: bool = True
    bootstrap_trades: int = 30
    fallback_stake_pct: float = 1.0

    # ── 执行 ──
    max_slippage_pct: float = 2.0
    order_timeout_sec: int = 30
    enforce_min_order_size: bool = True
    sim_fee_bps: float = 0.0

    # ── 监控 ──
    monitor_source: str = "dataapi"  # chain | dataapi
    poll_interval_sec: int = 15
    signal_ttl_sec: int = 90
    settle_interval_sec: int = 60
    chain_confirmations: int = 2
    log_block_range: int = 10
    chain_max_lookback_blocks: int = 150
    exchange_addresses: tuple[str, ...] = (CTF_EXCHANGE, NEG_RISK_CTF_EXCHANGE)

    # ── 外部服务地址 ──
    clob_url: str = "https://clob.polymarket.com"
    gamma_url: str = "https://gamma-api.polymarket.com"
    data_api_url: str = "https://data-api.polymarket.com"
    price_feed_url: str = "https://api.exchange.coinbase.com"
    http_timeout_sec: float = 10.0

    # ── 持久化与日志 ──
    db_path: str = "data/copybot.db"
    log_dir: str = "logs"
    log_level: str = "INFO"

    # ── 通知 / 人工确认 ──
    require_approval: bool = True
    approval_timeout_sec: int = 120
    live_capital_cap_usd: float = 20.0

    # ── 机密（repr=False；DRY_RUN 下 private_key 恒为 None）──
    polygon_rpc_url: Optional[str] = field(default=None, repr=False)
    telegram_bot_token: Optional[str] = field(default=None, repr=False)
    telegram_chat_id: Optional[str] = field(default=None, repr=False)
    private_key: Optional[str] = field(default=None, repr=False)
    clob_api_key: Optional[str] = field(default=None, repr=False)
    clob_api_secret: Optional[str] = field(default=None, repr=False)
    clob_api_passphrase: Optional[str] = field(default=None, repr=False)
    clob_funder: Optional[str] = None
    clob_signature_type: int = 1  # 0=EOA, 1=POLY_PROXY(邮箱/Magic 账户), 2=GNOSIS_SAFE

    @property
    def is_live(self) -> bool:
        return self.mode is Mode.LIVE

    @property
    def bootstrap_active(self) -> bool:
        """冷启动探索仅 DRY_RUN 可用：LIVE 永远不允许"为凑数据"而绕过 Kelly 边际检验。"""
        return self.enable_bootstrap and not self.is_live

    def secret_values(self) -> list[str]:
        vals = [
            self.polygon_rpc_url, self.telegram_bot_token, self.private_key,
            self.clob_api_key, self.clob_api_secret, self.clob_api_passphrase,
        ]
        out = [v for v in vals if v]
        if self.private_key and self.private_key.startswith("0x"):
            out.append(self.private_key[2:])
        # 库的异常信息有时只回显 URL 的一段：把 RPC Key（路径末段/查询值）与 Bot Token 的密钥半段也单独脱敏
        if self.polygon_rpc_url:
            u = urlsplit(self.polygon_rpc_url)
            out += [seg for seg in u.path.split("/") if len(seg) >= 12]
            out += [v for vals_ in parse_qs(u.query).values() for v in vals_ if len(v) >= 8]
        if self.telegram_bot_token and ":" in self.telegram_bot_token:
            out.append(self.telegram_bot_token.split(":", 1)[1])
        return out

    def public_summary(self) -> dict:
        """可安全打印的配置摘要（不含任何机密值，仅标注机密是否已配置）。"""
        return {
            "mode": self.mode.value,
            "confirm_mode": self.confirm_mode.value,
            "target_wallet": self.target_wallet,
            "bankroll_usd": self.bankroll_usd,
            "max_position_pct": self.max_position_pct,
            "kelly_multiplier": self.kelly_multiplier,
            "max_daily_loss_pct": self.max_daily_loss_pct,
            "max_total_drawdown_pct": self.max_total_drawdown_pct,
            "market_types": list(self.market_types),
            "monitor_source": self.monitor_source,
            "bootstrap_active": self.bootstrap_active,
            "require_approval": self.require_approval,
            "polygon_rpc_configured": bool(self.polygon_rpc_url),
            "telegram_configured": bool(self.telegram_bot_token and self.telegram_chat_id),
            "private_key_loaded": bool(self.private_key),
        }

    # ── 构造 ────────────────────────────────────────────
    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        errors: list[str] = []

        def get(key: str, default: Optional[str] = None) -> Optional[str]:
            v = env.get(key)
            if v is None or v.strip() == "":
                return default
            return v.strip()

        def num(key: str, default: float, lo: float, hi: float) -> float:
            raw = get(key)
            if raw is None:
                return default
            try:
                x = float(raw)
            except ValueError:
                errors.append(f"{key} 必须是数字")
                return default
            if not (lo <= x <= hi) or x != x:
                errors.append(f"{key} 必须在 [{lo}, {hi}] 内")
                return default
            return x

        def integer(key: str, default: int, lo: int, hi: int) -> int:
            return int(num(key, default, lo, hi))

        def boolean(key: str, default: bool) -> bool:
            raw = get(key)
            if raw is None:
                return default
            if raw.lower() in ("1", "true", "yes", "on"):
                return True
            if raw.lower() in ("0", "false", "no", "off"):
                return False
            errors.append(f"{key} 必须是 true/false")
            return default

        mode_raw = (get("MODE", "DRY_RUN") or "").upper()
        try:
            mode = Mode(mode_raw)
        except ValueError:
            raise ConfigError("MODE 只能是 DRY_RUN 或 LIVE") from None

        try:
            confirm_mode = ConfirmMode((get("CONFIRM_MODE", "CONFIRM") or "").upper())
        except ValueError:
            raise ConfigError("CONFIRM_MODE 只能是 COPY_ONLY 或 CONFIRM") from None

        target = get("TARGET_WALLET")
        if target is None:
            errors.append("TARGET_WALLET 未设置（需要用户提供完整的 42 位地址）")
            target = ""
        elif not _ADDRESS_RE.match(target):
            errors.append("TARGET_WALLET 必须是完整的 42 位十六进制地址（0x + 40 位），不能是 0xb27b...b82 这类缩写")

        monitor_source = (get("MONITOR_SOURCE") or ("chain" if get("POLYGON_RPC_URL") else "dataapi")).lower()
        if monitor_source not in ("chain", "dataapi"):
            errors.append("MONITOR_SOURCE 只能是 chain 或 dataapi")
        if monitor_source == "chain" and not get("POLYGON_RPC_URL"):
            errors.append("MONITOR_SOURCE=chain 需要 POLYGON_RPC_URL")

        exchanges = tuple(a.strip() for a in (get("EXCHANGE_ADDRESSES") or "").split(",") if a.strip()) \
            or (CTF_EXCHANGE, NEG_RISK_CTF_EXCHANGE)
        for a in exchanges:
            if not _ADDRESS_RE.match(a):
                errors.append("EXCHANGE_ADDRESSES 含非法地址")
                break

        market_types = tuple(t.strip().upper() for t in (get("MARKET_TYPES") or "").split(",") if t.strip()) \
            or ("BTC_HOURLY", "BTC_SHORT", "BTC_OTHER")

        bankroll = num("BANKROLL_USD", 20.0, 1.0, 1_000_000.0)
        live_cap = num("LIVE_CAPITAL_CAP_USD", 20.0, 1.0, 1_000_000.0)
        require_approval = boolean("REQUIRE_APPROVAL", True)
        tg_token, tg_chat = get("TELEGRAM_BOT_TOKEN"), get("TELEGRAM_CHAT_ID")

        # ── LIVE 专属守卫 ──
        private_key = None
        api_key = api_secret = api_pass = None
        if mode is Mode.LIVE:
            pk = get("PRIVATE_KEY")
            if not pk:
                errors.append("MODE=LIVE 需要通过环境变量注入 PRIVATE_KEY")
            elif not _PRIVKEY_RE.match(pk):
                errors.append("PRIVATE_KEY 格式非法（应为 64 位十六进制）")
            else:
                private_key = pk
            if bankroll > live_cap:
                errors.append(f"LIVE 模式下 BANKROLL_USD 不得超过 LIVE_CAPITAL_CAP_USD（当前上限 {live_cap:g}）")
            if require_approval and not (tg_token and tg_chat):
                errors.append("REQUIRE_APPROVAL=true 需要配置 TELEGRAM_BOT_TOKEN 与 TELEGRAM_CHAT_ID")
            api_key, api_secret, api_pass = (
                get("CLOB_API_KEY"), get("CLOB_API_SECRET"), get("CLOB_API_PASSPHRASE"))
            if any((api_key, api_secret, api_pass)) and not all((api_key, api_secret, api_pass)):
                errors.append("CLOB_API_KEY / CLOB_API_SECRET / CLOB_API_PASSPHRASE 必须同时提供（或都不提供，由私钥派生）")
            funder = get("CLOB_FUNDER_ADDRESS")
            if funder and not _ADDRESS_RE.match(funder):
                errors.append("CLOB_FUNDER_ADDRESS 必须是完整 42 位地址")
        else:
            funder = get("CLOB_FUNDER_ADDRESS")

        settings = cls(
            mode=mode,
            confirm_mode=confirm_mode,
            target_wallet=target,
            bankroll_usd=bankroll,
            max_position_pct=num("MAX_POSITION_PCT", 5.0, 0.01, 100.0),
            kelly_multiplier=num("KELLY_MULTIPLIER", 0.5, 0.01, 1.0),
            max_daily_loss_pct=num("MAX_DAILY_LOSS_PCT", 10.0, 0.1, 100.0),
            max_total_drawdown_pct=num("MAX_TOTAL_DRAWDOWN_PCT", 20.0, 0.1, 100.0),
            api_failure_limit=integer("API_FAILURE_LIMIT", 5, 1, 100),
            market_types=market_types,
            min_window_winrate_pct=num("MIN_WINDOW_WINRATE_PCT", 65.0, 0.0, 100.0),
            window_min_samples=integer("WINDOW_MIN_SAMPLES", 10, 1, 100_000),
            volatility_threshold_pct=num("VOLATILITY_THRESHOLD_PCT", 2.0, 0.001, 100.0),
            bayes_alpha=num("BAYES_ALPHA", 1.0, 0.001, 1000.0),
            bayes_beta=num("BAYES_BETA", 1.0, 0.001, 1000.0),
            enable_bootstrap=boolean("ENABLE_BOOTSTRAP", True),
            bootstrap_trades=integer("BOOTSTRAP_TRADES", 30, 0, 100_000),
            fallback_stake_pct=num("FALLBACK_STAKE_PCT", 1.0, 0.01, 100.0),
            max_slippage_pct=num("MAX_SLIPPAGE_PCT", 2.0, 0.0, 50.0),
            order_timeout_sec=integer("ORDER_TIMEOUT_SEC", 30, 1, 3600),
            enforce_min_order_size=boolean("ENFORCE_MIN_ORDER_SIZE", True),
            sim_fee_bps=num("SIM_FEE_BPS", 0.0, 0.0, 1000.0),
            monitor_source=monitor_source,
            poll_interval_sec=integer("POLL_INTERVAL_SEC", 15, 1, 3600),
            signal_ttl_sec=integer("SIGNAL_TTL_SEC", 90, 5, 86_400),
            settle_interval_sec=integer("SETTLE_INTERVAL_SEC", 60, 5, 86_400),
            chain_confirmations=integer("CHAIN_CONFIRMATIONS", 2, 0, 100),
            log_block_range=integer("LOG_BLOCK_RANGE", 10, 1, 10_000),
            chain_max_lookback_blocks=integer("CHAIN_MAX_LOOKBACK_BLOCKS", 150, 1, 100_000),
            exchange_addresses=exchanges,
            clob_url=(get("CLOB_URL", cls.clob_url) or "").rstrip("/"),
            gamma_url=(get("GAMMA_URL", cls.gamma_url) or "").rstrip("/"),
            data_api_url=(get("DATA_API_URL", cls.data_api_url) or "").rstrip("/"),
            price_feed_url=(get("PRICE_FEED_URL", cls.price_feed_url) or "").rstrip("/"),
            http_timeout_sec=num("HTTP_TIMEOUT_SEC", 10.0, 1.0, 120.0),
            db_path=get("DB_PATH", cls.db_path) or cls.db_path,
            log_dir=get("LOG_DIR", cls.log_dir) or cls.log_dir,
            log_level=(get("LOG_LEVEL", "INFO") or "INFO").upper(),
            require_approval=require_approval,
            approval_timeout_sec=integer("APPROVAL_TIMEOUT_SEC", 120, 10, 3600),
            live_capital_cap_usd=live_cap,
            polygon_rpc_url=get("POLYGON_RPC_URL"),
            telegram_bot_token=tg_token,
            telegram_chat_id=tg_chat,
            private_key=private_key,
            clob_api_key=api_key,
            clob_api_secret=api_secret,
            clob_api_passphrase=api_pass,
            clob_funder=funder,
            clob_signature_type=integer("CLOB_SIGNATURE_TYPE", 1, 0, 2),
        )
        if errors:
            raise ConfigError("配置错误：\n  - " + "\n  - ".join(errors))
        return settings


def load_env_file(path: str | os.PathLike, *, strict_permissions: bool) -> None:
    """把 .env 载入 os.environ（不覆盖已存在的环境变量）。

    strict_permissions=True（LIVE）时，文件若对 group/other 可读写则拒绝加载——
    私钥文件必须是 0600。
    """
    p = Path(path)
    if not p.exists():
        return
    mode = stat.S_IMODE(p.stat().st_mode)
    if strict_permissions and mode & 0o077:
        raise ConfigError(f"{p} 权限过宽（{mode:04o}），请执行 chmod 600 {p}")
    from dotenv import dotenv_values  # 延迟导入：纯配置测试不需要

    for k, v in dotenv_values(p).items():
        if v is not None and k not in os.environ:
            os.environ[k] = v
