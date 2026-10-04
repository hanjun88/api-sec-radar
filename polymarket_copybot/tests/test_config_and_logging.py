"""配置校验、LIVE 守卫、机密不外泄、日志脱敏与结构。"""

from __future__ import annotations

import io
import json
import logging
import os
from logging.handlers import TimedRotatingFileHandler

import httpx
import pytest

from copybot.config import ConfigError, Mode, Settings, load_env_file
from copybot.logging_setup import LOGGER_NAME, REDACTED, log_event, setup_logging
from tests.conftest import BASE_ENV, TARGET, make_settings

KEY = "0x" + "11" * 32
LIVE = dict(MODE="LIVE", PRIVATE_KEY=KEY, REQUIRE_APPROVAL="false")


class TestDefaults:
    def test_safe_defaults(self):
        s = make_settings()
        assert s.mode is Mode.DRY_RUN and s.confirm_mode.value == "CONFIRM"
        assert s.bankroll_usd == 20 and s.max_position_pct == 5 and s.kelly_multiplier == 0.5
        assert s.max_daily_loss_pct == 10 and s.max_total_drawdown_pct == 20
        assert s.api_failure_limit == 5 and s.max_slippage_pct == 2 and s.order_timeout_sec == 30
        assert s.min_window_winrate_pct == 65 and s.volatility_threshold_pct == 2
        assert s.poll_interval_sec == 15

    def test_mode_defaults_to_dry_run_when_unset(self):
        assert Settings.from_env({"TARGET_WALLET": TARGET}).mode is Mode.DRY_RUN

    def test_monitor_source_prefers_chain_when_rpc_present(self):
        s = Settings.from_env({"TARGET_WALLET": TARGET, "POLYGON_RPC_URL": "https://rpc.example/key123"})
        assert s.monitor_source == "chain"

    def test_chain_without_rpc_is_error(self):
        with pytest.raises(ConfigError, match="POLYGON_RPC_URL"):
            make_settings(MONITOR_SOURCE="chain")


class TestTargetWallet:
    def test_required(self):
        with pytest.raises(ConfigError, match="TARGET_WALLET"):
            Settings.from_env({"MODE": "DRY_RUN"})

    @pytest.mark.parametrize("bad", ["0xb27b...b82", "0x123", "b27b" + "0" * 36, "0x" + "zz" * 20])
    def test_truncated_or_malformed_rejected(self, bad):
        with pytest.raises(ConfigError, match="TARGET_WALLET"):
            make_settings(TARGET_WALLET=bad)


class TestValidation:
    @pytest.mark.parametrize("key,val", [
        ("MAX_POSITION_PCT", "abc"), ("MAX_POSITION_PCT", "0"), ("MAX_POSITION_PCT", "101"),
        ("MAX_DAILY_LOSS_PCT", "0"), ("KELLY_MULTIPLIER", "2"), ("BANKROLL_USD", "-5"),
        ("MAX_SLIPPAGE_PCT", "nan"), ("ENABLE_BOOTSTRAP", "maybe"),
    ])
    def test_bad_numbers_rejected(self, key, val):
        with pytest.raises(ConfigError, match=key):
            make_settings(**{key: val})

    def test_bad_mode_and_confirm_mode(self):
        with pytest.raises(ConfigError, match="MODE"):
            make_settings(MODE="PAPER")
        with pytest.raises(ConfigError, match="CONFIRM_MODE"):
            make_settings(CONFIRM_MODE="YOLO")

    def test_all_errors_reported_together(self):
        with pytest.raises(ConfigError) as ei:
            make_settings(MAX_POSITION_PCT="x", KELLY_MULTIPLIER="9")
        assert "MAX_POSITION_PCT" in str(ei.value) and "KELLY_MULTIPLIER" in str(ei.value)


class TestLiveGuards:
    def test_live_requires_private_key(self):
        with pytest.raises(ConfigError, match="PRIVATE_KEY"):
            make_settings(MODE="LIVE", REQUIRE_APPROVAL="false")

    def test_bad_key_format_rejected_without_echoing_it(self):
        with pytest.raises(ConfigError) as ei:
            make_settings(MODE="LIVE", PRIVATE_KEY="not-a-key-SECRETVALUE", REQUIRE_APPROVAL="false")
        assert "SECRETVALUE" not in str(ei.value)

    def test_valid_live_config(self):
        s = make_settings(**LIVE)
        assert s.is_live and s.private_key == KEY

    def test_live_capital_cap_enforced(self):
        with pytest.raises(ConfigError, match="LIVE_CAPITAL_CAP_USD"):
            make_settings(**LIVE, BANKROLL_USD="500")
        assert make_settings(**LIVE, BANKROLL_USD="500", LIVE_CAPITAL_CAP_USD="500").bankroll_usd == 500

    def test_approval_requires_telegram(self):
        with pytest.raises(ConfigError, match="TELEGRAM"):
            make_settings(MODE="LIVE", PRIVATE_KEY=KEY)  # REQUIRE_APPROVAL 默认 true
        s = make_settings(MODE="LIVE", PRIVATE_KEY=KEY, TELEGRAM_BOT_TOKEN="123456:ABCDEFGHIJ", TELEGRAM_CHAT_ID="42")
        assert s.require_approval

    def test_clob_creds_all_or_nothing(self):
        with pytest.raises(ConfigError, match="CLOB_API_KEY"):
            make_settings(**LIVE, CLOB_API_KEY="k")

    def test_bootstrap_can_never_be_active_in_live(self):
        assert make_settings(ENABLE_BOOTSTRAP="true").bootstrap_active
        assert not make_settings(**LIVE, ENABLE_BOOTSTRAP="true").bootstrap_active


class TestSecretsNeverLoadedOrLeaked:
    def test_dry_run_ignores_private_key_completely(self):
        s = make_settings(PRIVATE_KEY=KEY, CLOB_API_KEY="k", CLOB_API_SECRET="s", CLOB_API_PASSPHRASE="p")
        assert s.private_key is None and s.clob_api_key is None
        assert KEY not in s.secret_values()

    def test_repr_hides_secrets(self):
        s = make_settings(**LIVE, POLYGON_RPC_URL="https://rpc.example/RPCSECRET", TELEGRAM_BOT_TOKEN="123:TGSECRET")
        text = repr(s)
        for secret in (KEY, "RPCSECRET", "TGSECRET"):
            assert secret not in text

    def test_public_summary_has_no_secrets(self):
        s = make_settings(**LIVE, POLYGON_RPC_URL="https://rpc.example/RPCSECRET")
        blob = json.dumps(s.public_summary())
        assert KEY not in blob and "RPCSECRET" not in blob
        assert s.public_summary()["private_key_loaded"] is True

    def test_url_fragments_and_token_halves_are_redacted_too(self):
        s = make_settings(POLYGON_RPC_URL="https://polygon-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUv?apikey=QUERYSECRET1",
                          TELEGRAM_BOT_TOKEN="123456789:AAH-telegram-secret-half-xyz")
        vals = s.secret_values()
        for frag in ("AbCdEfGhIjKlMnOpQrStUv", "QUERYSECRET1", "AAH-telegram-secret-half-xyz"):
            assert frag in vals
        assert "v2" not in vals  # 过短的路径段不应被当作机密（否则会把日志里的普通词也抹掉）

    def test_secret_values_cover_key_with_and_without_prefix(self):
        vals = make_settings(**LIVE).secret_values()
        assert KEY in vals and KEY[2:] in vals


class TestEnvFile:
    def test_strict_mode_rejects_group_readable_file(self, tmp_path):
        p = tmp_path / ".env"
        p.write_text(f"PRIVATE_KEY={KEY}\n")
        os.chmod(p, 0o644)
        with pytest.raises(ConfigError, match="chmod 600"):
            load_env_file(p, strict_permissions=True)

    def test_strict_mode_accepts_0600_and_does_not_override_env(self, tmp_path, monkeypatch):
        p = tmp_path / ".env"
        p.write_text("ZZ_TEST_A=from_file\nZZ_TEST_B=from_file\n")
        os.chmod(p, 0o600)
        monkeypatch.setenv("ZZ_TEST_B", "from_env")
        monkeypatch.delenv("ZZ_TEST_A", raising=False)
        load_env_file(p, strict_permissions=True)
        assert os.environ["ZZ_TEST_A"] == "from_file" and os.environ["ZZ_TEST_B"] == "from_env"
        monkeypatch.delenv("ZZ_TEST_A")

    def test_missing_file_is_fine(self, tmp_path):
        load_env_file(tmp_path / "nope", strict_permissions=True)


class TestLogging:
    def _lines(self, stream):
        return [json.loads(l) for l in stream.getvalue().splitlines() if l.strip()]

    def test_structured_json_with_utc_timezone(self, log_stream):
        log_event(logging.getLogger(f"{LOGGER_NAME}.t"), logging.INFO, "signal_filtered", code="x", n=3)
        rec = self._lines(log_stream)[0]
        assert rec["event"] == "signal_filtered" and rec["code"] == "x" and rec["n"] == 3
        assert rec["level"] == "INFO" and rec["ts"].endswith("+00:00")

    def test_redacts_secrets_in_message_fields_and_tracebacks(self):
        stream = io.StringIO()
        setup_logging(None, "DEBUG", [KEY, "TOKEN-123456", "https://rpc.example/k3y-abcdef"], stream=stream)
        try:
            lg = logging.getLogger(f"{LOGGER_NAME}.t")
            lg.info(f"key is {KEY}")
            log_event(lg, logging.INFO, "evt", nested={"a": ["https://rpc.example/k3y-abcdef"]}, tok="TOKEN-123456")
            try:
                raise RuntimeError(f"failed with {KEY}")
            except RuntimeError:
                lg.exception("boom")
            out = stream.getvalue()
            assert KEY not in out and "TOKEN-123456" not in out and "k3y-abcdef" not in out
            assert REDACTED in out
        finally:
            logging.getLogger(LOGGER_NAME).handlers.clear()
            logging.getLogger(LOGGER_NAME).propagate = True

    def test_transaction_hashes_are_not_mistaken_for_keys(self):
        stream = io.StringIO()
        setup_logging(None, "DEBUG", [KEY], stream=stream)
        try:
            tx = "0x" + "ab" * 32  # 与私钥同形的 64 位十六进制
            log_event(logging.getLogger(f"{LOGGER_NAME}.t"), logging.INFO, "signal_detected", tx=tx)
            assert tx in stream.getvalue()
        finally:
            logging.getLogger(LOGGER_NAME).handlers.clear()
            logging.getLogger(LOGGER_NAME).propagate = True

    def test_file_handler_rotates_daily_and_keeps_30_days(self, tmp_path):
        setup_logging(str(tmp_path), "INFO", [])
        try:
            fh = next(h for h in logging.getLogger(LOGGER_NAME).handlers if isinstance(h, TimedRotatingFileHandler))
            assert fh.backupCount == 30 and fh.when == "MIDNIGHT" and fh.utc
        finally:
            for h in list(logging.getLogger(LOGGER_NAME).handlers):
                h.close()
            logging.getLogger(LOGGER_NAME).handlers.clear()
            logging.getLogger(LOGGER_NAME).propagate = True

    def test_http_libraries_are_quieted_so_urls_with_keys_are_not_logged(self, log_stream):
        assert logging.getLogger("httpx").level >= logging.WARNING

    def test_idempotent_setup_does_not_duplicate_handlers(self):
        s1, s2 = io.StringIO(), io.StringIO()
        setup_logging(None, "INFO", [], stream=s1)
        setup_logging(None, "INFO", [], stream=s2)
        try:
            log_event(logging.getLogger(f"{LOGGER_NAME}.t"), logging.INFO, "once")
            assert s1.getvalue() == "" and s2.getvalue().count("once") == 1
        finally:
            logging.getLogger(LOGGER_NAME).handlers.clear()
            logging.getLogger(LOGGER_NAME).propagate = True
