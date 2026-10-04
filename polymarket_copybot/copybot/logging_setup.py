"""结构化 JSON 日志：UTC 带时区、按天轮转保留 30 天、机密脱敏。

脱敏策略：按"已知机密的精确值"替换，而不是按正则猜——
交易哈希也是 0x+64 位十六进制，与私钥同形，正则会误伤。
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Iterable

LOGGER_NAME = "copybot"
REDACTED = "***REDACTED***"


class RedactFilter(logging.Filter):
    def __init__(self, secrets: Iterable[str]):
        super().__init__()
        # 长的先替换，避免短机密是长机密的子串时残留
        self._secrets = sorted({s for s in secrets if s and len(s) >= 6}, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for s in self._secrets:
            if s in text:
                text = text.replace(s, REDACTED)
        return text

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {k: self._scrub(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._scrub(v) for v in value]
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.redact(record.getMessage())
        record.args = ()
        fields = getattr(record, "fields", None)
        if fields:
            record.fields = self._scrub(fields)
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = self.redact(record.exc_text)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for k, v in (getattr(record, "fields", None) or {}).items():
            payload.setdefault(k, v)
        if record.exc_text:
            payload["exc"] = record.exc_text
        elif record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    """记录一条结构化事件：event 为事件名，其余键值进入 JSON 顶层。"""
    logger.log(level, event, extra={"fields": fields})


def setup_logging(
    log_dir: str | None,
    level: str = "INFO",
    secrets: Iterable[str] = (),
    *,
    stream: Any = None,
) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()

    redactor = RedactFilter(secrets)
    handlers: list[logging.Handler] = [logging.StreamHandler(stream or sys.stdout)]
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        handlers.append(TimedRotatingFileHandler(
            Path(log_dir) / "copybot.log", when="midnight", utc=True, backupCount=30, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(JsonFormatter())
        h.addFilter(redactor)
        logger.addHandler(h)

    # 第三方库默认会在 INFO 打印完整请求 URL——其中含 RPC Key / Telegram Bot Token
    for noisy in ("httpx", "httpcore", "urllib3", "web3", "websockets"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logger
