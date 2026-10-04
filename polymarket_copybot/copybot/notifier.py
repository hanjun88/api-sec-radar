"""Telegram 告警与人工确认（/approve）。

- 发送失败只记日志，绝不抛出——告警故障不能拖垮交易/风控主流程。
- 日志与异常里不出现 URL（URL 中含 Bot Token），只记异常类型。
- 只响应 TELEGRAM_CHAT_ID 对应会话里的指令；请把它配成你和 Bot 的私聊。
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

import httpx

from .db import Database
from .logging_setup import LOGGER_NAME, log_event
from .models import CopySignal, TradeOrder
from .util import utcnow

log = logging.getLogger(f"{LOGGER_NAME}.notifier")
_API = "https://api.telegram.org"
OFFSET_KEY = "tg:offset"


class NullNotifier:
    def send(self, text: str) -> None:
        log_event(log, logging.INFO, "alert_not_sent_no_telegram", text=text)


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str, http: httpx.Client):
        self._token, self._chat_id, self._http = token, str(chat_id), http

    def _url(self, method: str) -> str:
        return f"{_API}/bot{self._token}/{method}"

    def send(self, text: str) -> None:
        try:
            r = self._http.post(self._url("sendMessage"), json={"chat_id": self._chat_id, "text": text})
            if r.status_code >= 400:
                log_event(log, logging.ERROR, "telegram_send_failed", status=r.status_code)
        except Exception as e:  # noqa: BLE001 - 告警失败不得影响主流程
            log_event(log, logging.ERROR, "telegram_send_failed", error=type(e).__name__)

    def fetch_updates(self, offset: Optional[int]) -> list[dict]:
        params = {"timeout": 0, "allowed_updates": '["message"]'}
        if offset is not None:
            params["offset"] = offset
        try:
            r = self._http.get(self._url("getUpdates"), params=params)
            r.raise_for_status()
            return r.json().get("result", [])
        except Exception as e:  # noqa: BLE001
            log_event(log, logging.ERROR, "telegram_poll_failed", error=type(e).__name__)
            return []

    @property
    def chat_id(self) -> str:
        return self._chat_id


@dataclass
class PendingApproval:
    approval_id: str
    order: TradeOrder
    signal: CopySignal
    expires_at: datetime


class ApprovalGate:
    """LIVE 首周：每单发到 Telegram，收到 `/approve <id>` 才放行；超时或 `/reject <id>` 丢弃。"""

    def __init__(self, notifier: TelegramNotifier, db: Database, timeout_sec: int, *,
                 clock: Callable[[], datetime] = utcnow):
        self._n, self._db, self._timeout, self._clock = notifier, db, timeout_sec, clock
        self.pending: dict[str, PendingApproval] = {}

    def submit(self, order: TradeOrder, sig: CopySignal) -> str:
        aid = uuid.uuid4().hex[:8]
        self.pending[aid] = PendingApproval(aid, order, sig, self._clock() + timedelta(seconds=self._timeout))
        self._n.send(
            f"待确认订单 {aid}\n{order.side.value} {order.shares:g} 份 @ ≤{order.limit_price:.4f}"
            f"（约 ${order.size_usd:.2f}）\n{order.reason}\n"
            f"回复 /approve {aid} 放行，/reject {aid} 丢弃；{self._timeout}s 后自动作废。")
        return aid

    def poll(self) -> tuple[list[PendingApproval], list[tuple[PendingApproval, str]]]:
        """返回 (已批准, [(已作废, 原因)])。"""
        approved: list[PendingApproval] = []
        dropped: list[tuple[PendingApproval, str]] = []
        raw_offset = self._db.kv_get(OFFSET_KEY)
        updates = self._n.fetch_updates(int(raw_offset) if raw_offset else None)
        for u in updates:
            self._db.kv_set(OFFSET_KEY, str(int(u["update_id"]) + 1))
            msg = u.get("message") or {}
            if str((msg.get("chat") or {}).get("id")) != self._n.chat_id:
                continue  # 非授权会话，忽略
            parts = (msg.get("text") or "").split()
            if len(parts) != 2 or parts[0] not in ("/approve", "/reject"):
                continue
            item = self.pending.pop(parts[1], None)
            if item is None:
                continue
            if parts[0] == "/approve":
                approved.append(item)
            else:
                dropped.append((item, "rejected_by_user"))
        now = self._clock()
        for aid in [a for a, p in self.pending.items() if p.expires_at <= now]:
            dropped.append((self.pending.pop(aid), "approval_timeout"))
        return approved, dropped
