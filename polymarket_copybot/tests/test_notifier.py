"""Telegram 告警与 /approve 人工确认。"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from copybot.db import Database
from copybot.models import CopySignal, Side, TradeOrder
from copybot.notifier import OFFSET_KEY, ApprovalGate, NullNotifier, TelegramNotifier
from tests.conftest import FakeClock, make_settings
from tests.fakes import COND, TOKEN_UP, FakeWorld

CHAT = "424242"
TOKEN = "123456:SUPER-SECRET-BOT-TOKEN"


def order() -> TradeOrder:
    return TradeOrder("s1", COND, TOKEN_UP, "BTC_HOURLY", Side.BUY, 0.52, 5.0, 2.6, 0.05, "kelly: test")


def make_gate(timeout=120):
    w = FakeWorld(make_settings())
    clock, db = FakeClock(), Database(":memory:")
    n = TelegramNotifier(TOKEN, CHAT, w.client())
    sig = CopySignal("s1", TOKEN_UP, Side.BUY, 0.5, 1, 1, "0x", clock.now, clock.now)
    return w, clock, db, n, ApprovalGate(n, db, timeout, clock=clock), sig


def upd(i, text, chat=CHAT):
    return {"update_id": i, "message": {"chat": {"id": int(chat)}, "text": text}}


class TestTelegramNotifier:
    def test_sends_message(self):
        w = FakeWorld(make_settings())
        TelegramNotifier(TOKEN, CHAT, w.client()).send("hello")
        assert w.tg_sent == ["hello"]

    def test_http_error_is_swallowed(self):
        w = FakeWorld(make_settings())
        w.fail["telegram"] = 500
        TelegramNotifier(TOKEN, CHAT, w.client()).send("hello")  # 不抛异常

    def test_network_error_swallowed_and_token_never_logged(self, log_stream):
        def boom(req):
            raise httpx.ConnectError(f"cannot reach {req.url}")

        n = TelegramNotifier(TOKEN, CHAT, httpx.Client(transport=httpx.MockTransport(boom)))
        n.send("hello")
        assert "telegram_send_failed" in log_stream.getvalue()
        assert TOKEN not in log_stream.getvalue() and "SUPER-SECRET" not in log_stream.getvalue()

    def test_null_notifier_never_raises(self):
        NullNotifier().send("x")


class TestApprovalGate:
    def test_submit_sends_actionable_message(self):
        w, _, _, _, gate, sig = make_gate()
        aid = gate.submit(order(), sig)
        assert aid in w.tg_sent[0] and "/approve" in w.tg_sent[0] and "/reject" in w.tg_sent[0]
        assert aid in gate.pending

    def test_approve_releases_order(self):
        w, _, _, _, gate, sig = make_gate()
        aid = gate.submit(order(), sig)
        w.tg_updates.append(upd(1, f"/approve {aid}"))
        approved, dropped = gate.poll()
        assert [p.order.signal_id for p in approved] == ["s1"] and dropped == []
        assert aid not in gate.pending

    def test_commands_from_other_chats_are_ignored(self):
        w, _, _, _, gate, sig = make_gate()
        aid = gate.submit(order(), sig)
        w.tg_updates.append(upd(1, f"/approve {aid}", chat="999"))
        assert gate.poll() == ([], [])
        assert aid in gate.pending

    def test_reject_drops_order(self):
        w, _, _, _, gate, sig = make_gate()
        aid = gate.submit(order(), sig)
        w.tg_updates.append(upd(1, f"/reject {aid}"))
        approved, dropped = gate.poll()
        assert approved == [] and dropped[0][1] == "rejected_by_user"

    def test_unknown_or_malformed_commands_do_nothing(self):
        w, _, _, _, gate, sig = make_gate()
        aid = gate.submit(order(), sig)
        w.tg_updates += [upd(1, "/approve deadbeef"), upd(2, "/approve"), upd(3, f"/approve {aid} extra"),
                         upd(4, "hello"), {"update_id": 5, "message": {}}, {"update_id": 6}]
        assert gate.poll() == ([], [])
        assert aid in gate.pending

    def test_expires_after_timeout(self):
        w, clock, _, _, gate, sig = make_gate(timeout=120)
        gate.submit(order(), sig)
        clock.advance(seconds=119)
        assert gate.poll() == ([], [])
        clock.advance(seconds=2)
        approved, dropped = gate.poll()
        assert approved == [] and dropped[0][1] == "approval_timeout" and gate.pending == {}

    def test_late_approval_after_expiry_is_not_honoured(self):
        w, clock, _, _, gate, sig = make_gate(timeout=60)
        aid = gate.submit(order(), sig)
        clock.advance(seconds=120)
        gate.poll()  # 先过期
        w.tg_updates.append(upd(1, f"/approve {aid}"))
        approved, _ = gate.poll()
        assert approved == []

    def test_offset_persisted_so_updates_are_not_replayed(self):
        w, _, db, _, gate, sig = make_gate()
        aid = gate.submit(order(), sig)
        w.tg_updates.append(upd(7, f"/approve {aid}"))
        gate.poll()
        assert db.kv_get(OFFSET_KEY) == "8"
        aid2 = gate.submit(order(), sig)
        approved, _ = gate.poll()  # update 7 不会被再次取到
        assert approved == [] and aid2 in gate.pending
