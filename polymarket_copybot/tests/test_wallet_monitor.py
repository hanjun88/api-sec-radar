"""钱包监控：链上日志解码、游标/不回放历史、分块、聚合去重、Data API 源。"""

from __future__ import annotations

import queue
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from copybot.config import CTF_EXCHANGE, NEG_RISK_CTF_EXCHANGE
from copybot.db import Database
from copybot.models import Fill, Side
from copybot.wallet_monitor import (CURSOR_KEY, ORDER_FILLED_TOPIC, ChainTradeSource, DataApiTradeSource,
                                    WalletMonitor, aggregate_fills, decode_order_filled, parse_data_api_trades,
                                    signal_id_for)
from tests.conftest import TARGET, make_settings
from tests.fakes import FakeWorld

BASE_TS = 1_759_579_200  # 2025-10-04 12:00:00 UTC（区块时间基准）
TOKEN = "71321045679252212594626385532706912750332728571942532289631379312455583992563"  # 77 位，超 2^64
OTHER = "0x" + "cd" * 20


def pad(addr: str) -> str:
    return "0x" + addr.lower().removeprefix("0x").rjust(64, "0")


def word(x: int) -> str:
    return f"{x:064x}"


def order_filled(*, maker_asset, taker_asset, maker_amt, taker_amt, block=1000, tx="0x" + "11" * 32, maker=TARGET):
    return {
        "topics": [ORDER_FILLED_TOPIC, "0x" + "00" * 32, pad(maker), pad(OTHER)],
        "data": "0x" + word(maker_asset) + word(taker_asset) + word(maker_amt) + word(taker_amt) + word(0),
        "blockNumber": block, "transactionHash": tx, "logIndex": 0,
    }


def buy_log(shares=10.0, usdc=5.0, **kw):
    return order_filled(maker_asset=0, taker_asset=int(TOKEN), maker_amt=int(usdc * 1e6), taker_amt=int(shares * 1e6), **kw)


def sell_log(shares=10.0, usdc=6.0, **kw):
    return order_filled(maker_asset=int(TOKEN), taker_asset=0, maker_amt=int(shares * 1e6), taker_amt=int(usdc * 1e6), **kw)


class FakeEth:
    def __init__(self, owner: "FakeW3"):
        self._o = owner

    @property
    def block_number(self) -> int:
        return self._o.head

    def get_logs(self, params):
        o = self._o
        o.get_logs_calls.append(params)
        if o.fail_on_call is not None and len(o.get_logs_calls) == o.fail_on_call:
            raise ConnectionError("rpc down")
        return [l for l in o.logs if params["fromBlock"] <= l["blockNumber"] <= params["toBlock"]]

    def get_block(self, n):
        return {"timestamp": BASE_TS + 2 * n}


class FakeW3:
    def __init__(self, head=1000):
        self.head = head
        self.logs: list[dict] = []
        self.get_logs_calls: list[dict] = []
        self.fail_on_call: int | None = None
        self.eth = FakeEth(self)


def make_source(head=1000, **env):
    s = make_settings(CHAIN_CONFIRMATIONS="0", **env)
    db = Database(":memory:")
    w3 = FakeW3(head)
    reports = []
    src = ChainTradeSource(w3, s, db, report=lambda n, ok: reports.append((n, ok)))
    return SimpleNamespace(s=s, db=db, w3=w3, src=src, reports=reports)


class TestConstants:
    def test_topic0_matches_event_signature(self):
        web3 = pytest.importorskip("web3")
        sig = "OrderFilled(bytes32,address,address,uint256,uint256,uint256,uint256,uint256)"
        assert "0x" + web3.Web3.keccak(text=sig).hex().removeprefix("0x") == ORDER_FILLED_TOPIC

    def test_default_exchanges_match_official_client(self):
        assert CTF_EXCHANGE.lower() == "0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e"
        assert NEG_RISK_CTF_EXCHANGE.lower() == "0xc5d563a36ae78145c45a50134d48a1215220f80a"


class TestDecode:
    T = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)

    def test_buy_when_maker_pays_usdc(self):
        f = decode_order_filled(buy_log(shares=10, usdc=5), self.T)
        assert f.side is Side.BUY and f.token_id == TOKEN
        assert f.shares == pytest.approx(10) and f.price == pytest.approx(0.5)

    def test_sell_when_maker_pays_token(self):
        f = decode_order_filled(sell_log(shares=10, usdc=6), self.T)
        assert f.side is Side.SELL and f.token_id == TOKEN and f.price == pytest.approx(0.6)

    def test_huge_token_id_survives_exactly(self):
        assert decode_order_filled(buy_log(), self.T).token_id == TOKEN

    def test_bytes_inputs_supported(self):
        e = buy_log()
        e["data"] = bytes.fromhex(e["data"][2:])
        e["transactionHash"] = bytes.fromhex(e["transactionHash"][2:])
        assert decode_order_filled(e, self.T).side is Side.BUY

    @pytest.mark.parametrize("mutate", [
        lambda e: e.update(data="0x1234"),
        lambda e: e.pop("data"),
        lambda e: e.update(data="0x" + word(0) * 5),                      # 全 0
        lambda e: e.update(data="0x" + word(5) + word(6) + word(1) * 3),  # token↔token
    ])
    def test_malformed_returns_none(self, mutate):
        e = buy_log()
        mutate(e)
        assert decode_order_filled(e, self.T) is None


class TestChainSource:
    def test_first_run_starts_at_head_and_never_replays_history(self):
        c = make_source(head=1000)
        c.w3.logs = [buy_log(block=990)]  # 目标钱包很久以前的交易
        assert c.src.fetch() == []
        assert c.db.kv_get(CURSOR_KEY) == "1000"
        assert c.w3.get_logs_calls == []

    def test_picks_up_new_fills_and_advances_cursor(self):
        c = make_source(head=1000)
        c.src.fetch()
        c.w3.head = 1004
        c.w3.logs = [buy_log(block=1003)]
        fills = c.src.fetch()
        assert len(fills) == 1 and fills[0].side is Side.BUY
        assert c.db.kv_get(CURSOR_KEY) == "1004"
        assert c.src.fetch() == []  # 无新块 → 无新调用结果

    def test_trade_time_comes_from_block_timestamp(self):
        c = make_source(head=1000)
        c.src.fetch()
        c.w3.head = 1002
        c.w3.logs = [buy_log(block=1002)]
        f = c.src.fetch()[0]
        assert f.trade_time == datetime.fromtimestamp(BASE_TS + 2 * 1002, timezone.utc)

    def test_only_maker_topic_is_filtered_so_taker_side_is_not_double_counted(self):
        c = make_source(head=1000)
        c.src.fetch()
        c.w3.head = 1005
        c.src.fetch()
        call = c.w3.get_logs_calls[0]
        assert call["topics"] == [ORDER_FILLED_TOPIC, None, pad(TARGET)]
        assert [a.lower() for a in call["address"]] == [CTF_EXCHANGE.lower(), NEG_RISK_CTF_EXCHANGE.lower()]

    def test_range_is_chunked_without_gaps_or_overlap(self):
        c = make_source(head=1000, LOG_BLOCK_RANGE="10")
        c.src.fetch()
        c.w3.head = 1025
        c.src.fetch()
        ranges = [(p["fromBlock"], p["toBlock"]) for p in c.w3.get_logs_calls]
        assert ranges == [(1001, 1010), (1011, 1020), (1021, 1025)]

    def test_stale_backlog_is_skipped_after_long_outage(self):
        c = make_source(head=1000, CHAIN_MAX_LOOKBACK_BLOCKS="20", LOG_BLOCK_RANGE="100")
        c.src.fetch()
        c.w3.head = 50_000  # 停机很久
        c.src.fetch()
        assert c.w3.get_logs_calls[0]["fromBlock"] == 50_000 - 20

    def test_confirmations_lag_the_head(self):
        s = make_settings(CHAIN_CONFIRMATIONS="3")
        db, w3 = Database(":memory:"), FakeW3(1000)
        src = ChainTradeSource(w3, s, db)
        src.fetch()
        assert db.kv_get(CURSOR_KEY) == "997"

    def test_rpc_failure_does_not_advance_cursor_and_is_reported(self):
        c = make_source(head=1000, LOG_BLOCK_RANGE="10")
        c.src.fetch()
        c.w3.head = 1025
        c.w3.get_logs_calls.clear()
        c.w3.fail_on_call = 2  # 第 1 个分块(1001-1010)成功，第 2 个分块失败
        with pytest.raises(ConnectionError):
            c.src.fetch()
        assert c.db.kv_get(CURSOR_KEY) == "1010"  # 只推进到成功的分块
        assert c.reports[-1] == ("polygon_rpc", False)

    def test_success_is_reported(self):
        c = make_source(head=1000)
        c.src.fetch()
        assert c.reports[-1] == ("polygon_rpc", True)

    def test_undecodable_log_is_counted_not_fatal(self):
        c = make_source(head=1000)
        c.src.fetch()
        c.w3.head = 1002
        bad = buy_log(block=1001)
        bad["data"] = "0x00"
        c.w3.logs = [bad, buy_log(block=1002, tx="0x" + "22" * 32)]
        assert len(c.src.fetch()) == 1 and c.src.decode_failures == 1


T0 = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)


def fill(side=Side.BUY, price=0.5, shares=10.0, tx="0xAA", token="t1", t=T0):
    return Fill(tx, token, side, price, shares, t)


class TestAggregation:
    def test_same_tx_token_side_merge_into_one_signal_with_vwap(self):
        sigs = aggregate_fills([fill(price=0.50, shares=10), fill(price=0.60, shares=30)], T0)
        assert len(sigs) == 1
        assert sigs[0].shares == 40 and sigs[0].price == pytest.approx((5 + 18) / 40)
        assert sigs[0].amount_usd == pytest.approx(23.0)

    def test_buy_and_sell_in_same_tx_stay_separate(self):
        assert len(aggregate_fills([fill(), fill(side=Side.SELL)], T0)) == 2

    def test_different_tokens_stay_separate(self):
        assert len(aggregate_fills([fill(token="a"), fill(token="b")], T0)) == 2

    def test_signal_id_is_deterministic_and_tx_case_insensitive(self):
        assert signal_id_for("0xAB", "t", Side.BUY) == signal_id_for("0xab", "t", Side.BUY)
        assert signal_id_for("0xab", "t", Side.BUY) != signal_id_for("0xab", "t", Side.SELL)

    def test_zero_share_fill_is_dropped(self):
        assert aggregate_fills([fill(shares=0.0)], T0) == []


class FixedSource:
    def __init__(self, fills):
        self.fills, self.error = fills, None

    def fetch(self):
        if self.error:
            raise self.error
        return list(self.fills)


class TestWalletMonitor:
    def test_new_signal_is_persisted_and_enqueued(self, db):
        q = queue.Queue()
        m = WalletMonitor(FixedSource([fill()]), db, q, clock=lambda: T0 + timedelta(seconds=5))
        assert m.poll_once() == 1
        sig = q.get_nowait()
        assert db.get_signal(sig.signal_id)["status"] == "PENDING"

    def test_rescanning_same_fills_does_not_requeue(self, db):
        q = queue.Queue()
        m = WalletMonitor(FixedSource([fill()]), db, q, clock=lambda: T0)
        m.poll_once()
        assert m.poll_once() == 0 and q.qsize() == 1

    def test_dedupe_survives_restart(self, tmp_path):
        path = str(tmp_path / "m.db")
        q1 = queue.Queue()
        db1 = Database(path)
        WalletMonitor(FixedSource([fill()]), db1, q1, clock=lambda: T0).poll_once()
        db1.close()
        q2 = queue.Queue()
        db2 = Database(path)
        assert WalletMonitor(FixedSource([fill()]), db2, q2, clock=lambda: T0).poll_once() == 0
        assert q2.empty()

    def test_poll_safely_swallows_source_errors(self, db):
        src = FixedSource([])
        src.error = RuntimeError("boom")
        assert WalletMonitor(src, db, queue.Queue()).poll_safely() == 0


class TestDataApiSource:
    def test_parses_trades_and_skips_malformed_rows(self):
        w = FakeWorld(make_settings())
        w.data_api_rows = [
            w.target_trade(ts=BASE_TS, size=10, price=0.5),
            {"side": "BUY"},                                          # 缺字段
            w.target_trade(ts=BASE_TS, size=0, price=0.5, tx="0xb2"),  # 零份额
            w.target_trade(ts=BASE_TS, side="SELL", price=0.7, tx="0xc3"),
        ]
        fills = DataApiTradeSource(w.client(), w.s).fetch()
        assert [f.side for f in fills] == [Side.BUY, Side.SELL]
        assert fills[0].market_id and fills[0].trade_time == datetime.fromtimestamp(BASE_TS, timezone.utc)

    def test_queries_the_configured_wallet(self):
        w = FakeWorld(make_settings())
        DataApiTradeSource(w.client(), w.s).fetch()
        assert w.requests and w.requests[0][1].endswith("data-api.polymarket.com")

    def test_non_list_response_is_empty(self):
        assert parse_data_api_trades({"error": "x"}) == []
