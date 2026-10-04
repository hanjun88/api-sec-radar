"""测试替身：用 httpx.MockTransport 模拟 Polymarket / Coinbase / Telegram，并记录所有请求。

⚠️ 响应结构按官方 py-clob-client 与 Gamma/Data API 文档的已知形状构造，**不是**对线上真实响应的抓包。
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

import httpx

from copybot.config import Settings

TOKEN_UP, TOKEN_DOWN = "111", "222"
COND = "0xcond0000000000000000000000000000000000000000000000000000000001"
BTC_QUESTION = "Bitcoin Up or Down - October 4, 3PM ET"


def gamma_market(
    *, cond: str = COND, question: str = BTC_QUESTION, slug: str = "bitcoin-up-or-down-october-4-3pm-et",
    tokens: tuple[str, str] = (TOKEN_UP, TOKEN_DOWN), closed: bool = False, prices: tuple[str, str] = ("0.5", "0.5"),
) -> dict:
    return {
        "conditionId": cond, "question": question, "slug": slug,
        "outcomes": json.dumps(["Up", "Down"]), "clobTokenIds": json.dumps(list(tokens)),
        "outcomePrices": json.dumps(list(prices)), "closed": closed, "endDate": "2026-10-04T19:00:00Z",
    }


def raw_book(
    *, asks=((0.51, 100.0), (0.53, 100.0)), bids=((0.49, 100.0), (0.47, 100.0)),
    tick: str = "0.01", min_size: str = "5",
) -> dict:
    return {
        "market": COND, "asset_id": TOKEN_UP, "timestamp": "1759579200000", "hash": "h", "last_trade_price": "0.50",
        # 故意打乱顺序：服务端排序方向不应被依赖
        "bids": [{"price": str(p), "size": str(s)} for p, s in bids],
        "asks": [{"price": str(p), "size": str(s)} for p, s in reversed(asks)],
        "min_order_size": min_size, "tick_size": tick, "neg_risk": False,
    }


def candles(n: int = 60, base: float = 100_000.0, wiggle: float = 5.0, now: Optional[float] = None) -> list[list[float]]:
    """Coinbase 格式 [time, low, high, open, close, volume]，新→旧。"""
    now = now or time.time()
    out = []
    for i in range(n):
        close = base + (wiggle if i % 2 else -wiggle)
        out.append([now - 60 * i - 1, close - 1, close + 1, close, close, 1.0])
    return out


class FakeWorld:
    def __init__(self, settings: Settings):
        self.s = settings
        self.books: dict[str, dict] = {TOKEN_UP: raw_book()}
        self.markets_by_token: dict[str, dict] = {TOKEN_UP: gamma_market(), TOKEN_DOWN: gamma_market()}
        self.markets_by_condition: dict[str, dict] = {COND: gamma_market()}
        self.candle_rows: list[list[float]] = candles()
        self.data_api_rows: list[dict] = []
        self.tg_updates: list[dict] = []
        self.tg_sent: list[str] = []
        self.fail: dict[str, int] = {}  # host 关键字 → 强制返回的 HTTP 状态码
        self.requests: list[tuple[str, str, str]] = []  # (method, host, path)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handle))

    def _handle(self, req: httpx.Request) -> httpx.Response:
        u = urlparse(str(req.url))
        self.requests.append((req.method, u.netloc, u.path))
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        for key, status in self.fail.items():
            if key in u.netloc:
                return httpx.Response(status, json={"error": "forced"})

        if u.netloc.endswith("clob.polymarket.com") and u.path == "/book":
            raw = self.books.get(q.get("token_id", ""))
            return httpx.Response(200, json=raw) if raw else httpx.Response(404, json={"error": "No orderbook"})
        if u.netloc.endswith("gamma-api.polymarket.com") and u.path == "/markets":
            if "clob_token_ids" in q:
                m = self.markets_by_token.get(q["clob_token_ids"])
                return httpx.Response(200, json=[m] if m else [])
            if "condition_ids" in q:
                m = self.markets_by_condition.get(q["condition_ids"])
                return httpx.Response(200, json=[m] if m else [])
        if u.netloc.endswith("data-api.polymarket.com") and u.path == "/trades":
            return httpx.Response(200, json=self.data_api_rows)
        if u.netloc.endswith("coinbase.com") and u.path.endswith("/candles"):
            return httpx.Response(200, json=self.candle_rows)
        if u.netloc == "api.telegram.org":
            if u.path.endswith("/sendMessage"):
                self.tg_sent.append(json.loads(req.content)["text"])
                return httpx.Response(200, json={"ok": True})
            if u.path.endswith("/getUpdates"):
                offset = int(q.get("offset", 0))
                return httpx.Response(200, json={"ok": True, "result": [x for x in self.tg_updates if x["update_id"] >= offset]})
        return httpx.Response(404, json={"error": f"unmocked {req.method} {u.netloc}{u.path}"})

    def target_trade(self, *, side: str = "BUY", token: str = TOKEN_UP, price: float = 0.50, size: float = 20.0,
                     ts: float, tx: str = "0x" + "a1" * 32) -> dict:
        return {"proxyWallet": self.s.target_wallet, "side": side, "asset": token, "conditionId": COND,
                "size": size, "price": price, "timestamp": ts, "transactionHash": tx}

    def non_get_requests(self) -> list[tuple[str, str, str]]:
        return [r for r in self.requests if r[0] != "GET"]
