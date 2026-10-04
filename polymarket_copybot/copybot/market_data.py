"""行情服务：CLOB 订单簿（5 秒 TTL 缓存）+ Gamma 市场元数据 + 结算结果查询。

只发 GET 请求——本模块与 DRY_RUN 隔离审计相关：行情服务永远没有"下单"能力。
接口形状取自官方 py-clob-client（`GET /book?token_id=`）与 Gamma 公开文档；
沙箱无法访问这些主机，**字段名未对真实线上响应做过联调**，解析处尽量宽松并在失败时显式报错。
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any, Callable, Optional

import httpx

from .config import Settings
from .models import Level, MarketInfo, OrderBook
from .util import parse_iso

ApiReporter = Callable[[str, bool], None]


class ApiError(Exception):
    """外部 API 调用失败（网络错误、非 2xx、响应无法解析）。消息不含 URL，避免泄露密钥。"""


class ApiNotFound(ApiError):
    """服务正常但资源不存在（如已关闭市场没有订单簿）。不计入"连续失败"。"""


def get_json(
    http: httpx.Client, service: str, url: str, params: Optional[dict] = None,
    report: Optional[ApiReporter] = None,
) -> Any:
    try:
        resp = http.get(url, params=params)
    except httpx.HTTPError as e:
        if report:
            report(service, False)
        raise ApiError(f"{service}: 网络错误 {type(e).__name__}") from None
    if resp.status_code == 404:
        if report:
            report(service, True)
        raise ApiNotFound(f"{service}: 404")
    if resp.status_code >= 400:
        if report:
            report(service, False)
        raise ApiError(f"{service}: HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        if report:
            report(service, False)
        raise ApiError(f"{service}: 响应不是合法 JSON") from None
    if report:
        report(service, True)
    return data


def _as_list(v: Any) -> list:
    """Gamma 把数组字段编码成 JSON 字符串（如 '["Up","Down"]'），也兼容真正的数组。"""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            out = json.loads(v)
            return out if isinstance(out, list) else []
        except ValueError:
            return []
    return []


def _levels(raw: Any, *, descending: bool) -> tuple[Level, ...]:
    out = []
    for lv in raw or []:
        try:
            price, size = float(lv["price"]), float(lv["size"])
        except (KeyError, TypeError, ValueError):
            continue
        if size > 0 and 0.0 < price < 1.0:
            out.append(Level(price, size))
    # 不假设服务端排序（不同版本升降序不一），自己排
    out.sort(key=lambda x: x.price, reverse=descending)
    return tuple(out)


def parse_book(token_id: str, raw: dict) -> OrderBook:
    def f(key: str) -> Optional[float]:
        try:
            return float(raw[key])
        except (KeyError, TypeError, ValueError):
            return None

    return OrderBook(
        token_id=token_id,
        bids=_levels(raw.get("bids"), descending=True),
        asks=_levels(raw.get("asks"), descending=False),
        tick_size=f("tick_size") or 0.01,
        min_order_size=f("min_order_size"),
        neg_risk=bool(raw.get("neg_risk", False)),
    )


def parse_market(token_id: str, raw: dict) -> MarketInfo:
    token_ids = [str(t) for t in _as_list(raw.get("clobTokenIds"))]
    outcomes = [str(o) for o in _as_list(raw.get("outcomes"))]
    outcome = ""
    if token_id in token_ids:
        i = token_ids.index(token_id)
        outcome = outcomes[i] if i < len(outcomes) else ""
    end: Optional[datetime] = None
    if raw.get("endDate"):
        try:
            end = parse_iso(str(raw["endDate"]).replace("Z", "+00:00"))
        except ValueError:
            end = None
    cid = raw.get("conditionId") or raw.get("condition_id") or ""
    return MarketInfo(
        condition_id=str(cid), token_id=token_id, question=str(raw.get("question") or ""),
        slug=str(raw.get("slug") or ""), outcome=outcome, end_date=end, closed=bool(raw.get("closed", False)),
    )


class MarketDataService:
    def __init__(
        self,
        http: httpx.Client,
        settings: Settings,
        report: Optional[ApiReporter] = None,
        *,
        book_ttl_sec: float = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self._http = http
        self._s = settings
        self._report = report
        self._ttl = book_ttl_sec
        self._mono = monotonic
        self._books: dict[str, tuple[float, OrderBook]] = {}
        self._markets: dict[str, MarketInfo] = {}
        self._lock = threading.Lock()

    def get_book(self, token_id: str, *, fresh: bool = False) -> OrderBook:
        now = self._mono()
        if not fresh:
            with self._lock:
                hit = self._books.get(token_id)
            if hit and now - hit[0] < self._ttl:
                return hit[1]
        raw = get_json(self._http, "clob", f"{self._s.clob_url}/book", {"token_id": token_id}, self._report)
        if not isinstance(raw, dict):
            raise ApiError("clob: 订单簿响应结构异常")
        book = parse_book(token_id, raw)
        with self._lock:
            self._books[token_id] = (now, book)
        return book

    def get_market_info(self, token_id: str) -> MarketInfo:
        """token → 市场元数据。元数据基本不变，进程内长期缓存。"""
        with self._lock:
            cached = self._markets.get(token_id)
        if cached:
            return cached
        raw = get_json(self._http, "gamma", f"{self._s.gamma_url}/markets",
                       {"clob_token_ids": token_id}, self._report)
        records = raw.get("data") if isinstance(raw, dict) else raw
        if not records:
            raise ApiNotFound("gamma: 未找到该 token 对应的市场")
        info = parse_market(token_id, records[0])
        with self._lock:
            self._markets[token_id] = info
        return info

    def resolution_payoff(self, condition_id: str, token_id: str) -> Optional[float]:
        """市场已结算则返回该 token 每份的兑付（赢=1，输=0，作废≈0.5）；未结算返回 None。"""
        raw = get_json(self._http, "gamma", f"{self._s.gamma_url}/markets",
                       {"condition_ids": condition_id}, self._report)
        records = raw.get("data") if isinstance(raw, dict) else raw
        for rec in records or []:
            if str(rec.get("conditionId", "")).lower() != condition_id.lower():
                continue
            if not rec.get("closed"):
                return None
            token_ids = [str(t) for t in _as_list(rec.get("clobTokenIds"))]
            try:
                prices = [float(p) for p in _as_list(rec.get("outcomePrices"))]
            except (TypeError, ValueError):
                return None
            if token_id not in token_ids or len(prices) != len(token_ids):
                return None
            payoff = prices[token_ids.index(token_id)]
            if max(prices) >= 0.99:                      # 有明确赢家
                return 1.0 if payoff >= 0.99 else 0.0
            if all(abs(p - 0.5) < 0.05 for p in prices):  # 作废/平分
                return 0.5
            return None                                   # 已 closed 但结果尚未落定
        return None
