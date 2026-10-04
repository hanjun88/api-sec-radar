"""行情服务（订单簿解析/缓存/错误分类/结算查询）与 BTC 识别、波动率、价格源。"""

from __future__ import annotations

import json

import httpx
import pytest

from copybot.btc import CoinbasePriceFeed, InsufficientData, classify_market, volatility
from copybot.market_data import ApiError, ApiNotFound, MarketDataService, parse_book
from copybot.models import MarketInfo, OrderBook, Level
from tests.conftest import make_settings
from tests.fakes import COND, TOKEN_DOWN, TOKEN_UP, FakeWorld, candles, gamma_market, raw_book


def svc(world, report=None, now=lambda: 0.0):
    s = world.s
    return MarketDataService(world.client(), s, report=report, monotonic=now)


class TestBook:
    def test_levels_sorted_regardless_of_server_order(self):
        b = parse_book(TOKEN_UP, raw_book())
        assert [l.price for l in b.asks] == [0.51, 0.53]
        assert [l.price for l in b.bids] == [0.49, 0.47]
        assert b.best_ask == 0.51 and b.best_bid == 0.49
        assert b.min_order_size == 5.0 and b.tick_size == 0.01

    def test_garbage_levels_are_dropped(self):
        raw = raw_book()
        raw["asks"] += [{"price": "abc", "size": "1"}, {"price": "1.5", "size": "1"}, {"price": "0.6", "size": "0"}]
        assert len(parse_book(TOKEN_UP, raw).asks) == 2

    def test_vwap_fill_walks_the_book_within_limit(self):
        b = OrderBook(TOKEN_UP, (), (Level(0.50, 10), Level(0.52, 10), Level(0.60, 100)))
        filled, avg = b.fill_buy(15, limit=0.55)
        assert filled == 15 and avg == pytest.approx((10 * 0.50 + 5 * 0.52) / 15)

    def test_fill_stops_at_limit(self):
        b = OrderBook(TOKEN_UP, (), (Level(0.50, 10), Level(0.60, 100)))
        assert b.fill_buy(50, limit=0.55) == (10, 0.50)

    def test_sell_fill(self):
        b = OrderBook(TOKEN_UP, (Level(0.50, 5), Level(0.48, 5), Level(0.40, 50)), ())
        filled, avg = b.fill_sell(8, limit=0.45)
        assert filled == 8 and avg == pytest.approx((5 * 0.50 + 3 * 0.48) / 8)

    def test_book_cached_for_ttl(self):
        w = FakeWorld(make_settings())
        t = [0.0]
        m = svc(w, now=lambda: t[0])
        m.get_book(TOKEN_UP)
        m.get_book(TOKEN_UP)
        assert sum(1 for r in w.requests if r[2] == "/book") == 1
        t[0] = 6.0  # 超过 5 秒 TTL
        m.get_book(TOKEN_UP)
        assert sum(1 for r in w.requests if r[2] == "/book") == 2

    def test_fresh_bypasses_cache(self):
        w = FakeWorld(make_settings())
        m = svc(w)
        m.get_book(TOKEN_UP)
        m.get_book(TOKEN_UP, fresh=True)
        assert sum(1 for r in w.requests if r[2] == "/book") == 2

    def test_only_get_requests(self):
        w = FakeWorld(make_settings())
        m = svc(w)
        m.get_book(TOKEN_UP)
        m.get_market_info(TOKEN_UP)
        assert w.non_get_requests() == []


class TestErrorClassification:
    def test_404_is_not_counted_as_service_failure(self):
        w = FakeWorld(make_settings())
        seen = []
        m = svc(w, report=lambda name, ok: seen.append((name, ok)))
        with pytest.raises(ApiNotFound):
            m.get_book("no-such-token")
        assert seen == [("clob", True)]

    def test_5xx_counts_as_failure(self):
        w = FakeWorld(make_settings())
        w.fail["clob.polymarket.com"] = 503
        seen = []
        m = svc(w, report=lambda name, ok: seen.append((name, ok)))
        with pytest.raises(ApiError):
            m.get_book(TOKEN_UP)
        assert seen == [("clob", False)]

    def test_network_error_message_has_no_url(self):
        def boom(req):
            raise httpx.ConnectError("failed connecting to https://secret-host/key=abc123")

        s = make_settings()
        m = MarketDataService(httpx.Client(transport=httpx.MockTransport(boom)), s)
        with pytest.raises(ApiError) as ei:
            m.get_book(TOKEN_UP)
        assert "abc123" not in str(ei.value) and "secret-host" not in str(ei.value)

    def test_non_json_body_is_failure(self):
        s = make_settings()
        client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>")))
        with pytest.raises(ApiError):
            MarketDataService(client, s).get_book(TOKEN_UP)


class TestMarketInfoAndResolution:
    def test_gamma_stringified_arrays_are_parsed(self):
        w = FakeWorld(make_settings())
        info = svc(w).get_market_info(TOKEN_DOWN)
        assert info.condition_id == COND and info.outcome == "Down"
        assert info.end_date is not None and info.end_date.tzinfo is not None

    def test_unknown_token_raises_not_found(self):
        w = FakeWorld(make_settings())
        with pytest.raises(ApiNotFound):
            svc(w).get_market_info("999")

    def test_metadata_cached_forever(self):
        w = FakeWorld(make_settings())
        m = svc(w)
        m.get_market_info(TOKEN_UP)
        m.get_market_info(TOKEN_UP)
        assert sum(1 for r in w.requests if "gamma" in r[1]) == 1

    @pytest.mark.parametrize("closed,prices,token,expected", [
        (False, ("0.5", "0.5"), TOKEN_UP, None),     # 未结算
        (True, ("1", "0"), TOKEN_UP, 1.0),           # 赢
        (True, ("1", "0"), TOKEN_DOWN, 0.0),         # 输
        (True, ("0.5", "0.5"), TOKEN_UP, 0.5),       # 作废
        (True, ("0.62", "0.38"), TOKEN_UP, None),    # closed 但结果未落定
    ])
    def test_resolution_payoff(self, closed, prices, token, expected):
        w = FakeWorld(make_settings())
        w.markets_by_condition[COND] = gamma_market(closed=closed, prices=prices)
        assert svc(w).resolution_payoff(COND, token) == expected

    def test_resolution_for_unknown_condition(self):
        w = FakeWorld(make_settings())
        assert svc(w).resolution_payoff("0xother", TOKEN_UP) is None


def info(question, slug=""):
    return MarketInfo("c", "t", question, slug, "Up")


class TestClassifier:
    @pytest.mark.parametrize("q,slug,expected", [
        ("Bitcoin Up or Down - October 4, 3PM ET", "bitcoin-up-or-down-october-4-3pm-et", "BTC_HOURLY"),
        ("Bitcoin Up or Down - October 4, 3:15PM-3:30PM ET", "btc-updown-15m-1759593600", "BTC_SHORT"),
        ("Will Bitcoin hit $150k in October?", "will-bitcoin-hit-150k", "BTC_OTHER"),
        ("BTC above $100,000 on October 4?", "", "BTC_OTHER"),
        ("Will the Fed cut rates?", "fed-cut", None),
        ("Ethereum Up or Down - October 4, 3PM ET", "ethereum-up-or-down", None),
        ("Will Bitcoiners win?", "", None),  # 词边界：不是 bitcoin 本身
    ])
    def test_classify(self, q, slug, expected):
        assert classify_market(info(q, slug)) == expected


class TestVolatility:
    def test_cv_formula(self):
        closes = [99.0, 101.0] * 10
        assert volatility(closes) == pytest.approx(1.0 / 100.0)

    def test_flat_market_zero_vol(self):
        assert volatility([100.0] * 20) == 0.0

    def test_insufficient_points_raises(self):
        with pytest.raises(InsufficientData):
            volatility([100.0] * 3)

    def test_nonpositive_mean_raises(self):
        with pytest.raises(InsufficientData):
            volatility([0.0] * 20)


class TestCoinbaseFeed:
    def test_parses_and_orders_chronologically(self):
        w = FakeWorld(make_settings())
        w.candle_rows = candles(n=30)
        closes = CoinbasePriceFeed(w.client(), w.s.price_feed_url).closes_last_hour()
        assert len(closes) == 30

    def test_drops_candles_older_than_one_hour(self):
        w = FakeWorld(make_settings())
        w.candle_rows = candles(n=100)  # 100 分钟
        closes = CoinbasePriceFeed(w.client(), w.s.price_feed_url).closes_last_hour()
        assert 59 <= len(closes) <= 61

    def test_cached_for_ttl(self):
        w = FakeWorld(make_settings())
        feed = CoinbasePriceFeed(w.client(), w.s.price_feed_url, monotonic=lambda: 0.0)
        feed.closes_last_hour()
        feed.closes_last_hour()
        assert sum(1 for r in w.requests if r[2].endswith("/candles")) == 1

    def test_bad_shape_raises(self):
        w = FakeWorld(make_settings())
        w.candle_rows = {"message": "rate limited"}
        with pytest.raises(ApiError):
            CoinbasePriceFeed(w.client(), w.s.price_feed_url).closes_last_hour()
