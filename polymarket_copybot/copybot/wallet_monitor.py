"""钱包监控：捕获目标钱包在 Polymarket 上的成交，聚合成跟单信号入队。

两个数据源（MONITOR_SOURCE）：
  chain    读 Polygon 链上 Exchange 合约的 OrderFilled 日志（文档指定方案，需要 RPC Key）。
  dataapi  读 Polymarket Data API 的 /trades?user=（无需 RPC Key，延迟取决于其索引）。

链上匹配规则——**只按 maker == 目标地址 过滤**：
  在 CTF Exchange 中，目标地址的每一笔成交恰好以 maker 身份出现在一条 OrderFilled 事件里
  （无论它是挂单方，还是吃单方——吃单方会产生一条 taker=交易所合约 的汇总事件）。
  若同时匹配 taker 会把同一笔成交重复计入。

  方向判定：makerAssetId == 0 表示 maker 付出 USDC → 买入 token(takerAssetId)；
            否则 maker 付出 token(makerAssetId) → 卖出，收到 USDC。USDC 与份额都是 6 位小数。

注意：目标地址必须是 Polymarket 个人主页上显示的**代理钱包**地址（订单的 maker 是代理钱包，不是签名 EOA）。
"""

from __future__ import annotations

import logging
import queue
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Iterable, Optional, Protocol

import httpx

from .config import Settings
from .db import Database
from .logging_setup import LOGGER_NAME, log_event
from .market_data import ApiError, ApiReporter, get_json
from .models import CopySignal, Fill, Side
from .util import from_unix, utcnow

log = logging.getLogger(f"{LOGGER_NAME}.monitor")

# keccak256("OrderFilled(bytes32,address,address,uint256,uint256,uint256,uint256,uint256)")
ORDER_FILLED_TOPIC = "0xd0a08e8c493f9c94f29311604c9de1b4e8c8d4c06bd0c789af57f2d65bfec0f6"
CURSOR_KEY = "monitor:chain_cursor"
_SIGNAL_NS = uuid.UUID("6f1d3a52-0c0e-4a4e-9a52-5d2f6e0b8c11")
_SCALE = 1e6


class TradeSource(Protocol):
    def fetch(self) -> list[Fill]: ...


def signal_id_for(tx_hash: str, token_id: str, side: Side) -> str:
    """确定性 UUID：同一笔链上成交无论被抓到几次、重启几次，信号 ID 都相同 → 天然去重。"""
    return str(uuid.uuid5(_SIGNAL_NS, f"{tx_hash.lower()}:{token_id}:{side.value}"))


def aggregate_fills(fills: Iterable[Fill], detected_at: datetime) -> list[CopySignal]:
    """同一 tx 内同 token、同方向的多条成交合并为一个信号（份额求和、价格取加权均价）。"""
    groups: dict[tuple[str, str, Side], list[Fill]] = defaultdict(list)
    for f in fills:
        groups[(f.tx_hash.lower(), f.token_id, f.side)].append(f)
    out = []
    for (tx, token, side), fs in groups.items():
        shares = sum(f.shares for f in fs)
        usd = sum(f.usd for f in fs)
        if shares <= 0:
            continue
        out.append(CopySignal(
            signal_id=signal_id_for(tx, token, side), token_id=token, side=side, price=usd / shares,
            shares=shares, amount_usd=usd, tx_hash=tx, trade_time=max(f.trade_time for f in fs),
            detected_at=detected_at, market_id=next((f.market_id for f in fs if f.market_id), None)))
    out.sort(key=lambda s: s.trade_time)
    return out


# ── 数据源 1：链上日志 ──────────────────────────────────
def _pad_address(addr: str) -> str:
    return "0x" + addr.lower().removeprefix("0x").rjust(64, "0")


def _hex(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    return str(v) if str(v).startswith("0x") else "0x" + str(v)


def decode_order_filled(log_entry: dict, trade_time: datetime) -> Optional[Fill]:
    """解码一条 OrderFilled 日志。非预期结构返回 None（不抛异常，由调用方计数告警）。"""
    try:
        data = _hex(log_entry["data"])[2:]
        if len(data) < 64 * 5:
            return None
        words = [int(data[i * 64:(i + 1) * 64], 16) for i in range(5)]
        maker_asset, taker_asset, maker_amt, taker_amt = words[0], words[1], words[2], words[3]
        if maker_asset == 0:   # maker 付 USDC 买 token
            token, usdc, shares, side = taker_asset, maker_amt, taker_amt, Side.BUY
        elif taker_asset == 0:  # maker 付 token 卖，收 USDC
            token, usdc, shares, side = maker_asset, taker_amt, maker_amt, Side.SELL
        else:
            return None        # token↔token 的撮合（未见于二元市场），忽略
        if shares <= 0 or usdc <= 0:
            return None
        return Fill(tx_hash=_hex(log_entry["transactionHash"]).lower(), token_id=str(token), side=side,
                    price=(usdc / _SCALE) / (shares / _SCALE), shares=shares / _SCALE, trade_time=trade_time)
    except (KeyError, ValueError, TypeError):
        return None


class ChainTradeSource:
    def __init__(self, w3: Any, settings: Settings, db: Database, report: Optional[ApiReporter] = None):
        self._w3, self._s, self._db, self._report = w3, settings, db, report
        self._target_topic = _pad_address(settings.target_wallet)
        self._addresses = list(settings.exchange_addresses)
        self.decode_failures = 0

    def fetch(self) -> list[Fill]:
        try:
            fills = self._scan()
        except Exception:
            if self._report:
                self._report("polygon_rpc", False)
            raise
        if self._report:
            self._report("polygon_rpc", True)
        return fills

    def _scan(self) -> list[Fill]:
        s = self._s
        head = int(self._w3.eth.block_number) - s.chain_confirmations
        raw = self._db.kv_get(CURSOR_KEY)
        if raw is None:
            # 首次启动：从当前高度开始，**不回放历史**——否则会跟单目标钱包很久以前的旧交易
            self._db.kv_set(CURSOR_KEY, str(head))
            log_event(log, logging.INFO, "chain_cursor_initialized", block=head)
            return []
        cursor = int(raw)
        # 停机太久会积压大量区块，但过期信号本来就会被 TTL 丢弃，没必要补扫
        start = max(cursor + 1, head - s.chain_max_lookback_blocks)
        fills: list[Fill] = []
        ts_cache: dict[int, datetime] = {}
        while start <= head:
            end = min(start + s.log_block_range - 1, head)
            logs = self._w3.eth.get_logs({
                "fromBlock": start, "toBlock": end, "address": self._addresses,
                "topics": [ORDER_FILLED_TOPIC, None, self._target_topic],
            })
            for entry in logs:
                bn = int(entry["blockNumber"])
                if bn not in ts_cache:
                    ts_cache[bn] = from_unix(int(self._w3.eth.get_block(bn)["timestamp"]))
                fill = decode_order_filled(entry, ts_cache[bn])
                if fill is None:
                    self.decode_failures += 1
                    log_event(log, logging.WARNING, "order_filled_decode_failed", block=bn)
                else:
                    fills.append(fill)
            # 本段扫描成功后才推进游标；失败会抛出，下次从同一位置重试（信号 ID 确定，重复无害）
            self._db.kv_set(CURSOR_KEY, str(end))
            start = end + 1
        return fills


# ── 数据源 2：Polymarket Data API ─────────────────────────
def parse_data_api_trades(rows: Any) -> list[Fill]:
    out = []
    for r in rows if isinstance(rows, list) else []:
        try:
            side = Side(str(r["side"]).upper())
            price, size = float(r["price"]), float(r["size"])
            if price <= 0 or size <= 0:
                continue
            out.append(Fill(
                tx_hash=str(r["transactionHash"]).lower(), token_id=str(r["asset"]), side=side, price=price,
                shares=size, trade_time=from_unix(float(r["timestamp"])), market_id=r.get("conditionId")))
        except (KeyError, ValueError, TypeError):
            continue
    return out


class DataApiTradeSource:
    def __init__(self, http: httpx.Client, settings: Settings, report: Optional[ApiReporter] = None, limit: int = 50):
        self._http, self._s, self._report, self._limit = http, settings, report, limit

    def fetch(self) -> list[Fill]:
        rows = get_json(self._http, "data_api", f"{self._s.data_api_url}/trades",
                        {"user": self._s.target_wallet, "limit": self._limit}, self._report)
        return parse_data_api_trades(rows)


# ── 监控器 ───────────────────────────────────────────
class WalletMonitor:
    def __init__(self, source: TradeSource, db: Database, out: "queue.Queue[CopySignal]", *,
                 clock: Callable[[], datetime] = utcnow):
        self._source, self._db, self._q, self._clock = source, db, out, clock
        self.captured = 0

    def poll_once(self) -> int:
        """拉取一次并入队新信号。返回新入队数量。数据源异常向上抛出，由调用方计入失败次数。"""
        fills = self._source.fetch()
        n = 0
        for sig in aggregate_fills(fills, self._clock()):
            if self._db.insert_signal(sig):  # False = 已见过（重复/重启后重扫）
                self._q.put(sig)
                n += 1
                self.captured += 1
                log_event(log, logging.INFO, "signal_detected", signal_id=sig.signal_id, side=sig.side.value,
                          token_id=sig.token_id, price=round(sig.price, 4), shares=round(sig.shares, 4),
                          target_usd=round(sig.amount_usd, 2), tx=sig.tx_hash,
                          latency_sec=round((sig.detected_at - sig.trade_time).total_seconds(), 1))
        return n

    def poll_safely(self) -> int:
        """poll_once 的兜底版本：任何异常只记日志（健康度已由数据源自己上报给风控）。"""
        try:
            return self.poll_once()
        except Exception as e:  # noqa: BLE001
            # ApiError 的消息只含服务名与状态码、不含 URL，可安全记录；其他异常只记类型（可能带 RPC 地址）
            detail = str(e) if isinstance(e, ApiError) else type(e).__name__
            log_event(log, logging.ERROR, "monitor_poll_failed", error=type(e).__name__, detail=detail)
            return 0


def build_chain_source(settings: Settings, db: Database, report: Optional[ApiReporter] = None) -> ChainTradeSource:
    from web3 import Web3  # 延迟导入：仅链上模式需要

    w3 = Web3(Web3.HTTPProvider(settings.polygon_rpc_url, request_kwargs={"timeout": settings.http_timeout_sec}))
    return ChainTradeSource(w3, settings, db, report)
