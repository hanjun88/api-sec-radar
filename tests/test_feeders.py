"""
test_feeders.py: 态势感知推流器与合成流发生器测试

覆盖之前 0% 的两个 CLI 驱动器中可纯函数化验证的关键契约：
- synthetic artifact 的三态分布与字段结构
- live scan feeder 对 MCP 工具入参/出参契约的解析
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline import live_scan_feeder
from src.pipeline import test_stream_feeder


class FakeMCP:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, arguments))
        if name == "ingest_openapi":
            return {
                "target_matrix": [
                    {
                        "method": "GET",
                        "url": "http://target.local/api/v1/accounts/1001",
                        "path_template": "/api/v1/accounts/{id}",
                        "primary_headers": {"Authorization": "Bearer token-alice"},
                        "secondary_headers": {"Authorization": "Bearer token-bob"},
                        "is_auditable": True,
                        "is_safe_method": True,
                    }
                ]
            }
        if name == "batch_differential_scan":
            assert arguments["target_matrix"]
            return {
                "status": "DELIVERED",
                "all_results": [
                    {
                        "endpoint": "GET /api/v1/accounts/{id}",
                        "verdict": "VULNERABLE",
                        "confidence": 0.97,
                        "primary_status": 200,
                        "secondary_status": 200,
                        "evidence": {
                            "primary_status": 200,
                            "secondary_status": 200,
                            "similarity": 0.96,
                            "elapsed_ms": 42,
                        },
                    }
                ],
            }
        raise AssertionError(f"unexpected tool call: {name}")


def test_live_scan_project_root_is_repository_root() -> None:
    root = Path(live_scan_feeder.PROJECT_ROOT)
    assert root.name == "api-sec-radar"
    assert (root / "src" / "auditor" / "auditor_mcp_server.py").is_file()


def test_live_scan_cycle_uses_mcp_contract_and_all_results() -> None:
    feeder = live_scan_feeder.LiveScanFeeder(
        openapi_spec={"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}},
        scan_interval_sec=0.01,
        primary_token="Bearer token-alice",
        secondary_token="Bearer token-bob",
    )
    feeder.mcp = FakeMCP()

    artifacts = feeder._run_single_scan_cycle()

    assert len(artifacts) == 1
    assert artifacts[0]["verdict"] == "VULNERABLE"
    assert artifacts[0]["evidence"]["response_similarity"] == 0.96

    ingest_name, ingest_args = feeder.mcp.calls[0]
    assert ingest_name == "ingest_openapi"
    assert json.loads(ingest_args["primary_headers_json"]) == {"Authorization": "Bearer token-alice"}
    assert json.loads(ingest_args["secondary_headers_json"]) == {"Authorization": "Bearer token-bob"}
    # 契约：批量差分扫描前必须先经 only_auditable 过滤（纵深防御的下游入口）
    assert ingest_args["only_auditable"] is True

    batch_name, batch_args = feeder.mcp.calls[1]
    assert batch_name == "batch_differential_scan"
    assert batch_args["allow_write"] is False


def test_build_artifact_reads_similarity_from_engine_evidence() -> None:
    artifact = live_scan_feeder.build_artifact_from_scan_result(
        {
            "endpoint": "GET /x",
            "verdict": "SAFE",
            "confidence": 0.88,
            "evidence": {
                "primary_status": 200,
                "secondary_status": 403,
                "similarity": 0.12,
                "elapsed_ms": 7,
            },
        }
    )
    assert artifact["evidence"]["response_similarity"] == 0.12
    assert artifact["evidence"]["elapsed_ms"] == 7


def test_synthetic_artifact_blocks_write_when_roll_low(monkeypatch) -> None:
    monkeypatch.setattr(test_stream_feeder.random, "choice", lambda _: "POST /api/v1/transfer")
    monkeypatch.setattr(test_stream_feeder.random, "random", lambda: 0.1)

    artifact = test_stream_feeder.build_synthetic_artifact()

    assert artifact["verdict"] == "BLOCKED"
    assert artifact["confidence"] == 1.0
    assert artifact["evidence"]["primary_status"] == 0


def test_synthetic_artifact_can_emit_vulnerable_read(monkeypatch) -> None:
    monkeypatch.setattr(test_stream_feeder.random, "choice", lambda _: "GET /api/v1/users/{id}")
    monkeypatch.setattr(test_stream_feeder.random, "random", lambda: 0.2)
    monkeypatch.setattr(test_stream_feeder.random, "uniform", lambda _a, _b: 0.93)
    monkeypatch.setattr(test_stream_feeder.random, "randint", lambda _a, _b: 33)

    artifact = test_stream_feeder.build_synthetic_artifact()

    assert artifact["verdict"] == "VULNERABLE"
    assert artifact["confidence"] == 0.93
    assert artifact["evidence"]["response_similarity"] == 0.93


def test_stream_feeder_stop_flips_running_flag() -> None:
    feeder = test_stream_feeder.StreamFeeder("ws://127.0.0.1:1")
    assert feeder.running is True
    feeder.stop()
    assert feeder.running is False


# --------------------------------------------------------------------------
# verdict 映射完整性：引擎产出的八类必须全部覆盖
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("VULNERABLE", "VULNERABLE"),
        ("PRIV_ESCALATION", "VULNERABLE"),  # 权限提升：高危，不得降级
        ("SUSPECT", "VULNERABLE"),  # 软越权嫌疑：引擎已判定
        ("LIKELY_SAFE", "SAFE"),
        ("SAFE", "SAFE"),
        ("INCONCLUSIVE", "INCONCLUSIVE"),
        ("BLOCKED", "BLOCKED"),
        ("ERROR", "INCONCLUSIVE"),
    ],
)
def test_normalize_verdict_covers_all_engine_verdicts(raw: str, expected: str) -> None:
    """八类 verdict 必须全部被映射。

    回归锁定：PRIV_ESCALATION / SUSPECT 曾因未覆盖而落到 INCONCLUSIVE，
    导致高危越权信号在态势雷达上静默消失。
    """
    assert live_scan_feeder.normalize_verdict(raw) == expected


def test_priv_escalation_reaches_frontend_as_vulnerable() -> None:
    """端到端：引擎的 PRIV_ESCALATION 经工件转换后必须是 VULNERABLE。"""
    artifact = live_scan_feeder.build_artifact_from_scan_result(
        {
            "endpoint": "GET /api/v1/accounts/{id}",
            "verdict": "PRIV_ESCALATION",
            "confidence": 0.75,
            "primary_status": 401,
            "secondary_status": 200,
            "evidence": {
                "primary_status": 401,
                "secondary_status": 200,
                "similarity": 0.9,
            },
        }
    )
    assert artifact["verdict"] == "VULNERABLE"


# --------------------------------------------------------------------------
# 循环控制 / 重连退避 / 停止语义
#
# 通过依赖注入（假 MCP 工厂、假 WebSocket 连接、假 sleep）确定性地驱动
# run() 的无限循环，无需真实子进程、真实网络或真实等待。
# 注入的是「外部依赖」，被测循环逻辑本身真实执行。
# --------------------------------------------------------------------------


class StubMCP:
    """记录生命周期与工具调用序列的假 MCP 客户端（供 LiveScanFeeder 注入）。"""

    def __init__(self) -> None:
        self.records: list[str] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def start(self) -> None:
        self.records.append("start")

    def is_alive(self) -> bool:
        return True

    def initialize(self) -> None:
        self.records.append("initialize")

    def list_tools(self) -> list[str]:
        self.records.append("list_tools")
        return ["ingest_openapi", "batch_differential_scan"]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, arguments))
        if name == "ingest_openapi":
            return {"target_matrix": [{"method": "GET", "url": "http://target.local/api/v1/accounts/1001"}]}
        if name == "batch_differential_scan":
            return {
                "all_results": [
                    {
                        "endpoint": "GET /api/v1/accounts/{id}",
                        "verdict": "VULNERABLE",
                        "confidence": 0.95,
                        "evidence": {
                            "primary_status": 200,
                            "secondary_status": 200,
                            "similarity": 0.97,
                        },
                    }
                ]
            }
        raise AssertionError(f"unexpected tool call: {name}")

    def stop(self) -> None:
        self.records.append("stop")


class FakeWS:
    """记录 send 内容的假 WebSocket 异步上下文管理器。"""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def __aenter__(self) -> "FakeWS":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def test_live_scan_feeder_run_loops_then_stop_exits() -> None:
    """注入假 MCP 与假 sleep：跑满 N 轮后 stop() 能退出，且生命周期完整。"""
    stub = StubMCP()
    ws_connections: list[FakeWS] = []

    def ws_connect(_url: str) -> FakeWS:
        conn = FakeWS()
        ws_connections.append(conn)
        return conn

    rounds = 3
    sleep_calls: list[float] = []

    async def fake_sleep(sec: float) -> None:
        sleep_calls.append(sec)
        if len(sleep_calls) >= rounds:
            feeder.stop()

    feeder = live_scan_feeder.LiveScanFeeder(
        ws_url="ws://127.0.0.1:1",
        openapi_spec={"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}},
        scan_interval_sec=0.01,
        mcp_factory=lambda: stub,
        sleep_fn=fake_sleep,
        ws_connect_fn=ws_connect,
    )

    asyncio.run(feeder.run())

    # 循环按注入的 sleep 计数确定性地跑满 N 轮后退出
    assert feeder.scan_count == rounds
    assert len(sleep_calls) == rounds
    assert all(sec == 0.01 for sec in sleep_calls)

    # 每轮真实调用 _run_single_scan_cycle（两阶段 MCP 工具各一次）
    tool_names = [name for name, _ in stub.calls]
    assert tool_names == ["ingest_openapi", "batch_differential_scan"] * rounds

    # 每轮都经过 _push_via_websocket，推送 1 条合法 JSON 工件
    assert len(ws_connections) == rounds
    assert feeder.artifact_count == rounds
    for conn in ws_connections:
        assert len(conn.sent) == 1
        assert json.loads(conn.sent[0])["verdict"] == "VULNERABLE"

    # 生命周期顺序：start → initialize → ... → finally 中的 stop()
    assert stub.records[0] == "start"
    assert stub.records[1] == "initialize"
    assert stub.records[-1] == "stop"


def test_live_scan_feeder_stops_without_push_when_no_artifacts() -> None:
    """扫描无产物时不应触发 WebSocket 推送，但循环与停止语义仍成立。"""
    stub = StubMCP()
    stub.call_tool = lambda name, arguments: (stub.calls.append((name, arguments)) or [])  # type: ignore[assignment]
    ws_connections: list[FakeWS] = []

    def ws_connect(_url: str) -> FakeWS:
        conn = FakeWS()
        ws_connections.append(conn)
        return conn

    sleep_calls: list[float] = []

    async def fake_sleep(sec: float) -> None:
        sleep_calls.append(sec)
        feeder.stop()

    feeder = live_scan_feeder.LiveScanFeeder(
        ws_url="ws://127.0.0.1:1",
        openapi_spec={"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}},
        scan_interval_sec=0.01,
        mcp_factory=lambda: stub,
        sleep_fn=fake_sleep,
        ws_connect_fn=ws_connect,
    )

    asyncio.run(feeder.run())

    assert feeder.scan_count == 1
    assert feeder.artifact_count == 0
    assert ws_connections == []
    assert stub.records[-1] == "stop"


def test_stream_feeder_reconnects_with_backoff_after_refused() -> None:
    """第 1 次连接被拒 → 退避 sleep(2.0) → 第 2 次成功重连。"""
    connect_calls: list[str] = []
    connections: list[FakeWS] = []

    def connect_fn(uri: str) -> FakeWS:
        connect_calls.append(uri)
        if len(connect_calls) == 1:
            raise ConnectionRefusedError("gateway down")
        conn = FakeWS()
        connections.append(conn)
        return conn

    sleep_calls: list[float] = []

    async def fake_sleep(sec: float) -> None:
        sleep_calls.append(sec)
        # 连接成功并发送 1 条后停止，避免无限注入
        if connections and connections[0].sent and sec != 2.0:
            feeder.stop()

    feeder = test_stream_feeder.StreamFeeder(
        uri="ws://127.0.0.1:1",
        interval_sec=0.01,
        connect_fn=connect_fn,
        sleep_fn=fake_sleep,
    )

    asyncio.run(feeder.run())

    assert len(connect_calls) == 2
    assert 2.0 in sleep_calls
    assert feeder.sent_count == 1
    assert len(connections) == 1
    assert len(connections[0].sent) == 1


def test_stream_feeder_no_retry_after_stop_during_backoff() -> None:
    """退避 sleep 期间 stop()：不应再重试连接（if not self.running: break）。"""
    connect_calls: list[str] = []
    sleep_calls: list[float] = []

    def connect_fn(uri: str) -> FakeWS:
        connect_calls.append(uri)
        raise ConnectionRefusedError("gateway down")

    async def fake_sleep(sec: float) -> None:
        sleep_calls.append(sec)
        feeder.stop()  # 模拟退避等待中收到停止信号

    feeder = test_stream_feeder.StreamFeeder(
        uri="ws://127.0.0.1:1",
        interval_sec=0.01,
        connect_fn=connect_fn,
        sleep_fn=fake_sleep,
    )

    asyncio.run(feeder.run())

    # 仅一次连接尝试；退避 sleep 后 break，不再进入下一轮 while
    assert len(connect_calls) == 1
    assert sleep_calls == [2.0]
    assert feeder.sent_count == 0


def test_stream_feeder_inner_loop_exits_immediately_on_stop() -> None:
    """连接建立后内层循环在 stop() 后立即退出，不真正等待 interval_sec。"""
    connections: list[FakeWS] = []

    def connect_fn(uri: str) -> FakeWS:
        conn = FakeWS()
        connections.append(conn)
        return conn

    sleep_calls: list[float] = []

    async def fake_sleep(sec: float) -> None:
        sleep_calls.append(sec)
        feeder.stop()

    feeder = test_stream_feeder.StreamFeeder(
        uri="ws://127.0.0.1:1",
        interval_sec=999.0,  # 若真等待将挂死；假 sleep 立即返回并停止
        connect_fn=connect_fn,
        sleep_fn=fake_sleep,
    )

    asyncio.run(feeder.run())

    assert feeder.sent_count == 1
    assert sleep_calls == [999.0]
    assert len(connections) == 1  # 停止后不再重连


def test_stream_feeder_sends_valid_json_artifacts() -> None:
    """正常发送路径：假连接记录的 payload 是含 endpoint/verdict 的合法 JSON。"""
    connections: list[FakeWS] = []

    def connect_fn(uri: str) -> FakeWS:
        conn = FakeWS()
        connections.append(conn)
        return conn

    rounds = 2
    sleep_calls: list[float] = []

    async def fake_sleep(sec: float) -> None:
        sleep_calls.append(sec)
        if len(sleep_calls) >= rounds:
            feeder.stop()

    feeder = test_stream_feeder.StreamFeeder(
        uri="ws://127.0.0.1:1",
        interval_sec=0.01,
        connect_fn=connect_fn,
        sleep_fn=fake_sleep,
    )

    asyncio.run(feeder.run())

    assert feeder.sent_count == rounds
    assert len(connections) == 1
    sent = connections[0].sent
    assert len(sent) == rounds
    for payload in sent:
        artifact = json.loads(payload)
        assert "endpoint" in artifact
        assert "verdict" in artifact
        assert artifact["verdict"] in {"VULNERABLE", "SAFE", "BLOCKED"}
