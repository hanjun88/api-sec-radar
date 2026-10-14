"""tests/test_batch_scan.py — 批量并发差分扫描的并发分支与契约测试。

聚焦 ``src/auditor/auditor_mcp_server.py`` 中两个此前覆盖薄弱的函数：

- ``_execute_single_entry``：worker 线程内单条矩阵条目的差分测试
  （限速 sleep / 动态 Hook 签名 / 独立 auditor 实例 / fast_mode / 异常兜底）。
- ``_run_batch_scan``：ThreadPoolExecutor 并发调度、按原始矩阵顺序排序、
  fast_mode 传播、写熔断聚合、scan_summary 统计与 vulnerable_endpoints 排序。

设计原则：**真实驱动，不 mock 被测逻辑**。
- 复用 ``tests/conftest.py`` 的 ``mock_target_server``（真实 HTTP 漏洞靶场）。
- 另起一个轻量真实 HTTP server（``timing_server``）用于制造
  「慢条目先提交却最后完成」以及「中等相似度 → 中置信度 VULNERABLE」两类场景，
  以便对顺序保持与置信度排序做有意义的断言（均走真实网络，非 mock）。
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("mcp", reason="mcp 未安装，跳过 MCP 服务层测试")

from src.auditor.auditor_mcp_server import (  # noqa: E402
    _execute_single_entry,
    _run_batch_scan,
)

# 与靶场约定一致：token-<owner>；1001=alice / 1002=bob / 1003=charlie
PRIMARY = "token-alice"
SECONDARY = "token-bob"
THRESHOLD = 0.85


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------


def _make_entry(
    method: str,
    url: str,
    *,
    is_auditable: bool = True,
    is_safe_method: bool = True,
    json_body: Optional[str] = None,
    path_template: Optional[str] = None,
) -> Dict[str, Any]:
    """构造一条待测矩阵条目（与 openapi.parse_openapi_spec 输出同构）。"""
    entry: Dict[str, Any] = {
        "method": method,
        "url": url,
        "primary_headers": {},
        "secondary_headers": {},
        "json_body": json_body,
        "is_auditable": is_auditable,
        "is_safe_method": is_safe_method,
    }
    if path_template is not None:
        entry["path_template"] = path_template
    return entry


def _closed_port() -> int:
    """返回一个当前无进程监听的本地端口（用于制造连接失败）。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------
# 辅助真实靶场：制造「慢条目」与「中等相似度」两类场景
# --------------------------------------------------------------------------

# 两个身份的响应体只有 JSON key 集合大小不同（值不参与相似度计算）：
# BIG=10 个 key，SMALL=8 个 key → Jaccard=0.8，长度比≈0.8，相似度≈0.8。
_BIG_BODY = json.dumps({k: 1 for k in "abcdefghij"})
_SMALL_BODY = json.dumps({k: 1 for k in "abcdefgh"})


class _TimingHandler(BaseHTTPRequestHandler):
    """轻量真实 HTTP server：/slow 慢响应、/vuln-low 中相似度、其余 200 同体。"""

    def log_message(self, *args: Any) -> None:  # noqa: D401 - 静默访问日志
        return

    def _token(self) -> str:
        auth = self.headers.get("Authorization", "")
        return auth[len("Bearer "):] if auth.startswith("Bearer ") else ""

    def _json(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 命名约定
        path = self.path.split("?")[0]
        if path == "/slow":
            time.sleep(0.5)
        if path == "/vuln-low":
            # primary(alice) 响应体更大 → 两身份 2xx 且相似度 0.8（< 阈值）
            self._json(_BIG_BODY if self._token().endswith("alice") else _SMALL_BODY)
            return
        # 默认：两身份响应体完全一致 → 相似度 1.0
        self._json(json.dumps({"id": 1, "owner": "x"}))


@pytest.fixture(scope="module")
def timing_server() -> Any:
    """启动辅助真实 HTTP server，返回基址。"""
    server = HTTPServer(("127.0.0.1", 0), _TimingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------
# 1. 顺序保持
# --------------------------------------------------------------------------


def test_batch_scan_preserves_matrix_order(timing_server: str) -> None:
    """乱序完成不得打乱输出：慢条目先提交、最后完成，仍须排在最前。"""
    urls: List[str] = [f"{timing_server}/slow"] + [
        f"{timing_server}/vuln-high?i={i}" for i in range(4)
    ]
    matrix = [_make_entry("GET", u) for u in urls]

    res = _run_batch_scan(matrix, 5, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    # 输出顺序严格等于输入矩阵顺序（靠 _matrix_index 排序，而非完成顺序）
    assert [r["url"] for r in res["all_results"]] == urls
    assert res["scan_summary"]["total"] == 5
    assert all(r["verdict"] == "VULNERABLE" for r in res["all_results"])
    # 内部排序字段不得泄漏到输出契约
    assert all("_matrix_index" not in r for r in res["all_results"])


def test_batch_scan_mixed_order_preserved(mock_target_server: str) -> None:
    """不同 verdict 混合时，all_results 仍按输入顺序返回。"""
    matrix = [
        _make_entry("GET", f"{mock_target_server}/api/v1/secure/1001"),   # SAFE
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/1001"),  # VULNERABLE
        _make_entry("GET", f"{mock_target_server}/api/v1/admin/users"),    # VULNERABLE
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/9999"),  # INCONCLUSIVE
    ]
    res = _run_batch_scan(matrix, 4, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    assert [r["url"] for r in res["all_results"]] == [e["url"] for e in matrix]
    assert [r["verdict"] for r in res["all_results"]] == [
        "SAFE", "VULNERABLE", "VULNERABLE", "INCONCLUSIVE",
    ]


# --------------------------------------------------------------------------
# 2. 错误隔离
# --------------------------------------------------------------------------


def test_batch_scan_isolates_connection_error(mock_target_server: str) -> None:
    """单条连接失败 → ERROR，且不影响其余条目，error 计数为 1。"""
    good1 = _make_entry("GET", f"{mock_target_server}/api/v1/accounts/1001")
    bad = _make_entry(
        "GET", f"http://127.0.0.1:{_closed_port()}/api/v1/accounts/1001"
    )
    good2 = _make_entry("GET", f"{mock_target_server}/api/v1/secure/1001")
    matrix = [good1, bad, good2]

    res = _run_batch_scan(matrix, 3, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    assert res["scan_summary"]["error"] == 1
    assert res["scan_summary"]["total"] == 3
    by_url = {r["url"]: r for r in res["all_results"]}

    err = by_url[bad["url"]]
    assert err["verdict"] == "ERROR"
    assert "error" in err["evidence"] and "type" in err["evidence"]
    # 其余条目仍正常判定
    assert by_url[good1["url"]]["verdict"] == "VULNERABLE"
    assert by_url[good2["url"]]["verdict"] == "SAFE"
    # 顺序不因错误条目被打乱
    assert [r["url"] for r in res["all_results"]] == [
        good1["url"], bad["url"], good2["url"],
    ]


def test_execute_single_entry_invalid_url_returns_error() -> None:
    """非法 URL 触发 RequestIdentity 校验异常 → 外层 except 兜底为 ERROR。"""
    entry = _make_entry("GET", "not-a-url")
    r = _execute_single_entry(entry, False, None, PRIMARY, SECONDARY, THRESHOLD)

    assert r["verdict"] == "ERROR"
    assert r["confidence"] == 0.0
    assert r["similarity"] == 0.0
    assert r["primary_status"] == 0 and r["secondary_status"] == 0
    assert r["evidence"]["type"] == "ValidationError"
    assert "error" in r["evidence"]


# --------------------------------------------------------------------------
# 3. fast_mode 语义
# --------------------------------------------------------------------------


def test_fast_mode_slims_non_auditable_evidence(mock_target_server: str) -> None:
    """fast_mode 下非 auditable 条目证据瘦身，仅保留状态码/相似度/标记。"""
    entry = _make_entry(
        "GET", f"{mock_target_server}/api/v1/health", is_auditable=False
    )
    r = _execute_single_entry(
        entry, False, None, PRIMARY, SECONDARY, THRESHOLD, fast_mode=True
    )

    assert r["is_auditable"] is False
    assert r["evidence"].get("_fast_mode") is True
    assert set(r["evidence"].keys()) == {
        "primary_status", "secondary_status", "similarity", "_fast_mode",
    }
    # verdict 仍被正常计算（未因瘦身而丢失判定）
    assert r["verdict"] == "VULNERABLE"


def test_fast_mode_keeps_auditable_full_evidence(mock_target_server: str) -> None:
    """fast_mode 下 auditable 条目保留完整证据链。"""
    entry = _make_entry(
        "GET", f"{mock_target_server}/api/v1/accounts/1001", is_auditable=True
    )
    r = _execute_single_entry(
        entry, False, None, PRIMARY, SECONDARY, THRESHOLD, fast_mode=True
    )

    assert r["is_auditable"] is True
    assert "_fast_mode" not in r["evidence"]
    assert "status_match" in r["evidence"]
    assert "threshold" in r["evidence"]


def test_run_batch_scan_fast_mode_propagates(mock_target_server: str) -> None:
    """_run_batch_scan(fast_mode=True) 须将开关透传到每条 worker。"""
    matrix = [
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/1001", is_auditable=True),
        _make_entry("GET", f"{mock_target_server}/api/v1/health", is_auditable=False),
    ]
    res = _run_batch_scan(
        matrix, 2, 0, False, "", PRIMARY, SECONDARY, THRESHOLD, fast_mode=True
    )

    auditable, non_auditable = res["all_results"]
    assert "_fast_mode" not in auditable["evidence"]
    assert non_auditable["evidence"]["_fast_mode"] is True


# --------------------------------------------------------------------------
# 4. 写熔断（P0-INVARIANT-03）
# --------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_write_methods_blocked_without_allow_write(
    method: str, mock_target_server: str
) -> None:
    """allow_write=False 时所有非安全方法零网络流量熔断。"""
    entry = _make_entry(
        method,
        f"{mock_target_server}/api/v1/accounts/1001",
        is_safe_method=False,
    )
    r = _execute_single_entry(entry, False, None, PRIMARY, SECONDARY, THRESHOLD)

    assert r["verdict"] == "BLOCKED"
    assert r["confidence"] == 1.0
    assert r["evidence"]["blocked_by"] == "P0-INVARIANT-03"
    assert r["evidence"]["method"] == method
    # 熔断发生在任何网络连接之前
    assert r["primary_status"] == 0 and r["secondary_status"] == 0


def test_put_not_blocked_when_allow_write_true(mock_target_server: str) -> None:
    """allow_write=True 时写操作放行，靶场越权写入被判定为 VULNERABLE。"""
    entry = _make_entry(
        "PUT", f"{mock_target_server}/api/v1/accounts/1001", is_safe_method=False
    )
    r = _execute_single_entry(entry, True, None, PRIMARY, SECONDARY, THRESHOLD)

    assert r["verdict"] == "VULNERABLE"
    assert r["primary_status"] == 200 and r["secondary_status"] == 200


def test_batch_scan_counts_blocked(mock_target_server: str) -> None:
    """批量扫描下写条目被熔断并计入 blocked 统计。"""
    matrix = [
        _make_entry(
            "PUT", f"{mock_target_server}/api/v1/accounts/1001", is_safe_method=False
        )
    ]
    res = _run_batch_scan(matrix, 1, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    assert res["scan_summary"]["blocked"] == 1
    assert res["all_results"][0]["verdict"] == "BLOCKED"


# --------------------------------------------------------------------------
# 5. 聚合统计正确性
# --------------------------------------------------------------------------


def test_scan_summary_counts_match_known_distribution(mock_target_server: str) -> None:
    """构造已知 verdict 分布的矩阵，逐一校验 scan_summary 各计数。"""
    closed = _closed_port()
    matrix = [
        # VULNERABLE（BOLA：任意 token 可读任意账户）
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/1001", is_auditable=True),
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/1002", is_auditable=True),
        # SAFE（正确拒绝：bob 读 alice 的 secure 资源 → 403）
        _make_entry("GET", f"{mock_target_server}/api/v1/secure/1001", is_auditable=True),
        # BLOCKED（写熔断）
        _make_entry(
            "PUT", f"{mock_target_server}/api/v1/accounts/1001",
            is_safe_method=False, is_auditable=True,
        ),
        # INCONCLUSIVE（双 404）
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/9999", is_auditable=True),
        # ERROR（连接失败）
        _make_entry("GET", f"http://127.0.0.1:{closed}/api/v1/accounts/1001"),
    ]

    res = _run_batch_scan(matrix, 6, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    assert res["scan_summary"] == {
        "total": 6,
        "vulnerable": 2,
        "priv_escalation": 0,
        "suspect": 0,
        "safe": 1,
        "likely_safe": 0,
        "blocked": 1,
        "inconclusive": 1,
        "error": 1,
        "auditable_vulnerable": 2,
    }
    # 顺序仍与输入一致
    assert [r["url"] for r in res["all_results"]] == [e["url"] for e in matrix]
    # vulnerable_endpoints 恰为两条 VULNERABLE
    assert len(res["vulnerable_endpoints"]) == 2
    assert all(r["verdict"] == "VULNERABLE" for r in res["vulnerable_endpoints"])


def test_scan_summary_total_equals_category_sum(mock_target_server: str) -> None:
    """契约：scan_summary.total 必须等于各 verdict 分类之和。

    回归锁定：曾因只统计 VULNERABLE/SAFE/BLOCKED/INCONCLUSIVE/ERROR 五类，
    漏计 core._verdict 还会产出的 PRIV_ESCALATION/SUSPECT/LIKELY_SAFE，
    导致 total != 各分类之和，且高危的 PRIV_ESCALATION 被排除在
    vulnerable_endpoints 之外。
    """
    # primary 无 token → 401；secondary token-bob → 200 ⇒ PRIV_ESCALATION（0.75）
    matrix = [
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/1001", is_auditable=True)
    ]
    res = _run_batch_scan(matrix, 1, 0, False, "", "", "token-bob", 0.85)

    assert res["all_results"][0]["verdict"] == "PRIV_ESCALATION"
    s = res["scan_summary"]
    assert s["total"] == sum(
        s[k]
        for k in (
            "vulnerable",
            "priv_escalation",
            "suspect",
            "safe",
            "likely_safe",
            "blocked",
            "inconclusive",
            "error",
        )
    )
    # 权限提升属高危，必须进入高危清单
    assert s["priv_escalation"] == 1
    assert [r["verdict"] for r in res["vulnerable_endpoints"]] == ["PRIV_ESCALATION"]


def test_vulnerable_endpoints_sorted_by_confidence_desc(timing_server: str) -> None:
    """vulnerable_endpoints 按 confidence 降序；all_results 仍保持输入顺序。

    M2 收紧低置信带后，/vuln-low（相似度≈0.8）不再判 VULNERABLE，降级为
    SUSPECT（conf≈0.5）；/vuln-high（相似度≈1.0）仍为 VULNERABLE（conf≈0.99）。
    两者同属高危清单（见 auditor_mcp_server.py high_risk_verdicts），
    故均进入 vulnerable_endpoints，但按置信度降序：high 在前。
    """
    low = _make_entry("GET", f"{timing_server}/vuln-low", is_auditable=True)   # conf≈0.5
    high = _make_entry("GET", f"{timing_server}/vuln-high", is_auditable=True)  # conf≈0.99
    matrix = [low, high]  # 输入顺序：低置信在前

    res = _run_batch_scan(matrix, 2, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    # all_results 保持输入顺序（低在前）
    assert [r["url"] for r in res["all_results"]] == [low["url"], high["url"]]
    # vulnerable_endpoints 按置信度降序（高在前）
    vuln = res["vulnerable_endpoints"]
    assert [r["url"] for r in vuln] == [high["url"], low["url"]]
    confs = [r["confidence"] for r in vuln]
    assert confs == sorted(confs, reverse=True)
    assert confs[0] > confs[1]
    # M2：低置信条目不再误判 VULNERABLE，降级为 SUSPECT；高置信仍为 VULNERABLE
    assert res["all_results"][0]["verdict"] == "SUSPECT"
    assert res["all_results"][1]["verdict"] == "VULNERABLE"
    assert res["scan_summary"]["vulnerable"] == 1
    assert res["scan_summary"]["suspect"] == 1
    assert res["scan_summary"]["auditable_vulnerable"] == 1


# --------------------------------------------------------------------------
# 6. 限速下沉到 worker + 并发度
# --------------------------------------------------------------------------


def test_interval_sleep_happens_inside_worker(mock_target_server: str) -> None:
    """interval_ms 在 worker 内 sleep，单条矩阵耗时应不低于该间隔。"""
    matrix = [_make_entry("GET", f"{mock_target_server}/api/v1/health")]
    res = _run_batch_scan(matrix, 1, 250, False, "", PRIMARY, SECONDARY, THRESHOLD)

    assert res["all_results"][0]["verdict"] == "VULNERABLE"
    # 若 sleep 未下沉到 worker，耗时仅为毫秒级；此处应 ≥ ~250ms
    assert res["elapsed_ms"] >= 200


def test_batch_scan_reports_effective_concurrency(mock_target_server: str) -> None:
    """小矩阵下并发度等于请求值（≤100 档，上限 10）。"""
    matrix = [
        _make_entry("GET", f"{mock_target_server}/api/v1/accounts/100{i}")
        for i in (1, 2, 3)
    ]
    res = _run_batch_scan(matrix, 3, 0, False, "", PRIMARY, SECONDARY, THRESHOLD)

    assert res["concurrency"] == 3
    assert res["status"] == "DELIVERED"
    assert res["scan_summary"]["total"] == 3
