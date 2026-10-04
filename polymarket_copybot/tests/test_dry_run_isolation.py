"""DRY_RUN 隔离审计：静态（AST）+ 运行时，证明模拟盘路径里**没有任何真实下单调用**。

这是文档 3.5 / Phase 1 验收项"代码审计确认零真实下单调用"的可执行版本。
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

import copybot
from copybot.app import build_bot, build_executor
from copybot.db import Database
from copybot.executor import DryRunExecutor
from tests.conftest import FakeClock, make_settings
from tests.fakes import FakeWorld

PKG = Path(copybot.__file__).parent
LIVE_FILE = "live_executor.py"
FORBIDDEN_CALLS = {"post_order", "post_orders", "create_order", "create_and_post_order",
                   "create_market_order", "cancel_all", "cancel_orders"}
POLYMARKET_HOSTS = ("polymarket.com",)


def modules():
    return [(p.name, ast.parse(p.read_text(encoding="utf-8"), filename=str(p))) for p in sorted(PKG.glob("*.py"))]


def non_live_modules():
    return [(n, t) for n, t in modules() if n != LIVE_FILE]


def _is_live_import(node) -> bool:
    return (
        (isinstance(node, ast.ImportFrom) and (node.module or "").endswith("live_executor"))
        or (isinstance(node, ast.Import) and any(a.name.endswith("live_executor") for a in node.names))
        or (isinstance(node, ast.ImportFrom) and bool(node.level)
            and any(a.name == "live_executor" for a in node.names)))


def module_level_live_imports(tree: ast.AST) -> list[int]:
    """返回不在任何函数体内的 live_executor 导入所在行号。"""
    out: list[int] = []

    def visit(node, in_function: bool) -> None:
        is_fn = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for child in ast.iter_child_nodes(node):
            if _is_live_import(child) and not (in_function or is_fn):
                out.append(child.lineno)
            visit(child, in_function or is_fn)

    visit(tree, False)
    return out


class TestStaticAudit:
    def test_live_file_exists_and_is_the_only_one_importing_the_sdk(self):
        assert (PKG / LIVE_FILE).exists()
        offenders = []
        for name, tree in non_live_modules():
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mods = [node.module or ""]
                if any(m.split(".")[0] == "py_clob_client" for m in mods):
                    offenders.append(name)
        assert offenders == []

    def test_no_order_placing_calls_outside_live_executor(self):
        offenders = []
        for name, tree in non_live_modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                    if called in FORBIDDEN_CALLS:
                        offenders.append((name, called, node.lineno))
        assert offenders == []

    def test_live_executor_is_only_imported_lazily_inside_a_function(self):
        offenders = [(name, ln) for name, tree in non_live_modules() for ln in module_level_live_imports(tree)]
        assert offenders == [], "live_executor 只能在函数体内（MODE=LIVE 分支）延迟导入"

    def test_audit_logic_really_catches_violations(self):
        """元测试：审计函数必须能识别模块级导入，同时放过函数体内（含 if 分支内）的延迟导入。"""
        bad = ast.parse("from .live_executor import LiveExecutor\n")
        assert module_level_live_imports(bad) == [1]
        bad2 = ast.parse("import copybot.live_executor\n")
        assert module_level_live_imports(bad2) == [1]
        bad3 = ast.parse("from . import live_executor\n")
        assert module_level_live_imports(bad3) == [1]
        good = ast.parse("def f(s):\n    if s:\n        from .live_executor import LiveExecutor\n")
        assert module_level_live_imports(good) == []

    def test_private_key_is_only_touched_by_config_and_live_executor(self):
        allowed = {"config.py", LIVE_FILE}
        offenders = []
        for name, tree in modules():
            if name in allowed:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "private_key":
                    offenders.append((name, node.lineno))
        assert offenders == []

    def test_http_post_exists_only_in_the_telegram_notifier(self):
        posters = set()
        for name, tree in non_live_modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "post":
                    posters.add(name)
        assert posters <= {"notifier.py"}


class TestRuntimeAudit:
    @pytest.fixture
    def sdk_blocked(self, monkeypatch):
        """让 `import py_clob_client` 直接失败——DRY_RUN 全流程必须在没有该库的环境里照常跑通。"""
        monkeypatch.setitem(sys.modules, "py_clob_client", None)
        monkeypatch.delitem(sys.modules, "copybot.live_executor", raising=False)

    def test_dry_run_pipeline_works_without_the_sdk_and_never_loads_live_code(self, sdk_blocked):
        s = make_settings(BANKROLL_USD="1000")
        clock, w = FakeClock(), None
        w = FakeWorld(s)
        bot = build_bot(s, http=w.client(), db=Database(":memory:"), clock=clock)
        assert isinstance(bot.executor, DryRunExecutor)
        w.data_api_rows = [w.target_trade(ts=clock.now.timestamp() - 5)]
        assert bot.monitor.poll_once() == 1
        bot.step()
        assert len(bot.db.open_trades(s.mode)) == 1
        assert "copybot.live_executor" not in sys.modules

    def test_every_request_to_polymarket_is_a_get(self, sdk_blocked):
        s = make_settings(BANKROLL_USD="1000")
        clock, w = FakeClock(), None
        w = FakeWorld(s)
        bot = build_bot(s, http=w.client(), db=Database(":memory:"), clock=clock)
        w.data_api_rows = [w.target_trade(ts=clock.now.timestamp() - 5)]
        bot.monitor.poll_once()
        bot.step()
        bot.settler.run_once()
        pm = [r for r in w.requests if any(h in r[1] for h in POLYMARKET_HOSTS)]
        assert pm, "应当访问过行情接口"
        assert all(r[0] == "GET" for r in pm)
        assert w.non_get_requests() == []

    def test_private_key_in_environment_is_ignored_in_dry_run(self):
        s = make_settings(PRIVATE_KEY="0x" + "11" * 32, CLOB_API_KEY="k", CLOB_API_SECRET="s", CLOB_API_PASSPHRASE="p")
        assert s.private_key is None and s.clob_api_key is None
        assert isinstance(build_executor(s, Database(":memory:"), None), DryRunExecutor)

    def test_live_mode_loads_the_live_executor_only_when_explicitly_selected(self, monkeypatch):
        import copybot.live_executor as live

        class StubClient:  # 防止测试真的去连网络/派生凭证
            pass

        monkeypatch.setattr(live, "build_client", lambda s: StubClient())
        monkeypatch.setattr(live, "load_sdk", lambda: object())
        s = make_settings(MODE="LIVE", PRIVATE_KEY="0x" + "11" * 32, REQUIRE_APPROVAL="false")
        ex = build_executor(s, Database(":memory:"), None)
        assert isinstance(ex, live.LiveExecutor)
