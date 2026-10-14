"""tests/test_sandbox_verifier_ast.py — AST 内部辅助函数的细粒度测试。

补充 test_sandbox_verifier.py（端到端状态契约）未覆盖的分支：
  - _extract_identifiers 的三种节点类型（Name / Attribute / Subscript 字符串常量）
  - _has_tenant_filter_ast 的 Compare / Call / If 全部真分支 + 反绕过（注释/字符串）
  - _has_not_found_hide_ast 的 Call / Raise / Assign 全部真分支 + 否定用例
  - _has_not_found_hide_ast_single（raise 路径委托函数）的独立契约
  - verify_python_patch_static 向后兼容别名

反绕过契约（该模块存在的意义）与「静态通过 ≠ 物理安全」契约在此一并锁死。
"""

from __future__ import annotations

import ast

import pytest

from src.auditor.sandbox_verifier import (
    _extract_identifiers,
    _has_not_found_hide_ast,
    _has_not_found_hide_ast_single,
    _has_tenant_filter_ast,
    verify_python_patch,
    verify_python_patch_static,
)


def _first_expr(code: str) -> ast.AST:
    """解析代码并返回首个语句（用于给 _extract_identifiers 喂单节点）。"""
    return ast.parse(code).body[0]


def _first_call(code: str) -> ast.AST:
    """解析代码并返回首个表达式语句里的 Call 节点。"""
    stmt = ast.parse(code).body[0]
    assert isinstance(stmt, ast.Expr)
    return stmt.value


# ── _extract_identifiers ─────────────────────────────────────


class TestExtractIdentifiers:
    def test_name_node(self) -> None:
        assert _extract_identifiers(_first_expr("user_id")) == {"user_id"}

    def test_attribute_node(self) -> None:
        node = _first_expr("account.owner_id")
        # Attribute.attr 收集 owner_id（基 Name account 也会被收集）
        assert "owner_id" in _extract_identifiers(node)

    def test_attribute_and_name_combined(self) -> None:
        node = _first_expr("account.owner_id")
        names = _extract_identifiers(node)
        # Attribute.attr 收集 owner_id；Name 收集 account
        assert "owner_id" in names
        assert "account" in names

    def test_subscript_string_constant(self) -> None:
        node = _first_expr("obj['tenant_id']")
        assert "tenant_id" in _extract_identifiers(node)

    def test_subscript_non_string_constant_ignored(self) -> None:
        """非字符串切片的 Subscript 不应把常量值误收为标识符。"""
        node = _first_expr("obj[0]")
        names = _extract_identifiers(node)
        assert names == {"obj"}
        assert "0" not in names

    def test_subscript_name_slice_is_not_constant(self) -> None:
        """slice 为 Name（非常量）时只收 Name，不误判为字符串常量。"""
        node = _first_expr("obj[user_id]")
        names = _extract_identifiers(node)
        assert names == {"obj", "user_id"}


# ── _has_tenant_filter_ast 真分支 ────────────────────────────


class TestTenantFilterCompare:
    def test_compare_attribute_form(self) -> None:
        code = "if account.owner_id == current_user.id:\n    pass\n"
        assert _has_tenant_filter_ast(code) is True

    def test_compare_name_form(self) -> None:
        assert _has_tenant_filter_ast("ok = user_id == other\n") is True

    def test_compare_camel_case_variant(self) -> None:
        assert _has_tenant_filter_ast("ok = tenantId == x\n") is True


class TestTenantFilterCall:
    def test_call_keyword_arg(self) -> None:
        code = "rows = db.query.filter(owner_id=current_user.id)\n"
        assert _has_tenant_filter_ast(code) is True

    def test_call_positional_arg(self) -> None:
        code = "rows = db.query.where(user_id)\n"
        assert _has_tenant_filter_ast(code) is True

    def test_call_get_or_404_keyword(self) -> None:
        code = "row = Account.query.get_or_404(tenant_id=account.tenant_id)\n"
        assert _has_tenant_filter_ast(code) is True

    def test_call_filter_by_keyword(self) -> None:
        code = "rows = Model.query.filter_by(current_user=u)\n"
        assert _has_tenant_filter_ast(code) is True

    def test_call_negative_wrong_kwarg(self) -> None:
        """filter 命中但参数名不含租户字段 → 不命中。"""
        code = "rows = db.query.filter(name='alice')\n"
        assert _has_tenant_filter_ast(code) is False

    def test_call_negative_non_filter_func(self) -> None:
        """非 filter/where 族函数即使参数含租户字段也不命中。"""
        code = "rows = do_something(owner_id=current_user.id)\n"
        assert _has_tenant_filter_ast(code) is False


class TestTenantFilterIf:
    def test_if_test_attribute(self) -> None:
        """If 分支：test 非 Compare（Attribute）但含租户字段。"""
        code = "if current_user.tenant_id:\n    pass\n"
        assert _has_tenant_filter_ast(code) is True

    def test_if_test_name(self) -> None:
        code = "if user_id:\n    pass\n"
        assert _has_tenant_filter_ast(code) is True


class TestTenantFilterAntiBypass:
    """反绕过：注释/纯字符串字面量绝不能被判为通过。"""

    def test_comment_only_not_matched(self) -> None:
        code = "# owner_id == current_user.id\nx = 1\n"
        assert _has_tenant_filter_ast(code) is False

    def test_string_literal_not_matched(self) -> None:
        code = 'note = "owner_id"\n'
        assert _has_tenant_filter_ast(code) is False

    def test_fstring_text_not_matched(self) -> None:
        code = 'msg = "filter by owner_id"\n'
        assert _has_tenant_filter_ast(code) is False

    def test_syntax_error_returns_false(self) -> None:
        assert _has_tenant_filter_ast("def broken(:") is False


# ── _has_not_found_hide_ast 真分支 ───────────────────────────


class TestNotFoundHide:
    def test_http_exception_status_code_404(self) -> None:
        code = "raise HTTPException(status_code=404)\n"
        assert _has_not_found_hide_ast(code) is True

    def test_json_response_status_code_404(self) -> None:
        code = "resp = JSONResponse(status_code=404, content={})\n"
        assert _has_not_found_hide_ast(code) is True

    def test_response_status_404(self) -> None:
        code = "resp = Response(status=404)\n"
        assert _has_not_found_hide_ast(code) is True

    def test_abort_positional_404(self) -> None:
        assert _has_not_found_hide_ast("abort(404)\n") is True

    def test_attribute_call_abort_positional_404(self) -> None:
        """func 为 Attribute 的调用（obj.abort(404)）也应命中。"""
        assert _has_not_found_hide_ast("obj.abort(404)\n") is True

    def test_raise_not_found_positional_404(self) -> None:
        assert _has_not_found_hide_ast("raise NotFound(404)\n") is True

    def test_assign_status_code_404(self) -> None:
        code = "response.status_code = 404\n"
        assert _has_not_found_hide_ast(code) is True

    def test_assign_status_404(self) -> None:
        code = "response.status = 404\n"
        assert _has_not_found_hide_ast(code) is True

    def test_json_response_without_404_reaches_response_branch(self) -> None:
        """JSONResponse 命中响应类分支，但无 404 → 整体不命中。"""
        code = "resp = JSONResponse(content={})\n"
        assert _has_not_found_hide_ast(code) is False

    @pytest.mark.parametrize("status", [403, 500, 200, 401])
    def test_negative_non_404_status(self, status: int) -> None:
        code = f"raise HTTPException(status_code={status})\n"
        assert _has_not_found_hide_ast(code) is False

    def test_negative_abort_non_404(self) -> None:
        assert _has_not_found_hide_ast("abort(500)\n") is False

    def test_negative_assign_non_404(self) -> None:
        assert _has_not_found_hide_ast("response.status_code = 500\n") is False

    def test_syntax_error_returns_false(self) -> None:
        assert _has_not_found_hide_ast("def broken(:") is False

    def test_anti_bypass_string_literal_404(self) -> None:
        """字符串里的 'status_code=404' 不应被判为通过。"""
        assert _has_not_found_hide_ast('note = "status_code=404"\n') is False

    def test_anti_bypass_comment_404(self) -> None:
        assert _has_not_found_hide_ast("# return 404\nx = 1\n") is False


class TestNotFoundHideFlaskTuple:
    """M4：Flask 元组式返回与无参 NotFound 此前漏检。"""

    def test_flask_tuple_return_404(self) -> None:
        """return jsonify(account), 404 —— 404 为 Tuple 内裸 Constant。"""
        code = "return jsonify(account), 404\n"
        assert _has_not_found_hide_ast(code) is True

    def test_flask_tuple_return_make_response_404(self) -> None:
        code = "return make_response(data), 404\n"
        assert _has_not_found_hide_ast(code) is True

    def test_flask_tuple_return_no_404_not_matched(self) -> None:
        """元组返回但状态码非 404 → 不命中。"""
        code = "return jsonify(account), 200\n"
        assert _has_not_found_hide_ast(code) is False

    def test_raise_not_found_no_arg(self) -> None:
        """raise NotFound() 无 404 参数（Flask/Werkzeug 默认即 404）。"""
        assert _has_not_found_hide_ast("raise NotFound()\n") is True

    def test_raise_not_found_no_arg_attribute(self) -> None:
        assert _has_not_found_hide_ast("raise werkzeug.exceptions.NotFound()\n") is True


class TestTenantFilterSemantics:
    """M5：归属语义词典 + 排除非授权标识符。"""

    def test_uid_g_user_compare(self) -> None:
        """obj.uid == g.user —— 合法归属检查（原词表外而失败）。"""
        code = "if obj.uid == g.user:\n    pass\n"
        assert _has_tenant_filter_ast(code) is True

    def test_resource_owner_compare(self) -> None:
        """resource.owner == account.owner —— 合法归属检查。"""
        code = "if resource.owner == account.owner:\n    pass\n"
        assert _has_tenant_filter_ast(code) is True

    def test_user_is_admin_excluded(self) -> None:
        """user_is_admin(current_user) 是权限检查而非归属过滤，不得通过 tenant 断言。"""
        code = "if user_is_admin(current_user):\n    pass\n"
        assert _has_tenant_filter_ast(code) is False

    def test_is_admin_excluded(self) -> None:
        code = "if is_admin(request.user):\n    pass\n"
        assert _has_tenant_filter_ast(code) is False

    def test_legit_filter_still_matches(self) -> None:
        """原有合法归属检查仍应命中。"""
        code = "if account.owner_id == current_user.id:\n    pass\n"
        assert _has_tenant_filter_ast(code) is True


# ── _has_not_found_hide_ast_single ───────────────────────────


class TestNotFoundHideSingle:
    def test_keyword_status_code_404(self) -> None:
        node = _first_call("HTTPException(status_code=404)")
        assert _has_not_found_hide_ast_single(node) is True

    def test_keyword_status_404(self) -> None:
        node = _first_call("Response(status=404)")
        assert _has_not_found_hide_ast_single(node) is True

    def test_positional_404(self) -> None:
        node = _first_call("abort(404)")
        assert _has_not_found_hide_ast_single(node) is True

    def test_neither_matches(self) -> None:
        node = _first_call("HTTPException(status_code=403)")
        assert _has_not_found_hide_ast_single(node) is False

    def test_non_call_node_returns_false(self) -> None:
        node = _first_expr("x = 1")
        assert _has_not_found_hide_ast_single(node) is False


# ── verify_python_patch 三条主路径 ───────────────────────────


_GOOD = '''
def handler(account, current_user):
    if account.owner_id != current_user.user_id:
        raise HTTPException(status_code=404)
    return account
'''

_MISSING_404 = '''
def handler(account, current_user):
    if account.owner_id != current_user.user_id:
        return None
    return account
'''

_MISSING_TENANT = '''
def handler(account):
    if account is None:
        raise HTTPException(status_code=404)
    return account
'''

_BAD_SYNTAX = "def broken(:"


class TestVerifyCompileError:
    def test_evidence_contains_line_number(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _BAD_SYNTAX, "a", "b")
        assert r["remediation_status"] == "COMPILE_ERROR"
        assert "补丁语法错误" in r["evidence_details"]
        assert "行 1" in r["evidence_details"]


class TestVerifyPartial:
    def test_missing_tenant_message(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _MISSING_TENANT, "a", "b")
        assert r["remediation_status"] == "PARTIAL"
        assert "过滤绑定" in r["evidence_details"]
        # 该用例 404 存在，缺失文案不应包含 404 项
        assert "404实体屏蔽" not in r["evidence_details"]

    def test_missing_404_message(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _MISSING_404, "a", "b")
        assert r["remediation_status"] == "PARTIAL"
        assert "404实体屏蔽" in r["evidence_details"]
        assert "过滤绑定" not in r["evidence_details"]


class TestVerifyStaticPassed:
    """静态通过 ≠ 物理安全：诚实声明必须锁死。"""

    def test_status_and_honest_flags(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _GOOD, "a", "b")
        assert r["patch_compiles"] is True
        assert r["remediation_status"] == "STATIC_AST_PASSED"
        assert r["verified_safe"] is False
        assert r["primary_status_post_fix"] == 0
        assert r["secondary_status_post_fix"] == 0

    def test_evidence_admits_no_physical_check(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _GOOD, "a", "b")
        assert "物理" in r["evidence_details"]
        assert "STATIC_AST_PASSED" == r["remediation_status"]


class TestBackwardCompatAlias:
    def test_alias_is_same_function(self) -> None:
        assert verify_python_patch_static is verify_python_patch

    def test_alias_behavior_matches(self) -> None:
        via_alias = verify_python_patch_static("http://t/api", "orig", _GOOD, "a", "b")
        direct = verify_python_patch("http://t/api", "orig", _GOOD, "a", "b")
        assert via_alias == direct
