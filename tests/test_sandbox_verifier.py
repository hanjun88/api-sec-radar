"""tests/test_sandbox_verifier.py — 修复补丁静态验证测试（诚实状态契约）。

verify_python_patch 现为纯静态检查：
  - 语法错误 → COMPILE_ERROR
  - 缺 tenant filter / 404 → PARTIAL（verified_safe=False，post_fix 状态为 0）
  - AST 双特征命中 → STATIC_AST_PASSED（verified_safe=False，post_fix 状态为 0）
  物理运行时验证不在本函数内执行。
"""

from __future__ import annotations

from src.auditor.sandbox_verifier import verify_python_patch


_GOOD_PATCH = '''
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


class TestCompileError:
    def test_syntax_error_returns_compile_error(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _BAD_SYNTAX, "a", "b")
        assert r["patch_compiles"] is False
        assert r["verified_safe"] is False
        assert r["remediation_status"] == "COMPILE_ERROR"

    def test_syntax_error_statuses_zero(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _BAD_SYNTAX, "a", "b")
        assert r["primary_status_post_fix"] == 0
        assert r["secondary_status_post_fix"] == 0


class TestPartial:
    def test_missing_tenant_filter(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _MISSING_TENANT, "a", "b")
        assert r["patch_compiles"] is True
        assert r["verified_safe"] is False
        assert r["remediation_status"] == "PARTIAL"
        assert "缺失" in r["evidence_details"]

    def test_missing_404_hide(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _MISSING_404, "a", "b")
        assert r["verified_safe"] is False
        assert r["remediation_status"] == "PARTIAL"

    def test_partial_statuses_zero(self) -> None:
        """未做物理请求，post_fix 状态必须为 0。"""
        r = verify_python_patch("http://t/api", "orig", _MISSING_TENANT, "a", "b")
        assert r["primary_status_post_fix"] == 0
        assert r["secondary_status_post_fix"] == 0


class TestHonestStaticPass:
    """AST 通过 ≠ 物理安全：诚实标记。"""

    def test_static_ast_passed_status(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _GOOD_PATCH, "a", "b")
        assert r["patch_compiles"] is True
        assert r["remediation_status"] == "STATIC_AST_PASSED"

    def test_static_pass_not_verified_safe(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _GOOD_PATCH, "a", "b")
        assert r["verified_safe"] is False

    def test_static_pass_statuses_zero(self) -> None:
        """未发真实 HTTP 请求，post_fix 状态为 0。"""
        r = verify_python_patch("http://t/api", "orig", _GOOD_PATCH, "a", "b")
        assert r["primary_status_post_fix"] == 0
        assert r["secondary_status_post_fix"] == 0

    def test_evidence_mentions_no_physical_check(self) -> None:
        r = verify_python_patch("http://t/api", "orig", _GOOD_PATCH, "a", "b")
        assert "物理" in r["evidence_details"]
