"""
sandbox_verifier.py: 修复补丁热载入与沙盒反向验证引擎

对生成的修复补丁执行语法编译检查与行级安全语义断言，
确保补丁严格绑定当前安全凭据上下文并统一返回 404 实体屏蔽。
"""

from __future__ import annotations

import ast
import json
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel


class VerificationResult(BaseModel):
    patch_compiles: bool
    verified_safe: bool
    primary_status_post_fix: int
    secondary_status_post_fix: int
    remediation_status: str  # SUCCESS, PARTIAL, REGRESSION, COMPILE_ERROR, STATIC_AST_PASSED
    evidence_details: str


# 行级过滤关键特征：补丁必须绑定当前安全凭据上下文（AST 级检测）
_TENANT_FILTER_NAMES = {
    "tenant_id", "owner_id", "current_user", "user_id",
    "tenantId", "ownerId", "currentUser", "userId",
}
# 实体屏蔽特征：越权访问必须统一返回 404（AST 级检测 HTTPException/status_code=404）
_NOT_FOUND_STATUS_CODES = {404}


def _extract_identifiers(node: ast.AST) -> set[str]:
    """从 AST 节点中提取所有标识符（Name.id、Attribute.attr、Subscript.slice 字符串常量）。"""
    names: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, ast.Attribute):
            names.add(n.attr)
        elif isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant):
            if isinstance(n.slice.value, str):
                names.add(n.slice.value)
    return names


def _has_tenant_filter_ast(patch_code: str) -> bool:
    """
    AST 级检测：补丁中必须存在对 owner_id/current_user/tenant_id/user_id 的
    真实比较表达式或 filter/where 调用参数，而非注释或字符串字面量。

    支持的代码模式：
    - 比较表达式：Account.owner_id == current_user["user_id"]
    - 函数调用：.filter(owner_id=current_user.id) / .where(user_id=...)
    - 变量引用：if account.owner_id != current_user.id
    """
    try:
        tree = ast.parse(patch_code)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        # 比较表达式：如 user_id == current_user.id / Account.owner_id != owner_id
        if isinstance(node, ast.Compare):
            names = _extract_identifiers(node)
            if names & _TENANT_FILTER_NAMES:
                return True
        # 函数调用：如 .filter(owner_id=current_user.id) / .where(user_id=...)
        if isinstance(node, ast.Call):
            func_names = set()
            for n in ast.walk(node.func):
                if isinstance(n, ast.Name):
                    func_names.add(n.id)
                elif isinstance(n, ast.Attribute):
                    func_names.add(n.attr)
            if func_names & {"filter", "where", "filter_by", "get_or_404", "get"}:
                # 检查关键字参数名
                kw_names = {kw.arg for kw in node.keywords if kw.arg}
                if kw_names & _TENANT_FILTER_NAMES:
                    return True
                # 检查位置参数中的标识符
                for arg in node.args:
                    if _extract_identifiers(arg) & _TENANT_FILTER_NAMES:
                        return True
        # if 语句中的条件表达式：如 if account.owner_id != current_user.id
        if isinstance(node, ast.If):
            if _extract_identifiers(node.test) & _TENANT_FILTER_NAMES:
                return True
    return False


def _has_not_found_hide_ast(patch_code: str) -> bool:
    """
    AST 级检测：补丁中必须存在返回 404 状态码的真实代码。

    支持的代码模式：
    - HTTPException(status_code=404)
    - JSONResponse(status_code=404, ...)
    - Response(status=404, ...)
    - abort(404)
    - raise NotFound()
    - 直接赋值：response.status_code = 404
    """
    try:
        tree = ast.parse(patch_code)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        # 函数调用：HTTPException(status_code=404) / JSONResponse(status_code=404) / abort(404)
        if isinstance(node, ast.Call):
            func_names = set()
            for n in ast.walk(node.func):
                if isinstance(n, ast.Name):
                    func_names.add(n.id)
                elif isinstance(n, ast.Attribute):
                    func_names.add(n.attr)
            # 检查关键字参数 status_code=404 / status=404
            for kw in node.keywords:
                if kw.arg in ("status_code", "status") and isinstance(kw.value, ast.Constant):
                    if kw.value.value in _NOT_FOUND_STATUS_CODES:
                        return True
            # 检查位置参数：abort(404) / raise NotFound(404)
            if func_names & {"abort", "NotFound", "not_found"}:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and arg.value in _NOT_FOUND_STATUS_CODES:
                        return True
            # JSONResponse / Response 等常见响应类
            if func_names & {"JSONResponse", "Response", "jsonify", "make_response", "ORJSONResponse"}:
                for kw in node.keywords:
                    if kw.arg in ("status_code", "status") and isinstance(kw.value, ast.Constant):
                        if kw.value.value in _NOT_FOUND_STATUS_CODES:
                            return True
        # raise 语句：raise HTTPException(status_code=404)
        if isinstance(node, ast.Raise) and node.exc:
            if _has_not_found_hide_ast_single(node.exc):
                return True
        # 直接赋值：response.status_code = 404
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr in ("status_code", "status"):
                    if isinstance(node.value, ast.Constant) and node.value.value in _NOT_FOUND_STATUS_CODES:
                        return True
    return False


def _has_not_found_hide_ast_single(node: ast.AST) -> bool:
    """单节点 404 检测（用于 raise 语句的 exc 子节点）。"""
    if isinstance(node, ast.Call):
        for kw in node.keywords:
            if kw.arg in ("status_code", "status") and isinstance(kw.value, ast.Constant):
                if kw.value.value in _NOT_FOUND_STATUS_CODES:
                    return True
        for arg in node.args:
            if isinstance(arg, ast.Constant) and arg.value in _NOT_FOUND_STATUS_CODES:
                return True
    return False


def verify_python_patch(
    test_url: str,
    original_handler_snippet: str,
    patch_code_snippet: str,
    primary_token: str,
    secondary_token: str,
) -> Dict[str, Any]:
    """
    对补丁代码执行**纯静态**安全语义验证（不发起任何真实网络请求）。

    验证范围（诚实声明）：
      1. 静态编译检查（SyntaxError → COMPILE_ERROR）；
      2. AST 级行级安全语义断言：必须同时包含 tenant_filter 绑定与 404 实体屏蔽。

    重要约束：本函数**不做物理运行时验证**——它不会在隔离环境对真实目标执行
    差分测试，因此即使静态断言通过，``verified_safe`` 仍为 False，
    ``remediation_status`` 为 ``STATIC_AST_PASSED``，``primary/secondary_status_post_fix``
    均为 0（未执行物理请求）。静态通过 ≠ 物理安全；物理运行时验证必须由调用方
    在隔离环境中对真实目标另行执行差分测试后才能给出 ``SUCCESS``。

    注意：``test_url`` / ``original_handler_snippet`` / ``primary_token`` /
    ``secondary_token`` 当前仅为接口占位，不参与静态判定。
    """
    # 1. 语法合规性静态编译检查
    try:
        compile(patch_code_snippet, "<string>", "exec")
        compiles = True
    except SyntaxError as e:
        return VerificationResult(
            patch_compiles=False,
            verified_safe=False,
            primary_status_post_fix=0,
            secondary_status_post_fix=0,
            remediation_status="COMPILE_ERROR",
            evidence_details=f"补丁语法错误: 行 {e.lineno}, {e.msg}",
        ).model_dump()

    # 2. AST 级行级安全语义断言（替代字符串子串匹配，防止注释/字符串绕过）
    has_tenant_filter = _has_tenant_filter_ast(patch_code_snippet)
    has_not_found_hide = _has_not_found_hide_ast(patch_code_snippet)

    if not (has_tenant_filter and has_not_found_hide):
        missing = []
        if not has_tenant_filter:
            missing.append(f"AST级行级过滤绑定（{', '.join(sorted(_TENANT_FILTER_NAMES))}）")
        if not has_not_found_hide:
            missing.append("AST级404实体屏蔽（HTTPException/JSONResponse status_code=404等）")
        return VerificationResult(
            patch_compiles=True,
            verified_safe=False,
            primary_status_post_fix=0,
            secondary_status_post_fix=0,
            remediation_status="PARTIAL",
            evidence_details=(
                "补丁未通过AST级安全语义断言。"
                f"缺失: {'; '.join(missing)}"
            ),
        ).model_dump()

    # 3. 静态断言通过，但未做物理运行时验证——诚实标记，不伪造 200/404 结果。
    return VerificationResult(
        patch_compiles=True,
        verified_safe=False,
        primary_status_post_fix=0,
        secondary_status_post_fix=0,
        remediation_status="STATIC_AST_PASSED",
        evidence_details=(
            "已通过 AST 级安全语义断言（tenant_filter + 404_hide），"
            "但未执行物理运行时验证；物理运行时验证需在隔离环境中对真实目标执行差分测试。"
        ),
    ).model_dump()


# 向后兼容别名：明确该函数只做静态 AST 验证
verify_python_patch_static = verify_python_patch
