"""
test_safety.py: P0-INVARIANT-03 写操作熔断与对抗检测回归测试

覆盖目标：
1. ``validate_method_safety`` 白名单 fail-closed 模型（安全方法 / 写方法 / 
   安全方法携带写语义 body 的绕过）。
2. ``validate_request_security`` 统一门禁的七步短路路径：
   URL 拒绝 → Header 拒绝 → 方法覆盖升级 → 通用写熔断 → 对抗阻断 → 放行标记。
3. ``adversarial_guard`` 三个符号的直接契约（返回值结构与语义）。

注意：``validate_request_security`` 的签名顺序为 ``(url, method, ...)``，
与直觉的 ``(method, url)`` 相反，调用时勿颠倒。
"""

from __future__ import annotations

import base64

import pytest

from src.auditor.adversarial_guard import (
    BypassDetector,
    validate_headers,
    validate_url,
)
from src.auditor.safety import (
    SAFE_HTTP_METHODS,
    validate_method_safety,
    validate_request_security,
)

BASE_URL = "http://127.0.0.1:8080/api/users"


def _b64(payload: bytes) -> str:
    """生成 base64 编码的 JSON body（满足 _detect_body_encoding 判定条件）。"""
    return base64.b64encode(payload).decode("ascii")


# --------------------------------------------------------------------------
# validate_method_safety
# --------------------------------------------------------------------------


@pytest.mark.parametrize("method", sorted(SAFE_HTTP_METHODS))
def test_safe_methods_allowed_by_default(method: str) -> None:
    """安全方法默认放行，无需 allow_write。"""
    assert validate_method_safety(method, allow_write=False) == (True, None)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE"])
def test_write_methods_blocked_without_flag(method: str) -> None:
    """非安全方法在 allow_write=False 时物理熔断（P0-INVARIANT-03）。"""
    allowed, reason = validate_method_safety(method, allow_write=False)
    assert allowed is False
    assert reason is not None and "P0-INVARIANT-03_VIOLATION" in reason


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_write_methods_allowed_with_flag(method: str) -> None:
    """显式 allow_write=True 时写方法放行。"""
    assert validate_method_safety(method, allow_write=True) == (True, None)


@pytest.mark.parametrize(
    "content_type",
    ["application/json", "Application/JSON; charset=utf-8", "text/json"],
)
def test_safe_method_with_json_body_is_suspicious(content_type: str) -> None:
    """安全方法携带写语义 JSON body → 判定为绕过，allow_write 不豁免。"""
    allowed, reason = validate_method_safety(
        "GET", allow_write=True, body='{"a":1}', content_type=content_type
    )
    assert allowed is False
    assert reason is not None and "SAFE_METHOD_WITH_BODY" in reason


def test_safe_method_with_plain_body_allowed() -> None:
    """安全方法携带非写语义 body（text/plain）不触发绕过判定。"""
    assert validate_method_safety(
        "GET", allow_write=False, body="hello", content_type="text/plain"
    ) == (True, None)


# --------------------------------------------------------------------------
# validate_request_security：放行路径
# --------------------------------------------------------------------------


def test_plain_get_passes() -> None:
    allowed, reason, findings = validate_request_security(BASE_URL, "GET")
    assert allowed is True
    assert reason is None
    assert findings == []


def test_body_encoding_reported_as_non_blocking() -> None:
    """base64 编码 JSON body → 放行但附加解码提示（不阻断）。"""
    body = _b64(b'{"user_id": 123, "action": "delete"}')
    allowed, reason, findings = validate_request_security(
        BASE_URL,
        "POST",
        headers={"Content-Type": "text/plain"},
        body=body,
        allow_write=True,
    )
    assert allowed is True, reason
    encoding_findings = [f for f in findings if f["type"] == "body_encoding"]
    assert len(encoding_findings) == 1
    assert encoding_findings[0]["blocked"] is False


# --------------------------------------------------------------------------
# validate_request_security：阻断路径
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://127.0.0.1/x",
        "file:///etc/passwd",
        "http://",
        "http://127.0.0.1:99999/x",
    ],
)
def test_url_rejected(url: str) -> None:
    allowed, reason, _ = validate_request_security(url, "GET")
    assert allowed is False
    assert reason is not None and reason.startswith("URL_REJECTED")


def test_crlf_header_rejected() -> None:
    allowed, reason, _ = validate_request_security(
        BASE_URL, "GET", headers={"X-Foo": "bar\r\nX-Injected: 1"}
    )
    assert allowed is False
    assert reason is not None and reason.startswith("HEADER_REJECTED")
    assert "CRLF" in reason


@pytest.mark.parametrize(
    "header_name", ["X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL"]
)
def test_route_rewriting_header_rejected(header_name: str) -> None:
    """可改写服务端路由的转发头在审计重放中必须拒绝。"""
    allowed, reason, _ = validate_request_security(
        BASE_URL, "GET", headers={header_name: "1.2.3.4"}
    )
    assert allowed is False
    assert reason is not None and reason.startswith("HEADER_REJECTED")


def test_method_override_upgrade_blocked() -> None:
    """GET 被 header 覆盖为 DELETE 且未授权 → 以方法覆盖专属原因阻断。"""
    allowed, reason, _ = validate_request_security(
        BASE_URL, "GET", headers={"X-HTTP-Method-Override": "DELETE"}
    )
    assert allowed is False
    assert reason is not None
    assert "P0-INVARIANT-03_VIOLATION" in reason
    assert "HEADER_OVERRIDE" in reason


def test_method_override_allowed_when_write_permitted() -> None:
    """显式 allow_write=True 时，方法覆盖升级放行。"""
    allowed, reason, findings = validate_request_security(
        BASE_URL,
        "GET",
        headers={"X-HTTP-Method-Override": "DELETE"},
        allow_write=True,
    )
    assert allowed is True, reason
    # 放行路径上仍留痕，便于回溯
    assert any(f["type"] == "method_override" for f in findings)


def test_query_method_override_blocked() -> None:
    """query 参数 _method 覆盖同样触发阻断。"""
    allowed, reason, _ = validate_request_security(
        BASE_URL, "GET", query_params={"_method": "PUT"}
    )
    assert allowed is False
    assert reason is not None and "QUERY_OVERRIDE" in reason


def test_path_traversal_blocked() -> None:
    allowed, reason, findings = validate_request_security(
        "http://127.0.0.1:8080/api/../../etc/passwd", "GET"
    )
    assert allowed is False
    assert reason is not None and reason.startswith("ADVERSARIAL_BLOCK")
    assert findings and findings[0]["type"] == "path_traversal"


def test_null_byte_in_url_rejected_at_url_gate() -> None:
    """URL 含 NUL 由更前的 URL 闸门拦下（控制字符），不到对抗检测阶段。"""
    allowed, reason, _ = validate_request_security(
        "http://127.0.0.1:8080/api/x\x00.png", "GET"
    )
    assert allowed is False
    assert reason is not None and reason.startswith("URL_REJECTED")


def test_null_byte_in_body_blocked() -> None:
    """body 含 NUL 走到对抗检测阶段被阻断。"""
    allowed, reason, findings = validate_request_security(
        BASE_URL,
        "POST",
        headers={"Content-Type": "text/plain"},
        body="a\x00b",
        allow_write=True,
    )
    assert allowed is False
    assert reason is not None and reason.startswith("ADVERSARIAL_BLOCK")
    assert any(f["type"] == "null_byte" for f in findings)


def test_write_without_flag_blocked_via_full_gate() -> None:
    """统一门禁下，写方法未授权同样熔断。"""
    allowed, reason, _ = validate_request_security(BASE_URL, "DELETE")
    assert allowed is False
    assert reason is not None and "P0-INVARIANT-03_VIOLATION" in reason


# --------------------------------------------------------------------------
# adversarial_guard 契约直测
# --------------------------------------------------------------------------


def test_validate_url_contract() -> None:
    ok, reason = validate_url("https://example.com:8443/a/b?c=d")
    assert (ok, reason) == (True, "")


def test_validate_url_rejects_control_chars() -> None:
    ok, reason = validate_url("http://example.com/a\r\nX: 1")
    assert ok is False
    assert "控制字符" in reason


def test_validate_headers_returns_empty_on_clean_input() -> None:
    assert validate_headers({"Accept": "application/json"}) == []


def test_validate_headers_rejects_non_dict() -> None:
    problems = validate_headers(["Accept: */*"])  # type: ignore[arg-type]
    assert problems and "dict" in problems[0]


def test_bypass_detector_finding_schema() -> None:
    """finding 必须含 type / blocked / reason 三键，供上层 f['blocked'] 消费。"""
    findings = BypassDetector().check_request(
        "http://127.0.0.1:8080/api?next=..%2f..%2fetc", "GET", {}, {}, None
    )
    assert findings
    for finding in findings:
        assert set(finding) >= {"type", "blocked", "reason"}
        assert isinstance(finding["blocked"], bool)


def test_bypass_detector_marks_userinfo_without_blocking() -> None:
    """userinfo 混淆仅标记不阻断（可能是合法的 basic-auth 写法）。"""
    findings = BypassDetector().check_request(
        "http://user:pass@127.0.0.1:8080/api", "GET", {}, {}, None
    )
    userinfo = [f for f in findings if f["type"] == "url_userinfo"]
    assert userinfo and userinfo[0]["blocked"] is False
