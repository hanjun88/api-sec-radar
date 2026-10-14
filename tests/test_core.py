"""
test_core.py: 差分审计引擎端到端测试（真实 HTTP 靶场驱动）

复用 conftest 的 ``mock_target_server`` 靶场，对 ``ApiAccessAuditor``
做真实网络调用验证，而非以 mock 断言替代。靶场内建漏洞类型：
BOLA/IDOR（accounts）、功能级越权（admin/users）、正确拒绝（secure）、
限速（rate-limited）、越权写入（PUT accounts）。

覆盖：
- 五类判定分支：VULNERABLE / SAFE / INCONCLUSIVE / BLOCKED / PRIV_ESCALATION
- P0-INVARIANT-03 写熔断的「零网络流量」证据（status_code == 0）
- 入参硬约束（同源 URL / 同方法）
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.auditor.core import (
    ApiAccessAuditor,
    DifferentialTestInput,
    DifferentialTestOutput,
    RequestIdentity,
    _body_similarity,
)

# 靶场账户（见 conftest._MOCK_ACCOUNTS）：1001=alice 1002=bob 1003=charlie
VICTIM_TOKEN = "token-alice"
ATTACKER_TOKEN = "token-bob"


def _identity(
    label: str,
    url: str,
    token: str,
    method: str = "GET",
    body: str | None = None,
    content_type: str | None = None,
) -> RequestIdentity:
    headers: dict[str, str] = {}
    # 空 token 不发送 Authorization 头：httpx 会拒绝 "Bearer " 这类空值头
    # （LocalProtocolError: Illegal header value），那是传输层错误而非越权信号。
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    return RequestIdentity(
        label=label,
        method=method,
        url=url,
        headers=headers,
        body=body,
    )


def _diff(
    base: str,
    path: str,
    victim_token: str = VICTIM_TOKEN,
    attacker_token: str = ATTACKER_TOKEN,
    method: str = "GET",
    body: str | None = None,
    allow_write: bool = False,
) -> DifferentialTestOutput:
    """对同一端点以两个身份发起差分测试。"""
    url = f"{base}{path}"
    # 带 body 的请求须声明写语义 Content-Type，否则熔断的绕过检测不会触发
    content_type = "application/json" if body else None
    params = DifferentialTestInput(
        primary=_identity("victim", url, victim_token, method, body, content_type),
        secondary=_identity("attacker", url, attacker_token, method, body, content_type),
        allow_write=allow_write,
    )
    return ApiAccessAuditor().execute(params)


# --------------------------------------------------------------------------
# 漏洞检出
# --------------------------------------------------------------------------


def test_bola_detected_when_both_identities_read_same_record(
    mock_target_server: str,
) -> None:
    """BOLA：靶场不校验所有权，两身份读到同一账户 → VULNERABLE。"""
    result = _diff(mock_target_server, "/api/v1/accounts/1001")
    assert result.verdict == "VULNERABLE"
    assert result.primary.status_code == 200
    assert result.secondary.status_code == 200
    assert result.similarity >= 0.85


def test_functional_authorization_bypass_detected(
    mock_target_server: str,
) -> None:
    """功能级越权：普通用户可访问 admin 端点 → VULNERABLE。"""
    result = _diff(mock_target_server, "/api/v1/admin/users")
    assert result.verdict == "VULNERABLE"
    assert result.evidence["secondary_status"] == 200


def test_secure_endpoint_reported_as_safe(mock_target_server: str) -> None:
    """正确实现所有权重校验的端点：属主 200 / 他人 403 → SAFE。"""
    result = _diff(mock_target_server, "/api/v1/secure/1001")
    assert result.verdict == "SAFE"
    assert result.primary.status_code == 200
    assert result.secondary.status_code == 403


def test_unauthenticated_pair_is_inconclusive(mock_target_server: str) -> None:
    """双方均被 401 拒绝 → 无法判定（非 SAFE，因未验证到真实权限边界）。"""
    result = _diff(mock_target_server, "/api/v1/accounts/1002", "", "")
    assert result.verdict == "INCONCLUSIVE"
    assert result.primary.status_code == 401
    assert result.secondary.status_code == 401


# --------------------------------------------------------------------------
# P0-INVARIANT-03 写操作熔断
# --------------------------------------------------------------------------


def test_write_operation_physically_blocked_before_any_network_call(
    mock_target_server: str,
) -> None:
    """写方法未授权 → BLOCKED，且 status_code 为 0 证明未发出任何请求。"""
    result = _diff(
        mock_target_server,
        "/api/v1/accounts/1003",
        method="PUT",
        body='{"balance": 1}',
        allow_write=False,
    )
    assert result.verdict == "BLOCKED"
    assert result.primary.status_code == 0
    assert result.secondary.status_code == 0
    assert result.evidence["blocked_by"] == "P0-INVARIANT-03"
    assert "P0-INVARIANT-03_VIOLATION" in result.evidence["reason"]


def test_write_operation_executes_when_explicitly_allowed(
    mock_target_server: str,
) -> None:
    """显式 allow_write=True → 写请求真实发出，靶场越权写入被检出。"""
    result = _diff(
        mock_target_server,
        "/api/v1/accounts/1003",
        method="PUT",
        body='{"balance": 1}',
        allow_write=True,
    )
    assert result.verdict != "BLOCKED"
    assert result.primary.status_code == 200
    assert result.secondary.status_code == 200


def test_get_with_json_body_blocked_as_write_bypass(
    mock_target_server: str,
) -> None:
    """GET 携带 JSON body 视为写绕过，allow_write 不豁免。"""
    result = _diff(
        mock_target_server,
        "/api/v1/accounts/1003",
        method="GET",
        body='{"balance": 1}',
        allow_write=True,
    )
    # 安全方法带写语义 body 时被 validate_method_safety 判定为绕过
    assert result.verdict == "BLOCKED"
    assert "SAFE_METHOD_WITH_BODY" in result.evidence["reason"]


# --------------------------------------------------------------------------
# 入参硬约束
# --------------------------------------------------------------------------


def test_endpoint_mismatch_rejected(mock_target_server: str) -> None:
    """差分测试两身份必须指向同一 URL。"""
    params = DifferentialTestInput(
        primary=_identity("a", f"{mock_target_server}/api/v1/accounts/1001", VICTIM_TOKEN),
        secondary=_identity("b", f"{mock_target_server}/api/v1/accounts/1002", ATTACKER_TOKEN),
    )
    with pytest.raises(ValueError, match="ENDPOINT_MISMATCH"):
        ApiAccessAuditor().execute(params)


def test_method_mismatch_rejected(mock_target_server: str) -> None:
    """差分测试两身份必须使用相同 HTTP 方法。"""
    url = f"{mock_target_server}/api/v1/accounts/1001"
    params = DifferentialTestInput(
        primary=_identity("a", url, VICTIM_TOKEN, "GET"),
        secondary=_identity("b", url, ATTACKER_TOKEN, "PUT"),
    )
    with pytest.raises(ValueError, match="METHOD_MISMATCH"):
        ApiAccessAuditor().execute(params)


def test_invalid_url_rejected_at_model_boundary() -> None:
    """缺少 scheme/host 的 URL 在 pydantic 边界即被拒绝。"""
    with pytest.raises(ValidationError, match="INVALID_URL"):
        RequestIdentity(label="a", url="/api/v1/accounts/1001")


def test_method_normalized_to_uppercase() -> None:
    assert RequestIdentity(label="a", url="http://x/api", method="post").method == "POST"


# --------------------------------------------------------------------------
# 相似度计算
# --------------------------------------------------------------------------


def test_similarity_identical_bodies_is_one() -> None:
    assert _body_similarity('{"a": 1}', '{"a": 1}') == pytest.approx(1.0)


def test_similarity_disjoint_bodies_is_low() -> None:
    assert _body_similarity('{"alpha": 1}', '{"zeta": 2}') < 0.5


def test_similarity_empty_bodies() -> None:
    assert _body_similarity("", "") == pytest.approx(1.0)


# --------------------------------------------------------------------------
# H1: SSRF 护栏已接入 core.execute（fail-closed）
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "evil_url",
    [
        "file:///etc/passwd",      # 无 netloc，pydantic 边界即拒（同为 fail-closed）
    ],
)
def test_ssrf_urls_rejected_at_model_boundary(evil_url: str) -> None:
    """file:// 等无 host 的 URL 在 pydantic 边界被拒，无法进入 execute。"""
    with pytest.raises(ValidationError):
        RequestIdentity(label="a", url=evil_url)


@pytest.mark.parametrize(
    "evil_url",
    [
        "gopher://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "gopher://internal-host.local/",
        "http://10.0.0.1/internal/",
        "http://192.168.1.1/admin",
    ],
)
def test_ssrf_urls_blocked_by_execute_fail_closed(evil_url: str) -> None:
    """H1：完整安全护栏已接入 execute，SSRF 类 URL 在建连前被 fail-closed 拦截。"""
    params = DifferentialTestInput(
        primary=_identity("victim", evil_url, VICTIM_TOKEN),
        secondary=_identity("attacker", evil_url, ATTACKER_TOKEN),
    )
    result = ApiAccessAuditor().execute(params)
    assert result.verdict == "BLOCKED"
    assert result.primary.status_code == 0
    assert result.secondary.status_code == 0
    # 由 REQUEST_SECURITY_GATE（validate_request_security → URL_REJECTED）拦截
    assert result.evidence["blocked_by"] == "REQUEST_SECURITY_GATE"
    assert "URL_REJECTED" in result.evidence["reason"]


def test_legit_http_url_not_blocked_by_security_gate(
    mock_target_server: str,
) -> None:
    """合法 http(s) 端点不应被安全护栏误拦（确保 H1 不破坏正常审计）。"""
    result = _diff(mock_target_server, "/api/v1/accounts/1001")
    assert result.verdict != "BLOCKED"
    assert result.evidence.get("blocked_by") != "REQUEST_SECURITY_GATE"


# --------------------------------------------------------------------------
# H4: PRIV_ESCALATION 误报修复（构造响应做 verdict 单测）
# --------------------------------------------------------------------------


class TestPrivEscalationVerdict:
    def test_owner_401_attacker_200_is_priv_escalation(self) -> None:
        v, c = ApiAccessAuditor._verdict(401, 200, 0.0, 0.85)
        assert v == "PRIV_ESCALATION"
        assert c == 0.75

    def test_owner_403_attacker_200_is_priv_escalation(self) -> None:
        v, _ = ApiAccessAuditor._verdict(403, 200, 0.0, 0.85)
        assert v == "PRIV_ESCALATION"

    def test_owner_429_transient_not_priv_escalation(self) -> None:
        """属主瞬时限流(429)而攻击者 200 → 不应误判权限提升。"""
        v, _ = ApiAccessAuditor._verdict(429, 200, 0.0, 0.85)
        assert v != "PRIV_ESCALATION"
        assert v == "INCONCLUSIVE"

    def test_owner_5xx_transient_not_priv_escalation(self) -> None:
        """属主瞬时 5xx 故障而攻击者 200 → 不应误判权限提升。"""
        v, _ = ApiAccessAuditor._verdict(500, 200, 0.0, 0.85)
        assert v != "PRIV_ESCALATION"
        assert v == "INCONCLUSIVE"

    def test_owner_404_not_priv_escalation(self) -> None:
        """属主请求不存在资源(404)而攻击者命中 → 非鉴权拒绝，不升级。"""
        v, _ = ApiAccessAuditor._verdict(404, 200, 0.0, 0.85)
        assert v != "PRIV_ESCALATION"


# --------------------------------------------------------------------------
# M2: VULNERABLE 低置信宽带收紧（构造响应做 verdict 单测）
# --------------------------------------------------------------------------


class TestLowConfidenceBand:
    def test_high_similarity_still_vulnerable(self) -> None:
        v, _ = ApiAccessAuditor._verdict(200, 200, 0.92, 0.85)
        assert v == "VULNERABLE"

    def test_low_confidence_no_longer_vulnerable(self) -> None:
        """相似度落在原低置信宽带(threshold*0.7=0.595)但低于新阈值(0.7225)：
        端点忽略 id 返回调用者自身同形数据的常见误报来源，现不再判 VULNERABLE。"""
        v, _ = ApiAccessAuditor._verdict(200, 200, 0.75, 0.85)
        assert v != "VULNERABLE"
        assert v in ("SUSPECT", "INCONCLUSIVE")

    def test_below_band_inconclusive(self) -> None:
        v, _ = ApiAccessAuditor._verdict(200, 200, 0.60, 0.85)
        assert v != "VULNERABLE"
