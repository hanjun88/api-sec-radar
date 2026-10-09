"""api_access_auditor: API 访问控制差分审计引擎。

全链路模块面：
- core: 差分审计引擎（SystemSkill 契约）
- safety / adversarial_guard: P0-INVARIANT-03 写熔断 + 对抗门禁
- hook: 动态签名 Hook（Timestamp/Nonce/HMAC-SHA256）
- openapi / har_ingestor: 白盒契约 / 黑盒流量双通道摄入
- batch_scan: 批量差分扫描引擎（MCP 与编排器共享）
- poc_builder: PoC 报告构建与赏金估算
- report_emitter: Markdown + JSON 双通道报告落盘
- scope: 授权范围策略
- pipeline_orchestrator / pipeline_bridge: 全链路编排与 WebSocket 推流
- sandbox_verifier: 修复补丁静态 AST 验证
- auditor_mcp_server: MCP stdio 服务入口
"""

from .core import ApiAccessAuditor, DifferentialTestInput, DifferentialTestOutput

__all__ = ["ApiAccessAuditor", "DifferentialTestInput", "DifferentialTestOutput"]
