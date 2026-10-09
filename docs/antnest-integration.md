# AntNest 集成指南

把 API Security Radar 的 MCP 审计引擎注册为 AntNest（蚁巢）的 MCP server，
让蚁后 / 工蚁在桌面 Agent 工作流中直接调用差分越权审计能力。

## 接入方式

AntNest 的 `mcp_client.py` 支持 stdio / http / sse 三种传输。
本仓库的 `auditor_mcp_server.py` 是 stdio 传输的 MCP server，
与 AntNest 的 `McpSession`（stdio）契约兼容。

### 1. 配置 AntNest MCP server

把 `antnest-mcp.json` 合并到 AntNest 的 MCP 配置
（AntNest 设置 → MCP servers，或 `mcp.json`）：

```json
{
  "servers": {
    "api_sec_radar": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "src.auditor.auditor_mcp_server"],
      "env": {}
    }
  }
}
```

> `command` 需指向本仓库的 Python 解释器；
> `args` 中的 `-m src.auditor.auditor_mcp_server` 要求
> 工作目录为仓库根（含 `src/auditor/`）。
> 若 AntNest 的工作目录不是仓库根，把 `args` 改为
> 绝对路径脚本：`["/abs/path/to/src/auditor/auditor_mcp_server.py"]`
> 并在 `env` 中设 `PYTHONPATH=/abs/path/to`。

### 2. 验证接入

AntNest 加载后，`mcp_list_tools` 应能看到 8 个工具：

| 工具 | 用途 |
|---|---|
| `differential_access_test` | 单端点差分越权测试（主/次身份） |
| `probe_endpoint` | 端点探测（状态码 / 响应指纹） |
| `ingest_openapi` | OpenAPI 契约摄入 → 待测矩阵 |
| `batch_differential_scan` | 批量差分扫描（完整证据） |
| `batch_differential_scan_fast` | 批量差分扫描（快速模式） |
| `emit_audit_report` | 扫描结果落盘（Markdown + JSON） |
| `run_full_pipeline` | 全链路：摄入→扫描→PoC→赏金→报告→推流 |
| `verify_remediation` | 修复补丁静态 AST 验证 |

### 3. 蚁后 / 工蚁调用示例

对蚁后说：

> 「用 api_sec_radar 对 http://target.local/api/v1/accounts/1001
> 做差分越权测试，主身份 token-alice，次身份 token-bob」

蚁后会调用 `differential_access_test`：

```json
{
  "url": "http://target.local/api/v1/accounts/1001",
  "method": "GET",
  "primary_headers": {"Authorization": "Bearer token-alice"},
  "secondary_headers": {"Authorization": "Bearer token-bob"}
}
```

返回确定性证据链（verdict / confidence / similarity /
primary_status / secondary_status / evidence）。

## 安全不变量（P0-INVARIANT-03）

- 非幂等写操作（POST/PUT/PATCH/DELETE）默认物理熔断，
  必须显式 `allow_write=True` 才产生网络流量。
- 方法覆盖（`X-Http-Method-Override` header / `_method` query）
  与 GET+写特征 body 均视为写操作。
- 统一安全门禁：URL 合法性 / Header CRLF 注入 / 对抗载荷
  （XSS / SQLi / 路径遍历 / 代码注入）在核心路径上阻断。

## 与 AntNest 权限模型的对应

AntNest 的 L0–L5 权限分级与本仓库的安全门禁互补：

| AntNest 档位 | 对应本仓库行为 |
|---|---|
| L0 只读 | `probe_endpoint` / `differential_access_test`（GET） |
| L2 执行 | `batch_differential_scan`（默认 allow_write=False） |
| L3 网络+写入 | `run_full_pipeline`（需显式 allow_write=True 才发写请求） |

> 注意：AntNest 的权限分级是闸门，不是护栏。
> 本仓库的 P0-INVARIANT-03 写熔断是物理门禁——
> 即使 AntNest 批准了 L3，写操作仍需 `allow_write=True`。

## 推流集成（可选）

若 AntNest 与本仓库的 WebSocket 网关（ws://127.0.0.1:8765）
同机运行，`run_full_pipeline` 的 `ws_bridge_url` 参数可把
漏洞工件实时推送到 3D 态势大屏：

```json
{
  "openapi_spec": "<spec 内容或路径>",
  "ws_bridge_url": "ws://127.0.0.1:8765",
  "primary_token": "Bearer token-alice",
  "secondary_token": "Bearer token-bob"
}
```
