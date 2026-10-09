# API 安全雷达技术栈演进决策报告

> 生成时间: 2026-10-09
> 仓库: hanjun88/api-sec-radar
> 分支: baseline/union
> 查询日期: 2026-10-09

---

## 1. 演进背景

`api-sec-radar` 从单体审计脚本演进为 MCP 驱动的自动化安全测试平台。核心动因：

- 现有防御依赖静态 Header，易被网关拒绝
- 缺少统一的测试门禁与依赖锁定
- 大屏前端与后端管道的 WebSocket 通道未打通

## 2. 技术栈现状

| 层 | 技术 | 版本约束 |
|---|---|---|
| Python | 3.10+ | - |
| 测试 | pytest, pytest-asyncio | >=8.0.0, >=0.23.0 |
| HTTP | httpx, requests | >=0.25.0, >=2.31.0 |
| 实时 | websockets | >=12.0 |
| 数据 | pydantic | >=2.0.0 |
| MCP | mcp SDK | >=1.0.0, <2 |
| 前端 | Three.js, vite, vitest, tsc | - |

## 3. 依赖锁定策略

- `requirements.txt`: 下界 + 上界写法
- `mcp>=1.0.0,<2`: 防止 SDK 大版本破坏性变更
- `requirements.lock`: 由 `pip freeze` 生成，精确锁定

## 4. 测试门禁 (Stage Zero)

### 4.1 测试统计

| 文件 | 测试数 | 覆盖组 |
|---|---|---|
| test_hook_signature.py | 19 | A（签名 Hook） |
| test_safety_gate.py | 16 | B（写熔断） |
| test_safety_adversarial.py | 13 | C（对抗检测） |
| test_pipeline_contract.py | 15 | D（流水线契约） |
| test_report_emitter.py | 6 | E（报告落盘） |
| test_mock_target.py | 7 | F（Mock 靶机） |
| test_report.py | 3 | 报告 |
| test_sandbox_verifier.py | 9 | 沙箱验证 |
| **总计** | **83** | |

### 4.2 变异验证

- 变异 1: `safety.py` fail-closed → fail-open → 3 项测试变红
- 变异 2: `hook.py` 签名基串去掉 nonce → 2 项测试变红
- 恢复后 83 项全绿

### 4.3 前端验证

- vitest: 16/16 passed
- tsc: 0 errors

## 5. P0 修复

### 5.1 D1 nginx WebSocket 反向代理

`Dockerfile.dashboard` 新增 `location /ws` 块：
```
proxy_pass http://ws-bridge:8765;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 86400s;
```

### 5.2 大屏 WS 端点解析

`vuln_topology_dashboard.html` 新增 `resolveWsEndpoint()`：
优先级: 显式入参 > `window.__WS_ENDPOINT__` > `?ws=` query > 同源 `/ws`

### 5.3 安全守则

- `_detect_body_encoding` 支持 bytes 输入（gzip 魔数检测）
- `validate_method_safety` fail-closed 白名单模型
- `BypassDetector` 覆盖 XSS/SQLi/路径穿越/代码注入

## 6. 报告产出

- `src/auditor/report_emitter.py`: MD/JSON 双轨报告
- 文件名: `audit_<YYYYMMDD_HHMMSS>.{md,json}`
- `src/auditor/report.py`: batch 聚合报告

## 7. 迁移脚本

`scripts/migrate-mcp.sh`:
- `set -euo pipefail`
- 自动备份 requirements.txt / requirements.lock
- 安装目标版本
- 模块导入验证
- pytest 验证
- 失败自动回滚

## 8. C1-C7 验证状态

| 判据 | 状态 | 证据 |
|---|---|---|
| C1 冷启动 | **未验证（无 Docker）** | 依赖 docker compose up |
| C2 容器内报告落盘 | **未验证（无 Docker）** | 依赖容器内文件系统 |
| C3 测试门禁 | 已验证 | pytest 83 passed, 0 skipped |
| C4 依赖锁定 | 已验证 | requirements.lock 存在, mcp<2 |
| C5 变异验证 | 已验证 | 两次变异均真实变红 |
| C6 P0 修复 | 已验证 | proxy_pass /ws, resolveWsEndpoint |
| C7 迁移脚本 | 已验证 | scripts/migrate-mcp.sh 可执行 |

## 9. 来源 URL

- MCP SDK: https://modelcontextprotocol.io
- pytest: https://docs.pytest.org
- Three.js: https://threejs.org
- NGINX: https://nginx.org

## 10. 后续建议

- 搭建 Docker 环境以验证 C1/C2
- 增加性能基准测试（--run-performance）
- 接入真实 bounty platform E2E 测试