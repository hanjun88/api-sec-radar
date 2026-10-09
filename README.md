# API Security Radar

工业级 API 越权审计与三维态势感知雷达系统。**2026-10 全链路自动化工程版**：
从契约/流量摄入到漏洞证据广播至三维大屏，一条命令闭环。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 0: 摄入层（双通道）                                    │
│   - OpenAPI/Swagger 白盒契约 (openapi.py)                   │
│   - HAR 黑盒流量录制 (har_ingestor.py)                      │
│   - 授权范围策略 (scope.py: host 白名单 + 路径正则)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ 标准化 Target Matrix（同构）
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: 审计引擎 (src/auditor/)                            │
│   - FastMCP→MCPServer stdio 服务 (auditor_mcp_server.py)   │
│   - 差分审计核心 (core.py: 共享 httpx 连接池)                │
│   - 批量扫描引擎 (batch_scan.py: MCP 与编排器共享实现)       │
│   - 动态签名 Hook (hook.py: Timestamp/Nonce/HMAC-SHA256)    │
│   - 安全守则 (safety.py + adversarial_guard.py)             │
│     · P0-INVARIANT-03 写操作物理熔断                        │
│     · 方法覆盖 / GET+body 绕过 / XSS / SQLi / 遍历 / 注入    │
│   - OpenAPI 契约摄入 (openapi.py)                            │
│   - 补丁沙盒验证 (sandbox_verifier.py: AST 级断言)           │
└──────────────────────────────┬──────────────────────────────┘
                               │ VulnEvidencePayload (JSON)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 1.5: 升维层                                            │
│   - PoC 构建与赏金估算 (poc_builder.py)                      │
│   - 报告落盘 Markdown+JSON (report_emitter.py)               │
│   - 全链路编排 (pipeline_orchestrator.py)                    │
│   - 工件推流 (pipeline_bridge.py)                            │
└──────────────────────────────┬──────────────────────────────┘
                               │ WebSocket Stream
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: 数据中继 (src/pipeline/)                           │
│   - WebSocket 广播网关 (ws_bridge_server.py :8765)          │
│   - 实时扫描驱动器 (live_scan_feeder.py)                     │
│   - 全链路工件推流器 (artifact_emitter.py) ← 新增            │
│   - 压测备用流 (test_stream_feeder.py)                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: 三维态势雷达 (vuln_topology_dashboard.html)        │
│   - Three.js InstancedMesh (128 节点, 1 Draw Call)          │
│   - GLSL 脉冲着色器告警                                     │
│   - SceneManager.ts 生命周期与显存管理 (16/16 Vitest)        │
└─────────────────────────────────────────────────────────────┘
```

## 快速启动

### Docker Compose（推荐）

```bash
docker compose up -d --build                     # 网关 + 大屏
docker compose --profile pipeline run --rm artifact-emitter   # 全链路一轮审计
```

- 态势大屏: http://localhost:3000/vuln_topology_dashboard.html?live=1
- WebSocket 网关: ws://localhost:8765

### 全链路一把梭（artifact_emitter）

```bash
# 摄入(OpenAPI/HAR) → 范围过滤 → 差分扫描 → PoC → 赏金 → 报告 → WS 广播
python3 src/pipeline/artifact_emitter.py \
    --openapi-spec ./specs/target.json \
    --base-url https://target.example.com \
    --primary-token "Bearer token-alice" \
    --secondary-token "Bearer token-bob" \
    --ws-url ws://127.0.0.1:8765 \
    --output-dir ./audit_reports \
    --interval 30            # 省略 --once 则周期推流
```

身份令牌也可经环境变量注入：`PRIMARY_TOKEN` / `SECONDARY_TOKEN`。

### 裸机运行

```bash
# 终端 1: 启动网关 + HTTP 托管 + 浏览器
chmod +x run_dashboard.sh
./run_dashboard.sh

# 终端 2: 全链路自动推流（推荐）
python3 src/pipeline/artifact_emitter.py --once

# 终端 2 备选: 实时扫描
python3 src/pipeline/live_scan_feeder.py

# 终端 3 备选: 压测模式 (2.5 artifacts/s)
python3 src/pipeline/test_stream_feeder.py
```

### MCP stdio 服务（Agent 接入）

```bash
python3 -m src.auditor.auditor_mcp_server
```

工具面：`differential_access_test` / `probe_endpoint` / `ingest_openapi` /
`batch_differential_scan(_fast)` / `emit_audit_report` / `run_full_pipeline` /
`verify_remediation`。

## 测试

```bash
# 前端 Vitest (16 项)
npm install
npx vitest run tests/SceneManager.test.ts

# 后端 Pytest（171 项，含 E2E 全链路：MCP stdio + 真实网关 + 真实靶场）
pip install -r requirements.txt
pytest tests/ -v

# Lint（ruff，显式契约见 pyproject.toml）
ruff check src tests
```

## CI/CD

`.github/workflows/ci.yml` 定义四阶段并行门禁：
1. **frontend-gate**: TypeScript 7 类型检查 + Vitest 16/16（Node 24 LTS）
2. **backend-gate**: Ruff lint + Python AST 编译 + Pytest 171 项回归（Python 3.14）
3. **container-gate**: Docker Compose 配置验证 + 多阶段镜像构建
4. **security-gate**: Trivy CRITICAL CVE 扫描 + CycloneDX SBOM 生成与留存

## 技术栈（2026-10 推演锁定）

| 层 | 选型 |
|---|---|
| 运行时 | Python 3.14（交付）/ 兼容性地板 3.10；Node 24 LTS |
| HTTP/审计 | httpx 0.28（共享连接池）、mcp 2.3（MCPServer stdio）、pydantic 2.14 |
| 数据中继 | websockets 16 |
| 测试 | pytest 9 + pytest-asyncio 1.4、Vitest 5 + jsdom 30 |
| 前端 | three 0.186、TypeScript 7（原生） |
| 工程门禁 | ruff 0.16（pyproject.toml 显式规则契约） |
| 容器 | python:3.14-slim / nginx:1.31-alpine（非 root） |
| CI Actions | checkout v7 / setup-node v7 / setup-python v7 / build-push v7 / trivy v0.36 |

## 安全特性

- **P0-INVARIANT-03**: 非幂等写操作（POST/PUT/PATCH/DELETE）默认物理熔断；
  方法覆盖（X-HTTP-Method-Override / _method）与 GET+写特征 body 绕过同样拦截
- **统一请求门禁**: URL/Header 合法性 + CRLF 注入 + XSS/SQLi/路径遍历/代码注入
  对抗检测（adversarial_guard.py，阻断型 finding 直接拒绝）
- **动态签名 Hook**: 自动重算 X-Timestamp / X-Nonce / HMAC-SHA256 签名
- **补丁反向验证**: 沙盒 AST 断言（tenant 绑定 + 404 实体屏蔽），诚实区分
  静态通过与物理安全
- **显存零泄漏**: 11 级递归 GPU 资源销毁链
- **范围硬约束**: scope.py 授权边界过滤，出界端点绝不进入扫描队列
