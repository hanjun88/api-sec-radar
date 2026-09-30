# API Security Radar

工业级 API 越权审计与三维态势感知雷达系统。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: 审计引擎 (src/auditor/)                            │
│   - FastMCP stdio 服务 (auditor_mcp_server.py)             │
│   - 差分审计核心 (core.py)                                   │
│   - OpenAPI 契约摄入 (openapi.py)                           │
│   - 动态签名 Hook (hook.py)                                  │
│   - 写操作熔断 (safety.py)                                   │
│   - 补丁沙盒验证 (sandbox_verifier.py)                      │
└──────────────────────────────┬──────────────────────────────┘
                               │ VulnEvidencePayload (JSON)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: 数据中继 (src/pipeline/)                           │
│   - WebSocket 广播网关 (ws_bridge_server.py :8765)         │
│   - 实时扫描驱动器 (live_scan_feeder.py)                    │
│   - 压测备用流 (test_stream_feeder.py)                      │
└──────────────────────────────┬──────────────────────────────┘
                               │ WebSocket Stream
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: 三维态势雷达 (vuln_topology_dashboard.html)       │
│   - Three.js InstancedMesh (128 节点, 1 Draw Call)         │
│   - GLSL 脉冲着色器告警                                      │
│   - SceneManager.ts 生命周期与显存管理 (16/16 Vitest)      │
└─────────────────────────────────────────────────────────────┘
```

## 快速启动

### Docker Compose（推荐）

```bash
docker compose up -d --build
```

- 态势大屏: http://localhost:3000/vuln_topology_dashboard.html?live=1
- WebSocket 网关: ws://localhost:8765

### 裸机运行

```bash
# 终端 1: 启动网关 + HTTP 托管 + 浏览器
chmod +x run_dashboard.sh
./run_dashboard.sh

# 终端 2: 启动实时扫描
python3 src/pipeline/live_scan_feeder.py

# 备选: 压测模式 (2.5 artifacts/s)
python3 src/pipeline/test_stream_feeder.py
```

### 实时扫描环境变量（live_scan_feeder.py）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OPENAPI_SPEC_PATH` | （内置演示规范） | OpenAPI 3.0 规范 JSON 文件路径 |
| `TARGET_BASE_URL` | `http://127.0.0.1:18099` | 覆盖规范中 `servers[0].url` 的真实目标基址 |
| `PRIMARY_TOKEN` / `SECONDARY_TOKEN` | `token-alice` / `token-bob` | 差分双身份凭证（原始 token，不带 `Bearer ` 前缀） |
| `WS_SERVER_URL` | `ws://127.0.0.1:8765` | WebSocket 广播网关地址 |
| `SCAN_INTERVAL_SEC` | `5.0` | 扫描轮次间隔（秒） |
| `CONCURRENCY_LIMIT` | `2` | batch 扫描并发度 |

未设置 `OPENAPI_SPEC_PATH` / `TARGET_BASE_URL` 时，启动会打 WARNING 警告：
当前扫描的是默认假目标，仅供演示。

## 测试

```bash
# 前端 Vitest (16 项)
npm install
npx vitest run tests/SceneManager.test.ts

# 后端 Pytest
pip install -r requirements.txt
pytest tests/ -v
```

## CI/CD

`.github/workflows/ci.yml` 定义三阶段并行门禁：
1. **frontend-gate**: TypeScript 类型检查 + Vitest 16/16
2. **backend-gate**: Python AST 编译 + Pytest 回归
3. **container-gate**: Docker Compose 配置验证 + 多阶段镜像构建

## 安全特性

- **P0-INVARIANT-03**: 非幂等写操作（POST/PUT/PATCH/DELETE）默认物理熔断
- **动态签名 Hook**: 自动重算 X-Timestamp / X-Nonce / HMAC-SHA256 签名
- **补丁静态验证**（诚实声明）: `sandbox_verifier.py` 仅做纯静态检查——语法编译
  + AST 级行级断言（tenant_filter 绑定 + 404 实体屏蔽），不发起任何真实网络请求，
  因此 `verified_safe` 恒为 `False`、`primary/secondary_status_post_fix` 恒为 0。
  静态通过记为 `remediation_status=STATIC_AST_PASSED`，**不等于**物理安全。
- **后续 feature（物理重放验证）**: 在隔离环境对真实目标执行差分测试，
  验证修复后 Context A 维持 200 / Context B 返回 404 实体屏蔽，
  物理验证通过后方可标记 `verified_safe=True`、宣告自愈闭环。
- **显存零泄漏**: 11 级递归 GPU 资源销毁链
