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
│   - SceneManager.ts 生命周期与显存管理 (28/28 Vitest)      │
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

## 测试

```bash
# 前端 Vitest (28 项)
npm install
npx vitest run

# 后端 Pytest (235 项)
pip install -r requirements.txt
pytest tests/ -v

# 带覆盖率门禁（CI 下限见 COVERAGE_MIN，当前 78）
pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=78
```

## CI/CD

`.github/workflows/ci.yml` 定义四阶段门禁：
1. **frontend-gate**: TypeScript 类型检查 + Vitest 28/28
2. **backend-gate**: Python AST 编译（`src/auditor` + `src/pipeline` + `tests`） + Pytest 回归 + 覆盖率门禁；以 **mcp 双版本矩阵**（`<2` 与 `>=2`）各跑一次，覆盖率门禁与 artifact 上传仅挂 `<2` 分支
3. **container-gate**: Docker Compose 配置验证 + 多阶段镜像构建（依赖前两阶段）
4. **security-gate**: Trivy CRITICAL 漏洞扫描 + CycloneDX SBOM 生成（依赖 container-gate）

## 安全特性

- **P0-INVARIANT-03**: 非幂等写操作（POST/PUT/PATCH/DELETE）默认物理熔断
- **对抗绕过检测**: `src/auditor/adversarial_guard.py` 提供 URL 合法性、请求头注入（CRLF/NUL/危险转发头）与路径穿越检测；**确凿项阻断，可疑项标记不阻断**，避免误报致合法扫描失败
- **动态签名 Hook**: 自动重算 X-Timestamp / X-Nonce / HMAC-SHA256 签名；**签名校验失败不消耗 nonce**，防止错误签名污染缓存
- **补丁反向验证**: 沙盒环境验证修复后 Context A 维持 200，Context B 返回 404
- **显存零泄漏**: 11 级递归 GPU 资源销毁链

> 注意：`src/auditor/adversarial_guard.py` 原依赖外部私有包 `bounty_platform`，
> 该包未随仓库分发导致 `validate_request_security()` 必崩。现为仓内本地实现。

## 依赖兼容

- **mcp v1 / v2 双代兼容**：`src/auditor/auditor_mcp_server.py` 对
  `mcp.server.fastmcp.FastMCP`（v1）与 `mcp.server.mcpserver.MCPServer`（v2，
  FastMCP 在 2.x 被重命名）做了导入回退，`requirements.txt` 因此放宽为
  `mcp>=1.0.0,<3.0.0`。已在 **1.30.0** 与 **2.3.0** 两个版本下分别跑通全量测试。
