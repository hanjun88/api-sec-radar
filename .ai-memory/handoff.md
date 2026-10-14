# Handoff — api-sec-radar 升级推进（2026-10-11 00:16）

## 一、已完成（带证据）

| 项 | 证据 |
|---|---|
| P0 依赖缺失修复 | `validate_request_security()` 不再依赖外部私有包 `bounty_platform`，本地实现见 `src/auditor/adversarial_guard.py` |
| 安全核心回归 | `tests/test_safety.py` 40 项 |
| 差分引擎端到端 | `tests/test_core.py` 14 项，真实 HTTP 靶场驱动 |
| 签名与防重放 | `tests/test_hook.py` 30 项，含「签名失败不消耗 nonce」 |
| OpenAPI 摄入 | `tests/test_openapi.py` 17 项 |
| WebSocket 网关 | `tests/test_pipeline.py` 6 项，真实 socket 双客户端 |
| MCP 服务层单元 | `tests/test_auditor_mcp_server.py` 21 项 |
| MCP 协议级 E2E | `tests/test_mcp_protocol.py` 7 项，真实 stdio 子进程 |
| 批量并发扫描 | `tests/test_batch_scan.py` 18 项，顺序保持 / 错误隔离 / fast_mode / 熔断 / 聚合 |
| 前端生命周期 | `tests/SceneManager.lifecycle.test.ts` 12 项，资源销毁链 |
| mcp 双版本兼容 | 1.30.0 与 2.3.0 下均全绿；`requirements.txt` 放宽至 `<3.0.0` |
| **feeder 入口解耦** | `LiveScanFeeder` / `StreamFeeder` 注入外部依赖，`run()` 循环体抽为 `_run_one_iteration()`；`tests/test_feeders.py` 21 项 |
| **AST 分支补齐** | `tests/test_sandbox_verifier_ast.py` 51 项；`sandbox_verifier.py` 覆盖率 65% → **100%** |
| **全链路 soak** | `tests/test_soak_pipeline.py`：靶场 → MCP → feeder → 网关 → 客户端，3 轮 / 6 工件，`1 passed in 4.77s` |
| CI 加固 | mcp 双版本矩阵（`<2` / `>=2`）；AST 覆盖 `src/auditor` + `src/pipeline` + `tests`；`COVERAGE_MIN=78`；前端门禁补跑 lifecycle |

**总验证**：后端 `235 passed` / 覆盖率 `82.33%` / 门禁 78 通过；前端 `tsc` 0 错 + Vitest `28/28`；
`docker compose config --quiet` 无 warning；`ast.parse OK: 27 files`。

## 二、相关文件

- 新增实现：`src/auditor/adversarial_guard.py`
- 新增测试：`test_safety.py`、`test_core.py`、`test_hook.py`、`test_openapi.py`、`test_pipeline.py`、
  `test_auditor_mcp_server.py`、`test_mcp_protocol.py`、`test_batch_scan.py`、`test_feeders.py`、
  `test_sandbox_verifier_ast.py`、`test_soak_pipeline.py`、`SceneManager.lifecycle.test.ts`
- 修改：`src/auditor/safety.py`、`src/auditor/core.py`、`src/auditor/auditor_mcp_server.py`、
  `src/auditor/sandbox_verifier.py`、`src/pipeline/ws_bridge_server.py`、`src/pipeline/live_scan_feeder.py`、
  `src/pipeline/test_stream_feeder.py`、`src/webgl/SceneManager.ts`、`tests/conftest.py`、
  `.github/workflows/ci.yml`、`docker-compose.yml`、`requirements.txt`、`.gitignore`、`README.md`

## 三、已修复缺陷清单（共 10 项）

1. `safety.py` 延迟导入不存在的 `bounty_platform.adversarial_guard`。
2. `core.py` 对 `Content-Type` 大小写敏感 → GET+JSON body 写绕过检测可能静默失效。
3. `tests/conftest.py` 靶场 PUT 端点误用 `self._MOCK_ACCOUNTS`。
4. `ws_bridge_server.py` 广播未排除发送者，与注释契约不符。
5. `auditor_mcp_server.py` `scan_summary` 漏计三类 verdict，`total != 各分类之和`。
6. `live_scan_feeder.py` `normalize_verdict` 未覆盖新 verdict，高危信号在雷达上消失。
7. `SceneManager.ts` `disposeObject3D` 未调 `InstancedMesh.dispose()`，实例矩阵显存泄漏。
8. `live_scan_feeder.py` 三处链路断点：`PROJECT_ROOT` 错误、`ingest_openapi` 参数名不符、未解析 `all_results`。
9. `live_scan_feeder.py` 调 `ingest_openapi` 漏传 `only_auditable` → 无对象引用的端点被误报为 `VULNERABLE`（假阳性）。
10. `sandbox_verifier.py:132-136` 与上方通用分支条件逐字相同的恒不可达死代码。

## 四、未完成 / 剩余风险

1. **`live_scan_feeder.py`（81%）/ `test_stream_feeder.py`（80%）**：循环入口与退避语义已覆盖，
   剩余未覆盖为 stderr 异常打印分支与 `main()` 信号注册。
2. **`ws_bridge_server.py`（69%）**：`start()` 的 serve 生命周期与信号处理未覆盖。
3. **security-gate 本地未验证**：trivy 未安装，Trivy CRITICAL 扫描只能在 GitHub Actions 观察。
4. **mcp 2.x 未进 CI 实际运行验证**：矩阵已配好，但本地无法执行 GitHub Actions；
   需首次 push 后在 Actions 页面确认两条 leg 均绿。
5. **前端 WebGL 层未做真实渲染验证**：jsdom 无 WebGL 上下文，`dispose()` 调用链已断言，
   但驱动层实际回收无法验证。
6. **`_verdict` 不做可审计性过滤**：属分层约定（由 ingest 层负责），
   若调用方直接向 `batch_differential_scan` 传非可审计条目，仍会得到 `VULNERABLE`。

## 五、建议下一 Wave

1. **补 `ws_bridge_server.py` 生命周期测试**：`start()` 的 serve 与信号处理，把该模块从 69% 拉起。
2. **CI 首次 push 后核对双版本 leg**：确认 mcp `<2` / `>=2` 两条矩阵均绿（本地无法验证）。
3. **前端 WebGL 真实渲染验证**：引入 headless GL（如 `gl` 包）或 Playwright，
   验证 128 节点实例矩阵的真实显存回收。
