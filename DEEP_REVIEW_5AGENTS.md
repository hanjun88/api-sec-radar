# API 安全雷达 · 五维深度审查报告

> 生成时间：2026-10-11 | 方法：5 个并行只读子代理，分别覆盖 **审计核心 / MCP与安全 / 流水线 / 打包与基础设施 / 测试盲区**
> 范围：`src/`（3098 行）、`tests/`、`Dockerfile.*`、`docker-compose.yml`、`.github/workflows/ci.yml`
> 原则：只读审查，未改动任何文件。已剔除与已知修复（#9 假阳性、#10 死代码）重复的条目；已标注"经核实无问题"以避免误报。

---

## 一、结论速览

| 维度 | 高 | 中 | 低 | 一句话结论 |
|---|---|---|---|---|
| 审计核心逻辑 | 2 | 4 | 0 | 过滤依赖调用方、存在 PRIV_ESCALATION 误报与对象引用漏识 |
| MCP 与安全 | 2 | 1 | 1 | **SSRF 防护代码是死代码未接入**、`ingest_openapi` 可任意读本地文件 |
| 流水线 | 0 | 3 | 4 | MCP 崩溃静默空转、广播单连接拖垮全局 |
| 打包与基础设施 | 0 | 3 | 3 | Trivy `ignore-unfixed` 漏杀零日、`requirements` 未锁版、`test-feeder` 死锁风险 |
| 测试体系 | 2 | 3 | 2 | `ws_bridge` 未测分支确为真实缺陷、soak 只有 happy path |

**最高优先（P0，安全/正确性）**
1. SSRF 防护全链路未接入运行路径（`adversarial_guard` 是死代码）→ 可被 `gopher://`、`file://`、`169.254.169.254` 利用。
2. `ingest_openapi` 任意本地文件读取（无 allowlist）。
3. `batch_differential_scan` 不强制 `is_auditable` 过滤 → 任何直接调用方复现 #9 假阳性（纵深防御缺失）。

---

## 二、详细发现（按严重度）

### 🔴 高（必须修）

| # | 维度 | 位置 | 发现 | 证据 / 触发 | 建议 |
|---|---|---|---|---|---|
| H1 | MCP/安全 | `safety.py:169` `validate_request_security` 仅 docstring 引用；运行路径只接弱 `validate_method_safety`(`core.py:423`) | **完整安全护栏从未接入运行路径**，`adversarial_guard.validate_url/validate_headers/BypassDetector` 全是死代码 | 工具 `differential_access_test`(`auditor_mcp_server.py:75`)、`probe_endpoint`(`:117`)、`batch_differential_scan`(`:237`)、`ingest_openapi`(`:162 base_url`) 直接把 URL 交给 `httpx`(`core.py:527`) → SSRF / 请求走私（`gopher://`、`file://`、`http://169.254.169.254/`、`%0d%0a`） | 在 `core.execute` 建连前调用 `validate_request_security`；`base_url` 也过 `validate_url` |
| H2 | MCP/安全 | `auditor_mcp_server.py:118-122` | **`ingest_openapi` 任意本地文件读取** | 入参非 `{`/`[` 即 `open()`，无 allowlist → 可探测/读服务器文件 | 限定目录或强制 JSON 字符串入参 |
| H3 | 审计核心 | `auditor_mcp_server.py:358-364`（`_run_batch_scan`）、`:263`（`fast_mode`） | **`batch_differential_scan` 不强制 auditable 过滤** | 遍历全部 entry 无 `is_auditable` 守卫；过滤完全依赖调用方（`ingest:171-172` + 已修的 feeder `:286`）。任何直接传入 `/health` 类同内容端点的调用方都会复现 #9 假阳性 | 在 `_execute_single_entry` 入口对 `is_auditable is False` 强制降级为 INCONCLUSIVE/跳过（纵深防御） |
| H4 | 审计核心 | `core.py:590` | **PRIV_ESCALATION 误报路径** | `primary_status>=400 and 200<=secondary<300 → PRIV_ESCALATION(0.75)`。当属主 token 过期(401)/限流(429)/瞬时5xx 而攻击者 200 时，被误判为权限提升 | 对 primary 4xx 增加"是否预期错误"判定，避免偶发 4xx 误报 |
| H5 | 测试 | `ws_bridge_server.py:98-124`、`59-69` | **`ws_bridge` 未测分支确为真实缺陷** | `start/stop/main` 全程未测；`broadcast` 的 `except→unregister`(:65-69) 与 `handler` 的 `ConnectionClosed`(:92-93) 未测。`test_client_disconnect_is_cleaned_up` 只覆盖"收完消息后断开"，**广播途中掉线的客户端不会被该 except 清理**（仅待下次收消息才触发 `finally`） | 在两次 `broadcast` 之间关闭一个 client，断言 `bridge.clients` 收缩且无异常；补 `stop()/start()` 事件循环单测 |
| H6 | 测试 | `test_soak_pipeline.py` | **soak 仅 happy path**（4.75s、~3 轮） | 未覆盖靶场 500、MCP 子进程崩溃、WS 中途断连。此前 #9 靠真实 soak 暴露，但 soak 本身缺异常韧性 | 注入故障靶场(500)与主动 kill MCP proc，断言 feeder 降级不崩溃 / 可续扫 |

### 🟠 中（应修）

| # | 维度 | 位置 | 发现 | 证据 / 触发 | 建议 |
|---|---|---|---|---|---|
| M1 | MCP/安全 | `auditor_mcp_server.py:15-22` | **mcp 双版本兼容假设不实** | 注释称 v2 将 FastMCP 改名 `mcp.server.mcpserver.MCPServer`；实测装 mcp 1.30.0 且 `mcp.server.mcpserver` 不存在(`ModuleNotFoundError`)，try 必失败落 except，CI 双矩阵实际只跑 FastMCP 一路，v2 路径从未被验证 | CI 对每个固定版本断言 `_MCPServer` 真解析并真实子进程握手 |
| M2 | 审计核心 | `core.py:581` | **VULNERABLE 低置信宽带** | `similarity>=threshold*0.7`(默认 0.595) 即判 VULNERABLE(0.8×sim)。端点忽略 id 返回调用者自身同形数据时被误报 | 收紧低置信区间或要求 secondary 确为"他人对象"才升级 |
| M3 | 审计核心 | `openapi.py:18-21` | **对象引用漏识** | 关键词白名单(id/uuid/key/account/order/user/tenant/product/item/ref) 不覆盖 `slug`/`code`/`handle`/`email`，如 `/posts/{slug}`、`?email=` 漏审计 → BOLA 覆盖缺口 | 扩充白名单 + 增加路径参数类型启发式 |
| M4 | 审计核心 | `sandbox_verifier.py:139-143` | **Flask 元组式 404 漏检** | 仅匹配 `Assign(status_code=404)` 与 `Call(kw/pos 404)`；`return jsonify(...), 404`（Flask 常见写法，404 为 Tuple 内裸 Constant）不命中 → 合法补丁被判 PARTIAL；`raise NotFound()` 无 404 参数亦漏 | 增加 Return/Tuple 与无参 NotFound 分支匹配 |
| M5 | 审计核心 | `sandbox_verifier.py:28-31,65-92` | **tenant 匹配过宽/过窄** | 仅按标识符名判定，`user_is_admin(current_user)` 这类非授权引用即可通过 tenant 断言（弱保证）；而 `obj.uid==g.user`、`resource.owner==` 等合法归属检查因词表外而失败 | 引入归属语义词典 + 排除已知非授权标识符 |
| M6 | 流水线 | `live_scan_feeder.py:269-299,362-366` | **MCP 子进程无存活检测/重连** | `run()` 仅有 `while self.running` 轮询；MCP 进程崩溃 → `_send_request` 抛 `RuntimeError` 被 except 吞掉返回 `[]`，feeder 静默空转永远推不出数据，也不重启进程或退出 | 加进程存活探测 + 退避重连 + 连续失败退出 |
| M7 | 流水线 | `live_scan_feeder.py:362-366,316-344` | **迭代体无异常兜底** | `_run_one_iteration` 未被 `try` 包裹，Phase3/4（结果解析、`build_artifact_from_scan_result`）无异常保护，一条畸形结果即可永久杀死推流 | 包 `try/except` 捕获解析异常并续跑 |
| M8 | 流水线 | `ws_bridge_server.py:59-69` | **广播串行无超时，单坏连接拖垮全局** | 顺序 `await client.send()`，无每连接超时/并发；任一慢/挂起客户端 head-of-line 阻塞所有其他客户端 | 每连接 `asyncio.wait_for` + 并发 broadcast |
| M9 | 打包/CI | `ci.yml:147,157` | **security-gate 漏杀零日** | `ignore-unfixed: true` + `severity: CRITICAL`：仅拦"有补丁的"CRITICAL，**无上游修复的 CRITICAL 被静默放过** | 至少对 os 类 CRITICAL 去掉 `ignore-unfixed` 或加钉版 |
| M10 | 打包/CI | `compose:65-66` + `51-52,67-69` | **`test-feeder` profile 死锁风险** | `test-feeder` 带 `profiles:[test]`，默认 `up` 不启动；`live-feeder`/`test-feeder` 均 `depends_on: ws-bridge: service_healthy`，若 ws-bridge 探针失败则死锁不启动 | 文档化 `--profile test`；为 feeder 加 `restart` 与探针软依赖 |
| M11 | 打包/CI | `requirements.txt:1-13` | **依赖未锁定精确版本/无 hash** | 仅设下界 `>=` + mcp 上限，pip 可得不同 patch，CI 与本地/镜像不可完全复现 | 加 `pip-compile` 生成锁定文件或 hash |
| M12 | 测试 | `core.py:87-95,106-128`；`adversarial_guard.py:86,70-71,103`；`openapi.py:72-90,147` | **具体未测分支** | 连接池 `configure_pool`/`get_pool_stats`(75%)；adversarial 端口越界/ValueError/headers=None(89%)；openapi server override/param 解析(73%) | 补参数化边界用例 |

### 🟡 低（可延后）

| # | 维度 | 位置 | 发现 | 建议 |
|---|---|---|---|---|
| L1 | MCP/安全 | `auditor_mcp_server.py:88,123` | 单条工具错误隔离不一致（批量有隔离，单条仅捕 `httpx.HTTPError`） | 统一包裹返回 `{status:ERROR}` |
| L2 | 流水线 | `test_feeders.py:86-93` | 契约测试漏断言 `only_auditable=True`（仅 soak 间接验证） | 补参数集合断言 |
| L3 | 流水线 | `live_scan_feeder.py:227 vs 385` | `main()` 硬编码间隔 `5.0`，忽略 `SCAN_INTERVAL_SEC` env | 统一读 env |
| L4 | 流水线 | `ws_bridge_server.py:101`；`:104-108`；`:89-108` | `start()` 死赋值 `self.server=True`；stdout 行协议假定严格锁步；同步子进程 I/O 阻塞 feeder 事件循环 | 清理死代码 / 用 asyncio 子进程 PIPE |
| L5 | 打包/CI | `Dockerfile.pipeline/dashboard` | 实为**单阶段**（非"多阶段"描述） | 文档修正 |
| L6 | 打包/CI | `Dockerfile.pipeline:9` | `apt-get upgrade` 对 slim 有限，部分需 `dist-upgrade` | 评估 dist-upgrade |
| L7 | 打包/CI | `ci.yml:34` | `npm ci \|\| npm install` 缺 lock 时掩盖可复现（当前 lock 存在，风险低） | 固定 `npm ci` |
| L8 | 测试 | `tests/SceneManager.lifecycle.test.ts` | 仅 mock `WebGLRenderer`，真实 GL 渲染像素未验证（jsdom 无 GL，已知限制） | 需视觉正确性时引入 headless-gl |
| L9 | 测试 | `conftest.py:43`、测试组织 | 集成/单元混放(全量 15.44s)，无 `integration` marker；`performance` marker 注册但无用例 | 加 marker 分流 |

---

## 三、经核实无问题（避免误报）

- **#9 / #10 修复有效**：`live_scan_feeder.py:286` 已传 `only_auditable=True`；`sandbox_verifier` 死代码已移除（A1 验证）。
- **`_verdict` 不接收 `is_auditable` 符合设计约定**；`_flatten_keys` 时间戳黑名单正确（A1）。
- **MCP 入口参数透传不漏**：`only_auditable`/`only_safe_methods` 在 `ingest_openapi` 已接收并本地过滤（A2）。
- **`hook.py` 无命令注入/任意代码执行**：纯 HMAC/Bearer/签名，`hmac.compare_digest` 常数时间；`verify_remediation` 仅 `compile()`+AST 静态断言，无执行（A2）。
- **批量并发分级(≤10)、结果压缩、错误隔离、91 项测试通过**（A2）。
- **`.gitignore` 已含 `.coverage`/`coverage.xml`/`node_modules/`/`*.bak`**（用户疑似漏项，实际已覆盖，A4）。
- **HEALTHCHECK 端口/路径对齐**，服务绑 `0.0.0.0:8765` 探针可达（A4）。
- **mcp 双版本矩阵两条 leg 结构有效**（A4 与 M1 交叉：结构 OK，但 v2 运行期行为未验证）。
- **`COVERAGE_MIN=78` vs 实测 82.33% ≈ 4.3pt 缓冲合理**（A4）。
- **feeder 解耦注入默认值等价于原硬编码，`main()` CLI 入口未变；断连清理、`normalize_verdict` 全覆盖**（A3）。
- **`test_mcp_protocol`/`test_batch_scan` 真子进程+真靶场断言不变量；`test_safety` fail-closed 全面；soak 的 health 排除断言即 #9 回归门禁**（A5）。

---

## 四、修复优先级路线图

1. **P0（本周）**：H1 SSRF 接入 → H2 文件读限制 → H3 batch 过滤纵深防御。这三项直接决定工具是否"安全可用"。
2. **P1（下轮）**：H4 PRIV_ESCALATION 误报、M2-M5 检测精度、M6-M8 流水线韧性、M9-M11 供应链/CI 加固、H5/H6 补关键测试。
3. **P2（择机）**：L1-L9 清理与文档修正。

---

## 五、关于"打包"的补充（回应原问）

- **当前未打包**：本地无相关 Docker 镜像、无 `dist/build/tar` 产物，且 20+ 文件改动未 commit。
- **前置清单**（来自 A4）：装 Docker Engine + compose v2；构建上下文为本地 `.`（**无需先 commit**）；`test-feeder` 需 `docker compose up -d --build --profile test`；确保 `ws-bridge` 监听 8765（受 `WS_HOST/WS_PORT` 影响），否则依赖它的服务因 `service_healthy` 永不释放（见 M10）。
- **审计发现对打包的影响**：M9（Trivy 漏杀零日）意味着即便 `container-gate` 绿，仍可能带未修 CRITICAL 出镜；M11（依赖未锁）意味着镜像不可完全复现。建议打包前先修这两项。
