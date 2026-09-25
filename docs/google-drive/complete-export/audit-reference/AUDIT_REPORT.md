# 心镜 (HeartMirror) 后端引擎与安全总控 Spec→Code→Test 全链路审计与演进报告

## 1. 审计概述与工程背景

本次审计针对心镜系统在 Google Drive 中的核心工程资产开展，贯彻“以真实解释器执行为准，不接受文档报告体”的工程原则，对早期原型与新版安全总控代码进行了逐行语法、类型契约、接口签名及单元测试的动态覆盖验证。

### 审计对象资产清单
1. **早期后端原型**：`heartmirror_backend_engine.py` (Google Drive Doc ID: `1W96dYlAhVEsdz10eoak0SahzBB3yHwt0G3yGnj4uMls`)
2. **原型单元测试套件**：`test_heartmirror.py` (Google Drive Doc ID: `1LHaK4XeW3by_zG3eiswpc_ugrgn0voC12NlLxX7XFSA`)
3. **新版安全总控引擎**：`engine.py（Meta-Arbiter v2 + MultiModalRouter v1）.py` (Google Drive File ID: `1aMXrnfpHHkkmCb27z8_7M4Q7LN-j-GQP`)
4. **前端运行时工程包**：`heartmirror-runtime-v2.1.2.zip (RC-1.2 完整工程).zip` (Google Drive File ID: `1y07d1P6bNfSqwJDWVBC5ptUEy715-7EU`)

---

## 2. 早期原型核心缺陷与执行审计结论

### 缺陷 1：模块级 NameError 阻断启动
* **现象**：`UserBirthProfile.gender: Gender` 中引用了未定义的 `Gender` 类；经查 `MALE` 与 `FEMALE` 被错误定义在 `CAPCapability` 枚举内部。
* **影响**：纯 Python 语法与模块求值层面直接抛出 `NameError: name 'Gender' is not defined`，导致无论采用原生还是 stub 环境，服务在 `import` 阶段即崩溃。

### 缺陷 2：测试套件与引擎接口严重失配（0/8 通过率）
* **类名断层**：测试文件 `test_heartmirror.py` 从引擎导入 `BaziEngine`，但实际定义类名为 `BaziV3Engine`。该缺陷证明测试文件自编写后从未在当前版本代码上被实际运行。
* **缺失契约方法**：
  * `CrossEngineArbitrator.analyze_single_cap`、`fuse_caps`、`trigger_pivot_flow` 三个方法在引擎中均未实现。
  * `CrossEngineArbitrator.arbitrate` 在测试中以引擎类列表 `[BaziEngine, ...]` 调用，而引擎实现签名要求传入解构后的四组元组数据。
  * `ZiweiV3Engine.generate_cap`、`analyze_features` 方法在引擎中不存在。
  * `ZiweiV3Engine.project_to_upiv` 期望返回具有 `.vector` 属性及 `.version == "V1.4"` 的特定投影结构，引擎中直接返回 `UnifiedPersonaVector` Pydantic 模型。
  * `CrisisCircuitBreaker.check_safety` 返回字典缺少测试期待的 `status_code: 422` 与 `is_intercepted: True` 键值。

### 缺陷 3：业务接口处于静态 Mock 占位状态
* `/v1/diagnostic/full-report` 收集了用户提交的经纬度、出生时间戳及性别，但在函数内部八字与星盘推演参数完全为硬编码静态字面量（固定辛金生于子月），未消费入参。
* `/v1/sos/chamber` 清醒舱对任何用户草稿均返回固定的一套情绪标签与呼吸引导文案。

### 缺陷 4：CORS 跨域安全配置规范冲突
* `allow_origins=["*"]` 与 `allow_credentials=True` 同时配置，在现代浏览器及 Fetch 规范中会被严格拦截，无法在跨域生产环境中携带凭证访问。

---

## 3. 修复方案与验证结果

针对上述缺陷，完成了 `heartmirror_backend_engine.py` 的修复与补全：
1. **抽离独立枚举**：定义 `Gender(str, Enum)`，清理 `CAPCapability` 内部的误写成员。
2. **类名兼容映射**：增加 `BaziEngine = BaziV3Engine` 别名。
3. **接口契约全量补齐**：
   * 补全 `CrossEngineArbitrator` 的 `analyze_single_cap`、`fuse_caps`、`trigger_pivot_flow` 及针对多引擎列表的 `arbitrate` 重载支持。
   * 补全 `ZiweiV3Engine` 的 `generate_cap`（置信度收敛于 `0.38`，`is_actionable=False`）、`analyze_features` 与 `project_to_upiv` 契约。
   * 补全 `CrisisCircuitBreaker` 的 422 状态码与拦截标示。
   * 修复 CORS 冲突，显式调整为 `allow_credentials=False`。

### 单元测试回归结果
```text
test_12356_crisis_circuit_breaker ... ok
test_multi_cap_hit_and_truncation ... ok
test_pivot_turnaround_handover ... ok
test_single_cap_hit ... ok
test_tc12_01_cap_contract_bounds ... ok
test_tc12_02_ast_proof_generation ... ok
test_tc12_03_upiv_v1_4_projection ... ok
test_tc12_04_four_engine_fusion_and_truncation ... ok
----------------------------------------------------------------------
Ran 8 tests in 0.002s
OK (8/8 Passed)
```

---

## 4. 新版生产架构：Meta-Arbiter v2 封装与端到端验证

Google Drive 中已归档的 `engine.py（Meta-Arbiter v2 + MultiModalRouter v1）.py` 代表了当前架构演进的正式方向。为实现微服务化生产交付，已将其完整封装为 `heartmirror_meta_arbiter_service.py`。

### 核心架构特性
1. **0~4 级不可逆安全分流状态机**：
   * Level 0 `CRISIS`：自杀/掐扼/武器/致命恐吓，硬熔断并下发 12356 卡片（HTTP 422 拦截）。
   * Level 1 `SAFETY_PLAN`：高致死分（>= 4）识别，启动物理安全规划与去接触隔离。
   * Level 2 `STABILIZE`：躯体高唤起（>= 0.65），强制执行 13 步闪回着陆与批判者终止技术。
   * Level 3 `REPAIR`：急性关系冲突进入 EFT 循环降温，慢性关系维护进入 Gottman 维护模式。
   * Level 4 `SYMBOLIC`：星盘、八字、紫微、吠陀全量物理隔离，仅作为只读镜像旁注。
2. **象征层置信度硬锁与物理隔离**：
   * 象征层置信度强制约束在区间 [0.36, 0.40]。
   * `is_symbolic_annotation = True` 强类型断言，严禁玄学标签篡改 0~3 级循证干预决策。
3. **6 大跨书仲裁判例系统**：
   * 判例 1：危机现行压倒一切。
   * 判例 2：先验安全与边界建立优先于依恋理解。
   * 判例 3：施虐控制情境下，解离优先于同理沟通。
   * 判例 4：急性冲突用 EFT，慢性维护用 Gottman。
   * 判例 5：高唤起态抑制认知重构，身体着陆优先。
   * 判例 6：象征层一律侧置，永不进入主决策链。

### FastAPI RESTful 接口规格
* `GET /health`：健康状态、服务版本与象征层锁定范围检查。
* `POST /v2/safety/evaluate`：轻量级安全风险分流评级。
* `POST /v2/arbitrate/route`：多候选技能跨书确定性仲裁路由。
* `POST /v2/arbitrate/decision-chain`：决策树全链条推演与危机 422 拦截。
* `POST /v2/symbolic/verify`：象征层参数合规性校验。

### 端到端 E2E 验证结果
```text
test_01_health ... ok
test_02_safety_evaluate_levels ... ok
test_03_crisis_intercept_422 ... ok
test_04_arbitrate_route_precedents ... ok
test_05_symbolic_lock_verification ... ok
----------------------------------------------------------------------
Ran 5 tests in 0.353s
OK (5/5 Passed)
```

---

## 5. 后续演进建议与工程路径

1. **废弃旧版单体原型**：建议以 `heartmirror_meta_arbiter_service.py` 替代原 `heartmirror_backend_engine.py` 的路由总控角色，原有八字与紫微计算作为纯算力引擎通过内部 RPC 或函数导入接入。
2. **前端 2.39:1 遮幅调度落地**：在 WebGL 运行时中将 `PresentationAdapter` 与 CSS Letterbox 遮幅进行信号总线绑定，在 ACT 0 星门初醒、ACT IV 终爻落定及 ACT V 水镜结算时动态注入电影高光遮幅。
