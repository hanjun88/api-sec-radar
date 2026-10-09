# AGENTS.md — 工程协作约定

本仓库为 **API Security Radar**（API 越权审计 + 三维态势大屏）。全链路：
摄入（OpenAPI/HAR）→ 范围过滤 → 差分扫描 → PoC → 赏金 → 报告 → WebSocket 广播 → 3D 大屏。

## 验证命令（提交前必须全部通过）

```bash
# 后端：全量回归（171 项；含 MCP stdio、真实 WS 网关、真实靶场的 E2E）
python3 -m pytest tests/ -v

# Lint（显式规则契约见 pyproject.toml，target-version py310 / 交付 3.14）
python3 -m ruff check src tests

# 前端：类型检查 + 组件测试（16 项）
npx tsc --noEmit
npx vitest run tests/SceneManager.test.ts

# Compose 配置校验（CI container-gate 同款）
docker compose config --quiet
```

本地 Python 需满足 `requirements.txt`（首次：`python3 -m pip install -r requirements.txt`；
沙箱无 pip 时先 `curl -sSL https://bootstrap.pypa.io/get-pip.py | python3`）。

## 不可破坏的安全不变量

- **P0-INVARIANT-03**：非幂等写操作默认熔断。任何改动不得让
  `POST/PUT/PATCH/DELETE` 在未显式 `allow_write=True` 时产生网络流量。
- 方法覆盖（header / `_method` query）与 GET+写特征 body 均视为写操作。
- `sandbox_verifier.verify_python_patch` 只做静态断言，**不得**伪造
  `verified_safe=True` 或伪造物理状态码（200/404）。
- 差分审计输出确定性证据链（verdict / confidence / similarity / evidence），
  不得为凑结论丢弃响应指纹。

## 代码约定

- 新模块放 `src/auditor/`（引擎层）或 `src/pipeline/`（中继层）；
  跨层复用的数据契约统一定义在 `artifact_contract.py`（VulnEvidencePayload）。
- MCP 工具层与全链路编排器共用 `batch_scan.py`，**不要**在
  `auditor_mcp_server.py` 内复制扫描循环。
- 中文注释/docstring 是本仓库既有风格，保持一致；RUF001-003 已在
  pyproject.toml 显式豁免（CJK 非歧义 Unicode）。
- 新增功能必须带 pytest 用例；端到端行为变更必须扩展
  `tests/test_e2e_full_chain.py`（真实子进程，不许 mock 掉网关）。
- 兼容性地板 Python 3.10（不发 3.11+ 专属语法），交付镜像 Python 3.14。
