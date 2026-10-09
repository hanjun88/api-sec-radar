"""
multi_agent.py: Multi-Agent 审计编排层

把 API Security Radar 的审计能力封装为可并行派发的
agent pipeline（蚁群架构：编排者 → 工蚁 → 归巢汇总），
通过 MCP 暴露为工具。

设计借鉴 agent-mcp-framework 的 pipeline 模式
（Sequential / Parallel / Conditional / MapReduce），
但基于本仓库的 mcp 2.x MCPServer（不依赖 mcp 1.x
的 FastMCP）。

Agent 角色：
- 编排者（Orchestrator）：拆解审计任务、派发工蚁、汇总
- 侦察蚁（ReconAgent）：端点探测 + 范围界定
- 差分蚁（DiffAgent）：单端点/批量差分越权测试
- 取证蚁（EvidenceAgent）：PoC 生成 + 证据链固化
- 修复蚁（RemediationAgent）：补丁静态验证

P0-INVARIANT-03 保持不变：工蚁的写操作默认物理熔断，
必须显式 allow_write=True 才产生网络流量。
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .core import ApiAccessAuditor, DifferentialTestInput, RequestIdentity
from .poc_builder import build_poc_reports
from .sandbox_verifier import verify_python_patch

# ── Agent 抽象 ──────────────────────────────────────────


@dataclass
class AgentResult:
    """单个工蚁的执行结果。"""

    agent_id: str
    agent_type: str
    status: str  # completed | failed | blocked
    output: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class AgentContext:
    """工蚁执行上下文（任务参数 + 安全边界）。"""

    task_id: str
    allow_write: bool = False
    primary_token: str = ""
    secondary_token: str = ""
    similarity_threshold: float = 0.85
    timeout_per_request: float = 10.0


class BaseAgent:
    """工蚁基类：子类实现 run()。"""

    agent_type: str = "base"

    def __init__(self, agent_id: str | None = None) -> None:
        self.agent_id = agent_id or f"{self.agent_type}-{uuid.uuid4().hex[:8]}"

    def run(self, context: AgentContext, task: dict[str, Any]) -> AgentResult:
        """执行工蚁任务。子类必须实现。"""
        raise NotImplementedError

    def _ok(self, output: dict[str, Any]) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            status="completed",
            output=output,
        )

    def _fail(self, error: str, output: dict[str, Any] | None = None) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            status="failed",
            output=output or {},
            error=error,
        )


class ReconAgent(BaseAgent):
    """侦察蚁：端点探测 + 范围界定（只读）。"""

    agent_type = "recon"

    def run(self, context: AgentContext, task: dict[str, Any]) -> AgentResult:
        url = str(task.get("url", ""))
        if not url:
            return self._fail("RECON_EMPTY_URL: 缺少 url")
        auditor = ApiAccessAuditor()
        params = DifferentialTestInput(
            primary=RequestIdentity(
                label="recon", method="GET", url=url,
                headers={"Authorization": f"Bearer {context.primary_token}"}
                if context.primary_token else {},
            ),
            secondary=RequestIdentity(
                label="recon", method="GET", url=url,
                headers={"Authorization": f"Bearer {context.secondary_token}"}
                if context.secondary_token else {},
            ),
            similarity_threshold=context.similarity_threshold,
            allow_write=False,
        )
        try:
            result = auditor.execute(params)
            return self._ok({
                "url": url,
                "verdict": result.verdict,
                "primary_status": result.primary.status_code,
                "secondary_status": result.secondary.status_code,
                "similarity": result.similarity,
                "evidence": result.evidence,
            })
        except Exception as e:
            return self._fail(f"RECON_ERROR: {e}")


class DiffAgent(BaseAgent):
    """差分蚁：单端点差分越权测试。"""

    agent_type = "diff"

    def run(self, context: AgentContext, task: dict[str, Any]) -> AgentResult:
        url = str(task.get("url", ""))
        method = str(task.get("method", "GET")).upper()
        if not url:
            return self._fail("DIFF_EMPTY_URL: 缺少 url")
        auditor = ApiAccessAuditor()
        params = DifferentialTestInput(
            primary=RequestIdentity(
                label="primary", method=method, url=url,
                headers=task.get("primary_headers") or {},
                body=task.get("primary_body"),
            ),
            secondary=RequestIdentity(
                label="secondary", method=method, url=url,
                headers=task.get("secondary_headers") or {},
                body=task.get("secondary_body"),
            ),
            similarity_threshold=context.similarity_threshold,
            allow_write=context.allow_write,
        )
        try:
            result = auditor.execute(params)
            return self._ok({
                "url": url,
                "method": method,
                "verdict": result.verdict,
                "confidence": result.confidence,
                "similarity": result.similarity,
                "primary_status": result.primary.status_code,
                "secondary_status": result.secondary.status_code,
                "evidence": result.evidence,
            })
        except Exception as e:
            return self._fail(f"DIFF_ERROR: {e}")


class EvidenceAgent(BaseAgent):
    """取证蚁：PoC 生成 + 证据链固化。"""

    agent_type = "evidence"

    def run(self, context: AgentContext, task: dict[str, Any]) -> AgentResult:
        scan_results = task.get("scan_results")
        if not isinstance(scan_results, list) or not scan_results:
            return self._fail("EVIDENCE_EMPTY: 缺少 scan_results")
        try:
            reports = build_poc_reports(scan_results)
            return self._ok({
                "poc_count": len(reports),
                "poc_reports": reports,
            })
        except Exception as e:
            return self._fail(f"EVIDENCE_ERROR: {e}")


class RemediationAgent(BaseAgent):
    """修复蚁：补丁静态 AST 验证。"""

    agent_type = "remediation"

    def run(self, context: AgentContext, task: dict[str, Any]) -> AgentResult:
        patch = str(task.get("patch_code_snippet", ""))
        url = str(task.get("test_url", ""))
        if not patch or not url:
            return self._fail("REMEDIATION_EMPTY: 缺少 patch_code_snippet 或 test_url")
        try:
            result = verify_python_patch(
                test_url=url,
                patch_code_snippet=patch,
                original_handler_snippet=str(task.get("original_handler_snippet", "")),
                primary_token=context.primary_token or "token-alice",
                secondary_token=context.secondary_token or "token-bob",
            )
            return self._ok(result)
        except Exception as e:
            return self._fail(f"REMEDIATION_ERROR: {e}")


# ── Pipeline 编排 ───────────────────────────────────────


class SequentialPipeline:
    """顺序 pipeline：工蚁依次执行，后蚁继承前蚁上下文。"""

    def __init__(self, name: str, agents: list[BaseAgent]) -> None:
        self.name = name
        self.agents = agents

    def run(self, context: AgentContext, task: dict[str, Any]) -> list[AgentResult]:
        results: list[AgentResult] = []
        shared = dict(task)
        for agent in self.agents:
            result = agent.run(context, shared)
            results.append(result)
            if result.status == "completed":
                shared.update(result.output)
        return results


class ParallelPipeline:
    """并行 pipeline：工蚁并发执行（线程池），结果汇总。"""

    def __init__(self, name: str, agents: list[BaseAgent],
                 max_workers: int = 4) -> None:
        self.name = name
        self.agents = agents
        self.max_workers = max(1, min(max_workers, 10))

    def run(self, context: AgentContext, task: dict[str, Any]) -> list[AgentResult]:
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [
                pool.submit(agent.run, context, task) for agent in self.agents
            ]
            return [f.result() for f in futures]


class MapReducePipeline:
    """MapReduce pipeline：分片 → 并行工蚁 → 归巢汇总。"""

    def __init__(self, name: str, worker: BaseAgent,
                 max_workers: int = 4) -> None:
        self.name = name
        self.worker = worker
        self.max_workers = max(1, min(max_workers, 10))

    def run(
        self, context: AgentContext, shards: list[dict[str, Any]],
    ) -> list[AgentResult]:
        if not shards:
            return []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [
                pool.submit(self.worker.run, context, shard) for shard in shards
            ]
            return [f.result() for f in futures]


# ── 编排者（Orchestrator）───────────────────────────────


class AuditOrchestrator:
    """蚁后：拆解审计任务 → 派发工蚁 → 归巢汇总。

    编排者从不亲自执行网络请求（P0-INVARIANT-03：
    写操作熔断由工蚁的统一安全门禁强制）。
    """

    def __init__(self) -> None:
        self._auditor = ApiAccessAuditor()

    def plan_recon(
        self, urls: list[str], context: AgentContext,
    ) -> MapReducePipeline:
        """侦察计划：URL 分片 → 并行侦察蚁。"""
        shards = [{"url": url} for url in urls]
        return MapReducePipeline(
            name="recon-sweep",
            worker=ReconAgent(),
            max_workers=min(4, max(1, len(shards))),
        )

    def plan_diff_sweep(
        self, endpoints: list[dict[str, Any]], context: AgentContext,
    ) -> MapReducePipeline:
        """差分计划：端点矩阵分片 → 并行差分蚁。"""
        shards = [
            {
                "url": ep.get("url", ""),
                "method": ep.get("method", "GET"),
                "primary_headers": ep.get("primary_headers") or {},
                "secondary_headers": ep.get("secondary_headers") or {},
            }
            for ep in endpoints
        ]
        return MapReducePipeline(
            name="diff-sweep",
            worker=DiffAgent(),
            max_workers=min(8, max(1, len(shards))),
        )

    def plan_full_audit(
        self, urls: list[str], context: AgentContext,
    ) -> SequentialPipeline:
        """全链路计划：侦察 → 差分 → 取证（顺序依赖）。"""
        return SequentialPipeline(
            name="full-audit",
            agents=[
                ReconAgent(),
                DiffAgent(),
                EvidenceAgent(),
            ],
        )

    def run_pipeline(
        self,
        pipeline: SequentialPipeline | ParallelPipeline | MapReducePipeline,
        context: AgentContext,
        task: dict[str, Any] | list[dict[str, Any]],
    ) -> dict[str, Any]:
        """执行 pipeline 并归巢汇总。"""
        if isinstance(pipeline, MapReducePipeline):
            shards = task if isinstance(task, list) else [task]
            results = pipeline.run(context, shards)
        else:
            results = pipeline.run(context, task if isinstance(task, dict) else {})

        completed = [r for r in results if r.status == "completed"]
        failed = [r for r in results if r.status == "failed"]
        blocked = [r for r in results if r.status == "blocked"]

        return {
            "pipeline": pipeline.name,
            "total_agents": len(results),
            "completed": len(completed),
            "failed": len(failed),
            "blocked": len(blocked),
            "results": [
                {
                    "agent_id": r.agent_id,
                    "agent_type": r.agent_type,
                    "status": r.status,
                    "output": r.output,
                    "error": r.error,
                }
                for r in results
            ],
        }
