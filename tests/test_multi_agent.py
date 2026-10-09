"""tests/test_multi_agent.py — Multi-Agent 编排组"""
from __future__ import annotations

from src.auditor.multi_agent import (
    AgentContext,
    AuditOrchestrator,
    DiffAgent,
    EvidenceAgent,
    MapReducePipeline,
    ParallelPipeline,
    ReconAgent,
    RemediationAgent,
    SequentialPipeline,
)


def _context(allow_write: bool = False) -> AgentContext:
    return AgentContext(
        task_id="test-task",
        allow_write=allow_write,
        primary_token="token-alice",
        secondary_token="token-bob",
        similarity_threshold=0.85,
    )


class TestAgents:
    def test_recon_agent_blocked_write(self):
        """侦察蚁只读：写方法被统一安全门禁阻断。"""
        agent = ReconAgent()
        result = agent.run(_context(), {"url": "http://127.0.0.1:1/api", "method": "PUT"})
        # ReconAgent 固定 GET，PUT 不生效
        assert result.agent_type == "recon"

    def test_recon_agent_empty_url(self):
        agent = ReconAgent()
        result = agent.run(_context(), {})
        assert result.status == "failed"
        assert "RECON_EMPTY_URL" in result.error

    def test_diff_agent_empty_url(self):
        agent = DiffAgent()
        result = agent.run(_context(), {})
        assert result.status == "failed"
        assert "DIFF_EMPTY_URL" in result.error

    def test_diff_agent_write_blocked(self):
        """差分蚁写操作默认熔断（P0-INVARIANT-03）。"""
        agent = DiffAgent()
        result = agent.run(
            _context(allow_write=False),
            {"url": "http://127.0.0.1:1/api", "method": "PUT"},
        )
        assert result.status == "completed"
        assert result.output["verdict"] == "BLOCKED"
        assert result.output["evidence"]["blocked_by"] == "REQUEST_SECURITY_GATE"

    def test_evidence_agent_empty(self):
        agent = EvidenceAgent()
        result = agent.run(_context(), {})
        assert result.status == "failed"
        assert "EVIDENCE_EMPTY" in result.error

    def test_evidence_agent_builds_poc(self):
        agent = EvidenceAgent()
        scan_results = [{
            "endpoint": "GET /api/v1/accounts/1001",
            "method": "GET",
            "url": "http://t/api/v1/accounts/1001",
            "verdict": "VULNERABLE",
            "confidence": 0.97,
            "similarity": 0.98,
            "is_auditable": True,
            "primary_status": 200,
            "secondary_status": 200,
            "evidence": {"primary_status": 200, "secondary_status": 200},
            "root_cause": "missing ownership check",
        }]
        result = agent.run(_context(), {"scan_results": scan_results})
        assert result.status == "completed"
        assert result.output["poc_count"] == 1

    def test_remediation_agent_empty(self):
        agent = RemediationAgent()
        result = agent.run(_context(), {})
        assert result.status == "failed"
        assert "REMEDIATION_EMPTY" in result.error


class TestPipelines:
    def test_sequential_pipeline(self):
        pipeline = SequentialPipeline(
            name="test-seq",
            agents=[ReconAgent(), DiffAgent()],
        )
        results = pipeline.run(
            _context(),
            {"url": "http://127.0.0.1:1/api"},
        )
        assert len(results) == 2
        assert all(r.status in ("completed", "failed") for r in results)

    def test_parallel_pipeline(self):
        pipeline = ParallelPipeline(
            name="test-par",
            agents=[ReconAgent(), ReconAgent(), ReconAgent()],
            max_workers=3,
        )
        results = pipeline.run(
            _context(),
            {"url": "http://127.0.0.1:1/api"},
        )
        assert len(results) == 3

    def test_map_reduce_pipeline(self):
        pipeline = MapReducePipeline(
            name="test-map",
            worker=ReconAgent(),
            max_workers=2,
        )
        shards = [{"url": f"http://127.0.0.1:1/api/{i}"} for i in range(4)]
        results = pipeline.run(_context(), shards)
        assert len(results) == 4

    def test_map_reduce_empty_shards(self):
        pipeline = MapReducePipeline(name="empty", worker=ReconAgent())
        assert pipeline.run(_context(), []) == []


class TestOrchestrator:
    def test_plan_recon(self):
        orch = AuditOrchestrator()
        pipeline = orch.plan_recon(
            ["http://a/1", "http://a/2"], _context()
        )
        assert isinstance(pipeline, MapReducePipeline)
        assert pipeline.name == "recon-sweep"

    def test_plan_diff_sweep(self):
        orch = AuditOrchestrator()
        endpoints = [
            {"url": "http://a/1", "method": "GET"},
            {"url": "http://a/2", "method": "GET"},
        ]
        pipeline = orch.plan_diff_sweep(endpoints, _context())
        assert isinstance(pipeline, MapReducePipeline)
        assert pipeline.name == "diff-sweep"

    def test_plan_full_audit(self):
        orch = AuditOrchestrator()
        pipeline = orch.plan_full_audit(["http://a/1"], _context())
        assert isinstance(pipeline, SequentialPipeline)
        assert pipeline.name == "full-audit"
        assert len(pipeline.agents) == 3

    def test_run_pipeline_map_reduce(self):
        orch = AuditOrchestrator()
        pipeline = orch.plan_recon(["http://a/1", "http://a/2"], _context())
        summary = orch.run_pipeline(
            pipeline, _context(),
            [{"url": "http://a/1"}, {"url": "http://a/2"}],
        )
        assert summary["pipeline"] == "recon-sweep"
        assert summary["total_agents"] == 2
        assert "results" in summary

    def test_run_pipeline_sequential(self):
        orch = AuditOrchestrator()
        pipeline = orch.plan_full_audit(["http://a/1"], _context())
        summary = orch.run_pipeline(pipeline, _context(), {"url": "http://a/1"})
        assert summary["pipeline"] == "full-audit"
        assert summary["total_agents"] == 3
