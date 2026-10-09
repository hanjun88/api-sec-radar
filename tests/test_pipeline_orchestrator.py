"""tests/test_pipeline_orchestrator.py — 全链路编排组（真实靶场端到端）"""
from __future__ import annotations

import json
import os

import pytest

from src.auditor.pipeline_orchestrator import (
    PipelineConfig,
    PipelineSource,
    run_pipeline,
)
from src.auditor.scope import ScopePolicy


def _spec(base_url: str, with_write: bool = False) -> str:
    paths = {
        "/api/v1/accounts/{id}": {"get": {"summary": "BOLA candidate"}},
        "/api/v1/secure/{id}": {"get": {"summary": "Ownership enforced"}},
        "/api/v1/admin/users": {"get": {"summary": "BFLA candidate"}},
        "/api/v1/health": {"get": {"summary": "Health"}},
    }
    if with_write:
        paths["/api/v1/accounts/{id}"]["put"] = {"summary": "Unauthorized write"}
    return json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Orchestrator Fixture", "version": "1.0.0"},
        "servers": [{"url": base_url}],
        "paths": paths,
    })


def _cfg(**overrides) -> PipelineConfig:
    defaults = dict(
        program_id="PROG-TEST",
        program_name="Orchestrator Test",
        primary_token="Bearer token-alice",
        secondary_token="Bearer token-bob",
    )
    defaults.update(overrides)
    return PipelineConfig(**defaults)


class TestFullChain:
    def test_result_contract_keys(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))], config=_cfg()
        )
        for key in ("pipeline_id", "program_id", "program_name", "started_at",
                    "finished_at", "elapsed_ms", "ingestion", "scan", "poc",
                    "target_matrix", "scan_result", "poc_reports",
                    "estimated_bounty", "bounty_breakdown", "status", "errors"):
            assert key in result, f"missing key: {key}"
        assert result["status"] == "completed"
        assert result["errors"] == []

    def test_ingestion_stats(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))], config=_cfg()
        )
        ing = result["ingestion"]
        assert ing["total_ingested"] == 4
        assert ing["in_scope"] == 4
        assert ing["out_of_scope_filtered"] == 0
        assert ing["auditable_count"] == 2
        assert ing["safe_method_count"] == 4
        assert ing["sources"] == ["openapi"]

    def test_bola_detected_and_secure_safe(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))], config=_cfg()
        )
        verdicts = {r["path_template"] if "path_template" in r else r["endpoint"]: r["verdict"]
                    for r in result["scan_result"]["all_results"]}
        assert verdicts["GET /api/v1/accounts/{id}"] == "VULNERABLE"
        assert verdicts["GET /api/v1/secure/{id}"] == "SAFE"
        assert verdicts["GET /api/v1/admin/users"] == "VULNERABLE"

    def test_scan_stats_consistent(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))], config=_cfg()
        )
        scan = result["scan"]
        assert scan["status"] == "completed"
        assert scan["scanned"] == scan["total_targets"] == 4
        assert scan["vulnerable"] >= 2
        assert scan["safe"] >= 1
        assert scan["error"] == 0

    def test_poc_and_bounty(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))], config=_cfg()
        )
        assert result["poc"]["total_vulnerabilities"] == len(result["poc_reports"])
        assert set(result["poc"]["by_severity"]) >= {"critical", "high", "medium", "low", "informational"}
        assert round(sum(result["bounty_breakdown"].values()), 2) == result["estimated_bounty"]

    def test_report_files_emitted(self, mock_target_server, tmp_path):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))],
            config=_cfg(output_dir=str(tmp_path / "nested" / "reports")),
        )
        paths = result["report_paths"]
        assert os.path.isfile(paths["markdown_path"])
        assert os.path.isfile(paths["json_path"])
        with open(paths["json_path"], encoding="utf-8") as f:
            doc = json.load(f)
        assert doc["verdict_distribution"]["VULNERABLE"] >= 2

    def test_write_method_blocked_by_default(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server, with_write=True))],
            config=_cfg(),
        )
        put_results = [r for r in result["scan_result"]["all_results"]
                       if r["method"] == "PUT"]
        assert len(put_results) == 1
        assert put_results[0]["verdict"] == "BLOCKED"
        assert result["scan"]["blocked"] >= 1

    def test_only_auditable_narrows_matrix(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))],
            config=_cfg(only_auditable=True),
        )
        assert result["ingestion"]["in_scope"] == 2
        assert all(m["is_auditable"] for m in result["target_matrix"])

    def test_secret_signs_requests(self, mock_target_server):
        """注入 secret 后签名 Hook 生效，扫描仍完成（靶场不验签）。"""
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))],
            config=_cfg(secret_key="unit-secret"),
        )
        assert result["status"] == "completed"
        assert result["scan"]["scanned"] == 4

    def test_empty_sources_rejected(self):
        with pytest.raises(ValueError, match="EMPTY_SOURCES"):
            run_pipeline(sources=[], config=_cfg())

    def test_invalid_source_type_rejected(self):
        with pytest.raises(ValueError, match="INVALID_SOURCE_TYPE"):
            PipelineSource(source_type="postman", content="{}")

    def test_empty_source_content_rejected(self):
        with pytest.raises(ValueError, match="EMPTY_SOURCE_CONTENT"):
            PipelineSource(source_type="har", content="   ")


class TestScopePolicy:
    def test_host_allowlist(self):
        policy = ScopePolicy(include_hosts=["target.local"])
        assert policy.is_in_scope("http://target.local/api/v1/x") is True
        assert policy.is_in_scope("http://evil.local/api/v1/x") is False

    def test_exclude_path_regex(self):
        policy = ScopePolicy(exclude_path_patterns=[r"/admin/"])
        assert policy.is_in_scope("http://t/api/v1/health") is True
        assert policy.is_in_scope("http://t/api/v1/admin/users") is False

    def test_include_path_regex(self):
        policy = ScopePolicy(include_path_patterns=[r"/api/v1/accounts"])
        assert policy.is_in_scope("http://t/api/v1/accounts/1") is True
        assert policy.is_in_scope("http://t/api/v1/health") is False

    def test_out_of_scope_filtered_in_pipeline(self, mock_target_server):
        result = run_pipeline(
            sources=[PipelineSource("openapi", _spec(mock_target_server))],
            config=_cfg(scope=ScopePolicy(exclude_path_patterns=[r"/admin/"])),
        )
        assert result["ingestion"]["out_of_scope_filtered"] == 1
        assert result["ingestion"]["in_scope"] == 3
        endpoints = " ".join(r["endpoint"] for r in result["scan_result"]["all_results"])
        assert "admin" not in endpoints

    def test_malformed_url_out_of_scope(self):
        policy = ScopePolicy()
        assert policy.is_in_scope("not-a-url") is False


class TestHarChannel:
    def test_har_source_runs_through_pipeline(self, mock_target_server):
        har = json.dumps({"log": {"entries": [
            {"request": {"method": "GET", "url": f"{mock_target_server}/api/v1/accounts/1001",
                         "headers": [{"name": "Authorization", "value": "Bearer token-alice"}],
                         "queryString": []}},
            {"request": {"method": "GET", "url": f"{mock_target_server}/api/v1/secure/1001",
                         "headers": [{"name": "Authorization", "value": "Bearer token-alice"}],
                         "queryString": []}},
        ]}})
        result = run_pipeline(
            sources=[PipelineSource("har", har)],
            config=_cfg(secondary_token="Bearer token-bob"),
        )
        assert result["ingestion"]["sources"] == ["har"]
        assert result["ingestion"]["total_ingested"] == 2
        verdicts = {r["endpoint"]: r["verdict"] for r in result["scan_result"]["all_results"]}
        assert any(v == "VULNERABLE" for v in verdicts.values())

    def test_mixed_sources(self, mock_target_server):
        har = json.dumps({"log": {"entries": [
            {"request": {"method": "GET", "url": f"{mock_target_server}/api/v1/accounts/1002",
                         "headers": [], "queryString": []}},
        ]}})
        result = run_pipeline(
            sources=[
                PipelineSource("openapi", _spec(mock_target_server)),
                PipelineSource("har", har),
            ],
            config=_cfg(),
        )
        assert result["ingestion"]["total_ingested"] == 5
        assert result["ingestion"]["sources"] == ["openapi", "har"]
        assert result["scan"]["scanned"] == 5

    def test_bad_source_records_error_not_crash(self, mock_target_server):
        result = run_pipeline(
            sources=[
                PipelineSource("openapi", _spec(mock_target_server)),
                PipelineSource("har", "{not-json"),
            ],
            config=_cfg(),
        )
        assert result["status"] == "completed_with_errors"
        assert any(e["stage"] == "ingestion" for e in result["errors"])
        assert result["scan"]["scanned"] == 4  # 好源不受影响
