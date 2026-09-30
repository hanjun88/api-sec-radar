"""tests/test_report.py — emit_audit_report 单元测试。

覆盖：batch 聚合 dict 输入 → Markdown + JSON 双报告落盘，
报告包含目标/时间/扫描条目数/verdict 分布/每条 finding 的
endpoint/verdict/confidence/evidence。
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from src.auditor.report import emit_audit_report


def _sample_scan_result() -> Dict[str, Any]:
    return {
        "status": "DELIVERED",
        "scan_summary": {
            "total": 3, "vulnerable": 1, "safe": 1, "blocked": 0,
            "inconclusive": 0, "error": 0,
        },
        "elapsed_ms": 1234.5,
        "concurrency": 2,
        "vulnerable_endpoints": [],
        "all_results": [
            {
                "endpoint": "GET /api/v1/accounts/1001",
                "url": "http://127.0.0.1:18099/api/v1/accounts/1001",
                "method": "GET",
                "verdict": "VULNERABLE",
                "confidence": 0.97,
                "similarity": 0.98,
                "primary_status": 200,
                "secondary_status": 200,
                "evidence": {
                    "primary_status": 200,
                    "secondary_status": 200,
                    "similarity": 0.98,
                },
            },
            {
                "endpoint": "GET /api/v1/secure/1001",
                "url": "http://127.0.0.1:18099/api/v1/secure/1001",
                "method": "GET",
                "verdict": "SAFE",
                "confidence": 0.95,
                "similarity": 0.12,
                "primary_status": 200,
                "secondary_status": 403,
                "evidence": {
                    "primary_status": 200,
                    "secondary_status": 403,
                    "similarity": 0.12,
                },
            },
            {
                "endpoint": "GET /api/v1/accounts/1002",
                "url": "http://127.0.0.1:18099/api/v1/accounts/1002",
                "method": "GET",
                "verdict": "SUSPECT",
                "confidence": 0.55,
                "similarity": 0.86,
                "primary_status": 200,
                "secondary_status": 200,
                "evidence": {
                    "primary_status": 200,
                    "secondary_status": 200,
                    "similarity": 0.86,
                },
            },
        ],
    }


def test_emit_audit_report_writes_md_and_json(tmp_path) -> None:
    out_dir = str(tmp_path / "reports")
    result = emit_audit_report(
        _sample_scan_result(),
        target="http://127.0.0.1:18099",
        output_dir=out_dir,
    )

    md_path = result["markdown_path"]
    json_path = result["json_path"]
    assert os.path.isfile(md_path)
    assert os.path.isfile(json_path)
    assert result["finding_count"] == 3
    assert result["verdict_distribution"] == {
        "VULNERABLE": 1,
        "SUSPECT": 1,
        "SAFE": 1,
    }

    md = open(md_path, encoding="utf-8").read()
    # 目标 / 时间 / 扫描条目数 / verdict 分布
    assert "http://127.0.0.1:18099" in md
    assert "**扫描时间**" in md
    assert "**扫描条目数**: 3" in md
    assert "| VULNERABLE | 1 |" in md
    assert "| SUSPECT | 1 |" in md
    assert "| SAFE | 1 |" in md
    # 每条 finding 的 endpoint/verdict/confidence/evidence
    for endpoint in (
        "GET /api/v1/accounts/1001",
        "GET /api/v1/secure/1001",
        "GET /api/v1/accounts/1002",
    ):
        assert endpoint in md
    assert "**verdict**: VULNERABLE" in md
    assert "**verdict**: SAFE" in md
    assert "**verdict**: SUSPECT" in md
    assert "**confidence**: 0.97" in md
    assert "**primary_status**: 200" in md
    assert "**secondary_status**: 403" in md

    doc = json.load(open(json_path, encoding="utf-8"))
    assert doc["target"] == "http://127.0.0.1:18099"
    assert doc["scan_time"]
    assert doc["finding_count"] == 3
    assert doc["verdict_distribution"]["VULNERABLE"] == 1
    assert len(doc["findings"]) == 3
    f0 = doc["findings"][0]
    assert f0["endpoint"] == "GET /api/v1/accounts/1001"
    assert f0["verdict"] == "VULNERABLE"
    assert f0["confidence"] == 0.97
    assert f0["evidence"]["primary_status"] == 200
    assert f0["evidence"]["secondary_status"] == 200


def test_emit_audit_report_accepts_bare_list(tmp_path) -> None:
    """兼容裸 list 输入；空结果也应落盘且分布为空。"""
    result = emit_audit_report([], output_dir=str(tmp_path))
    assert result["finding_count"] == 0
    assert result["verdict_distribution"] == {}
    md = open(result["markdown_path"], encoding="utf-8").read()
    assert "**扫描条目数**: 0" in md
    doc = json.load(open(result["json_path"], encoding="utf-8"))
    assert doc["findings"] == []


def test_emit_audit_report_creates_output_dir(tmp_path) -> None:
    """output_dir 不存在时自动创建。"""
    out_dir = str(tmp_path / "nested" / "reports")
    result = emit_audit_report(
        _sample_scan_result(),
        target="http://target.local",
        output_dir=out_dir,
    )
    assert os.path.isdir(out_dir)
    assert os.path.isfile(result["markdown_path"])
    assert os.path.isfile(result["json_path"])
