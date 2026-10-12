"""tests/test_ingest_path_guard.py — 摄入通道文件路径 allowlist（H2 修复）

验证 OpenAPI / HAR 双摄入通道的路径模式只接受 .json/.har 后缀的
普通文件，阻断把任意本地文件（/etc/passwd、~/.ssh/id_rsa 等）
当规范文档摄入的读取面。
"""
from __future__ import annotations

import json

import pytest

from src.auditor.har_ingestor import parse_har
from src.auditor.openapi import parse_openapi_spec

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1.0.0"},
    "servers": [{"url": "http://target.local"}],
    "paths": {"/api/v1/accounts/{id}": {"get": {"summary": "x"}}},
}

_HAR = {
    "log": {
        "version": "1.2",
        "creator": {"name": "t", "version": "1"},
        "entries": [],
    }
}


class TestOpenApiPathGuard:
    def test_json_path_allowed(self, tmp_path):
        p = tmp_path / "spec.json"
        p.write_text(json.dumps(_SPEC), encoding="utf-8")
        matrix = parse_openapi_spec(spec_content_or_path=str(p))
        assert len(matrix) == 1
        assert matrix[0]["is_auditable"] is True

    def test_inline_content_unaffected(self):
        matrix = parse_openapi_spec(spec_content_or_path=json.dumps(_SPEC))
        assert len(matrix) == 1

    def test_non_allowlisted_suffix_rejected(self, tmp_path):
        """带 JSON 内容但后缀不在白名单 → 拒绝（防任意文件读取面）。"""
        p = tmp_path / "id_rsa"
        p.write_text(json.dumps(_SPEC), encoding="utf-8")
        with pytest.raises(ValueError, match="PATH_NOT_ALLOWED"):
            parse_openapi_spec(spec_content_or_path=str(p))

    def test_no_suffix_path_rejected(self, tmp_path):
        p = tmp_path / "passwd"
        p.write_text("root:x:0:0:", encoding="utf-8")
        with pytest.raises(ValueError, match="PATH_NOT_ALLOWED"):
            parse_openapi_spec(spec_content_or_path=str(p))

    def test_traversal_path_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="PATH_NOT_ALLOWED"):
            parse_openapi_spec(
                spec_content_or_path=str(tmp_path / ".." / ".." / "etc" / "shadow")
            )

    def test_directory_rejected(self, tmp_path):
        # 目录带 .json 后缀：过后缀白名单后仍须被“普通文件”检查拒绝
        d = tmp_path / "specs.json"
        d.mkdir()
        with pytest.raises(ValueError, match="SPEC_PATH_INVALID"):
            parse_openapi_spec(spec_content_or_path=str(d))

    def test_missing_file_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="SPEC_PATH_INVALID"):
            parse_openapi_spec(spec_content_or_path=str(tmp_path / "nope.json"))

    def test_uppercase_suffix_allowed(self, tmp_path):
        p = tmp_path / "SPEC.JSON"
        p.write_text(json.dumps(_SPEC), encoding="utf-8")
        matrix = parse_openapi_spec(spec_content_or_path=str(p))
        assert len(matrix) == 1


class TestHarPathGuard:
    def test_har_suffix_allowed(self, tmp_path):
        p = tmp_path / "traffic.har"
        p.write_text(json.dumps(_HAR), encoding="utf-8")
        assert parse_har(content_or_path=str(p)) == []

    def test_json_suffix_allowed(self, tmp_path):
        p = tmp_path / "traffic.json"
        p.write_text(json.dumps(_HAR), encoding="utf-8")
        assert parse_har(content_or_path=str(p)) == []

    def test_non_allowlisted_suffix_rejected(self, tmp_path):
        p = tmp_path / "traffic.log"
        p.write_text(json.dumps(_HAR), encoding="utf-8")
        with pytest.raises(ValueError, match="PATH_NOT_ALLOWED"):
            parse_har(content_or_path=str(p))

    def test_no_suffix_path_rejected(self, tmp_path):
        p = tmp_path / "credentials"
        p.write_text(json.dumps(_HAR), encoding="utf-8")
        with pytest.raises(ValueError, match="PATH_NOT_ALLOWED"):
            parse_har(content_or_path=str(p))

    def test_missing_file_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="SPEC_PATH_INVALID"):
            parse_har(content_or_path=str(tmp_path / "nope.har"))
