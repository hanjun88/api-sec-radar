"""tests/test_har_ingestor.py — HAR 黑盒通道摄入组"""
from __future__ import annotations

import json

from src.auditor.har_ingestor import filter_auditable, parse_har


def _har(entries: list) -> str:
    return json.dumps({"log": {"version": "1.2", "entries": entries}})


def _entry(method: str, url: str, headers: list | None = None,
           post_text: str | None = None) -> dict:
    req = {
        "method": method,
        "url": url,
        "headers": headers if headers is not None else [
            {"name": "Authorization", "value": "Bearer token-alice"},
            {"name": "Accept", "value": "application/json"},
        ],
        "queryString": [],
    }
    if post_text is not None:
        req["postData"] = {"mimeType": "application/json", "text": post_text}
    return {"request": req, "response": {"status": 200}}


HAR = _har([
    _entry("GET", "http://target.local/api/v1/accounts/1001"),
    _entry("GET", "http://target.local/api/v1/users/42?verbose=1"),
    _entry("POST", "http://target.local/api/v1/accounts", post_text='{"owner": "x"}'),
    _entry("GET", "http://target.local/api/v1/health"),
    _entry("GET", "http://target.local/api/v1/orders/ORD-9?account_id=7"),
])


class TestParseHar:
    def test_matrix_size_and_order(self):
        matrix = parse_har(HAR)
        assert len(matrix) == 5
        assert matrix[0]["method"] == "GET"
        assert matrix[0]["url"] == "http://target.local/api/v1/accounts/1001"

    def test_object_ref_makes_auditable(self):
        matrix = parse_har(HAR)
        by_path = {m["path_template"]: m for m in matrix}
        assert by_path["/api/v1/accounts/1001"]["is_auditable"] is True
        assert by_path["/api/v1/health"]["is_auditable"] is False
        assert by_path["/api/v1/orders/ORD-9"]["is_auditable"] is True  # query account_id

    def test_safe_method_flag(self):
        matrix = parse_har(HAR)
        by_path = {m["path_template"]: m for m in matrix}
        assert by_path["/api/v1/health"]["is_safe_method"] is True
        assert by_path["/api/v1/accounts"]["is_safe_method"] is False

    def test_primary_keeps_recorded_headers(self):
        matrix = parse_har(HAR)
        assert matrix[0]["primary_headers"]["Authorization"] == "Bearer token-alice"

    def test_secondary_strips_auth_and_accepts_override(self):
        matrix = parse_har(HAR)
        assert "Authorization" not in matrix[0]["secondary_headers"]
        matrix2 = parse_har(HAR, secondary_headers={"Authorization": "Bearer token-bob"})
        assert matrix2[0]["secondary_headers"]["Authorization"] == "Bearer token-bob"

    def test_primary_override_wins(self):
        matrix = parse_har(HAR, primary_headers={"Authorization": "Bearer token-carol"})
        assert matrix[0]["primary_headers"]["Authorization"] == "Bearer token-carol"

    def test_post_body_captured(self):
        matrix = parse_har(HAR)
        by_path = {m["path_template"]: m for m in matrix}
        assert by_path["/api/v1/accounts"]["json_body"] == '{"owner": "x"}'

    def test_query_stripped_from_url(self):
        matrix = parse_har(HAR)
        by_path = {m["path_template"]: m for m in matrix}
        assert "?" not in by_path["/api/v1/orders/ORD-9"]["url"]

    def test_max_entries_cap(self):
        big = _har([_entry("GET", f"http://t.local/api/x/{i}") for i in range(50)])
        assert len(parse_har(big, max_entries=10)) == 10

    def test_invalid_entries_skipped(self):
        har = _har([{"request": {"method": "BOGUS", "url": "http://t/"}},
                    {"no_request": True},
                    _entry("GET", "http://t/api/v1/health")])
        matrix = parse_har(har)
        assert len(matrix) == 1

    def test_empty_log(self):
        assert parse_har(_har([])) == []

    def test_file_path_input(self, tmp_path):
        p = tmp_path / "traffic.har"
        p.write_text(HAR, encoding="utf-8")
        assert len(parse_har(str(p))) == 5

    def test_filter_auditable(self):
        matrix = parse_har(HAR)
        auditable = filter_auditable(matrix)
        assert len(auditable) == 3
        assert all(m["is_auditable"] for m in auditable)


class TestHarbOpenapiIsomorphism:
    """双通道摄入必须同构（下游 run_batch_scan 无感接入）。"""

    def test_same_keys_as_openapi_entry(self):
        from src.auditor.openapi import parse_openapi_spec

        spec = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1"},
            "servers": [{"url": "http://target.local"}],
            "paths": {"/api/v1/accounts/{accountId}": {"get": {"summary": "x"}}},
        })
        har_entry = parse_har(_har([_entry("GET", "http://target.local/api/v1/accounts/1001")]))[0]
        oas_entry = parse_openapi_spec(spec)[0]
        assert set(har_entry.keys()) == set(oas_entry.keys())
        assert har_entry["is_auditable"] == oas_entry["is_auditable"]
        assert har_entry["is_safe_method"] == oas_entry["is_safe_method"]
