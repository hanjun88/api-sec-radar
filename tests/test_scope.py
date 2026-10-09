"""tests/test_scope.py — 范围策略组"""
from __future__ import annotations

from src.auditor.scope import ScopePolicy


class TestScopePolicy:
    def test_no_host_restriction(self):
        policy = ScopePolicy()
        assert policy.is_in_scope("http://any.example.com/api")

    def test_exact_host_match(self):
        policy = ScopePolicy(include_hosts=["target.local"])
        assert policy.is_in_scope("http://target.local/api")

    def test_subdomain_match(self):
        policy = ScopePolicy(include_hosts=["target.local"])
        assert policy.is_in_scope("http://api.target.local/api")

    def test_substring_bypass_blocked(self):
        """子串匹配绕过修复：eviltarget.local 不得匹配 target.local。"""
        policy = ScopePolicy(include_hosts=["target.local"])
        assert not policy.is_in_scope("http://eviltarget.local/api")
        assert not policy.is_in_scope("http://notarget.local/api")

    def test_case_insensitive(self):
        policy = ScopePolicy(include_hosts=["Target.Local"])
        assert policy.is_in_scope("http://TARGET.LOCAL/api")

    def test_trailing_dot_normalized(self):
        policy = ScopePolicy(include_hosts=["target.local"])
        assert policy.is_in_scope("http://target.local./api")

    def test_no_host_url_out_of_scope(self):
        policy = ScopePolicy()
        assert not policy.is_in_scope("/relative/path")

    def test_exclude_path_pattern(self):
        policy = ScopePolicy(exclude_path_patterns=[r"/admin"])
        assert not policy.is_in_scope("http://target.local/admin/users")
        assert policy.is_in_scope("http://target.local/api/users")

    def test_include_path_pattern(self):
        policy = ScopePolicy(include_path_patterns=[r"/api/v1"])
        assert policy.is_in_scope("http://target.local/api/v1/users")
        assert not policy.is_in_scope("http://target.local/internal/users")

    def test_filter_matrix_counts_out_of_scope(self):
        policy = ScopePolicy(include_hosts=["target.local"])
        matrix = [
            {"url": "http://target.local/a"},
            {"url": "http://evil.local/b"},
            {"url": "http://target.local/c"},
        ]
        in_scope, out_count = policy.filter_matrix(matrix)
        assert len(in_scope) == 2
        assert out_count == 1

    def test_filter_matrix_empty_url_out_of_scope(self):
        policy = ScopePolicy()
        in_scope, out_count = policy.filter_matrix([{"url": ""}, {"url": "http://x/y"}])
        assert len(in_scope) == 1
        assert out_count == 1
