"""
scope.py: 渗透测试范围策略（Scope Policy）

越权审计必须严格限定在授权范围内。本模块提供 host 白名单 +
路径正则包含/排除的范围裁决，供 pipeline_orchestrator 在摄入后、
扫描前对待测矩阵执行出界过滤（out_of_scope_filtered）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class ScopePolicy:
    """
    范围策略。

    Args:
        include_hosts: 允许的 host 列表（精确匹配或子域匹配，
            大小写不敏感）；None / 空列表表示不限制 host。
            例如 ``target.local`` 匹配 ``target.local`` 与
            ``api.target.local``，但不匹配 ``eviltarget.local``。
        include_path_patterns: 路径必须命中的正则列表（非空时启用，任一命中即入界）。
        exclude_path_patterns: 路径命中即出界的正则列表（优先级高于 include）。
    """
    include_hosts: list[str] | None = None
    include_path_patterns: list[str] = field(default_factory=list)
    exclude_path_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._include_res = [re.compile(p, re.IGNORECASE) for p in self.include_path_patterns]
        self._exclude_res = [re.compile(p, re.IGNORECASE) for p in self.exclude_path_patterns]
        self._include_hosts = [
            h.lower().rstrip(".") for h in (self.include_hosts or [])
        ]

    def _host_allowed(self, host: str) -> bool:
        """host 白名单裁决：精确匹配或子域匹配（防子串绕过）。"""
        if not self._include_hosts:
            return True
        host = host.rstrip(".")
        return any(
            host == allowed or host.endswith("." + allowed)
            for allowed in self._include_hosts
        )

    def is_in_scope(self, url: str) -> bool:
        """裁决单个 URL 是否在授权范围内。"""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            # 无 host 的 URL（相对路径 / 畸形输入）无法界定授权边界 → 出界
            return False
        path = parsed.path or "/"

        if self.include_hosts and not self._host_allowed(host):
            return False
        if any(pattern.search(path) for pattern in self._exclude_res):
            return False
        return not (
            self._include_res
            and not any(pattern.search(path) for pattern in self._include_res)
        )

    def filter_matrix(self, matrix: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
        """
        过滤待测矩阵。

        Returns:
            ``(in_scope_matrix, out_of_scope_count)``。
        """
        in_scope: list[dict[str, Any]] = []
        out_count = 0
        for entry in matrix:
            url = str(entry.get("url", ""))
            if url and self.is_in_scope(url):
                in_scope.append(entry)
            else:
                out_count += 1
        return in_scope, out_count
