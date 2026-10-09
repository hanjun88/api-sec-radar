#!/usr/bin/env python3
"""
artifact_emitter.py: 全链路自动化工件推流器（Spec → Scan → PoC → Dashboard）

一条命令完成：摄入（OpenAPI/HAR）→ 范围过滤 → 批量差分扫描 →
PoC 构建 → 赏金估算 → 报告落盘 → WebSocket 广播至 3D 态势大屏。

用法示例::

    # 单轮全链路审计（默认目标 spec，推送至本地网关）
    python3 src/pipeline/artifact_emitter.py --once

    # 自定义 OpenAPI 契约 + 身份 + 周期推流
    python3 src/pipeline/artifact_emitter.py \\
        --openapi-spec ./specs/target.json \\
        --base-url https://target.example.com \\
        --primary-token "Bearer token-alice" \\
        --secondary-token "Bearer token-bob" \\
        --ws-url ws://127.0.0.1:8765 \\
        --interval 30 --output-dir ./audit_reports

身份令牌也可经环境变量注入：PRIMARY_TOKEN / SECONDARY_TOKEN。
P0-INVARIANT-03：非幂等写操作默认熔断，--allow-write 才显式放行。
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
from typing import Any

# ── 路径引导（支持 `python3 src/pipeline/artifact_emitter.py` 直接运行）────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.auditor.pipeline_orchestrator import (  # noqa: E402
    PipelineConfig,
    PipelineSource,
    run_pipeline,
)

if importlib.util.find_spec("websockets") is None:
    print("[ERROR] 缺失 websockets 依赖，请执行: pip install websockets", file=sys.stderr)
    sys.exit(1)

DEFAULT_WS_URL = os.environ.get("WS_SERVER_URL", "ws://127.0.0.1:8765")
DEFAULT_PRIMARY_TOKEN = os.environ.get("PRIMARY_TOKEN", "Bearer token-alice")
DEFAULT_SECONDARY_TOKEN = os.environ.get("SECONDARY_TOKEN", "Bearer token-bob")

DEFAULT_OPENAPI_SPEC: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "Live Scan Target", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:18099"}],
    "paths": {
        "/api/v1/accounts/{id}": {
            "get": {
                "summary": "Get account by ID (BOLA candidate)",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/v1/users/{id}": {
            "get": {
                "summary": "Get user profile by ID (BOLA candidate)",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/v1/orders/{id}": {
            "get": {
                "summary": "Get order by ID (BOLA candidate)",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/api/v1/health": {
            "get": {"summary": "Health check (safe, no object ref)"}
        },
    },
}


def _load_text(path_or_inline: str) -> str:
    """文件路径 → 内容；否则按内联字符串返回。"""
    if os.path.exists(path_or_inline):
        with open(path_or_inline, encoding="utf-8") as f:
            return f.read()
    return path_or_inline


def build_sources(args: argparse.Namespace) -> list[PipelineSource]:
    """根据 CLI 参数构建摄入源列表。"""
    sources: list[PipelineSource] = []
    if args.openapi_spec:
        sources.append(PipelineSource(
            source_type="openapi",
            content=_load_text(args.openapi_spec),
            base_url_override=args.base_url or "",
        ))
    if args.har:
        sources.append(PipelineSource(
            source_type="har",
            content=_load_text(args.har),
        ))
    if not sources:
        # 缺省：内置演示契约（与 live_scan_feeder 对齐，可开箱即用）
        sources.append(PipelineSource(
            source_type="openapi",
            content=json.dumps(DEFAULT_OPENAPI_SPEC),
            base_url_override=args.base_url or "",
        ))
    return sources


def build_config(args: argparse.Namespace, ws_url: str) -> PipelineConfig:
    return PipelineConfig(
        program_id=args.program_id,
        program_name=args.program_name,
        primary_token=args.primary_token,
        secondary_token=args.secondary_token,
        secret_key=args.secret_key,
        allow_write=args.allow_write,
        similarity_threshold=args.similarity_threshold,
        max_concurrency=args.concurrency,
        interval_ms=args.interval_ms,
        fast_mode=args.fast,
        timeout_per_request=args.timeout,
        mock_id_value=args.mock_id,
        only_auditable=args.only_auditable,
        output_dir=args.output_dir or None,
        ws_bridge_url=ws_url,
    )


def _print_summary(result: dict[str, Any], cycle: int) -> None:
    scan = result.get("scan", {})
    poc = result.get("poc", {})
    print(
        f"[EMIT] [cycle #{cycle}] ingestion={result['ingestion']['in_scope']} "
        f"scanned={scan.get('scanned', 0)} "
        f"VULNERABLE={scan.get('vulnerable', 0)} "
        f"SAFE={scan.get('safe', 0)} "
        f"BLOCKED={scan.get('blocked', 0)} "
        f"PoC={poc.get('total_vulnerabilities', 0)} "
        f"bounty=${result.get('estimated_bounty', 0)} "
        f"pushed={result.get('pushed_artifacts', 0)} "
        f"status={result.get('status')}"
    )


async def run(args: argparse.Namespace) -> None:
    ws_url = args.ws_url
    sources = build_sources(args)
    config = build_config(args, ws_url)

    print(f"[EMIT] 全链路工件推流器启动 → {ws_url}")
    print(f"[EMIT] 摄入源: {[s.source_type for s in sources]} | 周期: {args.interval}s")

    cycle = 0
    while True:
        cycle += 1
        try:
            result = run_pipeline(sources=sources, config=config)
            _print_summary(result, cycle)
            report_paths = result.get("report_paths") or {}
            if report_paths:
                print(f"[EMIT] 报告已落盘: {report_paths.get('markdown_path')}")
            for err in result.get("errors", []):
                print(f"[EMIT][WARN] stage={err.get('stage')} error={err.get('error')}", file=sys.stderr)
        except Exception as e:
            print(f"[EMIT][ERROR] 第 {cycle} 轮流水线失败: {e}", file=sys.stderr)

        if args.once:
            break
        await asyncio.sleep(args.interval)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="API Security Radar 全链路工件推流器")
    parser.add_argument("--openapi-spec", default="", help="OpenAPI 规范 JSON 字符串或文件路径")
    parser.add_argument("--har", default="", help="HAR 流量 JSON 文件路径")
    parser.add_argument("--base-url", default="", help="覆盖 spec servers/host 的基址")
    parser.add_argument("--ws-url", default=DEFAULT_WS_URL, help="WebSocket 广播网关地址")
    parser.add_argument("--program-id", default="PROG-AUTO")
    parser.add_argument("--program-name", default="Automated Audit Program")
    parser.add_argument("--primary-token", default=DEFAULT_PRIMARY_TOKEN)
    parser.add_argument("--secondary-token", default=DEFAULT_SECONDARY_TOKEN)
    parser.add_argument("--secret-key", default="", help="可选 HMAC 签名密钥")
    parser.add_argument("--allow-write", action="store_true",
                        help="显式放行非幂等写操作（P0-INVARIANT-03 覆盖）")
    parser.add_argument("--similarity-threshold", type=float, default=0.85)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--mock-id", default="1001", help="Path {id} 参数替换探测值")
    parser.add_argument("--only-auditable", action="store_true", help="仅扫描对象级引用端点")
    parser.add_argument("--fast", action="store_true", help="快速模式（精简非 auditable 证据）")
    parser.add_argument("--output-dir", default="", help="审计报告落盘目录（可选）")
    parser.add_argument("--interval", type=float, default=30.0, help="推流周期秒数")
    parser.add_argument("--once", action="store_true", help="仅执行一轮后退出")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[EMIT] 推流器已停止。")


if __name__ == "__main__":
    main()
