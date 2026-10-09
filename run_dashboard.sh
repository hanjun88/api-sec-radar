#!/usr/bin/env bash
set -eo pipefail

# ==============================================================================
# VulnTopology Pipeline Launcher (CI/CD Automated Execution Spec v7.0-STRICT)
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_PORT=8765
HTTP_PORT=3000

echo "[PIPELINE] 正在初始化态势感知可视化大屏环境..."

# 1. 检查关键依赖
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] Python3 未安装"; exit 1; }
python3 -c "import websockets" 2>/dev/null || { echo "[ERROR] 缺失 websockets 依赖，请执行: pip install websockets"; exit 1; }

# 2. 释放残留端口（lsof 优先，ss 回退）
_port_pid() {
  local port="$1"
  local pid
  pid=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "$pid"
    return
  fi
  # ss 回退（lsof 不可用时）：解析 LISTEN 端口对应的 pid
  pid=$(ss -ltnp "sport = :$port" 2>/dev/null \
    | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  if [ -n "$pid" ]; then
    echo "$pid"
  fi
}

cleanup_ports() {
  for port in "$WS_PORT" "$HTTP_PORT"; do
    local pid
    pid=$(_port_pid "$port")
    if [ -n "$pid" ]; then
      echo "[CLEANUP] 释放占用端口: $port (PID: $pid)"
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
}
cleanup_ports

# 3. 注册退出 Trap，实现单一生命周期回收
PIDS=()
shutdown() {
  echo -e "\n[PIPELINE] 捕获中断信号，正在回收子进程..."
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
  cleanup_ports
  echo "[PIPELINE] 所有资源已安全销毁，退出完成。"
}
trap shutdown SIGINT SIGTERM EXIT

# 4. 启动 Python WebSocket 广播网关
BRIDGE_SERVER="${PROJECT_ROOT}/src/pipeline/ws_bridge_server.py"
if [ -f "$BRIDGE_SERVER" ]; then
  echo "[BRIDGE] 启动 WebSocket 广播网关 (端口: $WS_PORT)..."
  python3 "$BRIDGE_SERVER" &
  PIDS+=($!)
else
  echo "[BRIDGE] src/pipeline/ws_bridge_server.py 未找到，跳过 WS 网关 (仅 Auto Sim 模式可用)"
fi

# 5. 启动本地轻量 HTTP 静态服务器 (消除 ES Module file:// 协议限制)
echo "[HTTP] 托管态势大屏静态资源 (端口: $HTTP_PORT)..."
python3 -m http.server "$HTTP_PORT" --directory "$PROJECT_ROOT" >/dev/null 2>&1 &
PIDS+=($!)

# 6. 等待端口就绪
sleep 1.5

# 7. 打开默认浏览器并注入 ?live=1 参数直连实时数据流
TARGET_URL="http://127.0.0.1:${HTTP_PORT}/vuln_topology_dashboard.html?live=1"
echo "[BROWSER] 挂载态势雷达: $TARGET_URL"

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$TARGET_URL" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
  open "$TARGET_URL" >/dev/null 2>&1 &
fi

echo "[PIPELINE] 态势大屏全链路就绪。按 Ctrl+C 终止运行。"
wait
