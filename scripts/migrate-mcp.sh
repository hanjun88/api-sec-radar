#!/usr/bin/env bash
# scripts/migrate-mcp.sh — MCP 依赖迁移脚本 (P0)
# 用途：在升级 mcp SDK 版本前自动备份、执行迁移、验证、失败自动回滚。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${REPO_ROOT}/.mcp-backup-$(date +%Y%m%d_%H%M%S)"
TARGET_VERSION="${1:-1.0.0}"
LOG_FILE="${BACKUP_DIR}/migrate.log"

log() { echo "[$(date '+%Y-%m-%dT%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# ── 1. 前置检查 ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    log "ERROR: python3 未找到，中止迁移"
    exit 1
fi
if ! python3 -m pip --version &>/dev/null; then
    log "ERROR: pip 未安装，中止迁移"
    exit 1
fi

# ── 2. 备份当前状态 ──────────────────────────────────────────
log "创建备份目录: ${BACKUP_DIR}"
mkdir -p "${BACKUP_DIR}"
cp "${REPO_ROOT}/requirements.txt" "${BACKUP_DIR}/requirements.txt.bak" 2>/dev/null || true
cp "${REPO_ROOT}/requirements.lock" "${BACKUP_DIR}/requirements.lock.bak" 2>/dev/null || true
git -C "${REPO_ROOT}" rev-parse HEAD > "${BACKUP_DIR}/git-head.txt" 2>/dev/null || true
log "备份完成"

# ── 3. 记录迁移前 mcp 版本 ────────────────────────────────────
BEFORE_VERSION=$(python3 -c "import mcp; print(mcp.__version__)" 2>/dev/null || echo "unknown")
log "迁移前 mcp 版本: ${BEFORE_VERSION}"

# ── 4. 执行依赖升级 ──────────────────────────────────────────
log "安装目标 mcp 版本: ${TARGET_VERSION}"
if ! pip install --quiet "mcp>=${TARGET_VERSION},<2" >>"${LOG_FILE}" 2>&1; then
    log "ERROR: pip install 失败，回滚到备份"
    cp "${BACKUP_DIR}/requirements.txt.bak" "${REPO_ROOT}/requirements.txt" 2>/dev/null || true
    cp "${BACKUP_DIR}/requirements.lock.bak" "${REPO_ROOT}/requirements.lock" 2>/dev/null || true
    exit 1
fi

# ── 5. 验证迁移后状态 ────────────────────────────────────────
AFTER_VERSION=$(python3 -c "import mcp; print(mcp.__version__)" 2>/dev/null || echo "unknown")
log "迁移后 mcp 版本: ${AFTER_VERSION}"

VERIFY_OK=true
for mod in mcp.server.fastmcp mcp.types mcp.client.session; do
    if ! python3 -c "import ${mod}" >>"${LOG_FILE}" 2>&1; then
        log "ERROR: 模块导入失败: ${mod}"
        VERIFY_OK=false
        break
    fi
done

if [ "${VERIFY_OK}" != "true" ]; then
    log "ERROR: 验证失败，回滚"
    cp "${BACKUP_DIR}/requirements.txt.bak" "${REPO_ROOT}/requirements.txt" 2>/dev/null || true
    cp "${BACKUP_DIR}/requirements.lock.bak" "${REPO_ROOT}/requirements.lock" 2>/dev/null || true
    exit 1
fi

# ── 6. 运行测试套件验证 ──────────────────────────────────────
log "运行 pytest 验证..."
if ! python3 -m pytest tests/ -q >>"${LOG_FILE}" 2>&1; then
    log "ERROR: 测试失败，回滚"
    cp "${BACKUP_DIR}/requirements.txt.bak" "${REPO_ROOT}/requirements.txt" 2>/dev/null || true
    cp "${BACKUP_DIR}/requirements.lock.bak" "${REPO_ROOT}/requirements.lock" 2>/dev/null || true
    exit 1
fi

# ── 7. 重新生成 lock 文件 ────────────────────────────────────
pip freeze > "${REPO_ROOT}/requirements.lock"
log "迁移成功。备份保留于: ${BACKUP_DIR}"
log "新 requirements.lock 已生成"