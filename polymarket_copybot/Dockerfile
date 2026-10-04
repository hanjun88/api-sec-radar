# Polymarket 跟单机器人
#   默认构建（DRY_RUN）：镜像里**不包含** py-clob-client，从物理上无法下真实订单。
#   Phase 2 才加 --build-arg WITH_LIVE=1（或使用 docker-compose.live.yml）。
FROM python:3.12-slim AS base

ARG WITH_LIVE=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 与仓库其他镜像一致：升级系统包以修补基础镜像里的已知 CVE
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-live.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$WITH_LIVE" = "1" ]; then pip install --no-cache-dir -r requirements-live.txt; fi

RUN useradd -u 10001 -m -s /usr/sbin/nologin copybot \
    && mkdir -p /data /logs \
    && chown -R copybot:copybot /app /data /logs
USER copybot

COPY --chown=copybot:copybot copybot/ ./copybot/

ENV DB_PATH=/data/copybot.db \
    LOG_DIR=/logs

ENTRYPOINT ["python", "-m", "copybot"]
CMD ["run"]
