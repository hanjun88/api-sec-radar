# Polymarket 跟单机器人

复制目标钱包在 Polymarket 上的交易，叠加四条策略规则（时间窗口、波动率、贝叶斯胜率、Kelly 仓位）。
**当前为 Phase 1：模拟盘（DRY_RUN）——默认零真钱，不会提交任何真实订单。**

> ⚠️ 原策略帖的盈利数据无法核实，本系统**不承诺任何收益**。$20 试错资金请做好归零准备。
> Polymarket 的地区限制由你自行确认合规；本系统不提供任何绕过手段。

## 快速开始（模拟盘）

```bash
cd polymarket_copybot
cp .env.example .env && chmod 600 .env     # 填 TARGET_WALLET（完整 42 位地址）
docker compose up -d --build               # 或本地：pip install -r requirements.txt && python -m copybot run

docker compose exec copybot python -m copybot report --csv /data/curve.csv   # 复盘报表 + 权益曲线
docker compose exec copybot python -m copybot reset-halt                     # 人工解除熔断
python -m copybot check-config                                               # 校验配置（不打印机密）
```

开发与测试：`pip install -r requirements-dev.txt && pytest`（约 3 秒，无需联网）。

## 数据流

```
目标钱包 ─▶ WalletMonitor ─▶ 内存队列 ─▶ SignalEngine ─▶ Executor ─▶ trades / 报表
 (链上日志     (聚合+去重)               ├ 规则1 时间窗口      ├ DryRunExecutor（默认）
  或 Data API)                          ├ 规则2 波动率        └ LiveExecutor（仅 MODE=LIVE）
                  MarketData(CLOB/Gamma)├ 规则3 贝叶斯+Kelly
                  PriceFeed(Coinbase)   └ 风控（日亏/回撤/API 失败/敞口）
```

| 设计文档 | 模块 |
|---|---|
| 3.1 钱包监控 | `wallet_monitor.py`（`chain` 与 `dataapi` 两种数据源） |
| 3.2 行情服务 | `market_data.py`（订单簿 5 秒缓存、Gamma 元数据、结算查询）、`btc.py`（BTC 识别、Coinbase K 线） |
| 3.3 信号引擎 | `signal_engine.py`、`time_window.py`、`bayes.py` |
| 3.4 Kelly | `kelly.py` |
| 3.5 执行器 | `executor.py`（DRY_RUN）、`live_executor.py`（LIVE，唯一会下单的文件） |
| 3.6 风控 | `risk.py`、`notifier.py`（Telegram 告警 + `/approve`） |
| 3.7 可观测性 | `logging_setup.py`（JSON、UTC、按天轮转保留 30 天、机密脱敏）、`report.py` |
| 4 数据模型 | `db.py`（`signals` / `trades` / `bayesian_state` + `hourly_stats` / `kv`） |

## 规则的具体口径

- **规则 1 时间窗口**：按（市场类型, UTC 小时）统计**本系统已结算交易**的胜率，< 65% 丢弃。该时段样本 < `WINDOW_MIN_SAMPLES`(10) 时冷启动放行（否则永远没有数据）。
- **规则 2 波动率**：Coinbase 过去 60 根 1 分钟 K 线收盘价的 标准差/均值，> 2% 跳过。取不到行情时**不下单**（fail-closed）。
- **规则 3 贝叶斯**：`p = (wins+α)/(total+α+β)`，α=β=1；每笔结算在同一事务内更新，重启不丢。Kelly 用 `p` 与实际卖一价算边际：`p` 不高于价格隐含概率时无边际 → 不下单。
- **规则 4 确认模式**：`CONFIRM`（默认）= 目标钱包信号 + 规则 1–3 全过；`COPY_ONLY` = 目标信号直接触发，仅过风控。
- **仓位**：半 Kelly，单笔 ≤ 总资金 5%；总资金 = `BANKROLL_USD` + 已实现盈亏。
- **成交**：限价 = 信号价 ×(1+2%)，向下取整到 tick；DRY_RUN 按**最新订单簿**吃单算 VWAP（比"假设按信号价成交"更真实，能提前暴露跟单滞后）。
- **卖出**：目标钱包卖出我们持有的 token 时平掉整笔持仓；没持仓则忽略。**退出永远不被入场规则或熔断拦截。**

## 安全设计

| 风险 | 措施 |
|---|---|
| 模拟盘误下真单 | `py-clob-client` 默认不在镜像里；`live_executor.py` 仅在 `MODE=LIVE` 时延迟导入；DRY_RUN 下私钥变量被**忽略**。`tests/test_dry_run_isolation.py` 用 AST 静态审计 + 运行时（屏蔽 SDK、断言所有 Polymarket 请求均为 GET）证明这一点。 |
| 私钥泄露 | 只走环境变量/0600 的 `.env`（LIVE 下权限过宽直接拒绝启动）；`repr=False`；日志按"已知机密的精确值"脱敏；`httpx` 等库的 URL 日志被静音（URL 里有 RPC Key / Bot Token）。 |
| 熔断被自动重启绕过 | 总回撤（20%）与 API 连续失败（5 次）熔断**锁存进数据库**，需 `reset-halt` 人工解除；熔断后进程不退出，继续记录信号并标注 `risk_halted`。日亏损（10%）按 UTC 日历日，次日自动恢复。 |
| 模拟盈亏污染实盘风控 | 资金/熔断计算按 `mode` 隔离。 |
| 重复/过期信号 | 信号 ID 由 `tx+token+side` 确定性生成，重启后重扫也不会重复；超过 `SIGNAL_TTL_SEC`(90) 的信号标记 `EXPIRED`；首次启动从当前区块开始，**不回放目标钱包的历史交易**。 |
| LIVE 误操作 | `BANKROLL_USD` ≤ `LIVE_CAPITAL_CAP_USD`(20)；`REQUIRE_APPROVAL` 默认开启，每单 Telegram `/approve`，且仅响应 `TELEGRAM_CHAT_ID` 对应会话；LIVE 永远不启用冷启动探索仓位。 |

## 与设计文档的偏差 / 补充（请确认）

1. **冷启动探索仓位（仅 DRY_RUN）**：先验 p=0.5 时，Kelly 对价格 > 0.5 的买入永远无边际，模拟盘将永远没有数据可学。因此 DRY_RUN 下，每个市场类型在前 `BOOTSTRAP_TRADES`(30) 笔已结算交易内，无边际时改用固定 `FALLBACK_STAKE_PCT`(1%) 的小仓位收集数据。`ENABLE_BOOTSTRAP=false` 可关闭；**LIVE 下代码层面强制关闭**。
2. **交易所最小下单量会让 $20 默认值几乎无法成交**：单笔上限 5% × $20 = $1，而 CLOB 订单簿给出的 `min_order_size` 通常是 5 份——价格 > $0.20 时 $1 买不到 5 份。引擎在 DRY_RUN 也会校验这点（`below_min_order_size`），所以用默认值跑模拟盘，大部分信号会被这条拦下。要得到有统计意义的 Phase 1 数据，请调大 `MAX_POSITION_PCT` 或用更大的 `BANKROLL_USD` 做模拟（百分比逻辑等比放大）；或 `ENFORCE_MIN_ORDER_SIZE=false` 纯看策略逻辑。**这是你进入 Phase 2 前需要面对的现实约束。**
3. **接口路径**：文档写 `GET /book/{token_id}`，官方 `py-clob-client` 实际是 `GET /book?token_id=`，已按官方实现。
4. **监控数据源**：文档指定 Polygon 链上方案，已实现（`MONITOR_SOURCE=chain`）；另加了无需 RPC Key 的 `dataapi` 作备选，二者共用同一套聚合/去重。链上匹配**只按 `maker == 目标地址`**——目标地址的每笔成交恰好以 maker 身份出现一次，同时匹配 taker 会重复计数。
5. **波动率口径**：按文档用"价格水平的标准差/均值"。BTC 一小时内该值通常只有零点几个百分点，2% 阈值实际只会在极端行情触发；想让它更敏感请调低 `VOLATILITY_THRESHOLD_PCT`。
6. **价格源**：Coinbase（美国 IP 可用）；Binance 国际站对美国 IP 通常返回 451，故未采用。
7. **CLOB 凭证**：文档只列了 `CLOB_API_KEY`，实际 CLOB 凭证是 key/secret/passphrase 三件套，默认由私钥通过官方客户端派生；也可显式提供三件套。
8. **部分简化**：同一 token 已有持仓不加仓；目标卖出时整笔平仓（不按比例）；DRY_RUN 成交为"全成或不成"，不模拟 30 秒挂单与部分成交；LIVE 的手续费暂未记账（`fee_usd`=0），均价优先取下单响应里的成交额，取不到时按限价（对买单偏保守）。

## ⚠️ 尚未对真实接口联调的部分

开发环境的网络策略屏蔽了 `clob.polymarket.com`、`gamma-api.polymarket.com`、`data-api.polymarket.com`、`api.exchange.coinbase.com`，所以：

- 订单簿 / Gamma / Data API / Coinbase 的响应结构取自官方 `py-clob-client` 源码与已知文档，**测试用的是按该结构构造的替身，不是线上抓包**。上线 Phase 1 的第一天请先看日志里的 `signal_detected` / `signal_filtered`，确认市场识别（`btc.classify_market` 基于 question/slug 关键词）和价格字段符合预期。
- 链上 `OrderFilled` 的 topic0 已用 `web3` 核对；两个交易所合约地址取自官方客户端配置，若 Polymarket 升级合约需用 `EXCHANGE_ADDRESSES` 覆盖。
- **`live_executor.py` 从未触达真实 API**，只用假客户端测试，并离线核对了 SDK 的符号与参数名。这是 Phase 2 首周强制逐单人工确认的原因。
- Docker 镜像未能在无 daemon 的环境里实际构建；`docker compose config` 校验通过。

## Phase 1 验收对照

| 验收项 | 状态 |
|---|---|
| 钱包监控 30 秒内捕获 | 机制已实现（轮询 15s + 确认块 2 个 ≈ 4s）；捕获率需上线后用日志里的 `latency_sec` 统计 |
| 四条规则 + 过滤原因可查 | ✅ 每条信号落库 `reason_code`/`reason_detail`；`report` 输出漏斗 |
| Kelly / 贝叶斯 / 风控单元测试 | ✅ `test_kelly.py`、`test_bayes.py`、`test_risk.py` |
| 零实盘（代码审计） | ✅ `test_dry_run_isolation.py`（7 天运行部分需你实际跑） |
| 模拟盈亏曲线可查看 | ✅ `report --csv` |
| 稳定运行 7 天 | 待实际运行 |

## 切换到 Phase 2（由你决定）

1. Phase 1 通过后，在服务器上**手动**写入 `PRIVATE_KEY`（0600 的 `.env`，`chown 10001:10001`），设置 `MODE=LIVE`、`CLOB_FUNDER_ADDRESS`、`TELEGRAM_*`，保持 `REQUIRE_APPROVAL=true`。
2. `docker compose -f docker-compose.yml -f docker-compose.live.yml up -d --build`（需要 Compose ≥ 2.24 以支持 `!reset`）。
3. 同一个数据库会沿用 Phase 1 积累的贝叶斯与小时胜率；资金/熔断只统计 LIVE 交易。
4. 任何熔断触发立即停机复盘，不要急着 `reset-halt`。
