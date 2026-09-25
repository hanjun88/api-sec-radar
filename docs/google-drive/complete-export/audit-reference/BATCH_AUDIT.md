# 批次审计 v2 · 双合法通道（公版/CC BY开放书章 + 作者官网公开原文） 2026-09-11 P4 终版

## 两条已实测打通的合法全文通道
1. NCBI Bookshelf: 服务端渲染curl直抓完整章;许可分级 可演绎=public domain(SAMHSA TIP57)/CC BY(NIHR),禁演绎=CC BY-NC-ND(CADTH),待核=页面无许可行。
2. 目标作者官网公开文章: cptsd由pete-walker.com抓27篇作者公开原文45万字(现网200);feeling_good由feelinggood.com抓3篇;通用器 _AUDIT/fetch_author_open.py。

## 全量白盒状态总表（P4 终版 · 14本全部 COMPLETE）

| book_id | 状态 | 梯队 | 卡数 | DIGEST中文字 | 结论 |
|---|---|---|---:|---:|---|
| psych_cptsd | **COMPLETE** | P0 | 10 | 10063 | 三重真实底本TIP57公版+PeteWalker官网27篇+PMC8篇OA;10卡,八项自检ALL PASS |
| psych_body_keeps_score | **COMPLETE** | P0 | 5 | 10067 | 5卡+20压测+bundle,八项自检ALL PASS(2026-09-11终检) |
| psych_waking_tiger | **COMPLETE** | P0 | 5 | 10000 | 5卡+20压测+bundle;行号悬空修复后复检ALL PASS |
| psych_why_does_he_do_that | **COMPLETE** | P0 | 5 | 10015 | 5卡+20压测+bundle,lundybancroft官网公开原文回链 |
| psych_feeling_good | **COMPLETE** | P0 | 5 | 10005 | 5卡+20压测+bundle;P0终检ALL PASS |
| psych_hold_me_tight | **COMPLETE** | P0 | 5 | 10006 | 5卡+20压测+bundle;P0终检ALL PASS |
| psych_attached | **COMPLETE** | P1 | 5 | 10184 | 5卡+20压测+bundle;NICE OA论文+attachedbook公开发表回链 |
| psych_seven_principles | **COMPLETE** | P1 | 6 | 10419 | 6卡+20压测+bundle;Gottman官网公开文章15篇回链 |
| psych_boundaries | **COMPLETE** | P1 | 6 | 11995 | 6卡+20压测+bundle;Cloud/Townsend官网公开15篇回链 |
| psych_codependent_no_more | **COMPLETE** | P1 | 6 | 11905 | 6卡+20压测+bundle;MelodyBeattie官网公开15篇回链 |
| psych_nvc | **COMPLETE** | P2 | 6 | 10442 | 6卡+20压测+bundle;CNVC/作者公开文章28篇回链 |
| astro_transit | **COMPLETE** | P3 | 6 | 10028 | 西方星盘独立模块(热带黄道/Tropical Placidus);锁0.36-0.40/false |
| astro_composite | **COMPLETE** | P3 | 6 | 10054 | 西方星盘独立模块(关系盘/Composite);锁0.36-0.40/false |
| vedic_jyotish_core | **COMPLETE** | P3 | 6 | 10358 | 印度星盘独立模块(恒星黄道/Lahiri/D9+27宿);锁0.36-0.40/false |

**14书合计: 14本 COMPLETE ✅ / 82张能力卡 / 0本在制品。**
- 心理学循证层 11 本 = 76 卡（置信带 [0.70,0.90] + is_actionable=true）
- 象征层只读 3 本 = 18 卡（置信带硬锁 [0.36,0.40] + is_actionable=false, 仅作 side_annotation）

## 合规执行
- 未用影子图书馆/盗版;不声称逐字复制在版权原书。
- 公版/CC BY才演绎;ND只短引;许可待核只读。
- 底本逐行编号,R引句程序抽取,TIP57的31引用行全部可回链。
- 纠错留痕: 2张PeteWalker官网原文卡曾被误判伪造(grep仅认5位行号),经source_files/现网200/文末原书出处平反,见 rejected_units.md。
- 西方星盘(astrology-v3-engine/Tropical Placidus)与印度星盘(vedic_jyotish_core/Sidereal Lahiri)双引擎物理隔离,互不嵌套、不做星座翻译。

## P0 终检(2026-09-11 16:30)
- psych_feeling_good / psych_hold_me_tight: COMPLETE ✅ (DIGEST≥1万/六段卡5/压测20/行号全回链/bundle齐)
- Meta-Arbiter v1 已编译; pytest: 22/22 passed; tier_P0_audit.json 已生成

## P1 终检(2026-09-11 P4)
- psych_attached(5卡/10184字) / psych_seven_principles(6卡/10419字) / psych_boundaries(6卡/11995字) / psych_codependent_no_more(6卡/11905字)
- 全部: DIGEST≥1万 / 六段齐全 / R行号全回链 / cap命名 / 置信带[0.70,0.90]+actionable=true / UPIV六维 / 压测20(四类各5) / bundle齐 / COMPLETE
- tier_P1_audit.json: tier_gate=PASS

## P2 终检(2026-09-11 P4)
- psych_nvc(6卡/10442字): 八项质量门全过; tier_P2_audit.json: tier_gate=PASS

## P3 终检(2026-09-11 P4 · 象征层硬锁)
- astro_transit(6卡/10028字) / astro_composite(6卡/10054字) / vedic_jyotish_core(6卡/10358字)
- 象征层硬锁断言全过: 置信带 ∈ [0.36,0.40]、is_actionable=false、is_symbolic_annotation=true
- 三本书绝不进入循证决策流, 仅经 symbolic_profiles 注入 side_annotation
- tier_P3_audit.json: tier_gate=PASS（含 symbolic_hardlock 验证块）

## Meta-Arbiter v2 + MultiModalRouter 编译记录(2026-09-11 P4)
- 模块: `_AUDIT/meta_arbiter/engine.py`（Pydantic v2, 原179行 → v2 扩展）
- **Meta-Arbiter v2.0**: SKILL_REGISTRY 由单 skill 扩展为 {primary, related} 结构, 覆盖 11 本心理学书 76 张循证卡:
  - CRISIS(0)  → crisis_hotline_protocol（硬编码）
  - SAFETY_PLAN(1) → psych_why_does_he + related[psych_boundaries, psych_codependent_no_more]
  - STABILIZE(2)   → psych_cptsd + related[psych_body_keeps_score, psych_waking_tiger]
  - REPAIR(3)      → psych_hold_me_tight + related[psych_attached, psych_seven_principles, psych_nvc, psych_feeling_good]
- **MultiModalRouter v1.0**: 跨书仲裁判例路由, 确定性优先级 CRISIS>SAFETY_PLAN>STABILIZE>REPAIR>SYMBOLIC, 6 条判例固化:
  1. cptsd着陆 vs why_does_he隔离 → 危险因子优先
  2. attached依恋 vs boundaries边界 → 先验安全 > 边界 > 依恋理解
  3. codependent放弃控制 vs nvc同理 → 控制/虐待存在时 detachment 优先
  4. seven_principles维护 vs hold_me_tight修复 → 急性 EFT / 慢性 Gottman
  5. feeling_good认知重构 vs cptsd稳定 → 躯体唤起≥0.65 禁认知, 先着陆
  6. 象征层(astro/vedic)并存 → side_annotation, 绝不影响主决策
- 象征层硬锁保持: SYMBOLIC_CONFIDENCE_LOCK=(0.36,0.40), assert_symbolic_lock() 不变, 四引擎(西方/吠陀/八字/紫微)物理隔离。

## pytest 全量回归(P4 终版)
- 命令: `python3 -m pytest tests/ -v`
- 结果: **140 passed / 0 failed**（test_tier_p0.py 22 用例 + test_tier_all.py 118 用例）
- test_tier_all.py 覆盖: 14书八项质量门参数化(98) + Meta-Arbiter状态机(9) + MultiModalRouter六判例(7) + 象征硬锁(4)
- tier_all_final_audit.json: tier_gate=PASS

## 最终交付物
- `_AUDIT/reports/tier_P0_audit.json` / `tier_P1_audit.json` / `tier_P2_audit.json` / `tier_P3_audit.json` / `tier_all_final_audit.json`
- `_AUDIT/all_books_metrics.json`（82卡总指标）
- `_AUDIT/meta_arbiter/engine.py`（Meta-Arbiter v2 + MultiModalRouter）
- `tests/test_tier_p0.py` + `tests/test_tier_all.py`
- 终版全量包: `心镜_P1-P4全链路_14本终版_20260911.zip`
#（注：内容由AI生成）
