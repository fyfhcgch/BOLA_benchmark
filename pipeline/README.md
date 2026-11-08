# Pilot：最小可运行闭环

> 目标：在 30 分钟内跑通「采集 → API 恢复 → 语义推断 → 重放 → 判定 → 指标」整条链路，
> 验证 `研究方案.md` §2 的技术路线可行，并产出一份可写进论文 §VI-C 的案例。

---

## 1. 快速开始

```bash
cd BOLA_benchmark

# 首次：建虚拟环境（复用系统的 playwright/flask/httpx，只额外装 esprima）
python3 -m venv --system-site-packages .venv
.venv/bin/pip install esprima

# 启动靶场（另开一个终端，或后台运行）
.venv/bin/python systems/mock/app.py

# 跑全流程
.venv/bin/python -m pipeline.run --system mock
```

预期输出：

```
[jsapi] routes=4 ast=6 static=0 captured=6 confirmed=0 static_only=0 unobserved_with_ref=0
[seed] alice /workshop/api/shop/orders/{id} <- 2 个实例
[seed] alice /identity/api/v2/vehicle/{uuid}/location <- 1 个实例
[seed] alice /workshop/api/merchant/service_requests/{vin} <- 1 个实例
[replay] test cases (victims=3)
[VULN] GET    /api/orders/{id}   ids=1002   via=id_swap     leak:amount,note
[VULN] GET    /api/users/{id}/orders ids=1 via=id_swap     leak:amount,note
[VULN] DELETE /api/orders/{id}   ids=1001   via=method_swap side_effect_confirmed(404)
[VULN] PATCH  /api/orders/{id}   ids=1001   via=write_replay side_effect_confirmed

---- 指标（对象实例级） ----
labels=26  tested=26  uncovered=0  (coverage=1.000)
TP=18  FP=0  FN=0  TN=8
Precision=1.000  Recall=1.000  Recall(strict)=1.000  F1=1.000
```

`Recall` 只在被测到的实例上算，`Recall(strict)` 把未覆盖的漏洞标注算作漏报。
两个数一起报，才不会用"没测"换"没漏"。

---

## 2. 目录与职责

```
systems/mock/app.py     靶场：3 用户 / 5 订单 / 读型 BOLA + 写型 BOLA + 安全接口
pipeline/crawl.py       Playwright 采集：UI 登录 -> 遍历路由 -> 抓 XHR + JS bundle（仅同源）
pipeline/seed.py        种子路由：id_sources 解析标识 -> 列表取 id -> 受害者 token 补详情/写模板
pipeline/jsapi.py       esprima AST（失败降级正则）+ 常量表分支，按最长后缀与抓包合并
pipeline/infer.py       参数分类（数值/UUID/hex）+ 从响应自动推断 owner 字段与身份标识
pipeline/ids.py         对象标识抽取 + 路径模板归一化（全链路共用的实例键）
pipeline/replay.py      变异策略：id_swap / id_probe / method_swap / write_replay（含枚举字段翻转），输出 object_ids + scope
pipeline/judge.py       结构化判定：状态码 + 归属证据 + 敏感字段；写型走副作用二次确认
                        （另含 judge_read_similarity，仅用于消融）
pipeline/evaluate.py    实例级指标：TP/FP/FN/TN + coverage + unlabeled + gate violation
pipeline/run.py         编排（--judge / --sim-threshold / --no-write-check / --no-ast
                        / --no-infer-owner / --naive-owner / --no-public-suppression / --tag）
bench/sync_ids.py       刷新部署相关标识（车辆 UUID），全量重置后重跑
bench/ablation_report.py 汇总默认结果与消融结果成 Markdown 表（--csv 写 metrics.csv）
bench/stats.py          §III 的 4 张表 + 标注文件 sha256 指纹（--manifest）
bench/plot_benchmark.py Fig.2 基准构成（矢量 PDF + PNG）
tests/test_bench_labels.py 标注一致性：必填字段、枚举、id 唯一、安全对照归因、public↔public_resource 对应、noref 真无引用
tests/test_judge_write.py  写型判据：DELETE 以"受害者复读 404"确认，405/200/500 分别对应拒绝/无副作用/无法判定
bench/labels/mock.jsonl ground truth（26 条对象实例级标注）
bench/labels/mock.noref.jsonl  无对象引用端点（闸门对照组）
systems/vampi/          Flask 纯 API 靶场：compose + seed + reset（换栈对照）
```

### 判定开关（消融用）

```bash
# 默认：归属证据 + 可见性抑制
python -m pipeline.run --system crapi --skip-crawl

# CN03 风格：字符串相似度（阈值可调）
python -m pipeline.run --system crapi --skip-crawl --judge similarity --sim-threshold 0.9 \
  --tag sim_suppress

# 再关掉公开资源模型
python -m pipeline.run --system crapi --skip-crawl --judge similarity \
  --no-public-suppression --tag sim_nosuppress

# 写型消融：只看 2xx，不做副作用二次确认
python -m pipeline.run --system vampi --no-write-check --tag writecheck_off

# 前端语义消融：只把抓包当端点清单，不读 bundle
python -m pipeline.run --system crapi --skip-crawl --no-ast --tag no_ast

# 自动化消融：人工配置 owner/身份字段
python -m pipeline.run --system mock --no-infer-owner --tag no_owner
# 朴素操作员（不知道数据库内部主键，只知道账号名/邮箱）
python -m pipeline.run --system mock --skip-crawl --no-infer-owner --naive-owner \
  --tag no_owner_naive

# 汇总成表
python bench/ablation_report.py --csv results/processed/metrics.csv
```

`--tag` 把结果写到 `results/raw/<system>/ablation/<tag>/`，不覆盖默认结果。
`--no-ast` / `--no-infer-owner` 只影响端点清单与配置成本，**不影响当轮检出率**；
`--judge similarity` / `--no-write-check` 直接影响 Precision。两组变量不要混着解释，
明细见 `docs/ablation_ast_owner.md`、`docs/ablation_similarity.md`、`docs/ablation_writecheck.md`。

## 3. 本 pilot 已经验证了什么

| 方案中的论断 | pilot 证据 |
|---|---|
| 前端 bundle 能恢复 API（有条件） | mock：1.3 KB 可解析 bundle → 6 个端点 + 4 条路由；crAPI：1.6 MB 压缩 bundle → AST 0 条，但常量表 41 条候选，其中 25 条 UI 从未触发（补齐对象实例前为 29 条） |
| 静态恢复能补"未触发接口" | 按最长后缀合并后，crAPI 得到 43 条端点清单（抓包 18 + 静态独有 25），未触发接口带对象引用 0 条（4 条带引用的已全部进入测试集） |
| owner 关系可从响应反推 | `infer` 自动得出 `owner_keys=['user_id']`，无需人工指定 |
| 双账号重放能发现读型 BOLA | `id_swap` 在两个端点上命中 |
| 字段级判定不会把"自己的数据"误判为泄露 | `id_probe` 会撞到攻击者自己的对象（如 bob 请求自己的订单明细得 200），判定正确输出 `no_owner_evidence` |
| 安全接口不会被误报 | `/api/profile/{id}`、`/api/orders/{id}/items` 均返回 403，全部判定为 TN |
| 写型 BOLA 必须做副作用确认 | `method_swap` 删除后以受害者复读得 404；`write_replay` 用唯一 nonce 在受害者侧复读中确认，6/6 命中 |
| 单机可完成 | 全流程 20 秒内跑完，无 GPU、无外部 API |

## 3.5 已接入的真实靶场

| 靶场 | 状态 | 说明 |
|---|---|---|
| mock | ✅ | 自建，26 条实例标注，TP=18 FP=0，coverage=1.000（含 PATCH 写型） |
| `crapi` | ✅ | OWASP crAPI，真实微服务 + React SPA；TP=18 FP=0，TN=15，coverage=1.000（含读/写公开内容对照） |
| `vampi` | ✅ | VAmPI，Python/Flask 纯 API；TP=6 FP=0，TN=6，coverage=1.000（换栈 + 字符串标识 + login 型副作用） |

```bash
cd systems/crapi && docker compose up -d && cd ../..
python systems/crapi/seed.py
python -m pipeline.run --system crapi

cd systems/vampi && docker compose up -d && cd ../..
python3 systems/vampi/seed.py
python -m pipeline.run --system vampi
```

真实靶场暴露的问题与对策见 [`../docs/pilot_findings.md`](../docs/pilot_findings.md)：
UI 登录、静态提取失效、无对象引用端点的误报闸门、对象实例级标注、字符串标识、
登录失败也返回 200。

## 4. 已知局限（写进 Threats to Validity）

1. **mock 靶场是自建的**，漏洞分布比真实系统密集；结论不能直接外推到生产系统。
2. `method_swap` 只把 GET 换成 DELETE；`write_replay` 支持 POST/PUT/PATCH，但需要系统先提供写模板（crAPI 的 PUT 与 mock 的 PATCH 已各有一条）。
3. `infer` 的 owner 推断依赖响应中出现 owner 字段；对只返回聚合结果的接口会失效。
4. 未实现 source map 还原，也未处理需要多步前置操作的接口（这是 Phase 3 的后续工作）。
5. 指标在 107 条实例标注（mock 50 + crAPI 45 + VAmPI 12）上计算，**不具备统计意义**，仅用于验证链路。
6. 模板化时只保留带 id 语义的查询参数，其余查询参数被丢弃，可能合并不同行为的端点。
7. 常量表分支只补**接口级广度**：未触发接口没有对象实例，仍构造不出测试用例；合并依赖"最长后缀"，遇到不共享后缀的网关前缀会漏配。
8. `public_paths` 是**人工声明的可见性策略**，不是自动推断；未声明的公开资源会被计为 FP（crAPI 社区帖子是现成例子）。
9. 写型重放要求系统先提供一份"受害者自己的写请求模板"（`write_seeds`）；只靠抓包时，UI 没触发过的写接口覆盖不到。
10. 归属证据采用"响应中出现非攻击者身份"近似；对公开可见作者信息的对象可能过度告警（需配合第 8 条的可见性声明）。
11. 枚举字段（`status` 等）要求系统显式声明 `enum_values`，且"翻转"可能被业务状态机拒绝（只允许单向流转时）；这类接口需要"取一个当前状态能到达的下一状态"而不是任意另一个值。
12. `write_seeds` 目前每个系统只有 1–2 条模板，写型覆盖的上限由它决定，而不是由检测能力决定。
13. **纯 API 系统没有前端可爬**：VAmPI 的 capture 完全由 `detail_seeds` / `write_seeds` 生成，
    因此"前端语义驱动"这条贡献在无前端系统上退化为"人工声明的资源与字段语义"——
    泛化到 API-only 服务时，C3 的收益无法直接测量。
14. **自然键标识要人工声明**：VAmPI 的书名/用户名不匹配任何默认的数字/UUID 启发式，
    必须写进 `id_patterns`。这是配置成本，不是自动推断。
15. **登录成功不能用状态码判断**：VAmPI 登录失败也返回 200，只看状态码会把所有密码
    写操作判成"副作用已确认"。已改为检查 token 是否存在，但这类框架差异需要在
    接入新系统时逐个确认。
16. **归属证据只认配置里的账号**：crAPI 内置用户 `test@example.com` / `admin@example.com`
    的订单不在标注、也不在身份集合里，证据判据会漏掉它们（相似度判据反而会命中）。
    正式实验需要把系统自带的种子用户也写进 `accounts`。
17. **L3 只覆盖三类**：28 条覆盖批量读（6）、查询型导出与报表下载（18）、软删除（4），
    **权限继承仍缺**（父对象属主 A、子对象属主 B 的冲突场景，三个靶场都不提供）。
    写"已覆盖 L3"时必须限定到这三类。当前 L1:L2:L3 = 36:43:28。
18. **单人标注，κ 计时中**：`docs/labeling_spec.md` 已冻结，`bench/relabel.py` 与
    17 个用例就绪，计时到期 2026-11-06T11:29:50Z 后出盲标卷重标。
19. **漏洞与安全对照比例失衡**（62:45 ≈ 1.38:1，目标 1:3）：precision 的置信区间偏宽，
    所以所有 precision 数字只作可行性证据。
20. **整系统 clean control 只有 1 个**（MockShop-secure，50 条安全实例，FP-rate 0.000）。
    它与 mock 同代码同数据、只切 `MOCK_POLICY`，所以"零误报"可归因到判据；
    但只有一个系统，不能代表"任意无漏洞系统"。目标 3 个。
21. **相似度基线的口径必须显式**：`--sim-empty-guard` 默认给基线"空壳不算泄露"的优待，
    这等于把结论的一部分送给它。忠实复现 CN03 一类做法要用 `--no-sim-empty-guard`，
    两者指标差异很大（mock P 1.000 → 0.492）。论文里两个数字都要报。
22. **读种子必须校验"响应属于受害者"**（`replay._response_belongs_to_victim`）：抓包语料
    里含靶场本来就允许的跨用户请求（mock 的 bob 能读 alice 的订单 1001）。若照单全收，
    会生成 `DELETE /api/orders/1001`、victim=bob 的用例，而该实例真正的属主是 alice；
    重放时攻击者恰好是 alice，判据把"属主删自己的对象"判成越权。过滤后 mock 丢弃 3 条
    种子（366 用例），`self_read_alerts` 从 2 归零。**代价**：抓包里的跨用户读不再作为
    种子来源，纯 API 系统若一个身份字段都没有，只能退回"全部保留"（无法判断归属）。
23. **推断层会被越权探测污染，必须显式隔离**：`infer_owner_fields` 只从"某个身份字段在
    该响应里基数为 1"的响应认本人身份（`_sole_identity`），且 owner 值只从"响应里出现
    本人身份标识"的响应里收。不隔离时 mock 的 `bob` 会得到 `owner_values=[1,2]`
    （把 alice 的订单也当成自己的），判据随即产生 9 条属主自读告警。列表类响应
    （社区帖子列表一次点名 7 个作者）不能用来认定"我是谁"——这一条对 crAPI 是必需的。
24. **R0 分支在读写两侧各有一份，判据不是纯函数**：读型靠响应里的攻击者身份标识
    （`judge._attacker_is_owner`，强标识且长度 ≥ 5）；写型响应常无正文，只能靠 URL 段与
    推断出的 owner 值比对（`run._owns_path`）。两者都只是"排除退化用例"，不是新的检测能力；
    漏排会污染 `self_read_alerts` 这一披露指标，多排会吞掉真实的越权写。

## 5. 下一步（按优先级）

1. **人工盲标 + 出 κ 数字**：到期后 `bench/relabel.py sheet` → 填 `relabel.jsonl` → `score`
2. **权限继承类 L3 实例**：需自建靶场（父对象属主 A、子对象属主 B）
3. **再补 2 个整系统 clean control**（PetClinic / Django demo）兑现"目标 3 个"
4. 继续接真实靶场：crAPI / VAmPI 已接入，下一个是 RuoYi（国产 Java 后台，验证换生态）
5. 补更多对象的写种子模板（订单、用户资料）+ 批量数组注入
6. 加 `source map` 还原分支
7. 把消融扩展到更多工具族（响应相似度之外，再复现基于状态码 / 基于模式匹配的判据）
