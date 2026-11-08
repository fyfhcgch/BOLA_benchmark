# Pilot 实证发现（可直接写进论文 §VI-C / §IV-D）

> 数据来源：`results/raw/{mock,crapi,vampi}/`
> 复现命令：`python -m pipeline.run --system {mock,crapi,vampi}`
> 消融：`make ablate-all` + `make ablate-report`（5 变体 × 3 系统）
> 日期：2026-11-03

---

## 1. 三个靶场的结果（对象实例级）

| 靶场 | 标注实例 | 测到 | TP | FP | FN | TN | P | R | R(strict) | Coverage |
|---|---|---|---|---|---|---|---|---|---|---|
| MockShop（自建） | 50 | 50 | 32 | 0 | 0 | 18 | 1.000 | 1.000 | 1.000 | 1.000 |
| OWASP crAPI（Java/Go + SPA） | 45 | 45 | 24 | 0 | 0 | 21 | 1.000 | 1.000 | 1.000 | 1.000 |
| VAmPI（Python/Flask，纯 API） | 12 | 12 | 6 | 0 | 0 | 6 | 1.000 | 1.000 | 1.000 | 1.000 |
| **MockShop-secure（整系统 clean 对照）** | 50 | 50 | — | 0 | — | 50 | 不适用 | 不适用 | 不适用 | 1.000 |

> 样本量极小（合计 107 条，另有 50 条 clean 镜像），**不具备统计意义**，
> 仅用于验证链路与暴露设计问题。
> `R(strict)` 把未测到的漏洞标注算作漏报，`Coverage` 是测到的实例占比。
> 两个口径差多少，就是"用没测换没漏"的空间有多大。
>
> clean 对照没有漏洞实例，precision 分母为 0，按约定不报；它的口径是
> **FP-rate = 0.000 (0/50)**。这个 0 否证了一个具体失败模式：早期读型判据只看
> 响应里有没有 `user_id` 这个**键**、不比对**值**；`--owner-key-only` 下 clean 的
> 28 次属主自读里有 **14 次**被判越权（不进 precision 分母，故须单独计数）
> （攻击者读自己的订单也带 `user_id`）。修复后归零，锁进 `tests/test_judge_read.py`。

---

## 2. 发现一：真实 SPA 不接受注入的 token

**现象**：向 localStorage 注入 `token` 后访问 `/dashboard`，仍被重定向到 `/login`。

**原因**：React 应用在挂载时才从登录响应写入 token，静态注入的键值对不被路由守卫认可；且打包产物中没有任何 `localStorage.setItem` 调用（token 由懒加载 chunk 写入）。

**影响**：任何"注入 token 后直接爬"的采集器在真实 SPA 上都会失效，抓到的流量为空。

**处理**：`pipeline/crawl.py` 增加 `ui_login` 分支，走真实表单登录。crAPI 的登录后跳转从 `/login` 变为 `/dashboard`，可作为成功判据。

**论文意义**：现有工作（如 CN02 用 Selenium 动作链）都隐含"能自动登录"这一前提，但**没人报告登录自动化在真实 SPA 上的失败率**。这是"人工成本被低估"的又一佐证。

---

## 3. 发现二：真实 bundle 的静态提取会失效

**现象**：crAPI 的 `main.8c78208c.js`（1.6 MB）在 esprima 下直接报 `Unexpected token ILLEGAL`（ES2015+ 语法）；降级为正则后，**提取到的 API 端点数为 0**。

**原因**：crAPI 的 API 路径不是字符串字面量，而是由常量拼接而成：

```js
http.get(`${this.base}/workshop/api/shop/orders/${id}`)
```

压缩后连 `${...}` 的边界都被抹掉了，正则无从下手。

**对比**：MockShop 的 1.3 KB bundle 能 100% 恢复（6 个端点 + 4 条路由），因为它是按"可解析"的方式写的。

**论文意义（重要）**：这是对 C3 的一个**诚实约束**。前端静态恢复在真实工程产物上并不可靠，必须与抓包融合：

```
recall(纯静态) ≈ 0      （crAPI）
recall(抓包)   = 覆盖用户实际触发到的全部接口
recall(静态+抓包) = 抓包 ∪ 静态，后者主要用于补"未触发但存在"的接口
```

**写作建议**：不要把 C3 说成"完全替代人工"，而应说成"把人工配置从**枚举接口**降级为**补充未触发接口**"。这个降级本身就是可量化的贡献。

> **补充（务必写进论文）**：0 是**提取器的局限**，不是静态方法的上限。
> 事后检查 bundle 发现，crAPI 把接口写成一张常量表（`"api/merchant/service_requests/<vehicleVIN>"`），
> 共 **41 条** `api/...` 字面量。也就是说静态恢复能拿到"路径模板的广度"，
> 但拿不到 HTTP 方法、也拿不到对象实例。

**已实现**（`pipeline/jsapi.py` 的 `_regex_const_table` + `merge_with_capture`）：
把常量表作为独立的第三路来源，按**最长后缀**与抓包端点合并（占位符互相通配），
`<orderId>` 归一成 `{orderId}`，缺服务前缀的路径自动对齐：

```
api/shop/orders/<orderId>   ->   /workshop/api/shop/orders/{id}
```

crAPI 实测：

| 来源 | 数量 | 说明 |
|---|---|---|
| 抓包观测到的方法+模板 | 18 | 用户点到的接口 + 种子路由 + 写型种子（含 1 条 POST） |
| AST 调用点 | 0 | esprima 解析失败，正则也提取不到 |
| 常量表候选 | **41** | 路径广度 |
| 其中与抓包对齐 | 16 | 可确认存在、且拿到 HTTP 方法 |
| **UI 未触发的接口** | **25** | 静态独有的增量 |
| 其中带对象引用 | **0** | 4 条带对象引用的未触发接口已全部进入测试集 |

> 这里的 18 / 25 是补齐对象实例**之后**的数字。补齐前是 14 / 29，其中 4 条带
> 对象引用；4 条现已全部进入测试集（3 条读型 + 1 条写型重放，见 §7.3 / §7.4）。

对照组：MockShop 的 bundle 是调用点写法，`static=0`、`ast=6`、抓包 6 条，
静态没有增量——**静态恢复的收益取决于打包风格**，这正是需要在多靶场上量的东西。

**关键约束**：静态常量表补的是**接口级广度**，不是**实例级覆盖**。
25 条未触发接口里带对象引用的有 0 条（补齐前 29 条里有 4 条，现已全部进入测试集），
且没有对象实例仍然构造不出测试用例；
所以它不能替代种子路由（§7），两者是"先知道有哪些接口，再想办法拿到实例"的关系。

**写法建议**：不要把 C3 说成"完全替代人工"，而应说成"把人工配置从**枚举接口**降级为**补充未触发接口**"。这个降级本身就是可量化的贡献。

---

## 4. 发现三：误报的主要来源是"无对象引用的端点"

这是本次 pilot 最有价值的发现。

**未加闸门时**（crAPI，同一份抓包）：

```
[VULN] GET /identity/api/v2/user/dashboard              leak:email
[VULN] GET /community/api/v2/community/posts/recent     leak:email|email:alice@...
[VULN] GET /workshop/api/shop/orders/all                leak:email
[VULN] GET /workshop/api/mechanic/                      leak:email
→ 4 个误报，FPR = 4/5 = 80%
```

**加闸门后**（只对含对象标识的请求做重放）：

```
[VULN] GET /workshop/api/shop/orders/{id}               leak:amount,email|email:alice@...
→ 0 个误报，FPR = 0
```

**机理**：对一个不含对象标识的端点（`/dashboard`、`/orders/all`），换 token 重放得到的是**攻击者自己的数据**。响应里当然有 `email` 字段，但那是攻击者本人的邮箱，不是受害者的。仅凭"状态码 2xx + 有敏感字段"判定，必然全错。

**闸门规则**（已实现为 `pipeline/ids.py:has_object_ref()`，`replay` 复用）：

```
请求的 URL 中必须存在
  (a) 一个形如纯数字或 UUID 的路径段，或
  (b) 一个名字匹配 id|uid|uuid|no|code|sn 的查询参数
否则该请求不构成 BOLA 测试用例
```

另外，`bench/labels/<system>.noref.jsonl` 把这些端点登记为对照组：
如果闸门失效、对它们出了告警，`evaluate.py` 会记为 **gate violation**，
单独计数而不混进 FP——这样"闸门本身修好了没有"是可回归的。

**论文意义**：这可以直接写成一个失败模式（F11：**无对象引用端点被误纳入测试**），并给出定量证据——在 crAPI 上，**80% 的误报由这一条规则消除**。这条发现比"我们的方法 F1 更高"更有说服力，因为它解释的是**机理**而不是分数。

---

## 5. 发现四：BOLA 是"对象实例级"属性，不是"端点级"属性（已修复）

同一个端点 `/workshop/api/shop/orders/{id}`：

| 被访问的对象 | 归属 | 攻击者 | 结果 | 判定 |
|---|---|---|---|---|
| order 6, 7 | alice | bob / carol | 200 + alice 的 email | ✅ VULN |
| order 8 | bob | carol | 200 + bob 的 email | ✅ VULN |
| order 8 | bob | bob（本人） | 200 + bob 的 email | ⬜ 不是 BOLA 测试 |
| order 17 | 不存在 | bob | 500 | ❌ 不报 |

**这意味着端点级标注不充分**。同一端点在不同对象上可以既"有漏洞"又"没漏洞"，
按 `(method, path)` 做键会把上述四种情况压成同一个格子。

**已做的改动**（2026-11-03）：

| 位置 | 改动 |
|---|---|
| `bench/schema.json` | 标注单位改为 `(method, path_template, object_ids)`，新增 `victim` / `scope` |
| `bench/labels/*.jsonl` | mock 26 条、crAPI 33 条，全部是对象实例（数量随补实例增长） |
| `bench/labels/*.noref.jsonl` | 新增：无对象引用端点，单独作为闸门对照组 |
| `pipeline/ids.py` | 新增：`template()` / `object_ids()` / `case_key()`，各层共用同一个键 |
| `pipeline/evaluate.py` | 新增：实例级匹配 + coverage + unlabeled + gate violation |
| `pipeline/replay.py` | `TestCase` 带 `object_ids` 与 `scope`（same/cross tenant） |

**指标口径随之改变**（详见 §1）：`Recall` 与 `Recall(strict)` 必须同时报，
否则"没测到"会被当成"没漏报"。补种子之前 crAPI 的 `1.000 / 0.500` 就是现成的反例（见 §6）。

**写作建议**：在 §III-C（Oracle 设计）里明确写出这一点，并对比现有工作按端点
报告指标的做法——**它们的分母定义本身就掩盖了对象实例差异**。

### 5.1 发现四的副产品：归属证据不能只锚定一个受害者（F12）

改成实例级后，crAPI 上冒出一个新漏报：

```
[missed] GET /workshop/api/shop/orders/{id}  ids=8
```

订单 8 属于 bob，carol 读它是越权。但原判据只拿"配置里的 victim（alice）"
的身份去比对响应，而响应里是 `bob@example.com`，于是判 `no_owner_evidence`。

**修正**：归属证据改为"响应里出现了**不属于攻击者**的身份标识"，
即对每个攻击者构造 `others = 全部账号身份 − 攻击者本人身份`。
修正后 ids=8 被正确检出（`leak:email:bob@exampl`），TP 由 2 升到 3、FN 归零。

**论文意义**：这是失败模式 **F12（归属证据只锚定单一受害者）**。它只在
"对象属于第三方账号"时暴露，端点级标注下永远看不到——因为端点级标注默认
"被攻击的对象就是 victim 的"。**这正是实例级标注才能抓出来的问题**，
可以作为"为什么必须按实例标注"的第二条论据（第一条是 F11）。

---

## 6. 发现五：写型探测容易被方法不允许掩盖

crAPI 的 `DELETE /workshop/api/shop/orders/{id}` 返回 **405 Method Not Allowed**，而不是 403/404。

如果判定逻辑只看"是否 2xx"，会得到"未检出"；如果只看"是否非 2xx"就下结论"安全"，则会漏掉那些"支持 DELETE 但不校验归属"的系统。

**处理**：`judge_write()` 把 `pre / write / post` 三个状态分开记录，405 归入 `write_rejected`，并在结果里保留原始状态码，便于后续做失败模式归类。

---

## 7. 发现六：UI 爬虫只能覆盖"被点到的对象"（已修复）

**现象**：crAPI 的 UI 只把订单 7 的详情页点开过，订单 6/8/9/10/11 的实例
从未进入测试集。此时 15 条标注只测到 4 条，`Coverage=0.333`，
`Recall=1.000` 但 `Recall(strict)=0.500`。

**机理**：UI 爬虫的覆盖率取决于"人点了什么"，而不是"系统里有什么对象"。
一个详情接口只要有 N 个实例，UI 通常只暴露其中 1–2 个。

**修复**（`pipeline/seed.py` + 账户轮换）：

| 机制 | 做法 |
|---|---|
| `detail_seeds` | 声明"从哪个列表接口取 id、拼到哪个详情模板"（如 `orders[].id` → `/orders/{id}`），用**受害者自己的 token** 把全部实例取一遍 |
| `victims` 轮换 | alice / bob / carol 轮流当受害者，攻击者是其余账号；否则 bob/carol 的对象永远没有基线 |
| `seed_routes_by_account` | mock 上每个账号从自己的订单进入，而不是都用 `?id=1002` |
| `probe_deltas` | 默认 ±2/−1/+1…+5/+10，覆盖相邻 id |

**效果**：

| 靶场 | 修复前 Coverage | 修复后 Coverage | TP |
|---|---|---|---|
| crAPI | 0.333 | **1.000** | 3 → 9 |
| mock | 0.571 | **0.952** → 1.000 | 7 → 12 → 18 |

> 当时剩余 1 条未覆盖（mock 订单 1004 的 DELETE），原因是 bob 只从 1003 进入。
> 给 bob 补一条 `?id=1004` 的种子路由后覆盖率到 1.000——**覆盖率缺口大多不是
> 判定问题，而是基线采集问题**，所以必须把 coverage 和 recall 一起报。

**论文意义**：这是对 C3 定位最诚实的一次校准。前端恢复的增量**不是**
"自动发现接口"（crAPI 上静态提取为 0），而是：

```
从列表响应中恢复"对象实例"  +  多账号轮换把每个实例都测一遍
→ 覆盖率从 0.33 提到 1.00
```

覆盖率恰恰是现有工作不报的指标，因此这个提升是可量化、可复现的。

### 7.1 反面教材：不能把"匿名可读"当成"公开资源"

补种子时试过一个看起来很美的规则：先用无 token 请求探一次，能读就判定为
"公开对象，不算越权"。它在 crAPI 上**会直接错杀掉最核心的漏洞**：

```
GET /workshop/api/shop/orders/7   （无 Authorization）→ 200，返回 alice 的订单
```

crAPI 的订单详情不仅不校验归属，连认证都没挂。若按"匿名可读 = 公开"处理，
订单 BOLA 会被整类漏掉。结论：**可见性不能靠匿名探测推断**，必须由标注或
业务语义给出；判定层只应回答"非属主能否拿到他人数据"。这条已写进
Threats to Validity。

### 7.2 非数字标识：VIN 让整个端点被闸门漏掉（F2 的实证）

crAPI 有一个按 VIN 查询维修请求的接口：

```
GET /workshop/api/merchant/service_requests/7PV1ZVZRYXAM20962
```

VIN 是 17 位大写字母数字，既不是纯数字也不是 UUID。原来的
`has_object_ref()` 只认这两种形态，于是**整个端点被当作"无对象引用"排除**，
一条都没测——这正是失败模式 F2（非数字标识无法枚举）在自家流水线里的翻版。

**修复**：把标识形态做成配置，而不是写死：

```python
"id_patterns": [("vin", r"^[A-HJ-NPR-Z0-9]{17}$")]
```

`ids.template()` 会把它归一化成 `/service_requests/{vin}`，标注、重放、
指标匹配全链路自动对齐。补上后三个账号的服务请求实例全部检出，
TP 由 9 升到 12。

**论文意义**：F2 的解法不是"更强的枚举"，而是"先识别标识形态"。
枚举（id_probe）只对自增数字有效；UUID / VIN / NanoID 这类标识靠枚举是
不可行的，必须从列表接口或响应里回收。这也解释了为什么现有工具在
UUID 类对象上召回普遍偏低。

同一接口**匿名也能读**（无 `Authorization` 返回 200），再次印证 §7.1：
"能不能匿名读"不能用来判断资源是否公开。

### 7.3 从"静态广度"走到"实例可测"：3 条未触发接口真正被测到

§3 的常量表只给出路径，不能生成测试用例。把 4 条带对象引用的未触发接口
逐个补实例，结果如下：

| 未触发接口 | 实例来源 | 补实例后 | 结论 |
|---|---|---|---|
| `mechanic/service_request/{serviceId}` | 按 VIN 查 `merchant/service_requests/{vin}`，取 `service_requests[].id` | 3 个实例（每账号 1 条） | **真 BOLA**：任意登录用户可读他人维修请求，响应含车主 email/number |
| `mechanic/service_request/{serviceId}/comment` | 同上（评论挂在 service request 上） | 3 个实例 | 跨用户可读，但评论列表恒为空（普通用户写评论返回 500）→ 按"数据暴露"口径记安全 |
| `community/posts/{postId}` | `posts/recent` 过滤 `author.email == 本账号` | 3 个实例 | 公开内容 → 需要可见性模型，见下 |
| `community/posts/{postId}/comment` | 同上 | 3 个实例 | 只有 POST（GET 405）→ 用写型重放覆盖，见 §7.4 |

**机制改动**（都落在配置里，不改判定代码）：

```python
"id_sources": {                      # from 模板要用的受试者标识
  "vin":  {"from": ".../vehicles", "ids_path": "[].vin"},
  "uuid": {"from": ".../vehicles", "ids_path": "[].uuid"},
},
"detail_seeds": [
  {"path": ".../mechanic/service_request/{serviceId}",
   "from": ".../merchant/service_requests/{vin}",   # from 用 vin 填
   "ids_path": "service_requests[].id"},
  {"path": ".../community/posts/{postId}",
   "from": ".../community/posts/recent",
   "ids_path": "posts[].id",
   "where": {"list": "posts", "field": "author.email", "value": "{email}"}},  # 只要自己的
],
```

**公开内容的处理**：社区帖子对所有登录用户可见，读到作者 `email` 是设计行为。
如果不声明可见性，3 个帖子会被判成 6 次误报（每个帖子 2 个攻击者）。
这里把可见性作为**策略输入**写进配置：

```python
"public_paths": ["/community/api/v2/community/posts/{postId}"],
```

命中后判定层输出 `public_resource` 而不是 VULN。论文里要强调：可见性
**不能**从"匿名能否读"推断（§7.1），只能由业务策略或标注给出。

**指标变化**：

| 指标 | 补实例前 | 补实例后 |
|---|---|---|
| crAPI 标注实例 | 18 | **27** |
| TP | 12 | **15** |
| TN | 6 | **12** |
| Coverage | 1.000 | 1.000 |
| FP | 0 | 0 |

新增的 9 条标注里，3 条是真漏洞（维修请求），6 条是两类安全对照
（公开内容、空评论的横向可读）。**安全对照组从 1 类变成 3 类**：
订单归属校验、公开资源可见性、无数据泄露的授权缺陷。

### 7.4 写型重放：副作用确认为真，但"能写"不等于"越权"

读型重放只能覆盖 GET。crAPI 的最后一条未触发接口
`POST /community/api/v2/community/posts/{postId}/comment` 只有 POST（GET 405），
必须补写型重放。

**做法**不走"猜请求体"，而是复用受害者自己的写请求作为模板：

1. 种子阶段用**受害者自己的 token** 在自己的帖子上写一条评论，把请求体模板
   （`{"content": "BOLA-PROBE-{nonce}"}`）和复读地址记进 capture；
2. 重放阶段换成攻击者身份，`{nonce}` 渲染成每次唯一的标记；
3. 写完后以**受害者身份**复读帖子详情，看标记是否出现 —— 这才是副作用证据，
   而不是只看 POST 返回 200。

crAPI 实测：

```
[writereplay] 6 cases, side_effect=6      # 此时只有 POST 评论；补 PUT 后总数见 §7.5
```

6 条写请求全部产生了真实副作用（攻击者的评论出现在受害者帖子里）。
**但它们不是越权**：社区帖子是公开内容，任何登录用户都可以评论。因此
`public_paths` 把该端点声明为公开，判定输出 `public_resource`，6 条全部记为 TN。

**论文意义**（这是写型 BOLA 最容易出错的地方）：

| 只看什么 | 会得出什么 | 问题 |
|---|---|---|
| POST 返回 200 | "写成功 → 越权" | 把公开评论、点赞、下单全判成漏洞 |
| 只看状态码 403 | "安全" | 漏掉服务端不校验归属却仍返回 200 的写接口 |
| **副作用 + 授权策略** | 正确 | 先确认"确实写进了别人的对象"，再问"这个写操作本来允不允许" |

`return_order` 是另一类现成对照：`POST /workshop/api/shop/orders/return_order?order_id=8`
用 alice 的 token 退 bob 的订单，服务端返回 **403**。写型重放要能同时覆盖
"允许的写"（公开评论）和"被正确拒绝的写"（退货）两种安全形态。

### 7.5 PUT/PATCH：方法要从前端读，不能靠猜；枚举字段要换判据

补 `PUT` / `PATCH` 时先要回答一个问题：**怎么知道该用哪个方法？**

`method_swap` 的做法是拿 GET 的 URL 换成 DELETE，猜错了就什么都测不到。crAPI 的
`/workshop/api/mechanic/service_request/{serviceId}` 恰好是反例：

```
DELETE 该路径 -> 405 Method Not Allowed        # 猜的方法不存在
PUT    该路径 -> 200 + status 被改            # 真正的方法
```

方法不是猜出来的，是**从前端读出来的**。bundle 里有两个字面量：

```js
CHANGE_VIDEO_NAME:            "api/v2/user/videos/<videoId>"
UPDATE_SERVICE_REQUEST_STATUS: "api/mechanic/service_request/<serviceId>"
...
fetch(e, {method:"PUT", body: JSON.stringify({status:r})})
```

这正好落在 C3 的论点上：前端语义（路径模板 + 方法 + 请求体字段）比"变方法枚举"
更可靠。本节的 PUT 用例就是从 `method:"PUT"` 这条调用点恢复出来的。

#### 判据：枚举字段不能塞 nonce

先确认漏洞是真的：alice 改 bob 的维修请求 7：

```
GET  /workshop/api/mechanic/service_request/7   (bob)   status=completed
PUT  /workshop/api/mechanic/service_request/7   (alice) {"status":"pending"} -> 200
GET  /workshop/api/mechanic/service_request/7   (bob)   status=pending      # 真的改了
```

但 `status` 是枚举，写 `BOLA-PROBE-xxx` 会被服务端拒绝：

```
{"status":["\"BOLA-PROBE\" is not a valid choice."]}   400
```

所以 §7.4 的 nonce 判据在这里失效。改成**翻转 + 复读比对**：

1. 受害者先读当前值 A；
2. 攻击者写另一个合法值 B（`enum_values` 里与 A 不同的那个）；
3. 受害者再读，得到 B 且 B ≠ A → 副作用成立；
4. 受害者把值写回 A，保证复跑口径一致。

配置只多三个字段，判定代码不需要分支到具体业务：

```python
{"method": "PUT",
 "path":   "/workshop/api/mechanic/service_request/{serviceId}",
 "from":   "/workshop/api/merchant/service_requests/{vin}",
 "ids_path": "service_requests[].id",
 "json":   {"status": "{enum}"},
 "verify": "/workshop/api/mechanic/service_request/{serviceId}",
 "enum_field": "status",
 "enum_values": ["pending", "completed"]}
```

`[writereplay] 12 cases, side_effect=12`，其中 6 条 PUT 全部命中
`enum_flip:pending->completed`。

#### PATCH：在 mock 上补一条最小的端到端验证

crAPI 没有 PATCH 接口，所以给自建靶场加了一条 `PATCH /api/orders/{id}`
（不校验归属，改订单备注）。nonce 判据直接可用：

```
[seed] alice PATCH /api/orders/{id} <- 2 个实例     # 1001/1002，bob/carol 同理
[writereplay] 10 cases, side_effect=10
[VULN] PATCH /api/orders/{id} ids=1001 via=write_replay side_effect_confirmed
```

这样 POST（公开评论，TN）、PUT（枚举翻转，TP）、PATCH（nonce，TP）三种写型
都有真实用例，而不是只写在文档里。

#### 指标变化

| 指标 | 补 PUT/PATCH 前 | 补后（crAPI） | 补后（mock） |
|---|---|---|---|
| 标注实例 | 30 | **33** | **26** |
| TP | 15 | **18** | **18** |
| TN | 15 | 15 | 8 |
| Coverage | 1.000 | **1.000** | **1.000** |

#### 写作要点

1. **方法是前端语义的一部分**。只按"GET→DELETE"猜方法，会漏掉 PUT/PATCH 型的
   写越权；crAPI 的 DELETE 返回 405，但 PUT 是实打实的漏洞。
2. **写型判据必须和字段类型匹配**。自由文本用唯一 nonce，枚举用翻转比对，
   计数/金额用前后差值；没有一种标记能通吃。
3. **200 不是证据**。PUT 返回 200 只说明请求被接受，必须由受害者在**自己的视角**
   复读确认字段真的变了。
4. **前端位置不等于授权策略**。该接口在 UI 上只出现在 mechanic 面板，容易被误认为
   "只有 mechanic 能调"；服务端既不校验角色也不校验归属。

---

## 8. 发现七：换栈之后，"对象标识的形态假设"才是真瓶颈

把同一套 pipeline 原样套到 VAmPI（Python/Flask + SQLite，纯 API、无前端）上，
只改 `pipeline/config.py`，不改判定与指标代码。结果正常（12 条标注，
TP=6 / FP=0 / TN=6 / coverage=1.000），但过程中暴露出一个比"换语言"更本质的问题。

| 维度 | crAPI | VAmPI |
|---|---|---|
| 栈 | Java/Go 微服务 + React SPA | Python/Flask + SQLite |
| 采集 | Playwright 爬包（108 条） | 无前端，`crawl: False`，capture 仅 4 条种子记录 |
| 对象标识 | 自增 id / UUID / VIN / NanoID | **自然键**：书名、用户名 |
| 侧信道 | 列表接口给 id | 列表接口给书名，但**详情才给 secret** |

### 8.1 不加声明时，带对象引用的接口直接"消失"

首次运行，capture 里有 12 条记录（4 个模板 × 3 个受害者），但：

```
[jsapi] routes=0 ast=0 static=0 captured=12 confirmed=0 static_only=0 unobserved_with_ref=0
[replay] 0 test cases (victims=3)
labels=12  tested=0  uncovered=12  (coverage=0.000)
TP=0  FP=0  FN=0  TN=0
```

一个测试用例都没生成，6 条漏洞实例全部落在 `uncovered` 里。更危险的是
朴素指标此时显示 `FP=0 FN=0`——**"什么都没测"看起来和"什么都没漏"一模一样**。
这正是第 1 节要坚持同时报 `Recall(strict)` 与 `Coverage` 的原因。

原因：`ids.py` 的默认启发式只把**纯数字 / UUID / hex** 路径段当对象标识。
`alice1-notebook` 和 `alice1` 都不匹配，于是 `/books/v1/{title}` 在模板化时
被压成常量路径，`has_object_ref` 判为 false，整个端点进不了测试集。

加上两条声明后（不改代码）：

```python
"id_patterns": [
    ("bookTitle", r"^[a-z0-9]+-notebook$"),
    ("username",  r"^[a-z]{3,}[0-9]{1,3}$"),
]
```

`infer` 立刻恢复出 `owner_keys=['owner'] identity=['username','email']`，
`replay` 生成 36 条用例，与 crAPI 的链路完全一致。

**这是 F14（标识形态假设过窄）的实证**：它不是"枚举不到 id"（F2），
而是"id 明明在路径里，检测器不认为它是 id"。对 API-only 系统和大量使用
slug / 用户名 / 书名的业务（博客、论坛、电商详情页），这一类漏报是系统性的。

### 8.2 登录失败也返回 200：状态码不能当认证判据

`POST /users/v1/login` 密码错误时返回 **200**，body 是
`{"status":"fail","message":"Password is not correct..."}`。

如果按状态码判断"登录成功"，写型副作用确认会把**每一次**改密码都判成成功——
包括那些根本没生效的。处理：`login()` 取 `auth_token` 字段；写型确认用
`_login_ok()` 检查 token 是否存在，而不是 `status_code < 300`。

**论文意义**：跨栈评测里，"认证成功"的定义本身就不统一（有的用 200，有的用
token 字段，有的用 cookie）。统一评测必须先统一这个语义，否则工具间的差异
有一部分只是框架差异。

### 8.3 路径里有 username ≠ 真的按对象授权：一条现成的安全对照

| 接口 | 行为 | 判定 |
|---|---|---|
| `PUT /users/v1/{username}/password` | 路径 username 决定目标，不校验归属 | **VULN**（6/6） |
| `PUT /users/v1/{username}/email` | **忽略**路径 username，只改调用者自己 | 安全（6/6 TN） |

两条接口的路径形态完全相同，只差最后一段。任何"路径里出现对象标识就报越权"的
启发式都会在 email 上误报。这一组对照是基准里最便宜、也最有说服力的 FP 测试：
它的存在说明 **BOLA 判据必须落到"受害者的状态是否真的变了"，而不是"URL 里有没有别人的 id"**。

同理，`GET /users/v1/{username}` 被判为公开资源（列表接口本来就返回 email），
由 `public_paths` 声明可见性；不声明就会计 6 条 FP。

### 8.4 密码类写操作：副作用 = 受害者能用新密码登录

密码塞不进 nonce（写进去的是哈希后的凭据），也没有可复读的明文字段。判据改成：

1. 攻击者 `PUT` 受害者新密码 → 拿到 204；
2. 用受害者用户名 + **新密码**调登录，`auth_token` 存在 → 副作用确认；
3. 立刻用受害者原密码改回，并再次登录验证还原成功。

```
[VULN] PUT /users/v1/{username}/password ids=alice1 via=write_replay login_with_new_password_ok
[writereplay] 12 cases, side_effect=6
```

这是 F13 的第三种字段类型（自由文本 / 枚举 / **凭据**），三种判据不能互换。

### 8.5 写测试必须清理，否则会污染下一次运行

最初没有还原邮箱，结果攻击者自己的 email 被改成 `bola-BOLA-xxx@example.com`，
下一轮"受害者身份证据"和配置里的账号对不上，`public_resource` 抑制从 6 条掉到 4 条，
指标看起来"变了"，其实是测试自己把环境改了。

处理分两层：种子里 `restore`（写完立刻还原）、重放里 `restore_body` / `restore_as`
（测完用攻击者或受害者凭据还原）。连跑 3 次，账号密码与邮箱均回到初始值，指标稳定。

**写作要点**：写型 BOLA 的测评天然是**破坏性**的。现有工作很少报告"测试后如何恢复"，
但这直接决定了结果能否复现——这是基准设计里必须写清楚的一条工程约束。

### 8.6 指标

```
labels=12  tested=12  uncovered=0  (coverage=1.000)
TP=6  FP=0  FN=0  TN=6
Precision=1.000  Recall=1.000  Recall(strict)=1.000  F1=1.000
```

6 条 TP = 3 个账号各 1 条读型（书 secret）+ 1 条写型（改密码）；
6 条 TN = 3 条 email 安全对照 + 3 条公开资料页。连跑 3 次一致。

只改一条配置（是否声明 `id_patterns`）的对照：

| 配置 | tested | TP | FP | Coverage | Recall(strict) |
|---|---|---|---|---|---|
| 默认标识规则 | 0 | 0 | 0 | 0.000 | 0.000 |
| + `id_patterns` | 12 | 6 | 0 | 1.000 | 1.000 |

漏报 6 条全部来自 F14，而误报率在两种配置下都是 0——**只看 FP 完全看不出问题**。

---

## 9. 消融：字符串相似度判据的误报（复现 CN03）

把读型判据换成"攻击者响应 vs 属主响应"的字符串相似度（`difflib`，阈值 0.90），
写型仍用副作用确认，其余不变。完整数据与复现命令见
[`ablation_similarity.md`](ablation_similarity.md)。

| 系统 | 判据 | 可见性 | 空壳优待 | TP | FP | TN | P | R | F1 |
|---|---|---|---|---|---|---|---|---|---|
| mock | 归属证据 | on | — | 32 | 0 | 18 | 1.000 | 1.000 | 1.000 |
| mock | 相似度 | on | 给 | 32 | 0 | 18 | 1.000 | 1.000 | 1.000 |
| mock | 相似度 | on | **不给** | 32 | **33** | 17 | **0.492** | 1.000 | **0.660** |
| crAPI | 归属证据 | on | — | 24 | 0 | 21 | 1.000 | 1.000 | 1.000 |
| crAPI | 相似度 | on | 给 | 24 | **10** | 21 | **0.706** | 1.000 | **0.828** |
| crAPI | 相似度 | on | **不给** | 24 | **19** | 18 | **0.558** | 1.000 | **0.716** |
| crAPI | 相似度 | off | 给 | 24 | **16** | 15 | **0.600** | 1.000 | **0.750** |
| VAmPI | 归属证据 | on | — | 6 | 0 | 6 | 1.000 | 1.000 | 1.000 |
| VAmPI | 相似度 | on | 给 | 6 | 0 | 6 | 1.000 | 1.000 | 1.000 |
| VAmPI | 相似度 | off | 给 | 6 | **3** | 3 | **0.667** | 1.000 | **0.800** |

五条结论：

1. **相似度判据没有身份概念**（`self_read_alerts` 在 mock 上是 **14/28**，归属证据为 0/28）。
   攻击者恰好是属主时两个响应逐字节相同，相似度 1.000，必然判越权。这类用例不进
   precision 分母（不是 BOLA 测试），所以**默认报表里看不见**——这正是要单独计数的原因。
   它是判据形式的缺陷，不是阈值问题：给再多可见性声明也救不回来。
2. **相似度不掉 Recall，只掉 Precision**。所有 TP 的响应本来就和属主一致，
   该命中的都命中了；代价全在 FP。
3. **不是阈值问题**。0.80 / 0.90 / 0.99 三个阈值在 crAPI 上结果完全相同
   （P=0.706、FP=10）。
4. **三类结构性误报无法靠调参解决**：
   - **空容器**：`/mechanic/service_request/{id}/comment` 对谁都返回
     `{"comments":[]}`，mock 的 `/api/users/{id}/orders` 对无订单 uid 返回 `[]`；
     相似度 1.000。**"不给优待"时 mock 的 33 条 FP 里有 30 条来自后者。**
   - **公开资源**：社区帖子对谁都一样，越像越可疑；关掉可见性模型后 crAPI +6 条 FP。
   - **未标注第三方对象**：crAPI 残留的 10 条 FP 全落在内置用户 test/admin 的
     订单与维修请求上（真 BOLA 但未标注，按约定计 FP）。
5. **消融必须对基线忠实**：我们最初让相似度基线也享受"空壳不算泄露"这条规则，
   它在 mock 上零误报——但那是因为我们把结论的一部分预先送给了它。
   加上"不给优待"这一档后 mock 的 FP 从 0 跳到 33。**只报对自己有利的那一档，
   那不是消融，是演示。**

反过来，归属证据判据把 `{"comments":[]}` 当空壳（`no_owner_evidence`），
把公开帖子交给 `public_paths`，所以 FP=0。这组对照直接支撑 C3 的设计选择：

> **判定要问"这是谁的数据"，而不是"这看起来像不像"。**

另外，mock 上相似度零误报——只在单一靶场上评测，会得出"相似度够用"的错误结论，
这是 C1（多系统基准）必要性的直接证据。

---

## 10. 消融：去掉写型副作用确认（−WriteCheck）

把写型判据退化为"攻击者请求返回 2xx = 越权"，取消受害者复读、nonce 比对、
枚举翻转和新密码登录验证（清理逻辑保留）。完整数据见
[`ablation_writecheck.md`](ablation_writecheck.md)。

| 系统 | 写型校验 | TP | FP | TN | P | R | F1 |
|---|---|---|---|---|---|---|---|
| mock | on | 32 | 0 | 18 | 1.000 | 1.000 | 1.000 |
| mock | **off** | 32 | 0 | 18 | 1.000 | 1.000 | 1.000 |
| crAPI | on | 24 | 0 | 21 | 1.000 | 1.000 | 1.000 |
| crAPI | **off** | 24 | 0 | 21 | 1.000 | 1.000 | 1.000 |
| VAmPI | on | 6 | 0 | 6 | 1.000 | 1.000 | 1.000 |
| VAmPI | **off** | 6 | **3** | 3 | **0.667** | 1.000 | **0.800** |

3 条 FP 全部来自 `PUT /users/v1/{username}/email`：

```
/users/v1/{u}/email     → 204，但受害者邮箱不变（服务端忽略路径 username，只改调用者）
/users/v1/{u}/password  → 204，受害者密码真的被改（可用新密码登录）
```

**路径形态相同、状态码相同，唯一区别是受害者的状态有没有变。** 去掉副作用确认后，
这两个接口再也无法区分；crAPI 的安全写对照要么返回 405（DELETE），要么是公开资源
（评论），状态码判据"碰巧"没出错——只在 crAPI 上评测会得出"副作用确认没必要"的
错误结论。

---

## 11. 消融：−AST 与 −Owner（工程效率变量）

前两节（§9 −Semantic、§10 −WriteCheck）去掉的是**判据**，直接影响 Precision。
本节两个变体去掉的是**工程能力**，结论完全不同：指标不变，代价落在广度与人力上。
完整数据见 [`ablation_ast_owner.md`](ablation_ast_owner.md)。

| 变体 | mock P/R/F1 | crAPI P/R/F1 | VAmPI P/R/F1 | 端点清单 | 人工配置比 |
|---|---|---|---|---|---|
| Full | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 13 / 43 / 5 | 0 / 0 / 0 |
| −AST | 不变 | 不变 | 不变 | 12 / **20** / 5 | 0 / 0 / 0 |
| −Owner（知情） | **0.938** | 不变 | 不变 | 不变 | 0.462 / 0.186 / 0.800 |
| −Owner（朴素） | **0.812** / **0.897** | — | — | 不变 | 0.462 / — / — |

### 11.1 −AST：丢的不是检出率，是"待办清单"

去掉 AST/常量表后，crAPI 端点清单 43 → 20（−53%），**未触发端点 23 → 0**，但
TP/FP/FN 一个都没变。原因是那 23 条未触发端点没有对象实例，本来就构造不出用例：

```
ANY /api/v2/vehicle/add_vehicle
ANY /api/mechanic/download_report
ANY /api/shop/orders/return_order
...
```

它们的价值在**下一轮**——补上对象实例后才能被测。而补实例用的 `detail_seeds`
模板（`/workshop/api/shop/orders/{id}`）本来就是人工抄写的，所以 −AST 的真实
代价是"要把模板再抄一遍"，不是"直接漏测"。

> 写作口径：−AST 影响**接口级广度与人工成本**，不影响当轮检出率。
> 声称"AST 提升 F1"在本基准上不成立。

### 11.2 −Owner：人工配置的风险是"更容易错"，不是"更贵"

自动推断做的关键一件事是从响应里看出 `user_id` 是 owner 字段、且 alice 的
`user_id` 是 1。

- **知情配置**（操作员知道内部主键）把这件事抄对 → 指标完全等价，代价是
  crAPI 手写 8 条、VAmPI 手写 4 条（后者 100%）。
- **朴素配置**（只知道账号名与邮箱）在 mock 上立刻掉 3 条：

```
FN: GET /api/orders/{id}         [1003]   bob 的订单，被 alice/carol 读
FN: GET /api/orders/{id}         [1004]   bob 的订单
FN: GET /api/users/{id}/orders   [2]      bob 的用户 id
```

mock 的订单详情只有 `user_id`（数字）与 `username`，没有 email。人工身份集合里
没有 `user_id=2 → bob` 这条映射，判定层输出 `no_owner_evidence`，3 条真漏洞变 FN。

**这是 −Owner 的真实风险：配置错一处就漏一类对象。** 自动推断把 owner 字段名与
取值都从数据里对齐，人工配置则依赖操作员是否知道"响应里那个 `user_id` 对应谁"。

### 11.3 与 §9/§10 的对照（写进 §VI-C 开头）

| 变体 | 影响的量 | 数值 |
|---|---|---|
| −Semantic（给空壳优待） | Precision | crAPI 1.000 → **0.706**（FP 10） |
| −Semantic（忠实复现） | Precision | crAPI → **0.558**（FP 19）；mock → **0.492**（FP 33） |
| −WriteCheck | Precision | VAmPI 1.000 → 0.667（FP 3） |
| −AST | 端点广度 | crAPI 43 → 20（未触发 23 → 0） |
| −Owner（知情） | 人工成本 + Recall | 需手配 0.462 / 0.186 / 0.800 的端点；mock R → 0.938（FN 2） |
| −Owner（朴素） | Recall | mock 1.000 → 0.812（FN 6） |

**前两个是"判定正确性"变量，后三个是"工程效率"变量**（朴素配置额外伤到
Recall，属于配置错误的连带后果）。论文里不能把这五者混成一组"消融"讲。

---

## 12. 待补

- [x] 扩大 crAPI 覆盖率（0.333 → 1.000）：`detail_seeds` + 账户轮换
- [x] 常量表分支：crAPI 41 条候选，补出 25 个 UI 未触发的接口（补齐对象实例后从 29 降到 25）
- [x] 对 4 条"带对象引用但未触发"的接口补对象实例：3 条读型 + 1 条写型重放，全部进入测试集
- [x] 覆盖 `community/posts/{postId}/comment`：写型重放 + 公开可见性判定
- [x] 补对象类型：`service_requests/{VIN}`、`mechanic/service_request/{id}`、`posts/{postId}`、`posts/{postId}/comment`
- [x] 标注粒度升级到 `(method, path, object_ids)`
- [x] 指标层区分 `coverage` / `recall_strict` / `unlabeled` / `gate_violation`
- [x] 为 `PUT` / `PATCH` 补写种子模板：crAPI PUT（枚举翻转）+ mock PATCH（nonce）
- [x] 用 `--judge=similarity` 复现 CN03 的字符串相似度判据，量化其在本基准上的误报（见 §9）
- [x] 用 `--no-write-check` 做 −WriteCheck 消融：VAmPI P 1.000→0.667（见 §10）
- [x] 用 `--no-ast` / `--no-infer-owner` 做 −AST / −Owner 消融（见 §11）
- [x] 接入 VAmPI（Python/Flask，纯 API），验证换栈、字符串标识、login 型副作用
- [x] 补 L3 难度实例：28 条，L1:L2:L3 = 36:43:28
      （批量读 6 / 查询型导出与报表下载 18 / 软删除 4；各配安全对照）
- [x] 实现 72 小时重标工具与 Cohen's κ（`bench/relabel.py`，四子命令 + 17 个用例）；
      **计时已启动**，到期 2026-11-06T11:29:50Z（`results/relabel/frozen.meta.json`）
- [x] 接入整系统 clean control（MockShop-secure）：同代码同数据、只切 `MOCK_POLICY`，
      50 个安全实例 FP-rate 0.000；标注由 `bench/derive_clean.py` 机械派生
- [x] **独立复核 + κ 数字**：72h 冷却后出盲标卷 107 条，AI 助手仅依据规范与活靶场
      黑盒重放复核（`bench/ai_relabel.py`）：**κ = 0.981**（95% CI [0.940, 1.000]，
      1 条分歧 mock-0047），`control_kind` κ = 1.000，难度 κ = 0.677。
      口径为「规范可执行性检验」，**不是**人际信度；已披露复核者见过少量标注。
- [ ] 权限继承类 L3 实例（父对象属主 A、子对象属主 B 的冲突场景）——三个靶场都不提供，需自建
- [ ] 再补 2 个整系统 clean control（PetClinic / Django demo）兑现"目标 3 个"
- [ ] 接入 RuoYi（Java，国产真实系统）继续验证泛化
- [ ] 把 crAPI 内置用户（test/admin）的订单 4/5 纳入标注与身份集合（当前相似度判据命中、证据判据漏掉）
- [ ] 采集层过滤第三方域名（已加同源判断，需在更多系统上回归）
