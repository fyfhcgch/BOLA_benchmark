# 标注规范（`docs/labeling_spec.md`）

> Phase 0 交付物。配合 `bench/schema.json` 使用。
> 本规范的作用：让第二个人（或独立复核者）在不看答案的前提下标出同样的结果。
> 日期：2026-11-03

---

## 1. 标注单位

**一个标注 = 一个对象实例**，键是 `(method, path_template, object_ids)`。

```json
{"id": "crapi-0001", "system": "crapi", "method": "GET",
 "path": "/workshop/api/shop/orders/{id}", "victim": "alice",
 "object_ids": ["6"], "vulnerable": true, ...}
```

### 为什么不是端点级

crAPI 的 `GET /workshop/api/shop/orders/{id}`：

| 对象 | 属主 | 谁在读 | 结果 |
|---|---|---|---|
| 6 | alice | bob | 200，返回 alice 的 email/金额 → **漏洞** |
| 8 | bob | bob（本人） | 200，读自己的 → **不是测试**，不标注 |
| 8 | bob | carol | 200，返回 bob 的 email → **漏洞** |
| 17 | — | 任意 | 404/500 → **不是漏洞**（对象不存在） |

用 `(method, path)` 做键，这四种情况会被压成一个格子，**分母的定义本身就掩盖了结论**。

## 2. 三个必须填的字段

| 字段 | 规则 |
|---|---|
| `victim` | 该对象的**属主账号**，不一定是配置里的全局 victim。crAPI 订单 8 的 victim 是 bob。 |
| `object_ids` | 路径段里的标识 + 名字带 id 语义的查询参数值，按出现顺序。书名、用户名、VIN 这类自然键也算。 |
| `vulnerable` | `true` = 非属主访问应被判为漏洞；`false` = 安全对照，**任何告警都是误报**。 |
| `scope` | 该标注适用于哪一类攻击者。**当前 107 条全部为 `any`**：判定与攻击者租户无关。跨租户不是靠标注区分，而是由重放层对每个种子同时用同租户与跨租户攻击者重放（`pipeline/replay.py` 的 `_scope`）。 |

## 3. 判定规则（标注时用，评测时对齐）

### 3.0 第 0 步：先排除"攻击者就是属主"（R0）

任何一条规则之前先问一句：**这次访问的对象，属主是不是攻击者本人？** 如果是，
无论响应里出现什么身份标识、无论写操作是否成功，都**不是 BOLA 测试**，
`vulnerable` 必须为 `false`（且不进 precision 分母）。

这一条不是洁癖，是三个真实缺陷的共同根因：

| 缺陷 | 表现 | 复现 |
|---|---|---|
| R2-a 只比 owner **键名**、不比**值** | 属主读自己的订单也带 `user_id`，被判越权 | `make ablate-keyonly`（clean 上 14/28） |
| 推断层被越权探测污染 | bob 的 `owner_values` 变成 `[1, 2]`（把 alice 的订单当自己的） | `results/raw/*/endpoints.json` 的 `owner` 段 |
| 读种子不校验响应归属 | 把"受害者越权读到的别人的对象"当种子 | `[replay] 丢弃 N 条非本人对象的读种子` |

判据侧的实现是 `judge._attacker_is_owner`（只认强标识 email/username/number/phone，
长度 ≥ 5）与 `run._owns_path`（写型响应无正文时按 URL 段比对推断出的 owner 值）。
评测侧不静默跳过，而是计入 `self_read_alerts`（修复后四个系统全为 0）。

### 3.1 读型

```
VULN ⟺ 2xx
     ∧ 响应里出现"非攻击者"的身份标识（email / username / phone / number）
     ∧ 该标识属于被访问对象的属主
     ∧ 属主 ≠ 攻击者（R0）
```

补充：响应出现敏感字段（`email`/`phone`/`amount`/`secret`…）是必要条件，
但**只有敏感字段、没有归属证据**不算（那是"过度数据暴露"，不是 BOLA）。

### 3.2 写型

```
VULN ⟺ 攻击者的写请求被接受（2xx）
     ∧ 以受害者身份复读，观察到状态确实改变
     ∧ 改变的内容 == 攻击者提交的内容
     ∧ 被写的对象不属于攻击者本人（R0；响应常无正文，按 URL 段与 owner 值比对）
```

四种操作类型的确认方式不同，**不能互换**：

| 操作 / 字段类型 | 确认方式 | 例子 |
|---|---|---|
| 自由文本 | 写入唯一 nonce，受害者复读能看到该 nonce | 订单备注、评论内容 |
| 枚举值 | 读当前值 A → 写另一个合法值 B → 受害者复读为 B → 写回 A | `status: pending/completed` |
| 凭据 | 受害者用**新密码**登录成功 → 立即改回原密码 | 密码修改接口 |
| 删除 | 攻击者 `DELETE` 成功 → 受害者复读该对象由 200 变为 **404** | `DELETE /api/orders/{id}` |

删除没有"内容"可比，只能靠"对象还在不在"；这也是 `judge_write` 把
`post_status == 404` 判为副作用确认的原因（`pipeline/judge.py`）。

### 3.3 什么不算 BOLA（最容易标错的四类）

| 情形 | 为什么不标 | 例子 |
|---|---|---|
| 无对象引用 | 换 token 重放只会拿到攻击者自己的数据 | `/api/me`、`/orders/all`、`/dashboard` |
| 公开资源 | 所有登录用户本就可见，读到作者身份是设计行为 | crAPI 社区帖子、VAmPI 用户列表/资料页 |
| 对象不存在 | 404/500 不构成"访问了他人对象" | 订单 17 |
| 路径里有 id 但服务端忽略它 | 实际只改调用者自己的数据 | VAmPI `PUT /users/v1/{u}/email`（204 但受害者不变） |

第 1 类单列进 `<system>.noref.jsonl`，命中记为 **gate violation**，不混入 FP。
第 2 类必须显式标 `visibility: public`。第 4 类必须标 `vulnerable: false` 并
写清"为什么它看起来像漏洞但不是"。

## 4. 难度分级

| 级别 | 特征 | 例 |
|---|---|---|
| L1 | 自增数字，直接遍历 | `/api/orders/1002` → `1003` |
| L2 | 需间接获取标识（UUID / VIN / 自然键 / 嵌套路径） | 车辆 UUID、书名、NanoID |
| L3 | 需业务语义或跨接口组合 | 批量接口、导出、权限继承、软删除 |

目标比例 L1 : L2 : L3 ≈ 4 : 4 : 2。

## 5. 安全对照的配额

每个系统必须标"不漏洞"的实例，否则算不出 precision。目标 `vuln : safe ≈ 1 : 3`。

安全对照按**成因**分类（标注字段 `control_kind`，`vulnerable: false` 时必填），
而不是只标"返回 403"——不同成因对应完全不同的误报机理：

| control_kind | 例 | 当前数量 |
|---|---|---|
| `owner_check` 正确校验归属 | mock `/api/profile/{id}` 返回 403 | 17 |
| `public_resource` 公开资源 | crAPI 社区帖子、VAmPI 资料页 | 9 |
| `method_not_allowed` 方法不允许 | crAPI `DELETE /shop/orders/{id}` 返回 405 | 12 |
| `no_owner_evidence` 可读但无归属证据 | crAPI 维修请求评论列表（恒为空） | 4 |
| `ignored_identifier` 路径同形但忽略 id | VAmPI `PUT /users/v1/{u}/email` | 3 |
| **合计** | | **45** |

（数字由 `bench/stats.py` 从标注现算，不手抄；`tests/test_bench_labels.py`
校验 `vulnerable: false` 时 `control_kind` 必填、且在五类之内。）

后两种是基准里最有价值的对照：

- `ignored_identifier` 的路径形态与真漏洞完全相同，**只有"受害者的状态变没变"能区分**。
- `no_owner_evidence` 检验判据能否区分"读到别人的数据"与"读到一个空壳"——两个空
  列表是"完全相同"的，任何响应相似度判据都会在这里误报。

`control_kind` 由 `tests/test_bench_labels.py` 强制校验（含 `visibility: public` 必须且只能对应 `public_resource`），`bench/stats.py` 统计它的分布。

## 6. 可靠性（本规范的可执行性检验）

- 107 条标注于 **2026-11-03** 冻结（`results/relabel/frozen.meta.json`，sha256 `a60a3c01…`）。
  72 小时冷却后出盲标卷（107 条，跨系统按固定种子打乱、不含任何答案字段），
  由**独立复核者**仅依据本规范 + 活靶场黑盒重放重新判定全部条目。
- **结果：κ = 0.981**（95% bootstrap CI [0.940, 1.000]，n = 107，p_o = 0.991，
  p_e = 0.514）。混淆 62/44/0/1，唯一分歧为 `mock-0047`（trash 跨步组合：
  单发重放看到空 trash，补上"先软删除再读"后读到受害者文档全文）。
  安全对照成因 `control_kind`（n=44）κ = **1.000**。
- **口径必须写明**：复核者是 AI 助手（不是第二个人类标注员），且在早期会话中
  见过少量标注（mock trash 0001/0002、VAmPI email/password、crAPI 社区帖、
  mock batch/mine）。因此这个 κ 是**"规范能否被独立执行"的检验**，
  不能写成人类标注员之间的一致性。论文里统一用
  "AI-assisted second annotation / specification executability check"。
- **难度分级 κ 只有 0.677**（n=107）。分歧集中在：
  嵌套路径（`/{id}/items`、`/{id}/orders`、`/{id}/comment`）算 L1 还是 L2；
  自然键（用户名、书名）算 L1 还是 L2；报表下载算 L2 还是 L3。
  这说明 §4 的 L1–L3 定义**还不够可机械执行**。已冻结的难度分布不改；
  下一版规范若重写，应按"标识是否可直接枚举 / 是否需要跨接口获取 /
  是否需要业务语义"三条可判定问题来定义，而不是按路径形状。
- **禁止事后改标注**：如果检测器命中了未标注的对象，先判断它是不是真漏洞，
  是则新增标注并注明 `discovered_by: tool`，不要为了指标好看删掉告警。

复核产物：`results/relabel/answers_assistant.jsonl`（判定）、
`evidence_assistant.jsonl`（逐条 HTTP 证据）、`kappa_assistant.json`（κ 明细）。
复核脚本是 `bench/ai_relabel.py`；写型测试逐条恢复原值，mock 结束时调用
`/api/debug/reset`。

## 7. 当前标注现状（pilot，107 条）

| 系统 | 标注 | vuln | safe | (方法,路径) 对 | 对象类型 | noref |
|---|---|---|---|---|---|---|
| MockShop | 50 | 32 | 18 | 13 | order, user, document | 2 |
| crAPI | 45 | 24 | 21 | 13 | order, vehicle, service_request, comment, post, service_report, service_report_meta | 4 |
| VAmPI | 12 | 6 | 6 | 4 | book, user | 4 |
| **合计** | **107** | **62** | **45** | **30** | 11 类 | **10** |

另有一个**整系统 clean control**（`bench/labels/clean.jsonl`，50 条），
它由 `bench/derive_clean.py` 从 `mock.jsonl` 机械派生，**不计入上表**：
50 条全是 mock 的镜像（同实例键、同难度、同对象），算进去会把标注量虚增一倍。
clean 的口径是 FP-rate 而非 precision（它没有漏洞实例，precision 分母为 0）。

以上数字**不由人工维护**：`make bench-stats` 从 `bench/labels/*.jsonl` 现算，
并写 `results/processed/bench_manifest.json`（逐文件 sha256 + `bench_version`）。
论文表格与图（Fig.2）都引用这份输出，标注一改，表和指纹一起变。

已知偏差（写进 Threats to Validity）：

1. **vuln : safe = 62 : 45 ≈ 1.38 : 1**，低于目标 1 : 3 —— 漏洞样本偏多，
   precision 的置信区间偏宽。
2. **L1 : L2 : L3 = 36 : 43 : 28** —— L3 已补齐三类形态（批量读 6、查询型导出与
   报表下载 18、软删除 4），但**权限继承仍缺**（父对象属主 A、子对象属主 B 的冲突
   场景，三个靶场都不提供）。写"已覆盖 L3"时必须限定到这三类。
3. **独立复核已完成**：冻结快照 sha256 与到期时间记录在
   `results/relabel/frozen.meta.json`（2026-11-06T11:29:50Z）；盲标卷与
   κ 明细见 `results/relabel/`，κ = 0.981（AI 辅助二次标注 / 规范可执行性检验，
   不是人际信度），难度分级 κ = 0.677（见 §6）。
4. crAPI 内置用户（`test@example.com` / `admin@example.com`）的对象未纳入标注，
   它们的订单 4/5 与维修请求 4/5 实际可被任意登录用户读取 —— 按约定计入未标注告警
   （保守计为误报），这是**同时对基线与本文不利**的偏差（它也抬高我们的 FP 上限），
   必须披露。
