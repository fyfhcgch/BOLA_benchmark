# 独立复核（AI 辅助二次标注）产物说明

口径：**规范可执行性检验**，不是人类标注员之间的信度。
复核者是 AI 助手，只读 `docs/labeling_spec.md` 与活靶场的 HTTP 行为，
不读 `bench/labels/` 与 `docs/pilot_findings.md`。

## 文件

| 文件 | 内容 |
|---|---|
| `frozen.jsonl` / `frozen.meta.json` | 2026-11-03 冻结的 107 条标注快照（sha256 `a60a3c01…`） |
| `blind_sheet.{jsonl,md,csv}` | 72 小时后出的盲标卷：无答案字段，跨系统固定种子打乱 |
| `answers_assistant.jsonl` | 复核判定（vulnerable / difficulty / control_kind / uncertain / note） |
| `evidence_assistant.jsonl` | 逐条 HTTP 证据（状态码、响应片段、受害者复读、恢复值） |
| `kappa.json` / `kappa_assistant.json` | Cohen's κ 明细（两者内容相同） |
| `relabel.jsonl` | 盲标空白模板（未填写） |

## 结果

- **κ = 0.981**，95% bootstrap CI [0.940, 1.000]，n = 107（判不准 0 条）
- 一致率 p_o = 0.991，偶然一致 p_e = 0.514
- 混淆：两边漏洞 62 / 两边安全 44 / T0漏洞→复核安全 0 / T0安全→复核漏洞 1
- 安全对照成因 `control_kind`：κ = **1.000**（n = 44）
- 难度分级：κ = **0.677**（规范缺陷，见 `docs/labeling_spec.md` §6）

## 唯一分歧

`mock-0047`，`GET /api/documents/{uuid}/trash`（对象 `a1b2c3d4-0002-…`，属主 alice）：

- T0 = 安全。T0 的备注说明其意图是「**未被删除**的对象在同一 trash 端点返回
  `{"trash": []}`」，与漏洞实例同模板不同对象。
- 复核 = 漏洞。按 L3「软删除」定义补上组合步骤：攻击者 bob 先
  `DELETE /api/documents/{uuid}`，再读 `/trash`，得到
  `{"id": …, "owner_email": "alice@example.com", "body": "ALICE-DOC-SECRET-2", "deleted": true}`。
- 归因：**重放顺序差异**，不是判定规则差异。论文把它写进 Threats，
  并说明单发重放会低估这一条。

## 复现

```bash
# 需要先起 mock(8765) / clean(8766) / crAPI(8888) / VAmPI(5002)
make ai-relabel          # 复核 + 算 κ + 另存 kappa_assistant.json
make result-figures      # Fig.3 / Fig.4
make test                # 109 个用例
```

写型测试全部做恢复：PATCH 备注写回原值、PUT 状态写回原值、改密/改邮箱后用
新凭据改回；mock 结束调用 `/api/debug/reset`。
