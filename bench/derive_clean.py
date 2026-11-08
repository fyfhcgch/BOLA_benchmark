"""从 mock 的标注机械派生 clean 系统的标注。

为什么要派生而不是手写：clean 系统的对象、实例键、难度、对象类型都与 mock
**逐条相同**，唯一该变的是判定结论。手写 50 条必然出现"漏改一条"，
而漏改的那条会让 clean 对照看起来有漏洞 —— 这个错误会直接污染 §VI 的核心结论。

派生规则：

| mock 里 | clean 里 | 理由 |
|---|---|---|
| `vulnerable: true` | `vulnerable: false` + `control_kind: owner_check` | 同一实例，服务端补上了归属校验 |
| `vulnerable: false, owner_check` | `vulnerable: false, owner_check` | 本来就是安全对照 |
| `vulnerable: false, no_owner_evidence` | 同左 | 空容器与归属无关，策略切换不影响 |

`difficulty` / `object_type` / `object_ids` / `path` / `method` / `victim`
全部原样保留：难度描述的是"标识怎么拿到"，与授权策略无关；
改这些字段就等于换了一批对象，对照就不受控了。

派生后断言两件事（不满足就直接失败，不写文件）：
  1. 实例键集合与 mock 完全一致（一条不多一条不少）
  2. clean 里没有任何 `vulnerable: true`（clean 系统定义上无漏洞）

用法：
    python bench/derive_clean.py            # 写出 clean.jsonl
    python bench/derive_clean.py --check    # 只校验，不写
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

BENCH = Path(__file__).resolve().parent
LABELS = BENCH / "labels"
KEY_FIELDS = ("method", "path", "object_ids", "victim", "object_type",
              "difficulty", "request_path", "scope")

HEADER = """// 本文件由 bench/derive_clean.py 从 bench/labels/mock.jsonl 机械派生，请勿手改。
// clean 系统（systems/clean/app.py）与 mock 是同一个应用，只把 MOCK_POLICY 切成 secure。
// 因此实例键与 mock 逐条相同，唯一差别是 vulnerable: true -> false。
"""


def derive() -> tuple[list[dict], list[str]]:
    src = [json.loads(l) for l in
           (LABELS / "mock.jsonl").read_text(encoding="utf-8").splitlines()
           if l.strip() and not l.startswith("//")]
    out: list[dict] = []
    for r in src:
        row = {k: r[k] for k in ("system",) if k in r}
        row["system"] = "clean"
        row["id"] = "clean-" + r["id"].split("-", 1)[1]
        row["discovered_by"] = "manual"
        for k in KEY_FIELDS:
            if k in r:
                row[k] = r[k]
        if r["vulnerable"]:
            row["vulnerable"] = False
            # 从"缺校验"变成"有校验"：成因就是 owner_check
            row["control_kind"] = "owner_check"
            row["vuln_kind"] = "none"
            row["note"] = ("clean 对照：与 mock 的 " + r["id"] + " 是同一个对象实例、同一请求形态，"
                           "但 secure 策略下服务端校验归属，非属主被拒（403）或只拿到自己的行。"
                           "任何告警都是误报")
        else:
            row["vulnerable"] = False
            row["control_kind"] = r.get("control_kind", "owner_check")
            row["vuln_kind"] = r.get("vuln_kind", "none")
            row["note"] = ("clean 对照：与 mock 的 " + r["id"] + " 同实例；"
                           "原本就是安全对照（" + row["control_kind"] + "），策略切换不影响判定")
        row.setdefault("visibility", r.get("visibility", "private"))
        out.append(row)
    return out, src


def _keys(rows: list[dict]) -> set[tuple]:
    return {(r["method"], r["path"], tuple(r["object_ids"])) for r in rows}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)

    rows, src = derive()
    problems: list[str] = []

    # 断言 1：实例键集合与 mock 完全一致
    missing = _keys(src) - _keys(rows)
    extra = _keys(rows) - _keys(src)
    if missing:
        problems.append(f"clean 缺 {len(missing)} 个 mock 实例：{sorted(missing)[:3]}")
    if extra:
        problems.append(f"clean 多出 {len(extra)} 个 mock 没有的实例：{sorted(extra)[:3]}")

    # 断言 2：clean 定义上无漏洞
    vuln = [r["id"] for r in rows if r["vulnerable"]]
    if vuln:
        problems.append(f"clean 出现 {len(vuln)} 条 vulnerable=true：{vuln[:3]}")

    # 断言 3：id 不与 mock 冲突，且全局唯一
    ids = [r["id"] for r in rows]
    if len(set(ids)) != len(ids):
        problems.append("clean 内部 id 重复")

    if problems:
        for p in problems:
            print(f"[FAIL] {p}")
        return 1

    path = LABELS / "clean.jsonl"
    if not args.check:
        path.write_text(HEADER + "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                        encoding="utf-8")
        # clean 没有"无对象引用"的对照组：noref 的作用是抓闸门失效，
        # clean 系统上闸门失效会表现为对 /api/me 之类端点告警，同样计入 FP
        (LABELS / "clean.noref.jsonl").write_text(
            "// clean 系统与 mock 同构，noref 端点相同；这里显式列出，闸门失效会被记为 FP\n"
            + "\n".join(json.dumps({"method": "GET", "path": p},
                                   ensure_ascii=False) for p in ("/api/products", "/api/me")) + "\n",
            encoding="utf-8")

    from collections import Counter
    print(f"派生 {len(rows)} 条 -> {path}")
    print(f"  vulnerable: {dict(Counter(r['vulnerable'] for r in rows))}")
    print(f"  control_kind: {dict(Counter(r['control_kind'] for r in rows))}")
    print(f"  difficulty: {dict(Counter(r['difficulty'] for r in rows))}")
    print("  实例键与 mock 逐条一致 ✓")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
