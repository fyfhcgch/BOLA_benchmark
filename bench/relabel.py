"""72 小时重标与 Cohen's κ。

为什么需要它：单人标注的基准，评审第一句就是"你怎么知道标注是对的"。
没有第二个人时，退而求其次的做法是**隔 72 小时由本人重标一遍**——
72 小时足够忘掉具体条目，又不足以忘掉规范。前后两版的一致性用
Cohen's κ 量化，κ 低的地方就是规范写得含糊的地方。

## 三步，必须按顺序

    python bench/relabel.py freeze     # T0：冻结当前标注 + 启动 72 小时计时
    python bench/relabel.py status     # 看还剩多久；到点后才允许出卷
    python bench/relabel.py sheet      # 出盲标卷（不含 vulnerable / note）
    # ... 人工在 relabel.jsonl 里填 vulnerable ...
    python bench/relabel.py score      # 算 κ、混淆矩阵、分歧清单

## 两条纪律

1. **冻结后不许改 `frozen.jsonl`**。它是 T0 的快照，sha256 记在 meta 里；
   若标注在 T0 之后有变动（比如又补了实例），这些实例不进本次 κ 的计算，
   否则"重标"和"改标注"混在一起，κ 失去意义。
2. **盲标卷里不能出现答案**。`sheet` 只导出 id / 方法 / 路径 / 对象标识 /
   属主 / 对象类型，`vulnerable`、`difficulty`、`control_kind`、`note`
   全部剔除。顺序按固定种子打乱并跨系统交错，避免"按系统成块回忆"。

## 评分口径

- 主指标：`vulnerable` 的二元 κ（论文正文报这个）。
- 次指标：`difficulty` 的三类名义 κ、`control_kind` 的五类名义 κ
  （只有重标时填了才计算）。
- `uncertain: true` 的条目单独计数，**不计入 κ**：说不准本身就是结论，
  要在 Threats to Validity 里写明有几条。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
LABELS = BENCH / "labels"
OUT = ROOT / "results" / "relabel"

SYSTEMS = ["mock", "crapi", "vampi"]
HOLD_HOURS = 72
SHUFFLE_SEED = 20261103

# 盲标卷保留的字段：够定位对象，但不含任何判定结论
SHEET_FIELDS = ("id", "system", "method", "path", "request_path",
                "object_ids", "victim", "object_type")


# --------------------------------------------------------------------------- #
# 冻结与计时
# --------------------------------------------------------------------------- #

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_system(system: str) -> list[dict]:
    p = LABELS / f"{system}.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def cmd_freeze(args) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    frozen_path = OUT / "frozen.jsonl"
    meta_path = OUT / "frozen.meta.json"
    if frozen_path.exists() and not args.force:
        print(f"已经冻结过：{frozen_path}")
        print("  重新冻结会作废已过去的计时；确认要重来请加 --force")
        return 1

    rows: list[dict] = []
    per_file: dict[str, dict] = {}
    for s in SYSTEMS:
        p = LABELS / f"{s}.jsonl"
        part = _load_system(s)
        rows += part
        if p.exists():
            per_file[s] = {"sha256": _sha256(p), "labels": len(part)}

    now = datetime.now(timezone.utc)
    due = now + timedelta(hours=HOLD_HOURS)
    frozen_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
        encoding="utf-8")
    meta = {
        "frozen_at": now.isoformat(timespec="seconds"),
        "due_at": due.isoformat(timespec="seconds"),
        "hold_hours": HOLD_HOURS,
        "labels": len(rows),
        "vuln": sum(bool(r.get("vulnerable")) for r in rows),
        "safe": sum(not r.get("vulnerable") for r in rows),
        "systems": per_file,
        "frozen_sha256": _sha256(frozen_path),
        "protocol": "72 小时后由本人盲标一遍，比对 vulnerable 字段，报 Cohen's κ",
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"冻结 {len(rows)} 条（vuln {meta['vuln']} / safe {meta['safe']}）-> {frozen_path}")
    print(f"  sha256 = {meta['frozen_sha256'][:16]}…")
    print(f"  计时开始：{meta['frozen_at']}  ->  到期：{meta['due_at']}")
    return 0


def _meta() -> dict:
    p = OUT / "frozen.meta.json"
    if not p.exists():
        raise SystemExit("还没冻结。先跑：python bench/relabel.py freeze")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_status(args) -> int:
    m = _meta()
    now = datetime.now(timezone.utc)
    due = datetime.fromisoformat(m["due_at"])
    left = due - now
    print(f"冻结于 {m['frozen_at']}（{m['labels']} 条，sha256 {m['frozen_sha256'][:16]}…）")
    if left.total_seconds() > 0:
        h, rem = divmod(int(left.total_seconds()), 3600)
        print(f"还剩 {h} 小时 {rem // 60} 分（到期 {m['due_at']}）")
        print("  未到 72 小时不建议出卷：记忆还新鲜，κ 会虚高。")
    else:
        print(f"已到期（{m['due_at']}），可以出卷：python bench/relabel.py sheet")
    # 冻结之后标注是否又被改动 —— 改了就要说明哪些实例不进本次 κ
    for s, info in m["systems"].items():
        p = LABELS / f"{s}.jsonl"
        if not p.exists():
            continue
        cur = _sha256(p)
        if cur != info["sha256"]:
            n_now = len(_load_system(s))
            print(f"  [warn] {s}.jsonl 在冻结后改过（{info['labels']} -> {n_now} 条）；"
                  f"新增实例不参与本次 κ")
    return 0


# --------------------------------------------------------------------------- #
# 出卷
# --------------------------------------------------------------------------- #

def cmd_sheet(args) -> int:
    m = _meta()
    due = datetime.fromisoformat(m["due_at"])
    now = datetime.now(timezone.utc)
    if now < due and not args.early:
        left = due - now
        print(f"还没到 72 小时（剩 {int(left.total_seconds()) // 3600} 小时）。")
        print("  确实要提前出卷请加 --early，并在论文里写明实际间隔。")
        return 1

    rows = [json.loads(l) for l in (OUT / "frozen.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    if args.sample and args.sample < len(rows):
        # 按 (系统, 难度) 分层抽样：这两个维度与答案无关，不会泄露 vulnerable 的分布
        rng = random.Random(SHUFFLE_SEED)
        buckets: dict[tuple[str, str], list[dict]] = {}
        for r in rows:
            buckets.setdefault((r["system"], r.get("difficulty", "?")), []).append(r)
        take = max(1, round(args.sample * len(rows) / len(rows)))
        picked: list[dict] = []
        for k in sorted(buckets):
            group = buckets[k]
            n = max(1, round(args.sample * len(group) / len(rows)))
            picked += rng.sample(group, min(n, len(group)))
        rows = picked
        take = len(rows)

    rng = random.Random(SHUFFLE_SEED)
    rng.shuffle(rows)          # 跨系统交错，避免按系统成块回忆
    sheet = [{k: r.get(k) for k in SHEET_FIELDS} | {"seq": i + 1}
             for i, r in enumerate(rows)]

    sheet_path = OUT / "blind_sheet.jsonl"
    sheet_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in sheet) + "\n", encoding="utf-8")

    md = [
        "# 盲标卷（72 小时重标）",
        "",
        f"- 冻结时间：{m['frozen_at']}    出卷时间：{now.isoformat(timespec='seconds')}",
        f"- 冻结 sha256：`{m['frozen_sha256']}`",
        f"- 条目数：{len(sheet)}",
        "",
        "**规则**：不许翻 `bench/labels/`、不许翻 `docs/pilot_findings.md`，",
        "只按 `docs/labeling_spec.md` 的规范、对着跑起来的靶场重新判一遍。",
        "判不准就填 `uncertain`，那本身是结论。",
        "",
        "| # | id | 方法 | 路径 | 对象标识 | 属主 | vulnerable | difficulty | 备注 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sheet:
        md.append(f"| {r['seq']} | {r['id']} | {r['method']} | `{r['path']}` | "
                  f"`{','.join(r['object_ids'])}` | {r['victim']} |  |  |  |")
    (OUT / "blind_sheet.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # 表格版：直接在 LibreOffice/Excel 里填 vulnerable / difficulty / control_kind，
    # 比手改 107 行 JSON 现实得多。填完用 `relabel.py import-csv` 转回 relabel.jsonl。
    csv_path = OUT / "blind_sheet.csv"
    import csv as _csv
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["seq", "id", "system", "method", "path", "object_ids", "victim",
                    "vulnerable", "difficulty", "control_kind", "uncertain", "note"])
        for r in sheet:
            w.writerow([r["seq"], r["id"], r["system"], r["method"], r["path"],
                        ",".join(r["object_ids"]), r["victim"], "", "", "", "", ""])

    ans_path = OUT / "relabel.jsonl"
    if not ans_path.exists() or args.reset:
        ans_path.write_text(
            "\n".join(json.dumps({"id": r["id"], "vulnerable": None,
                                  "difficulty": None, "control_kind": None,
                                  "uncertain": False, "note": ""},
                                 ensure_ascii=False) for r in sheet) + "\n",
            encoding="utf-8")
    print(f"出卷 {len(sheet)} 条 -> {sheet_path}")
    print(f"  人读版：{OUT / 'blind_sheet.md'}")
    print(f"  表格版：{csv_path}（填 vulnerable=true/false，difficulty=L1/L2/L3）")
    print(f"  待填：  {ans_path}（vulnerable 填 true/false；difficulty 填 L1/L2/L3）")
    return 0


def _parse_bool(v: str):
    s = (v or "").strip().lower()
    if s in ("true", "t", "1", "yes", "y", "v", "是", "漏洞"):
        return True
    if s in ("false", "f", "0", "no", "n", "s", "否", "安全"):
        return False
    return None


def cmd_import_csv(args) -> int:
    """把填好的 blind_sheet.csv 转成 relabel.jsonl（保留 uncertain / note）。"""
    import csv as _csv

    sheet = {r["id"]: r for r in
             (json.loads(l) for l in (OUT / "blind_sheet.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())}
    path = Path(args.path)
    if not path.exists():
        print(f"没有表格：{path}")
        return 1
    rows, unfilled = [], []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for r in _csv.DictReader(fh):
            sid = (r.get("id") or "").strip()
            if sid not in sheet:
                continue
            vul = _parse_bool(r.get("vulnerable"))
            unc = _parse_bool(r.get("uncertain")) is True
            if vul is None and not unc:
                unfilled.append(sid)
            rows.append({
                "id": sid, "vulnerable": vul,
                "difficulty": (r.get("difficulty") or "").strip() or None,
                "control_kind": (r.get("control_kind") or "").strip() or None,
                "uncertain": unc, "note": (r.get("note") or "").strip(),
            })
    out_path = OUT / "relabel.jsonl"
    out_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    print(f"导入 {len(rows)} 条 -> {out_path}")
    if unfilled:
        print(f"  [warn] {len(unfilled)} 条未填 vulnerable（不计入 κ）：{unfilled[:8]}"
              f"{' …' if len(unfilled) > 8 else ''}")
    return 0


# --------------------------------------------------------------------------- #
# Cohen's κ
# --------------------------------------------------------------------------- #

def kappa_nominal(a: list, b: list) -> dict:
    """名义类别 κ。适用于二分类与多分类（difficulty / control_kind）。

    κ = (p_o - p_e) / (1 - p_e)，p_o 为观察一致率，p_e 为按边际分布算的
    偶然一致率。p_e = 1 时（两方都只用一个类别）κ 无定义：完全一致记 1.0，
    否则记 0.0 —— 这类退化情形必须显式处理，不能靠除零。
    """
    n = len(a)
    if n == 0:
        return {"n": 0, "po": 0.0, "pe": 0.0, "kappa": 0.0}
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    cats = sorted({*a, *b}, key=str)
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    if abs(1 - pe) < 1e-12:
        k = 1.0 if po == 1.0 else 0.0
    else:
        k = (po - pe) / (1 - pe)
    return {"n": n, "po": round(po, 4), "pe": round(pe, 4), "kappa": round(k, 4)}


def _bootstrap_ci(a: list, b: list, iters: int = 2000, seed: int = 7) -> tuple[float, float]:
    """κ 的 95% 置信区间（成对重采样）。n 只有百来条时必须报区间，不能只报点估计。"""
    if not a:
        return (0.0, 0.0)
    rng = random.Random(seed)
    ks = []
    n = len(a)
    for _ in range(iters):
        idx = [rng.randrange(n) for _ in range(n)]
        ks.append(kappa_nominal([a[i] for i in idx], [b[i] for i in idx])["kappa"])
    ks.sort()
    lo = ks[int(0.025 * iters)]
    hi = ks[int(0.975 * iters) - 1]
    return (round(lo, 4), round(hi, 4))


def cmd_score(args) -> int:
    m = _meta()
    frozen = {r["id"]: r for r in
              (json.loads(l) for l in (OUT / "frozen.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())}
    ans_path = Path(args.answers) if args.answers else OUT / "relabel.jsonl"
    if not ans_path.exists():
        print(f"没有答卷：{ans_path}（先跑 sheet）")
        return 1
    ans = [json.loads(l) for l in ans_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    # 只比对"冻结里有的、答卷里也真填了的"条目
    paired, uncertain, missing = [], [], []
    for a in ans:
        if a["id"] not in frozen:
            continue
        if a.get("uncertain"):
            uncertain.append(a["id"])
            continue
        if a.get("vulnerable") is None:
            missing.append(a["id"])
            continue
        paired.append((frozen[a["id"]], a))

    if missing:
        print(f"[warn] {len(missing)} 条未填，不计入 κ：{missing[:5]}{' …' if len(missing) > 5 else ''}")
    if not paired:
        print("没有可比的条目。")
        return 1

    a = [bool(f.get("vulnerable")) for f, _ in paired]
    b = [bool(x["vulnerable"]) for _, x in paired]
    k = kappa_nominal(a, b)
    lo, hi = _bootstrap_ci(a, b)

    tp = sum(1 for x, y in zip(a, b) if x and y)
    tn = sum(1 for x, y in zip(a, b) if not x and not y)
    f_yes_b_no = sum(1 for x, y in zip(a, b) if x and not y)   # T0=vuln，重标=safe
    f_no_b_yes = sum(1 for x, y in zip(a, b) if not x and y)   # T0=safe，重标=vuln

    out = {
        "frozen_at": m["frozen_at"],
        "scored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hold_hours": m["hold_hours"],
        "frozen_sha256": m["frozen_sha256"],
        "answers_sha256": _sha256(ans_path),
        "n_paired": len(paired),
        "n_uncertain": len(uncertain),
        "n_unfilled": len(missing),
        "kappa": k["kappa"],
        "kappa_ci95": [lo, hi],
        "observed_agreement": k["po"],
        "expected_agreement": k["pe"],
        "confusion": {"both_vuln": tp, "both_safe": tn,
                      "frozen_vuln_relabel_safe": f_yes_b_no,
                      "frozen_safe_relabel_vuln": f_no_b_yes},
    }

    # 次指标：难度与对照成因（只在答卷真填了时才算）
    diff_pairs = [(f.get("difficulty"), x.get("difficulty")) for f, x in paired
                  if x.get("difficulty") and f.get("difficulty")]
    if diff_pairs:
        out["difficulty_kappa"] = kappa_nominal([p[0] for p in diff_pairs],
                                                [p[1] for p in diff_pairs])
    ctrl_pairs = [(f.get("control_kind"), x.get("control_kind")) for f, x in paired
                  if x.get("control_kind") and f.get("control_kind")]
    if ctrl_pairs:
        out["control_kind_kappa"] = kappa_nominal([p[0] for p in ctrl_pairs],
                                                  [p[1] for p in ctrl_pairs])

    out["disagreements"] = [
        {"id": f["id"], "system": f["system"], "method": f["method"], "path": f["path"],
         "object_ids": f["object_ids"], "victim": f.get("victim"),
         "frozen": bool(f.get("vulnerable")), "relabel": bool(x["vulnerable"]),
         "frozen_note": f.get("note"), "relabel_note": x.get("note")}
        for f, x in paired if bool(f.get("vulnerable")) != bool(x["vulnerable"])
    ]
    (OUT / "kappa.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n== Cohen's κ（vulnerable，n={len(paired)}）==")
    print(f"  κ = {k['kappa']:.3f}   95% CI [{lo:.3f}, {hi:.3f}]")
    print(f"  一致率 p_o = {k['po']:.3f}   偶然一致 p_e = {k['pe']:.3f}")
    print(f"  混淆：两边都判漏洞 {tp} / 两边都判安全 {tn} / "
          f"T0漏洞->重标安全 {f_yes_b_no} / T0安全->重标漏洞 {f_no_b_yes}")
    if uncertain:
        print(f"  判不准（不计入）：{len(uncertain)} 条")
    if "difficulty_kappa" in out:
        print(f"  难度 κ = {out['difficulty_kappa']['kappa']:.3f} "
              f"(n={out['difficulty_kappa']['n']})")
    if "control_kind_kappa" in out:
        print(f"  对照成因 κ = {out['control_kind_kappa']['kappa']:.3f} "
              f"(n={out['control_kind_kappa']['n']})")
    if out["disagreements"]:
        print("\n  分歧条目（每条都要在 Threats to Validity 里解释）：")
        for d in out["disagreements"]:
            print(f"    {d['id']:12s} {d['method']:6s} {d['path']:44s} "
                  f"T0={'V' if d['frozen'] else 'S'} -> 重标={'V' if d['relabel'] else 'S'}")
    else:
        print("\n  无分歧。")
    verdict = ("达标" if k["kappa"] > 0.8 else
               "低于目标 0.8：先改标注规范里含糊的那几条，再重标")
    print(f"\n  目标 κ>0.8 -> {verdict}")
    print(f"  -> {OUT / 'kappa.json'}")
    return 0 if k["kappa"] > 0.8 else 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="72 小时重标 + Cohen's κ")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("freeze", help="T0 冻结当前标注并开始计时")
    p.add_argument("--force", action="store_true", help="覆盖已有冻结（会作废计时）")
    p.set_defaults(func=cmd_freeze)

    p = sub.add_parser("status", help="看计时与冻结后改动")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("sheet", help="出盲标卷")
    p.add_argument("--sample", type=int, default=0, help="抽样条数（0=全量）")
    p.add_argument("--early", action="store_true", help="未满 72 小时也出卷")
    p.add_argument("--reset", action="store_true", help="覆盖已填的答卷")
    p.set_defaults(func=cmd_sheet)

    p = sub.add_parser("score", help="算 κ")
    p.add_argument("answers", nargs="?", default="", help="答卷路径（默认 results/relabel/relabel.jsonl）")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("import-csv", help="把填好的 blind_sheet.csv 转成 relabel.jsonl")
    p.add_argument("path", nargs="?", default=str(OUT / "blind_sheet.csv"),
                   help="CSV 路径（默认 results/relabel/blind_sheet.csv）")
    p.set_defaults(func=cmd_import_csv)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
