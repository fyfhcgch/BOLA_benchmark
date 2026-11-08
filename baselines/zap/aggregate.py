#!/usr/bin/env python3
"""把 baselines/zap/<system>/summary.json 聚合成 §IV 的基线评测表。

论文纪律：表格数字**禁止手抄**，一律由本脚本从结果文件现算。
输出：
  - results/processed/zap_baseline.json  （机器可读，供 verify_paper_tables 核对）
  - stdout 打印 markdown 表（可直接粘进 §IV 的生成脚本/论文表格模板）

用法：.venv/bin/python baselines/zap/aggregate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SYS = Path(__file__).resolve().parent
OUT = ROOT / "results" / "processed" / "zap_baseline.json"

# §IV 表的行序与系统显示名
SYSTEMS = [("mock", "MockShop-vuln"), ("clean", "MockShop-secure"),
           ("crapi", "OWASP crAPI"), ("vampi", "VAmPI")]


def main() -> int:
    rows = []
    for sid, disp in SYSTEMS:
        f = SYS / sid / "summary.json"
        if not f.exists():
            print(f"缺 {f}，先跑 baselines/zap_access_control.py --system {sid}", file=sys.stderr)
            return 1
        d = json.loads(f.read_text(encoding="utf-8"))
        s = d.get("score") or {}
        labels = s.get("labels_total", 0)
        rows.append({
            "system": sid, "display": disp,
            # 规模与覆盖
            "labels": labels,
            "labels_tested": s.get("labels_tested", 0),
            "coverage": s.get("coverage"),
            # 混淆矩阵
            "tp": s.get("tp", 0), "fp": s.get("fp", 0), "fn": s.get("fn", 0),
            "tn": s.get("tn", 0),
            # 指标
            "precision": s.get("precision"),
            "precision_defined": s.get("precision_defined", True),
            "fp_rate": s.get("fp_rate"),
            "safe_tested": s.get("safe_tested", 0),
            "recall": s.get("recall"),
            "recall_strict": s.get("recall_strict"),
            "f1": s.get("f1"),
            # 诊断量（正文披露，不进 P/R）
            "tests_skipped_owner": s.get("tests_skipped_owner", 0),
            "self_read_alerts": s.get("self_read_alerts", 0),
            "gate_violations": s.get("gate_violations", 0),
            "fp_unlabeled": s.get("fp_unlabeled", 0),
            "ac_alerts": d.get("ac_alerts", 0),
            "ac_authz_alerts": d.get("ac_authz_alerts"),
            "improper_auth_alerts": (d.get("ac_alerts", 0)
                                     - (d.get("ac_authz_alerts")
                                        if d.get("ac_authz_alerts") is not None
                                        else d.get("ac_alerts", 0))),
            "rules_check": d.get("rules_check"),
            "fixture": {"before": d.get("fixture_before"), "after": d.get("fixture_after")},
        })

    # 汇总（clean 不计入 P/R 合计，它的口径是 FP-rate）
    scored = [r for r in rows if r["system"] != "clean"]
    tot = {
        "labels_tested": sum(r["labels_tested"] for r in scored),
        "tp": sum(r["tp"] for r in scored),
        "fp": sum(r["fp"] for r in scored),
        "fn": sum(r["fn"] for r in scored),
        "tn": sum(r["tn"] for r in scored),
    }
    tot["precision"] = round(tot["tp"] / (tot["tp"] + tot["fp"]), 4) if (tot["tp"] + tot["fp"]) else 0.0
    tot["recall"] = round(tot["tp"] / (tot["tp"] + tot["fn"]), 4) if (tot["tp"] + tot["fn"]) else 0.0
    tot["f1"] = (round(2 * tot["precision"] * tot["recall"] / (tot["precision"] + tot["recall"]), 4)
                 if (tot["precision"] + tot["recall"]) else 0.0)

    out = {"rows": rows, "totals_over_vuln_systems": tot}
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # ---- markdown 表 ----
    def num(x):
        return "-" if x is None else f"{x:.3f}" if isinstance(x, float) else str(x)

    print("| 系统 | 标注 | 被测 | Cov | TP | FP | FN | TN | P | FP-rate | R | R(strict) | F1 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        p = "undef" if not r["precision_defined"] else num(r["precision"])
        print(f"| {r['display']} | {r['labels']} | {r['labels_tested']} | {num(r['coverage'])} | "
              f"{r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | {p} | "
              f"{num(r['fp_rate'])} ({r['fp']}/{r['safe_tested']}) | {num(r['recall'])} | "
              f"{num(r['recall_strict'])} | {num(r['f1'])} |")
    print()
    print("P/R/F1 合计（不含 clean）：", json.dumps(tot, ensure_ascii=False))
    print(f"已写入 {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())