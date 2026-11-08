"""把默认结果与消融结果汇总成一张 Markdown 表。

用法：
    python bench/ablation_report.py
    python bench/ablation_report.py --systems mock crapi vampi

读取 `results/raw/<system>/summary.json`（默认判据）与
`results/raw/<system>/ablation/<tag>/summary.json`（消融）。
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results" / "raw"


def _row(system: str, d: dict, tag: str) -> dict:
    return {
        "system": system,
        "tag": tag,
        "judge": d.get("judge", "evidence"),
        "suppress": "on" if d.get("public_suppression", True) else "off",
        "write_check": "on" if d.get("write_check", True) else "off",
        "tested": d["labels_tested"],
        "tp": d["tp"],
        "fp": d["fp"],
        "fn": d["fn"],
        "tn": d["tn"],
        "p": d["precision"],
        "r": d["recall"],
        "r_strict": d["recall_strict"],
        "f1": d["f1"],
        "unlabeled": d.get("fp_unlabeled", 0),
        "inventory": d.get("inventory_endpoints"),
        "unobserved": d.get("unobserved_endpoints"),
        "ep_tested": d.get("endpoints_tested"),
        "manual_ratio": d.get("manual_config_ratio"),
        # 属主自读告警：不进 precision 分母，但"判据对身份不敏感"的证据
        "self_read": d.get("self_read_alerts", 0),
        "self_read_total": d.get("tests_skipped_owner", 0),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--systems", nargs="*", default=["mock", "crapi", "vampi"])
    ap.add_argument("--csv", metavar="PATH", help="同时写一份 CSV（Phase 6 交付物）")
    args = ap.parse_args()

    rows: list[dict] = []
    for sid in args.systems:
        base = RAW / sid / "summary.json"
        if base.exists():
            rows.append(_row(sid, json.loads(base.read_text(encoding="utf-8")), "default"))
        for p in sorted((RAW / sid / "ablation").glob("*/summary.json")):
            rows.append(_row(sid, json.loads(p.read_text(encoding="utf-8")), p.parent.name))

    if not rows:
        print("没有结果，先跑 pipeline.run")
        return

    if args.csv:
        out = Path(args.csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"CSV -> {out}\n")

    print("| 系统 | 配置 | 判据 | 可见性抑制 | 写型校验 | 端点清单 | 未触发 | 测到端点 | 人工配置比 | tested | TP | FP | FN | TN | P | R | F1 | 未标注告警 | 属主自读告警 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for x in rows:
        inv = "-" if x["inventory"] is None else str(x["inventory"])
        uno = "-" if x["unobserved"] is None else str(x["unobserved"])
        ep = "-" if x["ep_tested"] is None else str(x["ep_tested"])
        mr = "-" if x["manual_ratio"] is None else f"{x['manual_ratio']:.3f}"
        print(f"| {x['system']} | {x['tag']} | {x['judge']} | {x['suppress']} | {x['write_check']} | "
              f"{inv} | {uno} | {ep} | {mr} | "
              f"{x['tested']} | {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} | "
              f"{x['p']:.3f} | {x['r']:.3f} | {x['f1']:.3f} | {x['unlabeled']} | "
              f"{x['self_read']}/{x['self_read_total']} |")


if __name__ == "__main__":
    main()
