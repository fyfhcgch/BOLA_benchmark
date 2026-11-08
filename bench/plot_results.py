"""Fig. 3 / Fig. 4：§IV 实验结果的图（数字全部现算，不手填）。

Fig. 3（RQ1 主结果）
  (a) 三个漏洞系统上的 F1：本文流水线 vs ZAP Access Control，
      叠加随机猜测的 F1 经验区间（`results/processed/random_baseline.json`）。
  (b) Recall(strict)：只在工具真正评估过的实例上算召回，暴露覆盖上限。
  (c) FP-rate：四个系统（含整系统 clean control）。

Fig. 4（失败模式归因）
  每个系统的堆叠条：FP 归因到 F2（节点粒度塌缩）/ F5（非泄漏响应不可区分），
  以及因 F3（覆盖上限）从未被评估的漏洞实例数。F7 是机理、不是独立计数，
  用图注说明（修复靶场 `_drain_body` 前 mock 多 3 条 FP，5 -> 2）。

数据源：
  results/processed/metrics.csv          （本文流水线）
  results/processed/zap_baseline.json    （ZAP 基线）
  results/processed/random_baseline.json （随机猜测下界）
  results/processed/failure_modes.json   （Table 12 归因，已断言与基线一致）

用法：
    .venv/bin/python bench/plot_results.py            # 中英两版
    .venv/bin/python bench/plot_results.py --lang en  # 只出英文
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "results" / "processed"
OUT = ROOT / "paper" / "figures"
SYSTEMS = ["mock", "clean", "crapi", "vampi"]
VULN_SYSTEMS = ["mock", "crapi", "vampi"]
NAME = {"mock": "MockShop", "clean": "MockShop-secure", "crapi": "crAPI", "vampi": "VAmPI"}

TEXT = {
    "zh": {
        "f1": "(a) F1（灰带 = 随机猜测）",
        "f1_y": "F1",
        "recall": "(b) Recall(strict)",
        "recall_y": "Recall(strict)",
        "fpr": "(c) FP-rate",
        "fpr_y": "FP-rate",
        "ours": "本文流水线",
        "zap": "ZAP Access Control",
        "random": "随机猜测 F1",
        "fp_f2": "FP：F2 节点粒度塌缩",
        "fp_f5": "FP：F5 非泄漏响应不可区分",
        "miss_f3": "漏检：F3 覆盖上限（未评估）",
        "modes_y": "实例数",
        "modes_title": "失败模式归因（ZAP）",
    },
    "en": {
        "f1": "(a) F1 (band = random guess)",
        "f1_y": "F1",
        "recall": "(b) Recall(strict)",
        "recall_y": "Recall(strict)",
        "fpr": "(c) FP-rate",
        "fpr_y": "FP-rate",
        "ours": "Ours",
        "zap": "ZAP Access Control",
        "random": "Random-guess F1",
        "fp_f2": "FP: F2 node-granularity collapse",
        "fp_f5": "FP: F5 non-leaking responses",
        "miss_f3": "Missed: F3 coverage ceiling",
        "modes_y": "Instances",
        "modes_title": "Failure-mode attribution (ZAP)",
    },
}


def _use_cjk_font() -> None:
    for cand in ("Noto Sans CJK SC", "Noto Sans CJK JP", "WenQuanYi Zen Hei", "SimHei"):
        if any(cand in f.name for f in font_manager.fontManager.ttflist):
            plt.rcParams["font.sans-serif"] = [cand]
            break
    plt.rcParams["axes.unicode_minus"] = False


def load_data() -> dict:
    rows = list(csv.DictReader((PROC / "metrics.csv").open(encoding="utf-8")))
    ours = {r["system"]: r for r in rows if r["tag"] == "default"}
    zap = json.loads((PROC / "zap_baseline.json").read_text(encoding="utf-8"))
    zrows = {r["system"]: r for r in zap["rows"]}
    tot = zap["totals_over_vuln_systems"]
    rnd = json.loads((PROC / "random_baseline.json").read_text(encoding="utf-8"))
    modes = json.loads((PROC / "failure_modes.json").read_text(encoding="utf-8"))
    return {"ours": ours, "zap": zrows, "ztot": tot, "rnd": rnd,
            "modes": {r["system"]: r for r in modes["rows"]}}


def render_fig3(d: dict, lang: str) -> None:
    t = TEXT[lang]
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.45))

    # ---- (a) F1 ----
    ax = axes[0]
    xs = range(len(VULN_SYSTEMS))
    names = [NAME[s] for s in VULN_SYSTEMS]
    ours_f1 = [float(d["ours"][s]["f1"]) for s in VULN_SYSTEMS]
    zap_f1 = [float(d["zap"][s]["f1"]) for s in VULN_SYSTEMS]
    ax.bar([x - 0.19 for x in xs], ours_f1, width=0.36, color="0.15",
           edgecolor="black", label=t["ours"])
    ax.bar([x + 0.19 for x in xs], zap_f1, width=0.36, color="white",
           edgecolor="black", hatch="//", label=t["zap"])
    r = d["rnd"]["simulation"]["f1"]
    ax.axhspan(r["lo95"], r["hi95"], color="0.85", alpha=0.55, zorder=0)
    ax.axhline(r["mean"], color="0.35", linestyle="--", linewidth=0.8, zorder=1)
    for i, v in enumerate(ours_f1):
        ax.text(i - 0.19, v + 0.02, f"{v:.3f}", ha="center", fontsize=6.5)
    for i, v in enumerate(zap_f1):
        ax.text(i + 0.19, v + 0.02, f"{v:.3f}", ha="center", fontsize=6.5)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(names)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel(t["f1_y"])
    ax.set_title(t["f1"], fontsize=8.5)
    ax.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)

    # ---- (b) Recall(strict) ----
    ax = axes[1]
    ours_r = [1.0] * len(VULN_SYSTEMS)
    zap_r = [float(d["zap"][s]["recall_strict"]) for s in VULN_SYSTEMS]
    ax.bar([x - 0.19 for x in xs], ours_r, width=0.36, color="0.15", edgecolor="black")
    ax.bar([x + 0.19 for x in xs], zap_r, width=0.36, color="white",
           edgecolor="black", hatch="//")
    for i, (vo, vz) in enumerate(zip(ours_r, zap_r)):
        if abs(vo - vz) < 0.002:
            ax.text(i, vo + 0.02, f"{vo:.3f}", ha="center", fontsize=6.5)
        else:
            ax.text(i - 0.19, vo + 0.02, f"{vo:.3f}", ha="center", fontsize=6.5)
            ax.text(i + 0.19, vz + 0.02, f"{vz:.3f}", ha="center", fontsize=6.5)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(names)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel(t["recall_y"])
    ax.set_title(t["recall"], fontsize=8.5)
    ax.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)

    # ---- (c) FP-rate ----
    ax = axes[2]
    xs4 = range(len(SYSTEMS))
    names4 = ["MockShop", "MockShop-sec.", "crAPI", "VAmPI"]
    ours_fpr = []
    for s in SYSTEMS:
        if s == "clean":
            ours_fpr.append(0.0)  # 50 条安全实例、0 告警（results/raw/clean/results.jsonl）
        else:
            r0 = d["ours"][s]
            ours_fpr.append(float(r0["fp"]) / max(1.0, float(r0["fp"]) + float(r0["tn"])))
    zap_fpr = [float(d["zap"][s]["fp_rate"]) for s in SYSTEMS]
    ax.bar([x - 0.19 for x in xs4], ours_fpr, width=0.36, color="0.15", edgecolor="black")
    ax.bar([x + 0.19 for x in xs4], zap_fpr, width=0.36, color="white",
           edgecolor="black", hatch="//")
    for i, v in enumerate(zap_fpr):
        ax.text(i + 0.19, v + 0.015, f"{v:.3f}", ha="center", fontsize=6.2)
    for i, v in enumerate(ours_fpr):
        ax.text(i - 0.19, v + 0.015, f"{v:.3f}", ha="center", fontsize=6.2)
    ax.set_xticks(list(xs4))
    ax.set_xticklabels(names4, rotation=22, ha="right", fontsize=6.2)
    ax.set_ylim(0, max(zap_fpr) * 1.35)
    ax.set_ylabel(t["fpr_y"])
    ax.set_title(t["fpr"], fontsize=8.5)
    ax.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)

    fig.tight_layout(rect=(0, 0.08, 1, 1))
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, frameon=False, fontsize=7)
    _save(fig, "fig3_rq1", lang)


def render_fig4(d: dict, lang: str) -> None:
    t = TEXT[lang]
    fig, ax = plt.subplots(figsize=(4.6, 2.5))
    systems = ["mock", "clean", "crapi", "vampi"]
    ys = list(range(len(systems)))
    f2 = [d["modes"][s]["fp_f2"] for s in systems]
    f5 = [d["modes"][s]["fp_f5"] for s in systems]
    miss = [d["modes"][s]["miss_f3"] for s in systems]

    ax.barh(ys, f2, color="0.20", edgecolor="black", label=t["fp_f2"])
    ax.barh(ys, f5, left=f2, color="0.62", edgecolor="black", label=t["fp_f5"])
    ax.barh(ys, miss, left=[a + b for a, b in zip(f2, f5)], color="white",
            edgecolor="black", hatch="\\\\", label=t["miss_f3"])
    for i, s in enumerate(systems):
        total = f2[i] + f5[i] + miss[i]
        if total:
            ax.text(total + 0.3, i, str(total), va="center", fontsize=7)
    ax.set_yticks(ys)
    ax.set_yticklabels([NAME[s] for s in systems])
    ax.invert_yaxis()
    ax.set_xlabel(t["modes_y"])
    ax.set_title(t["modes_title"], fontsize=9)
    ax.legend(fontsize=6.2, frameon=False, loc="lower right")
    ax.grid(axis="x", linestyle=":", linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)
    ax.set_xlim(0, 22)
    fig.tight_layout()
    _save(fig, "fig4_failure_modes", lang)


def _save(fig, stem: str, lang: str) -> None:
    suffix = "" if lang == "zh" else "_en"
    for ext in ("pdf", "png"):
        p = OUT / f"{stem}{suffix}.{ext}"
        fig.savefig(p, dpi=300 if ext == "png" else None, bbox_inches="tight")
        print(f"-> {p}")
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", choices=["zh", "en", "both"], default="both")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    _use_cjk_font()
    plt.rcParams["font.size"] = 8
    d = load_data()
    for lang in (("zh", "en") if args.lang == "both" else (args.lang,)):
        render_fig3(d, lang)
        render_fig4(d, lang)


if __name__ == "__main__":
    main()