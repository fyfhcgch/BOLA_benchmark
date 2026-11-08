"""Fig.2：基准构成（§III-F）。所有数字从 bench/labels/ 现算，不手填。

两个分面：
  (a) 每个系统的标注量，按"漏洞实例 / 安全对照实例"堆叠
  (b) 难度分布（L1/L2/L3），按系统分组

输出 PDF（矢量，投稿用）+ PNG（预览用），灰度可辨（用填充图案而非仅靠颜色）。
中英文两版：中文期刊用 `--lang zh`，IEEE/arXiv 用 `--lang en`。

用法：
    python bench/plot_benchmark.py            # 两版都出
    python bench/plot_benchmark.py --lang en  # 只出英文
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = Path(__file__).resolve().parent.parent
LABELS = ROOT / "bench" / "labels"
OUT = ROOT / "paper" / "figures"
SYSTEMS = ["mock", "crapi", "vampi"]
NAME = {"mock": "MockShop", "crapi": "crAPI", "vampi": "VAmPI"}

TEXT = {
    "zh": {
        "ylabel": "标注实例数",
        "a_title": "(a) 标注量与安全对照",
        "b_title": "(b) 难度分布（L1/L2/L3）",
        "vuln": "漏洞实例",
        "safe": "安全对照",
    },
    "en": {
        "ylabel": "Labeled instances",
        "a_title": "(a) Label volume and safe controls",
        "b_title": "(b) Difficulty tiers (L1/L2/L3)",
        "vuln": "Vulnerable",
        "safe": "Safe control",
    },
}


def _use_cjk_font() -> None:
    for cand in ("Noto Sans CJK SC", "Noto Sans CJK JP", "WenQuanYi Zen Hei", "SimHei"):
        if any(cand in f.name for f in font_manager.fontManager.ttflist):
            plt.rcParams["font.sans-serif"] = [cand]
            break
    plt.rcParams["axes.unicode_minus"] = False


def load() -> dict:
    out = {}
    for s in SYSTEMS:
        rows = [json.loads(l) for l in (LABELS / f"{s}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        out[s] = {
            "vuln": sum(r["vulnerable"] for r in rows),
            "safe": sum(not r["vulnerable"] for r in rows),
            "L1": sum(r["difficulty"] == "L1" for r in rows),
            "L2": sum(r["difficulty"] == "L2" for r in rows),
            "L3": sum(r["difficulty"] == "L3" for r in rows),
        }
    return out


def render(d: dict, lang: str) -> None:
    t = TEXT[lang]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.6),
                                   gridspec_kw={"width_ratios": [1, 1.15]})

    xs = range(len(SYSTEMS))
    names = [NAME[s] for s in SYSTEMS]
    vuln = [d[s]["vuln"] for s in SYSTEMS]
    safe = [d[s]["safe"] for s in SYSTEMS]

    # (a) 漏洞 vs 安全对照
    ax1.bar(xs, vuln, width=0.55, color="0.25", edgecolor="black", label=t["vuln"])
    ax1.bar(xs, safe, width=0.55, bottom=vuln, color="white", edgecolor="black",
            hatch="//", label=t["safe"])
    for i in range(len(SYSTEMS)):
        ax1.text(i, vuln[i] + safe[i] + 1.0, f"{vuln[i]}/{safe[i]}", ha="center", fontsize=8)
    ax1.set_xticks(list(xs))
    ax1.set_xticklabels(names)
    ax1.set_ylabel(t["ylabel"])
    ax1.set_ylim(0, max(v + s for v, s in zip(vuln, safe)) * 1.25)
    ax1.set_title(t["a_title"], fontsize=9)
    ax1.legend(fontsize=7, frameon=False, loc="upper right")
    ax1.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.6)
    ax1.set_axisbelow(True)

    # (b) 难度分布：分组柱，灰度三级
    width = 0.26
    grays = {"L1": "0.20", "L2": "0.55", "L3": "0.85"}
    for k, off in zip(("L1", "L2", "L3"), (-width, 0, width)):
        ax2.bar([x + off for x in xs], [d[s][k] for s in SYSTEMS], width=width,
                color=grays[k], edgecolor="black", linewidth=0.6, label=k)
    ax2.set_xticks(list(xs))
    ax2.set_xticklabels(names)
    ax2.set_ylabel(t["ylabel"])
    ax2.set_title(t["b_title"], fontsize=9)
    ax2.legend(fontsize=7, frameon=False, ncol=3, loc="upper right")
    ax2.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.6)
    ax2.set_axisbelow(True)

    fig.tight_layout()
    suffix = "" if lang == "zh" else "_en"
    for ext in ("pdf", "png"):
        p = OUT / f"fig2_benchmark{suffix}.{ext}"
        fig.savefig(p, dpi=300 if ext == "png" else None, bbox_inches="tight")
        print(f"-> {p}")
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", choices=["zh", "en", "both"], default="both")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    _use_cjk_font()
    plt.rcParams["font.size"] = 9
    d = load()
    for lang in (("zh", "en") if args.lang == "both" else (args.lang,)):
        render(d, lang)


if __name__ == "__main__":
    main()
