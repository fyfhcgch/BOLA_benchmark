#!/usr/bin/env python3
"""随机猜测下界（chance-level floor）。

用途：回答一个审稿人必问的最小问题——「0.911 的 F1 是不是随便猜也能拿到？」
做法：对基准里的每一条标注，用一个**与标注无关的**随机判据（以标注基础
正例率为概率掷硬币）给出「有漏洞 / 无漏洞」，在全部 107 条上算 P/R/F1，
重复 10^4 次（固定种子）取均值与 95% 区间。

为什么不做「随机变异重放」的版本：那需要真的向靶场发写请求（PUT password /
DELETE 等），会不可逆地改掉 crAPI/VAmPI 的状态（ZAP 基线已经踩过这个坑，
VAmPI 三个账号的密码被改成 Bola-BASELINE-*）。随机猜测下界只需要标注文件，
零副作用、零外部依赖，且它是任何检测器都必须跨过的**信息下界**：低于它
说明判据连标签分布都没利用上。

输出：
  - results/processed/random_baseline.json （机器可读，供 verify_paper_tables 核对）
  - stdout 打印 markdown 片段

用法：.venv/bin/python baselines/random_baseline.py
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = ROOT / "bench" / "labels"
SYSTEMS = ["mock", "crapi", "vampi"]
OUT = ROOT / "results" / "processed" / "random_baseline.json"
TRIALS = 10_000
SEED = 20261104


def load_labels():
    """返回 [(system, vulnerable), ...]，只含标注实例（noref 不参与）。"""
    out = []
    for sid in SYSTEMS:
        f = LABELS / f"{sid}.jsonl"
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            r = json.loads(line)
            out.append((sid, bool(r.get("vulnerable"))))
    return out


def prf(tp: int, fp: int, fn: int):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def main() -> int:
    labels = load_labels()
    n = len(labels)
    pos = sum(1 for _, v in labels if v)
    base = pos / n

    # 随机判据：每条标注独立地以 base 为概率判「有漏洞」。
    # 期望值可直接解析：TP≈base*pos, FP≈base*(n-pos), FN≈(1-base)*pos
    exp_tp = base * pos
    exp_fp = base * (n - pos)
    exp_fn = (1 - base) * pos
    exp = prf(exp_tp, exp_fp, exp_fn)

    rng = random.Random(SEED)
    ps, rs, f1s = [], [], []
    for _ in range(TRIALS):
        tp = fp = fn = 0
        for _, v in labels:
            flagged = rng.random() < base
            if v and flagged:
                tp += 1
            elif v and not flagged:
                fn += 1
            elif not v and flagged:
                fp += 1
        p, r, f1 = prf(tp, fp, fn)
        ps.append(p)
        rs.append(r)
        f1s.append(f1)

    def q(vals, frac):
        s = sorted(vals)
        return s[int(frac * (len(s) - 1))]

    res = {
        "labels": n, "vulnerable": pos, "safe": n - pos,
        "base_rate": round(base, 4),
        "trials": TRIALS, "seed": SEED,
        "expected": {"precision": round(exp[0], 4), "recall": round(exp[1], 4),
                     "f1": round(exp[2], 4)},
        "simulation": {
            "precision": {"mean": round(sum(ps) / len(ps), 4),
                          "lo95": round(q(ps, 0.025), 4), "hi95": round(q(ps, 0.975), 4)},
            "recall": {"mean": round(sum(rs) / len(rs), 4),
                       "lo95": round(q(rs, 0.025), 4), "hi95": round(q(rs, 0.975), 4)},
            "f1": {"mean": round(sum(f1s) / len(f1s), 4),
                   "lo95": round(q(f1s, 0.025), 4), "hi95": round(q(f1s, 0.975), 4)},
        },
        "note": ("随机猜测下界：判据与标注无关，仅以基础正例率掷硬币；"
                 "重复 10^4 次取均值与 95% 经验区间。"),
    }
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"标注 {n} 条（漏洞 {pos} / 安全 {n - pos}），基础正例率 {base:.4f}")
    print(f"期望   P={exp[0]:.3f}  R={exp[1]:.3f}  F1={exp[2]:.3f}")
    for k in ("precision", "recall", "f1"):
        d = res["simulation"][k]
        print(f"{k:10s} mean={d['mean']:.3f}  95% [{d['lo95']:.3f}, {d['hi95']:.3f}]")
    print(f"已写入 {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
