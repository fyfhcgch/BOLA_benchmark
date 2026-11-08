"""Fig. 4 的数据源：把 §IV-C 的失败模式归因落成可核对的 JSON。

F2/F5 的逐系统归因来自正文 Table 12 的人工分析（哪条告警属于哪类机理），
本脚本**不重新判定**，只做两件事：
  1. 把归因写成 `results/processed/failure_modes.json`，供画图脚本消费；
  2. 断言归因之和 == `zap_baseline.json` 的 fp，且 F3 漏检 == vuln - tp，
     防止"表格写 11 条、图里画 12 条"这类漂移。

F7 不是独立计数：它是"判据对非预期响应脆弱"的机理，表现为修复靶场
`_drain_body` 之前 mock 多出的 3 条 FP（5 → 2）。因此图里只画 F2/F5/F3，
F7 用图注说明，避免把机理重复计成实例。

用法：
    .venv/bin/python baselines/zap/failure_modes.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ZAP = ROOT / "results" / "processed" / "zap_baseline.json"
LABELS = ROOT / "bench" / "labels"
OUT = ROOT / "results" / "processed" / "failure_modes.json"

# Table 12 的证据列逐条清点（人工分析，非脚本可推导）
FP_F2 = {"mock": 1, "clean": 2, "crapi": 0, "vampi": 0}   # 节点粒度塌缩：batch/mine 类
FP_F5 = {"mock": 1, "clean": 4, "crapi": 3, "vampi": 3}   # 非泄漏响应不可区分
EXPECTED_F2, EXPECTED_F5 = 3, 11


def vuln_count(system: str) -> int:
    path = LABELS / f"{system}.jsonl"
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return 0
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.lstrip().startswith(("#", "//"))]
    return sum(1 for r in rows if r.get("vulnerable"))


def main() -> None:
    zap = json.loads(ZAP.read_text(encoding="utf-8"))
    rows = []
    for r in zap["rows"]:
        sid = r["system"]
        fp = r["fp"]
        f2, f5 = FP_F2.get(sid, 0), FP_F5.get(sid, 0)
        assert f2 + f5 == fp, f"{sid}: F2+F5={f2 + f5} != fp={fp}"
        n_vuln = vuln_count(sid)
        miss = n_vuln - r["tp"]
        assert miss >= 0, f"{sid}: tp={r['tp']} > vuln={n_vuln}"
        rows.append({
            "system": sid,
            "display": r["display"],
            "vulnerable": n_vuln,
            "tested_vulnerable": r["tp"],
            "fp_total": fp,
            "fp_f2": f2,
            "fp_f5": f5,
            "miss_f3": miss,
        })

    assert sum(FP_F2.values()) == EXPECTED_F2, sum(FP_F2.values())
    assert sum(FP_F5.values()) == EXPECTED_F5, sum(FP_F5.values())

    payload = {
        "source": "results/processed/zap_baseline.json + bench/labels/*.jsonl",
        "attribution": "paper/empirical_draft.md Table 12 (manual analysis)",
        "totals": {
            "fp_f2": sum(FP_F2.values()),
            "fp_f5": sum(FP_F5.values()),
            "miss_f3": sum(r["miss_f3"] for r in rows if r["system"] != "clean"),
        },
        "f7_note": "F7 is a mechanism, not a separate count: 3 extra mock FPs before the "
                   "_drain_body fixture fix (5 -> 2), already excluded from post-fix counts.",
        "rows": rows,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"-> {OUT}")
    for r in rows:
        print(f"  {r['system']:6s} FP={r['fp_total']} (F2={r['fp_f2']}, F5={r['fp_f5']}) "
              f"miss(F3)={r['miss_f3']} / vuln={r['vulnerable']}")


if __name__ == "__main__":
    main()