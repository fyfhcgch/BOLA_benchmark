"""指标层：对象实例级匹配。

端点级指标会把不同对象实例混进同一个分母，正好掩盖"同一端点既漏洞又不
漏洞"这一事实。这里按 (method, path_template, object_ids) 一一匹配，并把
三类容易被静默吞掉的情况单独计数：

  uncovered        有标注但从未被测试到 —— 覆盖率缺口
  unlabeled        有告警但没有任何标注 —— 指标虚高的主要来源
  gate_violations  无对象引用的端点仍然出告警 —— has_object_ref 闸门失效

召回给两个口径：
  recall        只在"被测到的标注"上算（方法本身的能力）
  recall_strict 未覆盖的漏洞标注算漏报（端到端能力，写论文用这个）
"""

from __future__ import annotations

import json
from pathlib import Path

Key = tuple[str, str, tuple[str, ...]]


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("//"):
                rows.append(json.loads(line))
    return rows


def _k(record: dict, path_field: str) -> Key:
    return (
        str(record.get("method", "")).upper(),
        str(record.get(path_field) or ""),
        tuple(str(x) for x in (record.get("object_ids") or [])),
    )


def evaluate(results: list[dict], labels: list[dict],
             noref: list[dict] | None = None) -> dict:
    noref = noref or []
    lab: dict[Key, dict] = {_k(l, "path"): l for l in labels}

    tested: set[Key] = set()
    detected: dict[Key, dict] = {}
    unlabeled: list[dict] = []
    gate: list[dict] = []
    skipped_owner = 0
    self_read_alerts: list[dict] = []

    for r in results:
        k = _k(r, "endpoint")
        label = lab.get(k)
        if label is None:
            if not r.get("vuln"):
                continue
            if any(n["method"] == k[0] and n["path"] == k[1] for n in noref):
                gate.append(r)
            else:
                unlabeled.append(r)
            continue
        if r["attacker"] == label.get("victim"):
            # 攻击者就是对象属主，这不是 BOLA 测试。
            # 但它仍然是一次**判据体检**：属主读自己的对象却被判成越权，说明判据
            # 根本没在比对身份（典型是"只看 owner 键名、不看值"）。这类告警不进
            # precision 分母（它不是 BOLA 测试），但必须单独计数并披露——
            # 否则"静默 continue"会把判据的身份盲区藏起来。
            skipped_owner += 1
            if r.get("vuln"):
                self_read_alerts.append(r)
            continue
        tested.add(k)
        if r.get("vuln"):
            detected.setdefault(k, r)

    violated = [k for k in tested if k in detected and not lab[k].get("vulnerable")]
    tp = [k for k in tested if k in detected and lab[k].get("vulnerable")]
    fn = [k for k in tested if k not in detected and lab[k].get("vulnerable")]
    tn = [k for k in tested if k not in detected and not lab[k].get("vulnerable")]
    uncovered = [k for k in lab if k not in tested]
    uncovered_vuln = [k for k in uncovered if lab[k].get("vulnerable")]

    fp = len(violated) + len(unlabeled)
    p = len(tp) / (len(tp) + fp) if (len(tp) + fp) else 0.0
    r_tested = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) else 0.0
    denom = len(tp) + len(fn) + len(uncovered_vuln)
    r_strict = len(tp) / denom if denom else 0.0
    f1 = 2 * p * r_tested / (p + r_tested) if (p + r_tested) else 0.0
    coverage = len(tested) / len(lab) if lab else 0.0

    # 误报率：分母是"被测到的安全实例"。整系统 clean control 上没有任何漏洞实例，
    # precision 的分母为 0、按约定记 0.000，那个数字毫无意义；
    # 该看的是"50 个安全实例里被误报几个"。这个口径对所有系统都成立。
    safe_tested = len(tn) + len(violated)
    fp_rate = len(violated) / safe_tested if safe_tested else 0.0

    return {
        "labels_total": len(lab),
        "labels_tested": len(tested),
        "labels_uncovered": len(uncovered),
        "coverage": round(coverage, 4),
        "tp": len(tp), "fp": fp, "fn": len(fn), "tn": len(tn),
        "fp_unlabeled": len(unlabeled),
        "gate_violations": len(gate),
        "tests_total": len(results),
        "tests_skipped_owner": skipped_owner,
        # 属主读自己的对象却被判越权 = 判据对身份不敏感。不进 precision，但必须披露。
        "self_read_alerts": len(self_read_alerts),
        "self_read_alert_records": self_read_alerts[:50],
        # precision 在 TP+FP=0 时无定义；clean 对照必须看 fp_rate 而不是 precision
        "precision_defined": bool(len(tp) + fp),
        "precision": round(p, 4),
        "fp_rate": round(fp_rate, 4),
        "safe_tested": safe_tested,
        "recall": round(r_tested, 4),
        "recall_strict": round(r_strict, 4),
        "f1": round(f1, 4),
        # 明细供 failures 分析使用
        "tp_keys": [list(k) for k in tp],
        "fn_keys": [list(k) for k in fn],
        "tn_keys": [list(k) for k in tn],
        "fp_labeled_keys": [list(k) for k in violated],
        "fp_unlabeled_records": unlabeled,
        "gate_violation_records": gate,
        "uncovered_vuln_keys": [list(k) for k in uncovered_vuln],
    }


def report(res: dict, width: int = 46) -> list[str]:
    lines = [
        f"  labels={res['labels_total']}  tested={res['labels_tested']}  "
        f"uncovered={res['labels_uncovered']}  (coverage={res['coverage']:.3f})",
        f"  TP={res['tp']}  FP={res['fp']}  FN={res['fn']}  TN={res['tn']}",
    ]
    if res.get("precision_defined", True):
        lines.append(
            f"  Precision={res['precision']:.3f}  Recall={res['recall']:.3f}  "
            f"Recall(strict)={res['recall_strict']:.3f}  F1={res['f1']:.3f}"
        )
    else:
        # 整系统 clean control：没有漏洞实例，precision/F1 无定义。
        # 该报的是"安全实例被误报的比例"，见 evaluate.py 的注释。
        lines.append(
            f"  Precision=undefined(TP+FP=0)  Recall=undefined(无漏洞实例)  "
            f"FP-rate={res['fp_rate']:.3f} ({res['fp']}/{res['safe_tested']} 个安全实例)"
        )
    if res["fp_unlabeled"] or res["gate_violations"]:
        lines.append(
            f"  unlabeled_detections={res['fp_unlabeled']}  "
            f"gate_violations={res['gate_violations']}"
        )
    if res["tests_skipped_owner"]:
        lines.append(f"  skipped(attacker==owner)={res['tests_skipped_owner']}")

    if res["uncovered_vuln_keys"]:
        lines.append("  uncovered (vulnerable, never tested):")
        for m, tpl, ids in res["uncovered_vuln_keys"]:
            lines.append(f"    {m:6s} {tpl:{width}s} ids={','.join(ids)}")
    if res["fn_keys"]:
        lines.append("  missed (tested but not detected):")
        for m, tpl, ids in res["fn_keys"]:
            lines.append(f"    {m:6s} {tpl:{width}s} ids={','.join(ids)}")
    if res["fp_labeled_keys"]:
        lines.append("  false positives (labeled safe):")
        for m, tpl, ids in res["fp_labeled_keys"]:
            lines.append(f"    {m:6s} {tpl:{width}s} ids={','.join(ids)}")
    if res["fp_unlabeled_records"]:
        lines.append("  unlabeled detections (counted as FP):")
        for r in res["fp_unlabeled_records"]:
            ids = ",".join(str(x) for x in r.get("object_ids") or [])
            lines.append(f"    {r['method']:6s} {r['endpoint']:{width}s} ids={ids} "
                         f"via={r['variant']} {r.get('reason', '')}")
    if res["gate_violation_records"]:
        lines.append("  gate violations (no object ref, should never be tested):")
        for r in res["gate_violation_records"]:
            lines.append(f"    {r['method']:6s} {r['endpoint']:{width}s} {r.get('reason', '')}")
    return lines
