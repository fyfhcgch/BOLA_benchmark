"""基准统计：§III 需要的每一个数字都从这里算，不许手抄。

标注文件一改，表格就得跟着变；手抄的论文数字迟早会和 `bench/labels/` 脱节，
而"论文表格与发布数据不一致"是 artifact 评审最容易抓的问题。

用法：
    python bench/stats.py            # markdown 表格（直接贴进论文）
    python bench/stats.py --json     # 机器可读，给画图脚本用
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

BENCH = Path(__file__).resolve().parent
LABELS = BENCH / "labels"
# 标注系统（进论文表格的"基准规模"）
SYSTEM_ORDER = ["mock", "crapi", "vampi"]
SYSTEM_NAME = {"mock": "MockShop", "crapi": "crAPI", "vampi": "VAmPI"}

# 整系统 clean control：与 mock 同构、只差授权策略，**不计入基准规模**
# （它的 50 条标注是 mock 的镜像，算进去会把标注量虚增一倍）。
# 单独出表，用于回答"误报是不是被调低了"。
CONTROL_ORDER = ["clean"]
CONTROL_NAME = {"clean": "MockShop-secure"}


def load(system: str) -> tuple[list[dict], list[dict]]:
    # 派生文件（clean.jsonl）带 `//` 注释头，必须跳过，否则 json.loads 会炸
    rows = [json.loads(l) for l in (LABELS / f"{system}.jsonl").read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("//")]
    noref_path = LABELS / f"{system}.noref.jsonl"
    noref = ([json.loads(l) for l in noref_path.read_text(encoding="utf-8").splitlines()
              if l.strip() and not l.startswith("//")]
             if noref_path.exists() else [])
    return rows, noref


def collect_control(system: str) -> dict:
    """整系统 clean control 的单独口径。

    它没有漏洞实例，所以 precision/recall 无定义；该看的是
    "全部安全实例里有几个被误报"。数据来自 `results/raw/<system>/summary.json`
    （由 pipeline.run 现算），不手抄。
    """
    rows, noref = load(system)
    summary_path = Path(__file__).resolve().parent.parent / "results" / "raw" / system / "summary.json"
    info = {"labels": len(rows),
            "vuln": sum(r["vulnerable"] for r in rows),
            "safe": sum(not r["vulnerable"] for r in rows),
            "vulnerable_detections": None, "fp_rate": None,
            "note": "与 mock 同构，只把 MOCK_POLICY 切成 secure"}
    if summary_path.exists():
        d = json.loads(summary_path.read_text(encoding="utf-8"))
        info["vulnerable_detections"] = d.get("fp")
        info["fp_rate"] = d.get("fp_rate")
        info["coverage"] = d.get("coverage")
        info["safe_tested"] = d.get("safe_tested")
    return info


def collect(systems: list[str]) -> dict:
    per_system: dict[str, dict] = {}
    all_rows: list[dict] = []
    all_noref: list[dict] = []
    for s in systems:
        rows, noref = load(s)
        all_rows += rows
        all_noref += noref
        per_system[s] = {
            "labels": len(rows),
            "vuln": sum(r["vulnerable"] for r in rows),
            "safe": sum(not r["vulnerable"] for r in rows),
            "endpoints": len({(r["method"], r["path"]) for r in rows}),
            "templates": len({r["path"] for r in rows}),
            "instances": len({(r["path"], tuple(r["object_ids"])) for r in rows}),
            "object_types": sorted({r["object_type"] for r in rows if r.get("object_type")}),
            "noref": len(noref),
            "difficulty": dict(sorted(collections.Counter(r["difficulty"] for r in rows).items())),
            "kind": dict(sorted(collections.Counter(r.get("vuln_kind") or "?" for r in rows).items())),
            "visibility": dict(sorted(collections.Counter(r.get("visibility") or "?" for r in rows).items())),
            "methods": dict(sorted(collections.Counter(r["method"] for r in rows).items())),
        }
    totals = {
        "labels": len(all_rows),
        "vuln": sum(r["vulnerable"] for r in all_rows),
        "safe": sum(not r["vulnerable"] for r in all_rows),
        "endpoints": len({(r["method"], r["path"]) for r in all_rows}),
        "templates": len({r["path"] for r in all_rows}),
        "object_types": sorted({r["object_type"] for r in all_rows if r.get("object_type")}),
        "noref": len(all_noref),
        "difficulty": dict(sorted(collections.Counter(r["difficulty"] for r in all_rows).items())),
        "kind": dict(sorted(collections.Counter(r.get("vuln_kind") or "?" for r in all_rows).items())),
        "visibility": dict(sorted(collections.Counter(r.get("visibility") or "?" for r in all_rows).items())),
        "methods": dict(sorted(collections.Counter(r["method"] for r in all_rows).items())),
        # 安全对照按成因分类（labeling_spec §5）
        "control_kind": dict(sorted(collections.Counter(
            r["control_kind"] for r in all_rows if not r["vulnerable"] and r.get("control_kind")).items())),
        "vuln_by_kind": dict(sorted(collections.Counter(
            r.get("vuln_kind") for r in all_rows if r["vulnerable"]).items())),
        "scope": dict(sorted(collections.Counter(r.get("scope") or "?" for r in all_rows).items())),
    }

    # 端点清单：按 (系统, 方法, 路径模板) 聚合，给论文 Table 看实例级分布
    ep: dict[tuple[str, str, str], dict] = {}
    for r in all_rows:
        k = (r["system"], r["method"], r["path"])
        e = ep.setdefault(k, {"vuln": 0, "safe": 0, "types": set()})
        e["vuln" if r["vulnerable"] else "safe"] += 1
        if r.get("object_type"):
            e["types"].add(r["object_type"])
    endpoint_rows = [
        (k[0], k[1], k[2], e["vuln"], e["safe"], ",".join(sorted(e["types"])))
        for k, e in sorted(ep.items(), key=lambda kv: (SYSTEM_ORDER.index(kv[0][0]) if kv[0][0] in SYSTEM_ORDER else 99,
                                                        kv[0][2], kv[0][1]))
    ]
    return {"systems": per_system, "totals": totals, "endpoint_rows": endpoint_rows,
            "controls": {s: collect_control(s) for s in CONTROL_ORDER
                         if (LABELS / f"{s}.jsonl").exists()}}


def _table(head: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def render(data: dict) -> str:
    per, tot = data["systems"], data["totals"]
    blocks = []

    blocks.append("### 表 1 系统与标注规模\n\n" + _table(
        ["系统", "标注", "vuln", "safe", "(方法,路径) 对", "路径模板", "对象类型", "noref"],
        [[SYSTEM_NAME[s], str(v["labels"]), str(v["vuln"]), str(v["safe"]), str(v["endpoints"]),
          str(v["templates"]), str(len(v["object_types"])), str(v["noref"])]
         for s, v in per.items()]
        + [["**合计**", f"**{tot['labels']}**", f"**{tot['vuln']}**", f"**{tot['safe']}**",
            f"**{tot['endpoints']}**", f"**{tot['templates']}**",
            f"**{len(tot['object_types'])}**", f"**{tot['noref']}**"]]))

    blocks.append("### 表 2 难度分布\n\n" + _table(
        ["系统", "L1", "L2", "L3", "合计"],
        [[SYSTEM_NAME[s], str(v["difficulty"].get("L1", 0)), str(v["difficulty"].get("L2", 0)),
          str(v["difficulty"].get("L3", 0)), str(v["labels"])] for s, v in per.items()]
        + [["**合计**", f"**{tot['difficulty'].get('L1', 0)}**", f"**{tot['difficulty'].get('L2', 0)}**",
            f"**{tot['difficulty'].get('L3', 0)}**", f"**{tot['labels']}**"]]))

    blocks.append("### 表 3 漏洞类型与请求方法\n\n" + _table(
        ["维度", "取值"],
        [[f"vuln_kind（{tot['vuln']} 条漏洞）",
          ", ".join(f"{k}={v}" for k, v in tot["vuln_by_kind"].items())],
         ["全部 kind", ", ".join(f"{k}={v}" for k, v in tot["kind"].items())],
         ["方法", ", ".join(f"{k}={v}" for k, v in tot["methods"].items())],
         ["可见性", ", ".join(f"{k}={v}" for k, v in tot["visibility"].items())],
         ["scope", ", ".join(f"{k}={v}" for k, v in tot["scope"].items())]]))

    blocks.append("### 表 4 安全对照的成因分布\n\n" + _table(
        ["control_kind", "数量", "含义"],
        [[k, str(v), DESC.get(k, "")] for k, v in tot["control_kind"].items()]
        + [["**合计**", f"**{tot['safe']}**", ""]]))

    blocks.append("### 表 5 端点清单（实例级分布）\n\n" + _table(
        ["系统", "方法", "路径模板", "漏洞实例", "安全实例", "对象类型"],
        [[s, m, f"`{p}`", str(v), str(sf), t] for (s, m, p, v, sf, t) in data["endpoint_rows"]]))

    # 表 6：整系统 clean control。单独成表，且明写"不计入基准规模"。
    ctl = data.get("controls") or {}
    if ctl:
        rows6 = []
        for s, v in ctl.items():
            rows6.append([CONTROL_NAME.get(s, s), str(v["labels"]), str(v["vuln"]),
                          str(v["safe"]), str(v["vulnerable_detections"]),
                          f"{v['fp_rate']:.3f}", v["note"]])
        blocks.append("### 表 6 整系统 clean control（不计入基准规模）\n\n" + _table(
            ["系统", "实例", "vuln", "safe", "告警数", "FP-rate", "说明"], rows6))
    return "\n\n".join(blocks)


DESC = {
    "owner_check": "服务端正确校验归属，非属主返回 403",
    "method_not_allowed": "方法被服务端拒绝（405），写型探测应被排除",
    "public_resource": "资源对所有登录用户可见，读到作者身份是设计行为",
    "ignored_identifier": "路径里有标识，但服务端忽略它、只改调用者自己的对象",
    "no_owner_evidence": "可读但响应中没有任何归属证据（如恒为空容器）",
}


def manifest(systems: list[str]) -> dict:
    """标注文件的指纹：论文引用这里，读者可以核对拿到的是同一份数据。

    没有 git tag 的时候（本仓库目前就不是 git 仓库），这是 artifact 可复现性
    的最低要求：至少能证明"论文里的表来自这几个文件的这几个字节"。
    """
    import hashlib

    files = {}
    for s in list(systems) + list(CONTROL_ORDER):
        for name in (f"{s}.jsonl", f"{s}.noref.jsonl"):
            p = LABELS / name
            if not p.exists():
                continue
            raw = p.read_bytes()
            files[name] = {"sha256": hashlib.sha256(raw).hexdigest(),
                           "bytes": len(raw),
                           "lines": raw.decode("utf-8").count("\n")}
    return {"bench_version": (BENCH / "VERSION").read_text(encoding="utf-8").strip()
            if (BENCH / "VERSION").exists() else "dev",
            "files": files, "totals": collect(systems)["totals"]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--systems", nargs="*", default=SYSTEM_ORDER)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--manifest", metavar="PATH",
                    help="写标注文件指纹（论文引用它的 sha256）")
    args = ap.parse_args()
    data = collect(args.systems)
    if args.manifest:
        out = Path(args.manifest)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest(args.systems), ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        print(f"manifest -> {out}")
        return
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(render(data))


if __name__ == "__main__":
    main()
