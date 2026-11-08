"""72 小时重标工具（bench/relabel.py）的单元测试。

守住的四件事：
  1. κ 的计算与教科书公式一致（含完全一致、完全不一致、退化情形）
  2. 冻结后 `frozen.jsonl` 的 sha256 与 meta 记录一致
  3. 盲标卷里**绝对不能出现答案字段**（vulnerable / control_kind / note）
  4. 出卷按固定种子打乱，重跑同一条命令得到同一顺序（可复现）

跑法：
    .venv/bin/python -m pytest -q tests/test_relabel.py
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import relabel  # noqa: E402


# ---------------- κ ----------------

def test_kappa_perfect_agreement():
    a = [True, False, True, False, True, False]
    k = relabel.kappa_nominal(a, list(a))
    assert k["po"] == 1.0
    assert k["kappa"] == 1.0


def test_kappa_textbook_value():
    """经典例子：两方各判 50 正 50 负，一致 80 条 -> κ = 0.6。

    p_o = 0.8，p_e = 0.5*0.5 + 0.5*0.5 = 0.5，(0.8-0.5)/(1-0.5) = 0.6
    """
    a = [True] * 50 + [False] * 50
    b = [True] * 40 + [False] * 10 + [True] * 10 + [False] * 40
    k = relabel.kappa_nominal(a, b)
    assert k["n"] == 100
    assert k["po"] == pytest.approx(0.8)
    assert k["pe"] == pytest.approx(0.5)
    assert k["kappa"] == pytest.approx(0.6)


def test_kappa_total_disagreement_is_negative_one():
    """p_o=0 且 p_e=0.5 时 κ=-1（两方各用一半类别，但完全反着判）。

    注意：两方都只用**单一但不同**的类别时 p_e=0，κ=0 而不是 -1 ——
    这种退化情形容易写错，见下一个用例。
    """
    a = [True] * 10 + [False] * 10
    b = [False] * 10 + [True] * 10
    k = relabel.kappa_nominal(a, b)
    assert k["po"] == 0.0
    assert k["pe"] == pytest.approx(0.5)
    assert k["kappa"] == -1.0


def test_kappa_single_category_mismatch_is_zero_not_negative_one():
    """a 全是 True、b 全是 False：p_e = 1*0 + 0*1 = 0，κ=(0-0)/(1-0)=0。"""
    k = relabel.kappa_nominal([True] * 10, [False] * 10)
    assert k["po"] == 0.0
    assert k["pe"] == 0.0
    assert k["kappa"] == 0.0


def test_kappa_degenerate_single_category():
    """两方都只用一个类别时 p_e=1，κ 无定义；不能除零，要显式给 1.0。"""
    a = [True] * 8
    b = [True] * 8
    k = relabel.kappa_nominal(a, b)
    assert k["kappa"] == 1.0


def test_kappa_multiclass_nominal():
    """三分类名义 κ 与二分类走同一公式。"""
    a = ["L1", "L1", "L2", "L2", "L3", "L3"]
    b = ["L1", "L2", "L2", "L3", "L3", "L3"]
    k = relabel.kappa_nominal(a, b)
    assert k["n"] == 6
    assert k["po"] == pytest.approx(4 / 6, abs=1e-4)
    # p_e = (2/6)*(1/6) + (2/6)*(2/6) + (2/6)*(3/6)
    assert k["pe"] == pytest.approx((2 / 36) + (4 / 36) + (6 / 36), abs=1e-4)
    assert -1.0 <= k["kappa"] <= 1.0


def test_bootstrap_ci_brackets_point_estimate():
    a = [True, True, False, False, True, False, True, True]
    b = [True, True, False, True, True, False, True, False]
    point = relabel.kappa_nominal(a, b)["kappa"]
    lo, hi = relabel._bootstrap_ci(a, b, iters=200)
    assert lo <= point <= hi
    assert lo < hi


# ---------------- 冻结 / 出卷 / 评分 ----------------

@pytest.fixture()
def tmp_bench(tmp_path, monkeypatch):
    """把 relabel 的输出目录指到临时目录，避免动到真实 results/。"""
    labels = tmp_path / "labels"
    labels.mkdir()
    for s in ("mock", "crapi", "vampi"):
        rows = [
            {"id": f"{s}-0001", "system": s, "method": "GET", "path": "/a/{id}",
             "object_ids": ["1"], "victim": "alice", "object_type": "order",
             "vulnerable": True, "difficulty": "L1", "vuln_kind": "read",
             "note": "真漏洞"},
            {"id": f"{s}-0002", "system": s, "method": "GET", "path": "/b/{id}",
             "object_ids": ["2"], "victim": "bob", "object_type": "order",
             "vulnerable": False, "difficulty": "L2", "vuln_kind": "none",
             "control_kind": "owner_check", "note": "安全对照"},
        ]
        (labels / f"{s}.jsonl").write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8")
    monkeypatch.setattr(relabel, "LABELS", labels)
    monkeypatch.setattr(relabel, "OUT", tmp_path / "relabel")
    return tmp_path / "relabel"


def test_freeze_records_sha256_and_labels(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    meta = json.loads((tmp_bench / "frozen.meta.json").read_text(encoding="utf-8"))
    frozen = tmp_bench / "frozen.jsonl"
    assert meta["labels"] == 6
    assert meta["vuln"] == 3 and meta["safe"] == 3
    assert meta["frozen_sha256"] == relabel._sha256(frozen)
    assert meta["hold_hours"] == 72
    # 每个系统都记了自己的指纹（冻结后改动可被 status 发现）
    assert set(meta["systems"]) == {"mock", "crapi", "vampi"}
    for info in meta["systems"].values():
        assert len(info["sha256"]) == 64


def test_freeze_twice_refuses_without_force(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["freeze"]) == 1


def test_sheet_never_leaks_answer_fields(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    sheet = [json.loads(l) for l in
             (tmp_bench / "blind_sheet.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(sheet) == 6
    leaked = {"vulnerable", "control_kind", "note", "difficulty", "vuln_kind"}
    for r in sheet:
        assert not (leaked & set(r)), f"{r['id']} 泄露了答案字段 {leaked & set(r)}"
        assert set(r) == set(relabel.SHEET_FIELDS) | {"seq"}
    # 答案文件里 vulnerable 必须是空的，否则等于给了答案
    ans = [json.loads(l) for l in
           (tmp_bench / "relabel.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    assert all(a["vulnerable"] is None for a in ans)


def test_sheet_is_deterministic(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    first = (tmp_bench / "blind_sheet.jsonl").read_text(encoding="utf-8")
    assert relabel.main(["sheet", "--early"]) == 0
    assert (tmp_bench / "blind_sheet.jsonl").read_text(encoding="utf-8") == first


def test_sheet_interleaves_systems(tmp_bench):
    """打乱后不能是"三个 mock 连着三个 crapi"——那样会按系统成块回忆。"""
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    sheet = [json.loads(l) for l in
             (tmp_bench / "blind_sheet.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    systems = [r["system"] for r in sheet]
    blocks = sum(1 for i in range(1, len(systems)) if systems[i] == systems[i - 1])
    assert blocks <= len(systems) // 2, f"分块太多：{systems}"


def test_sheet_writes_fillable_csv(tmp_bench):
    """表格版必须存在、条数一致、答案列全空（否则等于提前给答案）。"""
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    path = tmp_bench / "blind_sheet.csv"
    assert path.exists()
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 6
    for r in rows:
        assert r["id"]
        assert r["vulnerable"] == "" and r["difficulty"] == ""
        assert r["control_kind"] == "" and r["uncertain"] == ""


def test_import_csv_roundtrip(tmp_bench):
    """填好 CSV 后导入：true/false/uncertain 正确转义，未填的保持 None。"""
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    path = tmp_bench / "blind_sheet.csv"
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    rows[0]["vulnerable"] = "true"
    rows[1]["vulnerable"] = "false"
    rows[2]["uncertain"] = "true"
    rows[2]["note"] = "说不准"
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    assert relabel.main(["import-csv"]) == 0
    ans = [json.loads(l) for l in
           (tmp_bench / "relabel.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    byid = {a["id"]: a for a in ans}
    assert byid[rows[0]["id"]]["vulnerable"] is True
    assert byid[rows[1]["id"]]["vulnerable"] is False
    assert byid[rows[2]["id"]]["uncertain"] is True
    assert byid[rows[2]["id"]]["note"] == "说不准"
    # 3 条真未填 + 1 条 fill 了 uncertain（vulnerable 允许为空）
    assert sum(1 for a in ans if a["vulnerable"] is None) == 4


def test_sheet_refuses_before_72h(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet"]) == 1


def test_score_perfect_relabel_gives_kappa_one(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    frozen = {r["id"]: r for r in
              (json.loads(l) for l in (tmp_bench / "frozen.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())}
    ans = [{"id": i, "vulnerable": bool(r["vulnerable"]), "difficulty": r["difficulty"],
            "control_kind": r.get("control_kind"), "uncertain": False, "note": ""}
           for i, r in frozen.items()]
    (tmp_bench / "relabel.jsonl").write_text(
        "\n".join(json.dumps(a, ensure_ascii=False) for a in ans) + "\n", encoding="utf-8")
    assert relabel.main(["score"]) == 0
    out = json.loads((tmp_bench / "kappa.json").read_text(encoding="utf-8"))
    assert out["kappa"] == 1.0
    assert out["n_paired"] == 6
    assert out["disagreements"] == []
    assert out["difficulty_kappa"]["kappa"] == 1.0


def test_score_uncertain_and_unfilled_are_excluded(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    frozen = [json.loads(l) for l in
              (tmp_bench / "frozen.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    # 一条判不准、一条不填，剩下的答对 -> κ 仍是 1.0 但 n 变小
    ans = []
    for i, r in enumerate(frozen):
        if i == 0:
            ans.append({"id": r["id"], "vulnerable": None, "uncertain": True, "note": "说不准"})
        elif i == 1:
            ans.append({"id": r["id"], "vulnerable": None, "uncertain": False, "note": ""})
        else:
            ans.append({"id": r["id"], "vulnerable": bool(r["vulnerable"]),
                        "uncertain": False, "note": ""})
    (tmp_bench / "relabel.jsonl").write_text(
        "\n".join(json.dumps(a, ensure_ascii=False) for a in ans) + "\n", encoding="utf-8")
    assert relabel.main(["score"]) == 0
    out = json.loads((tmp_bench / "kappa.json").read_text(encoding="utf-8"))
    assert out["n_paired"] == 4
    assert out["n_uncertain"] == 1
    assert out["n_unfilled"] == 1


def test_score_flags_disagreement(tmp_bench):
    assert relabel.main(["freeze"]) == 0
    assert relabel.main(["sheet", "--early"]) == 0
    frozen = [json.loads(l) for l in
              (tmp_bench / "frozen.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    # 故意把第一条判反
    ans = [{"id": r["id"],
            "vulnerable": (not bool(r["vulnerable"])) if i == 0 else bool(r["vulnerable"]),
            "uncertain": False, "note": ""}
           for i, r in enumerate(frozen)]
    (tmp_bench / "relabel.jsonl").write_text(
        "\n".join(json.dumps(a, ensure_ascii=False) for a in ans) + "\n", encoding="utf-8")
    rc = relabel.main(["score"])
    out = json.loads((tmp_bench / "kappa.json").read_text(encoding="utf-8"))
    assert len(out["disagreements"]) == 1
    d = out["disagreements"][0]
    assert d["id"] == frozen[0]["id"]
    assert d["frozen_note"]          # 分歧条目要能回溯到原始说明
    assert rc == 2                   # 未达标返回非零，方便 CI/Makefile 拦住


def test_status_detects_post_freeze_edit(tmp_bench, capsys):
    assert relabel.main(["freeze"]) == 0
    # 冻结后又往标注里加了一条（模拟"补 L3 之后忘了重新冻结"）
    p = relabel.LABELS / "mock.jsonl"
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"id": "mock-9999", "system": "mock", "method": "GET",
                            "path": "/c/{id}", "object_ids": ["9"], "victim": "carol",
                            "vulnerable": True, "difficulty": "L3", "vuln_kind": "read"},
                           ensure_ascii=False) + "\n")
    assert relabel.main(["status"]) == 0
    err = capsys.readouterr().out
    assert "冻结后改过" in err
