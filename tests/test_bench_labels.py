"""标注文件的一致性测试：论文表格的每个数字都来自这些文件，必须能自动校验。

跑法：
    .venv/bin/python -m pytest -q

守住的四件事：
  1. 标注的必填字段齐全、枚举值合法（schema.json 的机器可读部分）
  2. id 全局唯一、object_ids 非空
  3. 安全对照必须写清 control_kind（否则 §III 的成因分布表算不出来）
  4. noref 文件里的端点真的不带对象引用（否则闸门对照组本身是脏的）
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.ids import has_object_ref  # noqa: E402

LABELS = ROOT / "bench" / "labels"
SYSTEMS = ["mock", "crapi", "vampi"]
REQUIRED = {"id", "system", "method", "path", "victim", "object_ids", "vulnerable"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
DIFFICULTY = {"L1", "L2", "L3"}
KINDS = {"read", "write", "delete", "none"}
VISIBILITY = {"private", "public", "role_scoped"}
CONTROL = {"owner_check", "method_not_allowed", "public_resource",
           "ignored_identifier", "no_owner_evidence"}


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.fixture(scope="module")
def labels() -> dict[str, list[dict]]:
    return {s: _rows(LABELS / f"{s}.jsonl") for s in SYSTEMS}


@pytest.fixture(scope="module")
def noref() -> dict[str, list[dict]]:
    return {s: _rows(LABELS / f"{s}.noref.jsonl") for s in SYSTEMS}


def test_every_system_has_labels(labels):
    for s in SYSTEMS:
        assert labels[s], f"{s} 没有标注"


def test_required_fields_and_enums(labels):
    for s, rows in labels.items():
        for r in rows:
            missing = REQUIRED - set(r)
            assert not missing, f"{s}/{r.get('id')} 缺字段 {missing}"
            assert r["system"] == s, f"{r['id']} 的 system 与文件名不一致"
            assert r["method"] in METHODS, r["id"]
            assert r["difficulty"] in DIFFICULTY, r["id"]
            assert r["vuln_kind"] in KINDS, r["id"]
            assert r.get("visibility", "private") in VISIBILITY, r["id"]
            assert isinstance(r["vulnerable"], bool), r["id"]
            assert r["object_ids"], f"{r['id']} 的 object_ids 为空（不是 BOLA 测试）"


def test_ids_globally_unique(labels):
    ids = [r["id"] for rows in labels.values() for r in rows]
    dup = {i for i in ids if ids.count(i) > 1}
    assert not dup, f"重复 id: {dup}"


def test_safe_labels_declare_control_kind(labels):
    """安全对照必须能归因，否则 §III 的"误报产生在哪类对照上"统计无从算起。"""
    for s, rows in labels.items():
        for r in rows:
            if r["vulnerable"]:
                assert "control_kind" not in r, f"{r['id']} 是漏洞却标了 control_kind"
            else:
                assert r.get("control_kind") in CONTROL, \
                    f"{r['id']} 缺 control_kind（安全对照必须说明成因）"


def test_public_visibility_matches_public_resource(labels):
    """§II-B 把"公开资源"写进 scope(s)：public 可见性只能对应 public_resource 对照。

    这条约束是 §II 定义 1 与 §III-E 表 5 的接口。若以后有人把一条漏洞标成
    public，或者把一条 owner_check 标成 public，两节就会自相矛盾。
    """
    for s, rows in labels.items():
        for r in rows:
            if r.get("visibility") == "public":
                assert not r["vulnerable"], f"{r['id']} 标为 public 却是漏洞"
                assert r.get("control_kind") == "public_resource", \
                    f"{r['id']} 标为 public 但 control_kind={r.get('control_kind')}"
            if r.get("control_kind") == "public_resource":
                assert r.get("visibility") == "public", \
                    f"{r['id']} 是 public_resource 但 visibility={r.get('visibility')}"


def test_path_template_matches_object_ids(labels):
    """路径模板里的占位符数量应与 object_ids 一致（查询参数型除外）。"""
    for s, rows in labels.items():
        for r in rows:
            n_placeholders = r["path"].count("{")
            if n_placeholders:
                assert len(r["object_ids"]) >= n_placeholders, \
                    f"{r['id']}: {r['path']} 需要 {n_placeholders} 个标识，只有 {r['object_ids']}"


def test_noref_entries_have_no_object_ref(noref):
    for s, rows in noref.items():
        for r in rows:
            assert not has_object_ref(r["path"]), \
                f"{s} noref 里的 {r['method']} {r['path']} 其实带对象引用"
            assert "object_ids" not in r, "noref 条目不应带 object_ids"


def test_stats_script_agrees_with_labels():
    """论文表格由 bench/stats.py 生成，这里保证它不会因为读错文件而漂移。"""
    from bench.stats import collect

    data = collect(SYSTEMS)
    tot = data["totals"]
    assert tot["labels"] == sum(v["labels"] for v in data["systems"].values())
    assert tot["vuln"] + tot["safe"] == tot["labels"]
    assert tot["vuln"] == sum(1 for s in SYSTEMS
                              for r in _rows(LABELS / f"{s}.jsonl") if r["vulnerable"])
    assert set(tot["control_kind"]) == CONTROL
