"""整系统 clean control 的约束测试。

clean 对照的全部价值在于"两者只差授权策略"。一旦有人手改了 clean 的标注、
或者往 clean 应用里加了只有它才有的路由，对照就不再受控，而
"检测器在 clean 系统上零误报"这句话也就失去了归因。

守住的四件事：
  1. `bench/labels/clean.jsonl` 与 `bench/derive_clean.py` 的派生结果**逐字节一致**
     （即"只能由脚本生成，不能手改"）
  2. clean 的实例键集合与 mock 完全相同（同对象、同请求形态、同难度）
  3. clean 里没有任何 `vulnerable: true` —— 定义上无漏洞
  4. 派生脚本的断言本身有效（改坏 mock 的某条判定，派生结果跟着翻）

跑法：
    .venv/bin/python -m pytest -q tests/test_clean_control.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import derive_clean  # noqa: E402

LABELS = ROOT / "bench" / "labels"


def _rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("//")]


def _keys(rows: list[dict]) -> set[tuple]:
    return {(r["method"], r["path"], tuple(r["object_ids"])) for r in rows}


def test_clean_file_is_exactly_derived():
    """clean.jsonl 必须是脚本产物：手改一处就红。"""
    rows, _ = derive_clean.derive()
    on_disk = (LABELS / "clean.jsonl").read_text(encoding="utf-8")
    expected = derive_clean.HEADER + "\n".join(
        json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
    assert on_disk == expected, \
        "bench/labels/clean.jsonl 与派生结果不一致；跑 python bench/derive_clean.py 重新生成"


def test_clean_shares_instance_keys_with_mock():
    mock = _rows(LABELS / "mock.jsonl")
    clean = _rows(LABELS / "clean.jsonl")
    assert len(clean) == len(mock), "clean 与 mock 条数必须相同"
    assert _keys(clean) == _keys(mock), "clean 与 mock 的实例键必须逐条相同"


def test_clean_preserves_object_metadata():
    """难度、对象类型、属主都要原样保留：改这些就等于换了一批对象。"""
    mock = {(r["method"], r["path"], tuple(r["object_ids"])): r
            for r in _rows(LABELS / "mock.jsonl")}
    for r in _rows(LABELS / "clean.jsonl"):
        k = (r["method"], r["path"], tuple(r["object_ids"]))
        src = mock[k]
        assert r["difficulty"] == src["difficulty"], f"{r['id']} 的 difficulty 被改了"
        assert r["victim"] == src["victim"], f"{r['id']} 的 victim 被改了"
        assert r["object_type"] == src["object_type"], f"{r['id']} 的 object_type 被改了"


def test_clean_has_no_vulnerabilities():
    clean = _rows(LABELS / "clean.jsonl")
    assert clean, "clean.jsonl 为空"
    assert not any(r["vulnerable"] for r in clean), "clean 系统定义上无漏洞，不能有 vulnerable=true"
    assert all(r.get("control_kind") for r in clean), "clean 每条都要写 control_kind"


def test_clean_flips_exactly_the_vulnerable_entries():
    """mock 的漏洞 -> clean 的 owner_check 安全对照；mock 的安全对照原样保留。"""
    mock = {(r["method"], r["path"], tuple(r["object_ids"])): r
            for r in _rows(LABELS / "mock.jsonl")}
    for r in _rows(LABELS / "clean.jsonl"):
        src = mock[(r["method"], r["path"], tuple(r["object_ids"]))]
        if src["vulnerable"]:
            assert r["control_kind"] == "owner_check", \
                f"{r['id']} 由漏洞翻成安全，成因应是 owner_check"
            assert r["vuln_kind"] == "none", f"{r['id']} 翻成安全后 vuln_kind 应为 none"
        else:
            assert r["control_kind"] == src["control_kind"], \
                f"{r['id']} 原本就是安全对照，成因不该变"


def test_derive_main_rejects_key_mismatch(monkeypatch):
    """派生脚本必须真的会失败：从 mock 派生结果里删一条，main() 应返回非零且不写文件。"""
    real = derive_clean.derive
    monkeypatch.setattr(derive_clean, "derive",
                        lambda: (real()[0][1:], real()[1]))   # 少一条实例
    assert derive_clean.main([]) == 1


def test_derive_main_rejects_remaining_vulnerable(monkeypatch):
    """派生规则若被改成"保留 vulnerable"，main() 必须拒绝写文件。"""
    real = derive_clean.derive

    def leaky():
        rows, src = real()
        rows[0]["vulnerable"] = True      # 人为留一条漏洞
        return rows, src

    monkeypatch.setattr(derive_clean, "derive", leaky)
    assert derive_clean.main([]) == 1


def test_derive_main_writes_when_valid(monkeypatch, tmp_path):
    """正向对照：派生逻辑正确时 main() 应当返回 0（证明上面两个用例不是永远返回 1）。"""
    labels = tmp_path / "labels"
    labels.mkdir()
    for name in ("mock.jsonl", "clean.jsonl", "clean.noref.jsonl"):
        src = LABELS / name
        if src.exists():
            (labels / name).write_bytes(src.read_bytes())
    monkeypatch.setattr(derive_clean, "LABELS", labels)
    assert derive_clean.main([]) == 0
    # 写到临时目录后，与仓库里的版本一致
    assert (labels / "clean.jsonl").read_text(encoding="utf-8") == \
        (LABELS / "clean.jsonl").read_text(encoding="utf-8")
