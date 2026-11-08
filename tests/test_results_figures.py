"""Fig. 3 / Fig. 4 与 §III-F κ 的数据一致性测试。

守住的四件事：
  1. 失败模式归因之和必须等于 ZAP 基线里的 fp（图不能比表多算一条）
  2. F3 漏检 = 漏洞实例 - TP（覆盖上限的算术口径固定）
  3. 复核脚本的公开资源 / 难度映射与规范一致（防止口径在代码里漂移）
  4. κ 的四个关键数字与 `kappa_assistant.json` 一致

跑法：
    .venv/bin/python -m pytest -q tests/test_results_figures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import ai_relabel  # noqa: E402

PROC = ROOT / "results" / "processed"


def test_failure_mode_attribution_matches_baseline():
    zap = json.loads((PROC / "zap_baseline.json").read_text(encoding="utf-8"))
    fm = json.loads((PROC / "failure_modes.json").read_text(encoding="utf-8"))
    rows = {r["system"]: r for r in zap["rows"]}
    for r in fm["rows"]:
        z = rows[r["system"]]
        assert r["fp_f2"] + r["fp_f5"] == z["fp"], r["system"]
        assert r["fp_total"] == z["fp"], r["system"]
        assert r["miss_f3"] == r["vulnerable"] - z["tp"], r["system"]
        assert r["miss_f3"] >= 0


def test_failure_mode_totals():
    fm = json.loads((PROC / "failure_modes.json").read_text(encoding="utf-8"))
    assert fm["totals"]["fp_f2"] == 3
    assert fm["totals"]["fp_f5"] == 11
    assert fm["totals"]["miss_f3"] == 21


def test_public_and_difficulty_rules():
    assert ai_relabel.is_public("crapi", "GET",
                                "/community/api/v2/community/posts/{postId}")
    assert ai_relabel.is_public("crapi", "POST",
                                "/community/api/v2/community/posts/{postId}/comment")
    assert not ai_relabel.is_public("crapi", "GET", "/workshop/api/shop/orders/{id}")
    assert ai_relabel.is_public("vampi", "GET", "/users/v1/{username}")
    assert not ai_relabel.is_public("vampi", "GET", "/books/v1/{bookTitle}")

    assert ai_relabel.difficulty({"method": "GET", "path": "/api/orders/{id}",
                                  "object_ids": ["1001"]}) == "L1"
    assert ai_relabel.difficulty({"method": "GET", "path": "/api/documents/{uuid}",
                                  "object_ids": ["a1b2"]}) == "L2"
    assert ai_relabel.difficulty({"method": "POST", "path": "/api/orders/batch",
                                  "object_ids": ["1001"]}) == "L3"
    assert ai_relabel.difficulty({"method": "GET", "path": "/api/documents/{uuid}/trash",
                                  "object_ids": ["a1b2"]}) == "L3"


def test_kappa_numbers_are_frozen():
    kap = json.loads((ROOT / "results/relabel/kappa_assistant.json").read_text(encoding="utf-8"))
    assert kap["n_paired"] == 107 and kap["n_uncertain"] == 0
    assert round(kap["kappa"], 3) == 0.981
    assert round(kap["kappa_ci95"][0], 3) == 0.940
    assert kap["confusion"] == {"both_vuln": 62, "both_safe": 44,
                                "frozen_vuln_relabel_safe": 0,
                                "frozen_safe_relabel_vuln": 1}
    assert round(kap["difficulty_kappa"]["kappa"], 3) == 0.677
    assert round(kap["control_kind_kappa"]["kappa"], 3) == 1.0
    assert [d["id"] for d in kap["disagreements"]] == ["mock-0047"]