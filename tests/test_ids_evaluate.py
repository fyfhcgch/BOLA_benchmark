"""对象实例键与指标层的单元测试。

跑法：
    .venv/bin/python -m pytest -q
"""

from __future__ import annotations

from pipeline.evaluate import evaluate
from pipeline.ids import case_key, has_object_ref, object_ids, template, token_kind


# ---------------- ids ----------------

def test_template_numeric_and_uuid():
    assert template("/api/orders/1002") == "/api/orders/{id}"
    assert template("/identity/api/v2/vehicle/4af8884a-e11b-4254-b29a-386b9b4e3ec5/location") \
        == "/identity/api/v2/vehicle/{uuid}/location"
    assert template("/workshop/api/mechanic/") == "/workshop/api/mechanic"


def test_template_is_idempotent():
    t = "/api/orders/{id}"
    assert template(t) == t


def test_object_ids_path_and_query():
    assert object_ids("/api/orders/1002") == ["1002"]
    assert object_ids("/api/orders/1002/items") == ["1002"]
    assert object_ids("/api/orders", "id=7&offset=20") == ["7"]
    assert object_ids("/api/orders", "orderId=9&page=2") == ["9"]
    assert object_ids("/api/profile") == []


def test_gate_excludes_no_object_ref():
    assert not has_object_ref("/api/me")
    assert not has_object_ref("/workshop/api/shop/orders/all")
    assert not has_object_ref("/community/api/v2/community/posts/recent")
    assert has_object_ref("/workshop/api/shop/orders/7")


def test_case_key_ignores_useless_query():
    assert case_key("get", "/api/orders/7?offset=1") == ("GET", "/api/orders/{id}", ("7",))


# ---------------- evaluate ----------------

LABELS = [
    {"method": "GET", "path": "/api/orders/{id}", "victim": "alice",
     "object_ids": ["1"], "vulnerable": True},
    {"method": "GET", "path": "/api/orders/{id}", "victim": "bob",
     "object_ids": ["2"], "vulnerable": True},
    {"method": "GET", "path": "/api/profile/{id}", "victim": "alice",
     "object_ids": ["1"], "vulnerable": False},
    {"method": "GET", "path": "/api/orders/{id}", "victim": "alice",
     "object_ids": ["3"], "vulnerable": True},   # 从未被测试
]

NOREF = [{"method": "GET", "path": "/api/me"}]


def rec(method, tpl, ids, atk, vuln, variant="id_swap"):
    return {"method": method, "endpoint": tpl, "object_ids": list(ids),
            "attacker": atk, "variant": variant, "vuln": vuln, "reason": ""}


def test_instance_level_tp_fp_tn_fn():
    results = [
        rec("GET", "/api/orders/{id}", ["1"], "bob", True),      # TP
        rec("GET", "/api/orders/{id}", ["2"], "bob", True),      # 本人访问 -> 跳过
        rec("GET", "/api/profile/{id}", ["1"], "bob", False),    # TN
    ]
    res = evaluate(results, LABELS, NOREF)
    assert (res["tp"], res["fp"], res["fn"], res["tn"]) == (1, 0, 0, 1)
    assert res["tests_skipped_owner"] == 1
    assert res["labels_tested"] == 2
    assert res["labels_uncovered"] == 2          # order/2（只有本人访问）+ order/3
    assert res["recall"] == 1.0
    assert res["recall_strict"] == 0.3333        # 3 条漏洞标注只测到 1 条


def test_unlabeled_detection_counts_as_fp():
    results = [rec("GET", "/api/orders/{id}", ["1"], "bob", True),
               rec("GET", "/api/orders/{id}", ["99"], "bob", True)]
    res = evaluate(results, LABELS, NOREF)
    assert res["fp"] == 1
    assert res["fp_unlabeled"] == 1
    assert res["precision"] == 0.5


def test_gate_violation_is_separate():
    results = [rec("GET", "/api/me", [], "bob", True)]
    res = evaluate(results, LABELS, NOREF)
    assert res["gate_violations"] == 1
    assert res["fp"] == 0


# ---------------- 非数字标识（VIN） ----------------

VIN = "7PV1ZVZRYXAM20962"
VIN_PATTERNS = [("vin", r"^[A-HJ-NPR-Z0-9]{17}$")]


def test_vin_needs_explicit_pattern():
    path = f"/workshop/api/merchant/service_requests/{VIN}"
    # 没有配置时，VIN 不被当作对象标识 —— 这类端点会被闸门整类漏掉（F2）
    assert not has_object_ref(path)
    assert template(path) == path
    # 配置后正常识别
    assert template(path, VIN_PATTERNS) == "/workshop/api/merchant/service_requests/{vin}"
    assert object_ids(path, "", VIN_PATTERNS) == [VIN]


def test_numeric_still_wins_over_vin():
    # 纯数字段优先生成 {id}，不会被 VIN 规则抢走
    assert template("/api/orders/1002", VIN_PATTERNS) == "/api/orders/{id}"


def test_nanoid_post_id_pattern():
    # 22 位 NanoID：内置规则认不出，需系统声明
    pid = "qGrKQbNVxn4azEEDpC5Wbm"
    patterns = [("postId", r"^[A-Za-z0-9_-]{20,24}$")]
    # 未声明时整段原样保留：端点因此不会被识别为对象引用（闸门漏掉）
    assert template(f"/community/api/v2/community/posts/{pid}").endswith(pid)
    assert template(f"/community/api/v2/community/posts/{pid}", patterns) == \
        "/community/api/v2/community/posts/{postId}"
    # 17 位 VIN 不会被 20-24 位的 NanoID 规则误吞
    assert token_kind("7PV1ZVZRYXAM20962", patterns) is None
