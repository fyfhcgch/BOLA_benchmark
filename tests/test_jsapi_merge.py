"""常量表分支与三路合并的单元测试。"""

from __future__ import annotations

import json

from pipeline.jsapi import extract_from_file, merge_with_capture, suffix_match

BUNDLE = """
// 真实项目里常见的一张接口常量表：只有路径，没有调用点
export const API = {
  GET_ORDER: "api/shop/orders/<orderId>",
  GET_ORDERS: "api/shop/orders/all",
  GET_SERVICE: "api/merchant/service_requests/<vehicleVIN>",
  LOGIN: "api/auth/login",
  NOT_API: "some/other/string",
};
"""


def test_const_table_extraction(tmp_path):
    f = tmp_path / "bundle.js"
    f.write_text(BUNDLE, encoding="utf-8")
    got = extract_from_file(f)
    templates = {s["template"] for s in got["static"]}
    assert "/api/shop/orders/{orderId}" in templates
    assert "/api/merchant/service_requests/{vehicleVIN}" in templates
    # 不是 api/ 开头的普通字符串不算接口
    assert "/some/other/string" not in templates
    # 常量表没有 HTTP 方法
    assert all(s["method"] == "ANY" for s in got["static"])


def test_suffix_match_ignores_service_prefix_and_placeholder_names():
    # 静态模板缺服务前缀，占位符名字也不同
    assert suffix_match("/api/shop/orders/{orderId}",
                        "/workshop/api/shop/orders/{id}") == 4
    assert suffix_match("/api/orders/{id}", "/api/orders/{id}") == 3
    assert suffix_match("/api/orders/{id}", "/api/users/{id}") is None
    # 静态模板比抓包模板还长时不匹配
    assert suffix_match("/api/orders/{id}/items", "/api/orders/{id}") is None


def test_merge_quantifies_unseen_endpoints(tmp_path):
    js = {
        "endpoints": [],
        "static": [
            {"method": "ANY", "template": "/api/shop/orders/all", "params": []},
            {"method": "ANY", "template": "/api/shop/orders/{orderId}", "params": ["orderId"]},
            {"method": "ANY", "template": "/api/mechanic/service_request/{serviceId}", "params": []},
        ],
    }
    cap = tmp_path / "capture.jsonl"
    rows = [
        {"method": "GET", "path": "/workshop/api/shop/orders/all"},
        {"method": "GET", "path": "/workshop/api/shop/orders/7"},
    ]
    cap.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    m = merge_with_capture(js, cap)
    assert m["stats"] == {
        "captured": 2,
        "static": 3,
        "static_confirmed": 2,
        "static_only": 1,
        "inventory": 3,
        "unobserved": 1,
        "unobserved_with_ref": 1,
    }
    by_tpl = {e["template"]: e for e in m["endpoints"]}
    # 抓包模板保留完整服务前缀，并记下静态来源
    assert by_tpl["/workshop/api/shop/orders/{id}"]["sources"] == ["capture", "static"]
    assert by_tpl["/workshop/api/shop/orders/{id}"]["methods"] == ["GET"]
    # 未触发接口没有方法
    assert by_tpl["/api/mechanic/service_request/{serviceId}"]["methods"] == []
