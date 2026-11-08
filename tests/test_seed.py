"""种子路由的 id 提取测试。"""

from __future__ import annotations

from pipeline.seed import extract_ids


def test_extract_from_nested_list():
    body = {"orders": [{"id": 6}, {"id": 7}, {"id": 7}], "count": 2}
    assert extract_ids(body, "orders[].id") == ["6", "7"]


def test_extract_from_top_level_list():
    body = [{"uuid": "a"}, {"uuid": "b"}]
    assert extract_ids(body, "[].uuid") == ["a", "b"]


def test_extract_plain_field():
    assert extract_ids({"id": 42}, "id") == ["42"]


def test_extract_missing_path_is_empty():
    assert extract_ids({"orders": []}, "orders[].id") == []
    assert extract_ids({}, "orders[].id") == []


# ---------------- 占位符与列表过滤 ----------------

from pipeline.seed import _apply_where, _fill  # noqa: E402


def test_fill_prefers_oid_for_detail_paths():
    assert _fill("/mechanic/service_request/{serviceId}", "6") == "/mechanic/service_request/6"
    assert _fill("/community/posts/{postId}", "abc") == "/community/posts/abc"


def test_fill_uses_subject_for_source_endpoints():
    assert _fill("/merchant/service_requests/{vin}", subject={"vin": "V1"}) \
        == "/merchant/service_requests/V1"
    # 没有解析到标识时保留占位符，请求会失败但不会拼出错误路径
    assert _fill("/x/{vin}", subject={}) == "/x/{vin}"


def test_apply_where_keeps_only_own_items():
    body = {"posts": [
        {"id": "p1", "author": {"email": "a@x"}},
        {"id": "p2", "author": {"email": "b@x"}},
    ]}
    where = {"list": "posts", "field": "author.email", "value": "{email}"}
    got = _apply_where(body, where, {"email": "b@x"})
    assert [p["id"] for p in got["posts"]] == ["p2"]
    # 原始对象不被修改
    assert len(body["posts"]) == 2


def test_apply_where_passthrough_when_not_a_list():
    assert _apply_where({"x": 1}, {"list": "posts", "field": "a", "value": "b"}, {}) == {"x": 1}
