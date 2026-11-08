"""写型重放（POST/PUT/PATCH）的单元测试。"""

from __future__ import annotations

import json

from pipeline.replay import build_cases
from pipeline.seed import _render

PATTERNS = [("postId", r"^[A-Za-z0-9_-]{20,24}$")]
POST_ID = "A3PrAj72bxvcDWCDoZ5cGG"


def _record():
    return {
        "account": "alice",
        "method": "POST",
        "path": f"/community/api/v2/community/posts/{POST_ID}/comment",
        "status": 200,
        "req_body": {"content": "BOLA-PROBE-BASELINE-alice"},
        "req_body_template": {"content": "BOLA-PROBE-{nonce}"},
        "verify_path": f"/community/api/v2/community/posts/{POST_ID}",
    }


def test_write_case_keeps_victim_object_and_template():
    cases = build_cases([_record()], "alice", ["bob"], "http://x",
                        id_patterns=PATTERNS)
    writes = [c for c in cases if c.variant == "write_replay"]
    assert len(writes) == 1
    c = writes[0]
    assert c.method == "POST"
    assert c.endpoint == "/community/api/v2/community/posts/{postId}/comment"
    assert c.object_ids == [POST_ID]
    assert c.url.endswith(f"/posts/{POST_ID}/comment")
    assert c.verify_url.endswith(f"/posts/{POST_ID}")
    # 请求体是渲染后的 JSON，且带唯一标记
    body = json.loads(c.body)
    assert body["content"].startswith("BOLA-")
    assert body["content"] == f"BOLA-PROBE-{c.marker}"


def test_write_marker_is_unique_per_run():
    a = build_cases([_record()], "alice", ["bob"], "http://x", id_patterns=PATTERNS)
    b = build_cases([_record()], "alice", ["bob"], "http://x", id_patterns=PATTERNS)
    ma = [c.marker for c in a if c.variant == "write_replay"][0]
    mb = [c.marker for c in b if c.variant == "write_replay"][0]
    assert ma != mb


def test_read_cases_unchanged_by_write_record():
    cases = build_cases([_record()], "alice", ["bob"], "http://x", id_patterns=PATTERNS)
    # POST 记录不应生成读型用例
    assert all(c.variant == "write_replay" for c in cases)


def test_render_body_template():
    got = _render({"content": "X-{nonce}", "n": 1, "list": ["{victim}"]},
                  {"nonce": "N1", "victim": "alice"})
    assert got == {"content": "X-N1", "n": 1, "list": ["alice"]}


# ---------------- PUT + 枚举字段 ----------------

from pipeline.replay import dig, render_body  # noqa: E402


def _enum_record():
    return {
        "account": "alice",
        "method": "PUT",
        "path": "/mechanic/service_request/6",
        "status": 200,
        "req_body": {"status": "completed"},
        "req_body_template": {"status": "{enum}"},
        "verify_path": "/mechanic/service_request/6",
        "enum_field": "status",
        "enum_values": ["pending", "completed"],
    }


def test_enum_write_builds_template_case():
    cases = build_cases([_enum_record()], "alice", ["bob"], "http://x")
    writes = [c for c in cases if c.variant == "write_replay"]
    assert len(writes) == 1
    c = writes[0]
    # 枚举型不在构造期渲染：目标值要看受害者当前状态
    assert c.body is None
    assert c.body_template == {"status": "{enum}"}
    assert c.enum_field == "status"
    assert c.enum_values == ["pending", "completed"]
    # 没有 nonce 标记（枚举型靠字段比对）
    assert c.marker is None


def test_render_body_replaces_enum():
    assert render_body({"status": "{enum}"}, {"enum": "completed"}) == {"status": "completed"}
    assert render_body({"a": ["{enum}", 1]}, {"enum": "pending"}) == {"a": ["pending", 1]}


def test_dig_reads_nested_field():
    assert dig({"status": "pending"}, "status") == "pending"
    assert dig({"a": {"b": "x"}}, "a.b") == "x"
    assert dig({"a": 1}, "a.b") is None
    assert dig(None, "status") is None


def test_enum_flip_logic():
    """复读比对：写 B、读回 B 且与写前 A 不同才算副作用。"""
    before, target = "pending", "completed"
    for after in ("completed", "pending", None):
        confirmed = str(after) == target and str(after) != before
        assert confirmed is (after == "completed")


# ---------------- 密码类写操作：login 型副作用确认 ----------------

def _login_record():
    return {
        "account": "alice1",
        "method": "PUT",
        "path": "/users/v1/alice1/password",
        "status": 204,
        "req_body": {"password": "Bola-BASELINE!A1"},
        "req_body_template": {"password": "Bola-{nonce}!A1"},
        "verify_path": "/me",
        "verify_login": True,
    }


def test_login_verified_case_has_flag_and_nonce_marker():
    patterns = [("username", r"^[a-z]{3,}[0-9]{1,3}$")]
    cases = build_cases([_login_record()], "alice1", ["bob2"], "http://x",
                        id_patterns=patterns)
    writes = [c for c in cases if c.variant == "write_replay"]
    assert len(writes) == 1
    c = writes[0]
    assert c.verify_login is True
    assert c.marker is not None
    assert json.loads(c.body)["password"].endswith(c.marker + "!A1")


def test_restore_body_is_carried_into_case():
    rec = _record()
    rec["restore"] = {"email": "{email}"}
    cases = build_cases([rec], "alice", ["bob"], "http://x", id_patterns=PATTERNS)
    c = [x for x in cases if x.variant == "write_replay"][0]
    assert c.restore_body == {"email": "{email}"}
    assert c.restore_as == "attacker"
