"""推断层不能被越权探测污染。

抓包语料包含靶场本来就允许的跨用户请求（mock 漏洞版里 bob 能读 alice 的订单）。
若不加区分地把这些响应里的 `user_id` 记成 bob 的归属值，bob 的 owner_values
会变成 `[1, 2]`，alice 的邮箱也会混进 bob 的身份集合；判据随即把"属主读自己的
对象"判成越权（实测 mock 上 9 条）。本文件锁死这三条：
  * owner 值只从"响应里出现本人身份标识"的响应里收；
  * 本人身份只从"某个身份字段基数为 1"的响应里认；
  * 列表类响应（一次点名多个主体）不参与身份推断。
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.infer import infer_owner_fields, _sole_identity  # noqa: E402

ALICE_ORDER = {"id": 1001, "user_id": 1, "user_email": "alice@example.com",
               "item": "键盘", "amount": 599}
BOB_ORDER = {"id": 1003, "user_id": 2, "user_email": "bob@example.com",
             "item": "鼠标", "amount": 199}
BOB_ME = {"email": "bob@example.com", "phone": "13800000002", "username": "bob"}
POSTS_LIST = {"posts": [
    {"authoremail": "alice@example.com"},
    {"authoremail": "bob@example.com"},
    {"authoremail": "carol@example.com"},
]}


def _write(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "capture.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


def _row(account: str, path: str, body: dict) -> dict:
    return {"account": account, "method": "GET", "path": path, "status": 200,
            "resp_body": body}


def test_cross_user_read_does_not_pollute_owner_values(tmp_path):
    """bob 读了自己的订单，也读了 alice 的订单（越权）；owner 值只能是 2。"""
    p = _write(tmp_path, [
        _row("bob", "/api/me", BOB_ME),
        _row("bob", "/api/orders/1003", BOB_ORDER),
        _row("bob", "/api/orders/1001", ALICE_ORDER),  # 越权读到的
    ])
    got = infer_owner_fields(p, "bob")
    assert got["owner_values"]["user_id"] == [2], got["owner_values"]


def test_identity_values_not_polluted_by_cross_user_read(tmp_path):
    """alice 的邮箱不能进 bob 的身份集合——否则 R2-b 会把她的对象判成攻击者自己的。"""
    p = _write(tmp_path, [
        _row("bob", "/api/me", BOB_ME),
        _row("bob", "/api/orders/1003", BOB_ORDER),
        _row("bob", "/api/orders/1001", ALICE_ORDER),
    ])
    got = infer_owner_fields(p, "bob")
    assert got["identity_values"]["email"] == ["bob@example.com"]


def test_list_response_does_not_define_identity(tmp_path):
    """列表响应一次点名三个主体，不能用来认定"我是谁"。"""
    p = _write(tmp_path, [
        _row("bob", "/community/posts/recent", POSTS_LIST),
    ])
    got = infer_owner_fields(p, "bob")
    assert got["identity_values"] == {}, got["identity_values"]


def test_sole_identity_requires_single_value():
    assert _sole_identity({"email": "bob@example.com"}) == {"email": "bob@example.com"}
    assert _sole_identity(POSTS_LIST) == {}
    # 短值（空串、1 位数）不是身份标识
    assert _sole_identity({"number": "", "id": 9}) == {}


def test_prefixed_identity_key_is_canonicalized(tmp_path):
    """`user_email` / `owner_email` 必须归一成 `email`，否则身份集合里没有 email。"""
    p = _write(tmp_path, [
        _row("bob", "/api/me", BOB_ME),
        _row("bob", "/api/orders/1003", BOB_ORDER),
    ])
    got = infer_owner_fields(p, "bob")
    assert "email" in got["identity_values"]


def test_body_without_identity_falls_back_to_collecting(tmp_path):
    """响应里没有任何身份字段时无法判断归属，退回"全部收集"，不能凭空丢证据。"""
    p = _write(tmp_path, [
        _row("bob", "/api/orders/1003", {"id": 1003, "user_id": 2, "amount": 199}),
    ])
    got = infer_owner_fields(p, "bob")
    assert got["owner_values"]["user_id"] == [2]


def test_none_owner_value_is_not_recorded(tmp_path):
    """crAPI 的 `owner` 字段常为 null，不能记成归属值。"""
    p = _write(tmp_path, [
        _row("alice", "/identity/api/v2/user/dashboard", {"email": "alice@example.com"}),
        _row("alice", "/workshop/api/shop/orders/1",
             {"id": 1, "owner": None, "useremail": "alice@example.com"}),
    ])
    got = infer_owner_fields(p, "alice")
    assert None not in got["owner_values"].get("owner", [])
