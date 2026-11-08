"""读种子必须校验"响应属于受害者本人"。

抓包语料含靶场本来就允许的跨用户请求（mock 漏洞版里 bob 能读 alice 的订单 1001）。
若照单全收，会生成 `DELETE /api/orders/1001`、victim=bob 的用例，而该实例真正的属主
是 alice；重放时攻击者恰好是 alice，判据把"属主删自己的对象"判成越权，最终表现为
`self_read_alerts`（修复前 mock 残留 2 条）。
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.replay import _response_belongs_to_victim, build_cases  # noqa: E402

ALICE = {"email": ["alice@example.com"], "username": ["alice"]}
BOB = {"email": ["bob@example.com"], "username": ["bob"]}
IDENT = {"alice": ALICE, "bob": BOB}

ALICE_ORDER = {"id": 1001, "user_id": 1, "user_email": "alice@example.com",
               "item": "键盘", "amount": 599}
BOB_ORDER = {"id": 1003, "user_id": 2, "user_email": "bob@example.com",
             "item": "鼠标", "amount": 199}


def test_response_with_victim_identity_belongs_to_victim():
    assert _response_belongs_to_victim(BOB_ORDER, "bob", IDENT) is True


def test_response_with_only_other_identity_is_rejected():
    """bob 越权读到的 alice 订单，不能当 bob 的种子。"""
    assert _response_belongs_to_victim(ALICE_ORDER, "bob", IDENT) is False


def test_response_without_any_identity_is_kept():
    """纯 API 靶场（无身份字段）无法判断归属 → 保留，不能凭空丢覆盖。"""
    body = {"id": 1001, "amount": 599}
    assert _response_belongs_to_victim(body, "bob", IDENT) is True


def test_no_identity_config_keeps_everything():
    assert _response_belongs_to_victim(ALICE_ORDER, "bob", {}) is True


def _record(account: str, path: str, body: dict) -> dict:
    return {"account": account, "method": "GET", "path": path, "status": 200,
            "resp_body": body, "req_body": None, "req_body_template": None}


def test_build_cases_drops_cross_user_seed_and_reports_it():
    """只有越权读到的对象时，一条用例都不该生成。

    注意不能拿"路径里没有 1001"来断言：`id_probe` 会从 1003 探到 1002/1004，
    反过来也可能探到 1001，那个 1001 是从 bob 自己的对象变异来的，属于正常探测。
    所以这里只放一条越权种子，把断言收紧到"零用例 + 计数为 1"。
    """
    stats: dict = {}
    cases = build_cases([_record("bob", "/api/orders/1001", ALICE_ORDER)],
                        "bob", ["alice"], "http://x",
                        identity_values=IDENT, stats=stats)
    assert cases == []
    assert stats["seeds_rejected_not_owned"] == 1
