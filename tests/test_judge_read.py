"""读型判据（judge_read）的回归测试。

这条判据是整篇论文的核心组件，且曾经出过一个会直接污染结论的 bug：
R2-a 只检查"响应里有 `user_id` 这个**键**"且"配置里受害者有 id"，
没有比对响应里的**值**。后果是"攻击者读到自己订单"也被判成越权，
在整系统 clean control 上表现为 **14/28** 条属主自读告警（`make ablate-keyonly`
可复现；这些告警不进 precision 分母，只计入 `self_read_alerts`）。

守住的四件事：
  1. owner 证据必须比对值：响应里 user_id 是攻击者自己的 -> 不是证据
  2. 非攻击者的身份标识（email/number/username）仍能作为证据
  3. 空容器、错误壳、非 2xx 都不判
  4. 敏感字段与身份证据的两种通过路径都覆盖

跑法：
    .venv/bin/python -m pytest -q tests/test_judge_read.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.judge import _owner_evidence, judge_read  # noqa: E402

VICTIM_VALUES = {"user_id": ["1"], "username": ["alice"]}
VICTIM_IDENTITY = {"username": ["alice"], "email": ["alice@example.com"],
                   "phone": ["13800000001"]}
ATTACKER_IDENTITY = {"username": ["bob"], "email": ["bob@example.com"],
                     "phone": ["13800000002"]}
CAROL_IDENTITY = {"username": ["carol"], "email": ["carol@example.com"],
                  "phone": ["13800000003"]}

# 真实流水线传的是"除攻击者以外**所有**账号的身份集合"（run.py 的 _others），
# 不是只传受害者一个人的 —— 实例级标注下，被访问对象的属主未必是配置里的 victim。
NON_ATTACKER_IDENTITY = {
    "username": ["alice", "carol"],
    "email": ["alice@example.com", "carol@example.com"],
    "phone": ["13800000001", "13800000003"],
}

ORDER_ALICE = {"id": 1001, "user_id": 1, "user_email": "alice@example.com",
               "item": "键盘", "amount": 599, "note": "ALICE-ONLY-1001"}
ORDER_BOB = {"id": 1003, "user_id": 2, "user_email": "bob@example.com",
             "item": "鼠标", "amount": 199, "note": "BOB-ONLY-1003"}


def _read(body, status=200):
    return judge_read({"status": status, "body": body}, 1, ["user_id"],
                      VICTIM_VALUES, identity_values=NON_ATTACKER_IDENTITY,
                      attacker_values=ATTACKER_IDENTITY)


# ---------------- owner 证据必须比对值 ----------------

def test_attacker_reading_own_object_is_not_evidence():
    """属主读自己的对象，响应里带自己的邮箱 → R0 直接排除，不进 precision 分母。

    mock 默认配置下曾有 9 条这类告警（`self_read_alerts`），根因有两处：
    R2-a 不排除"攻击者即属主"，以及推断层被越权探测污染（bob 的 owner_values
    变成 [1, 2]）。两处都已修复，本用例锁死 R0 分支。
    """
    vuln, reason = _read(ORDER_BOB)
    assert vuln is False
    assert reason == "self_object"


def test_attacker_reading_own_object_without_identity_falls_through():
    """响应里没有攻击者身份时，R0 不触发，仍按 R2-a 判定（不能凭空放过）。"""
    body = {"id": 1003, "user_id": 2, "item": "鼠标", "amount": 199}
    vuln, reason = judge_read({"status": 200, "body": body}, 1, ["user_id"],
                              VICTIM_VALUES, identity_values=NON_ATTACKER_IDENTITY,
                              attacker_values={})
    assert vuln is False
    assert reason == "no_owner_evidence"


def test_victim_object_with_matching_owner_value_is_evidence():
    vuln, reason = _read(ORDER_ALICE)
    assert vuln is True
    assert "owner:user_id=1" in reason


def test_nested_owner_object_is_evidence():
    """crAPI 的订单详情把属主嵌在 user.email 里，没有扁平 user_id。"""
    body = {"id": 6, "user": {"email": "alice@example.com", "number": "13800000001"},
            "product": {"name": "Wheel"}, "amount": 10}
    vuln, reason = _read(body)
    assert vuln is True
    # 身份证据优先报 username（长度 >= 5 且不在攻击者集合里，最先命中）
    assert "username:alice" in reason or "email:alice@exam" in reason


def test_owner_evidence_helper_ignores_other_ids():
    """只有 owner 键名参与 R2-a；`product.id` 不是归属证据。"""
    body = {"id": 2, "product": {"id": 2, "name": "Wheel"}}
    assert _owner_evidence(body, ["user_id"], VICTIM_VALUES) is None


def test_owner_evidence_helper_handles_list_of_objects():
    """批量接口返回数组，每个元素都可能是受害者对象。"""
    body = {"orders": [ORDER_BOB, ORDER_ALICE]}
    assert _owner_evidence(body, ["user_id"], VICTIM_VALUES) == "user_id=1"


def test_owner_value_absent_from_config_is_not_evidence():
    """配置里没有该 owner 键的取值时不能凭空判越权。"""
    assert _owner_evidence(ORDER_ALICE, ["user_id"], {"username": ["alice"]}) is None


# ---------------- 其他身份证据 ----------------

def test_non_attacker_identity_is_evidence_even_without_owner_field():
    """响应里出现第三个账号（carol）的 email：既不是攻击者也不是受害者，
    但同样是"别人的身份"，必须算证据（这是实例级标注的核心要求）。"""
    body = {"email": "carol@example.com", "note": "CAROL-ONLY"}
    vuln, reason = _read(body)
    assert vuln is True
    assert "carol" in reason


def test_attacker_own_identity_is_not_evidence():
    body = {"email": "bob@example.com", "note": "BOB-ONLY"}
    vuln, _ = _read(body)
    assert vuln is False


# ---------------- 排除规则 ----------------

def test_empty_container_is_not_vuln():
    for body in ([], {}, {"orders": []}, {"trash": []}, {"comments": []}):
        vuln, reason = _read(body)
        assert vuln is False, f"{body} 是空容器，不该判越权"
        assert reason == "empty_shell"


def test_error_shell_is_not_vuln():
    vuln, reason = _read({"message": "You are not allowed to access this resource!"})
    assert vuln is False
    assert reason == "empty_shell"


def test_non_2xx_is_not_vuln():
    vuln, reason = _read(ORDER_ALICE, status=403)
    assert vuln is False
    assert reason == "status=403"


def test_identity_without_sensitive_field_still_counts():
    """有非攻击者身份标识时，即使没有敏感字段名也算泄露（如 PDF 里的 Owner Email）。"""
    body = "Service Report Owner Email alice@example.com"
    vuln, reason = _read(body)
    assert vuln is True
    assert "leak:identity" in reason


def test_owner_evidence_without_sensitive_field_or_identity_is_not_enough():
    """只有 owner 值、没有敏感字段也没有身份标识 -> 不判（保守，避免误报）。"""
    body = {"user_id": 1, "status": "ok"}
    vuln, reason = _read(body)
    assert vuln is False
    assert reason == "no_sensitive_field"


def test_csv_text_response_is_judged():
    """导出接口返回 text/csv，已被 textract 压成文本。"""
    body = "id,user_email,item,amount,note\n1001,alice@example.com,键盘,599,ALICE-ONLY-1001"
    vuln, reason = _read(body)
    assert vuln is True
