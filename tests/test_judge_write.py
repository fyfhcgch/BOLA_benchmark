"""写型判据的单元测试：§II-C 与 §III-C 承诺的四种确认方式必须真的在代码里成立。

删除型（`DELETE`）的确认方式是"受害者复读变 404"，它最容易被后续重构改坏——
因为这条规则不在 `judge_read` 里，而在 `judge_write` 的一个分支里。
"""

from __future__ import annotations

from pipeline.judge import judge_write


def test_delete_confirmed_by_victim_404():
    """攻击者 DELETE 成功 + 受害者复读 404 = 副作用确认（mock DELETE /api/orders/{id}）。"""
    vuln, reason = judge_write(pre_status=200, del_status=204, post_status=404)
    assert vuln
    assert reason == "side_effect_confirmed(404)"


def test_delete_not_confirmed_when_object_survives():
    """返回 2xx 但受害者仍能读到 = 服务端没真删（典型的静默过滤）。"""
    vuln, reason = judge_write(pre_status=200, del_status=200, post_status=200)
    assert not vuln
    assert reason == "no_side_effect"


def test_delete_rejected_by_method_not_allowed():
    """crAPI 的 DELETE /shop/orders/{id} 返回 405，属 method_not_allowed 对照。"""
    vuln, reason = judge_write(pre_status=200, del_status=405, post_status=200)
    assert not vuln
    assert reason == "write_rejected(405)"


def test_delete_without_readable_precondition_is_inconclusive():
    """攻击前受害者就读不到该对象（如已删除），不能判副作用。"""
    vuln, reason = judge_write(pre_status=404, del_status=204, post_status=404)
    assert not vuln
    assert reason == "precondition_failed(404)"


def test_delete_post_status_5xx_is_not_confirmed():
    """受害者复读 500 不等于对象消失：crAPI 订单 17 就是 500，不能算副作用。"""
    vuln, reason = judge_write(pre_status=200, del_status=204, post_status=500)
    assert not vuln
    assert reason.startswith("inconclusive")
