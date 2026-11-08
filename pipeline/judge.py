"""判定层：结构化语义判定，而不是字符串相似度。

四种判据（对照 研究方案 §2 Phase 4.3）：
  R1 状态码     2xx
  R2 归属证据   owner 字段值 == 受害者；或响应中出现**非攻击者**的身份标识（email/number）
  R3 敏感泄露   响应中出现敏感字段（email/phone/amount/note...）
  S1 副作用     写请求执行后，受害者视角的对象状态发生变化

读型测试需同时满足 R1 + R2 + R3 才判 VULN；
写型必须通过 S1 二次确认 —— 这一步是压低误报的关键。

另外提供 `judge_read_similarity`：复现 CN03 一类工作的字符串相似度判据，
只用于消融实验（`--judge=similarity`），不参与默认判定。
"""

from __future__ import annotations

import difflib
import json
from typing import Any

from .config import OWNER_KEYS, SENSITIVE_FIELDS


def _flat_keys(obj, out=None):
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(k)
            _flat_keys(v, out)
    elif isinstance(obj, list):
        for v in obj[:5]:
            _flat_keys(v, out)
    return out


def _leaf(k: str) -> str:
    """`user_id` / `user.id` / `orders[0].user_id` -> 末段键名。"""
    return k.split(".")[-1].split("[")[-1]


def _flat_items(obj, out=None) -> list[tuple[str, Any]]:
    """把响应摊平成 (叶子键名, 值) 列表。

    与 `_flat_keys` 的区别：这里保留**值**。判据必须比对值，
    只看"响应里有没有 user_id 这个键"会把"攻击者读到自己订单"也判成越权
    —— clean 对照里立刻表现为 FP。
    """
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _flat_items(v, out)
            else:
                out.append((_leaf(k), v))
    elif isinstance(obj, list):
        for v in obj[:5]:
            _flat_items(v, out)
    return out


def _empty_shell(body: Any) -> bool:
    """响应是否"什么都没给"。

    除了 `[]` / `{}` / 空串，还要覆盖**嵌套空容器**：批量接口的安全对照
    返回 `{"orders": []}`，回收站未删除时返回 `{"trash": []}` —— 这些都是
    "没有内容可泄露"，必须判成 empty_shell，否则失败模式分类会把它们
    错记成 no_owner_evidence，§VI 的成因分布就失真了。
    """
    if body is None:
        return True
    if body in ([], {}, ""):
        return True
    if isinstance(body, dict) and set(body).issubset({"error", "message", "code", "timestamp"}):
        return True
    if isinstance(body, dict) and body:
        # 所有值都是空容器 -> 整体是空壳
        vals = [v for v in body.values() if v not in (None, "", [], {})]
        if not vals:
            return True
    return False


def _owner_evidence(body: Any, owner_keys: list[str], victim_values: dict,
                    key_only: bool = False,
                    attacker_values: dict | None = None) -> str | None:
    """R2-a：响应里某个 owner 字段的**值**等于受害者的值。

    victim_values 形如 {"user_id": ["1"], "username": ["alice"]}，
    由 `infer_owner_fields(cap, victim)` 从受害者自己的响应里推断得到。
    必须比对值：crAPI 的 `user.id` 是 8（alice 的内部主键），
    bob 读 alice 的订单会看到 `user.id == 8`，这才叫归属证据；
    bob 读自己的订单看到 `user.id == 9`，不是证据。

    `key_only=True` 是**消融用的历史实现**：只要响应里出现 owner 键名就算归属，
    不比对值。它会在 clean 对照上稳定误报（攻击者读自己的对象也带 `user_id`），
    可用 `python -m pipeline.run --system clean --owner-key-only` 复现。

    `attacker_values` 用来排除"攻击者自己就是属主"的情形：当攻击者读自己的对象时，
    owner 值当然等于受害者值（受害者就是他自己），这不构成越权证据。不排除的话
    默认配置会在 mock 上产生 9 条属主自读告警（见 `make ablate-keyonly` 的对照列）。
    """
    keys = set(owner_keys or OWNER_KEYS)
    atk = {str(v) for vs in (attacker_values or {}).values() for v in vs}
    for leaf, val in _flat_items(body):
        if leaf not in keys:
            continue
        if key_only:
            return f"{leaf}={val}(key_only)"
        if str(val) in atk:
            continue
        want = {str(x) for x in (victim_values or {}).get(leaf) or []}
        if want and str(val) in want:
            return f"{leaf}={val}"
    return None


def _identity_evidence(body: Any, identity_values: dict, attacker_values: dict | None) -> str | None:
    """R2-b：响应里出现了受害者的身份标识，且不是攻击者自己的。

    覆盖 crAPI 这种 `user.email` / `owner.email` 嵌套结构，以及 CSV/PDF
    这类非 JSON 响应（已由 textract 压成文本）。
    """
    blob = str(body)
    atk = {str(v) for vs in (attacker_values or {}).values() for v in vs}
    for key, vals in (identity_values or {}).items():
        if key in ("name",):
            continue
        for v in vals:
            s = str(v)
            if len(s) < 5 or s in atk:
                continue
            if s in blob:
                return f"{key}:{s[:10]}"
    return None


def _attacker_is_owner(body: Any, attacker_values: dict | None) -> bool:
    """响应里出现了攻击者本人的身份标识 → 这是他自己对象，不构成越权。

    只认强标识（email / username / number / phone），且要求长度 ≥ 5，避免
    短字符串（如 `id: 1`）误命中。密码类字段不参与，因为它们可能出现在
    别人对象的日志里。
    """
    blob = str(body)
    for key, vals in (attacker_values or {}).items():
        if key == "name":
            continue
        for v in vals:
            s = str(v)
            if len(s) >= 5 and s in blob:
                return True
    return False


def judge_read(resp: dict, victim_id, owner_keys: list[str], victim_values: dict,
               identity_values: dict | None = None,
               attacker_values: dict | None = None,
               owner_key_only: bool = False) -> tuple[bool, str]:
    """读型判据：R1 状态码 + R2 归属证据 + R3 敏感字段。

    R2 有两条并列分支，任一成立即可（crAPI 的订单详情用嵌套 email，
    mock 的订单详情用扁平 user_id，两者都必须能判）：
      R2-a 响应里 owner 字段的**值** == 受害者的值
      R2-b 响应里出现**非攻击者**的身份标识（email / number / username）
    """
    if not (200 <= (resp.get("status") or 0) < 300):
        return False, f"status={resp.get('status')}"
    body = resp.get("body")
    if _empty_shell(body):
        return False, "empty_shell"

    # R0：先排除"攻击者读到的就是自己的对象"。
    # 抓包语料里含越权请求（靶场本来就允许跨用户读），重放时可能把属主本人
    # 当成攻击者；若不先排除，属主读自己的数据会因为 owner 值匹配而判成越权。
    # 这是判据的身份盲区，不是标注错误：mock 默认配置下会出 9 条（见 self_read_alerts）。
    # `owner_key_only` 复现的是**没有 R0 的历史实现**：那时既不看键值，也不排除
    # 攻击者即属主。若保留 R0，历史缺陷会被 R0 提前拦掉、复现不出来——
    # 消融变体必须忠实于被消融的那一版，而不是"当前版本少一条规则"。
    if not owner_key_only and _attacker_is_owner(body, attacker_values):
        return False, "self_object"

    own_hit = _owner_evidence(body, owner_keys, victim_values,
                              key_only=owner_key_only, attacker_values=attacker_values)
    id_hit = _identity_evidence(body, identity_values or {}, attacker_values)
    if not own_hit and not id_hit:
        return False, "no_owner_evidence"

    keys = set(_flat_keys(body))
    sensitive = [k for k in keys if k.lower() in SENSITIVE_FIELDS]
    if not sensitive and not id_hit:
        return False, "no_sensitive_field"

    reason = f"leak:{','.join(sorted(set(sensitive))[:4])}" if sensitive else "leak:identity"
    if own_hit:
        reason += f"|owner:{own_hit}"
    if id_hit:
        reason += f"|{id_hit}"
    return True, reason


def _canon(body: Any) -> str:
    """把响应体压成可比较的字符串；JSON 排序键，避免字段顺序影响相似度。"""
    if isinstance(body, (dict, list)):
        try:
            return json.dumps(body, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(body)
    return "" if body is None else str(body)


def judge_read_similarity(resp: dict, baseline_body: Any,
                          threshold: float = 0.90,
                          empty_guard: bool = True) -> tuple[bool, str]:
    """CN03 风格的读型判据：攻击者响应与受害者响应"足够像"就算越权。

    只用于消融实验。它不看归属、不看敏感字段，因此在公开资源上会稳定误报。

    `empty_guard` 控制是否先排除空壳。**默认 True 是给基线的优待**，必须显式说明：
    "空响应不算泄露"这一条本身是我们方法的一部分（`no_owner_evidence` 对照的由来），
    把它送给相似度基线，等于把结论的一部分预先塞进基线。消融时用 `empty_guard=False`
    才是对 CN03 一类做法的**忠实复现**：两个 `{"comments": []}` 的相似度是 1.000，
    基线必然误报。论文里两个数字都要报（见 §VI-C1）。

    baseline_body 为 None 表示受害者自己都读不到该对象，无法比较，直接判安全。
    """
    if not (200 <= (resp.get("status") or 0) < 300):
        return False, f"status={resp.get('status')}"
    body = resp.get("body")
    if empty_guard and _empty_shell(body):
        return False, "empty_shell"
    if baseline_body is None:
        return False, "no_baseline"
    a, b = _canon(body), _canon(baseline_body)
    if not a or not b:
        return False, "empty_comparison"
    # 大响应截断，SequenceMatcher 是 O(n^2)
    ratio = difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()
    if ratio >= threshold:
        return True, f"similarity:{ratio:.3f}"
    return False, f"similarity:{ratio:.3f}<{threshold:.2f}"


def judge_write(pre_status: int, del_status: int, post_status: int) -> tuple[bool, str]:
    """写型 BOLA 的二次确认。"""
    if pre_status != 200:
        return False, f"precondition_failed({pre_status})"
    if not (200 <= del_status < 300):
        return False, f"write_rejected({del_status})"
    if post_status == 404:
        return True, "side_effect_confirmed(404)"
    if post_status == 200:
        return False, "no_side_effect"
    return False, f"inconclusive({post_status})"
