"""重放层：把受害者的成功请求，换成攻击者身份重新发出。

变异策略（对照 研究方案 §2 Phase 4.2）：
  id_swap      用受害者自己的请求 + 攻击者 token  （最核心的 BOLA 测试）
  id_probe     数字 ID ±1 / ±2 / ±10（枚举型）
  method_swap  GET -> PUT/DELETE/PATCH（写型 BOLA）
  write_replay 用受害者自己的写请求模板（POST/PUT/PATCH）重放给攻击者，
               再以受害者身份复读，检查攻击者写入的 nonce 是否出现（副作用确认）。
               枚举型字段（如 status）不能塞 nonce，改用"翻转取值 + 复读比对"：
               攻击者写 B，受害者读回 B 且与写前 A 不同，才算副作用。

L3 的两类用例需要额外支持：
  * 标识在请求体里（批量接口）—— `id_swap` 必须连请求体一起重放
  * 跨接口组合（软删除后读回收站）—— 攻击前要先以受害者身份执行 `setup`，
    攻击后再执行 `teardown`，否则"回收站"永远是空的

每个用例都带上 `object_ids` 与 `scope`：BOLA 是对象实例级属性，
结果必须能定位到"哪个对象、跨不跨租户"，否则指标无法按实例聚合。
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .config import DEFAULT_HEADERS, DEFAULT_PROBE_DELTAS
from .ids import has_object_ref, object_ids, split_query, template

__all__ = [
    "TestCase", "load_capture", "build_cases", "send", "has_object_ref",
]

READ_METHODS = ("GET", "POST")     # POST 只用于"标识在请求体里"的批量读


@dataclass
class TestCase:
    endpoint: str                 # 路径模板
    method: str
    url: str                      # 完整 URL（含具体对象标识）
    attacker: str
    victim: str
    variant: str
    object_ids: list[str] = field(default_factory=list)
    scope: str = "any"            # same_tenant / cross_tenant
    headers: dict = field(default_factory=dict)
    body: str | None = None          # 重放的请求体（已渲染的 JSON 字符串）
    verify_url: str | None = None    # 写型重放后，以受害者身份复读的 URL
    marker: str | None = None        # 写进请求体、用于确认副作用的唯一标记
    body_template: dict | None = None   # 枚举型字段的请求体模板（运行时才渲染）
    enum_field: str | None = None       # 复读时要比对的字段，如 status
    enum_values: list[str] | None = None  # 该字段的合法取值
    verify_login: bool = False          # 副作用 = 受害者能用新密码登录（密码类写操作）
    restore_body: dict | None = None    # 测完把状态改回去（避免污染后续运行）
    restore_as: str = "attacker"        # 用谁的凭据还原：attacker / victim
    setup: dict | None = None           # 攻击前以受害者身份执行的跨接口前置动作
    teardown: dict | None = None        # 攻击后以受害者身份执行的清理动作


def load_capture(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def _scope(tenants: dict[str, str], victim: str, attacker: str) -> str:
    tv, ta = tenants.get(victim), tenants.get(attacker)
    if not tv or not ta:
        return "any"
    return "same_tenant" if tv == ta else "cross_tenant"


def _is_read_seed(r: dict) -> bool:
    """读型种子：成功的读请求，且不是写型模板记录。"""
    return (r["method"] in READ_METHODS
            and r.get("req_body_template") is None)


def _response_belongs_to_victim(body, victim: str,
                                identity_values: dict | None) -> bool:
    """这个响应里的对象，是不是受害者本人的？

    种子层最容易犯的错：把"受害者越权读到的别人的对象"当成受害者的对象。
    靶场漏洞版本来就允许跨用户读（mock 里 bob 能读 alice 的订单 1001），
    抓包语料里于是有这条记录。若照单全收，就会生成
    `DELETE /api/orders/1001`、victim=bob 的用例，而该实例真正的属主是 alice；
    重放时攻击者恰好是 alice，判据把"属主删自己的对象"判成越权，
    最终表现为 `self_read_alerts`（mock 上残留 2 条就是这么来的）。

    判据：响应里出现受害者本人的身份标识 → 是他的；只出现别人的身份标识 →
    不是他的；一个身份标识都没有（纯 API 靶场、无身份字段的对象）→ 无法判断，
    保留（宁可多测一条，也不要凭空丢覆盖）。
    """
    if not identity_values:
        return True
    own = {str(v) for vs in (identity_values.get(victim) or {}).values()
           for v in vs if len(str(v)) >= 5}
    others = {str(v) for a, ident in identity_values.items() if a != victim
              for vs in ident.values() for v in vs if len(str(v)) >= 5}
    if not own and not others:
        return True
    blob = str(body)
    if any(v in blob for v in own):
        return True
    if any(v in blob for v in others):
        return False
    return True


def build_cases(records: list[dict], victim: str, attackers: list[str],
                base_url: str, max_cases: int = 400,
                tenants: dict[str, str] | None = None,
                deltas: tuple[int, ...] | None = None,
                id_patterns=None, id_query_names=None,
                identity_values: dict | None = None,
                stats: dict | None = None) -> list[TestCase]:
    tenants = tenants or {}
    deltas = tuple(deltas or DEFAULT_PROBE_DELTAS)
    seeds = []
    rejected = 0
    for r in records:
        path, query = split_query(r["path"])
        body = r.get("req_body") if isinstance(r.get("req_body"), (dict, list)) else None
        if not (r["account"] == victim
                and _is_read_seed(r)
                and 200 <= (r["status"] or 0) < 300
                and isinstance(r.get("resp_body"), (dict, list, str))
                and has_object_ref(path, query, id_patterns, body, id_query_names)):
            continue
        if not _response_belongs_to_victim(r.get("resp_body"), victim, identity_values):
            rejected += 1
            continue
        seeds.append((r, path, query, body))
    if stats is not None:
        stats["seeds_rejected_not_owned"] = rejected

    cases: list[TestCase] = []
    seen: set[tuple] = set()

    def add(case: TestCase, dedupe: tuple) -> bool:
        if dedupe in seen:
            return True
        seen.add(dedupe)
        cases.append(case)
        return len(cases) < max_cases

    for r, path, query, body in seeds:
        suffix = f"?{query}" if query else ""
        ids = object_ids(path, query, id_patterns, body, id_query_names)
        endpoint = template(path, id_patterns)
        req_body = (json.dumps(body, ensure_ascii=False)
                    if isinstance(body, (dict, list)) else None)
        setup = r.get("setup")
        teardown = r.get("teardown")

        for atk in attackers:
            scope = _scope(tenants, victim, atk)

            # 1) id_swap：受害者请求原样重放（含请求体，L3 批量接口靠它）
            add(TestCase(endpoint, r["method"], base_url + path + suffix,
                         atk, victim, "id_swap", list(ids), scope,
                         body=req_body, setup=setup, teardown=teardown),
                ("id_swap", r["method"], path, query, atk))

            # 2) id_probe：只改第一段数字 ID，避免多 ID 路径被同时打乱
            for num in re.findall(r"/(\d+)(?=/|$)", path):
                for delta in deltas:
                    newnum = int(num) + delta
                    if newnum <= 0:
                        continue
                    newpath = re.sub(rf"/{num}(?=/|$)", f"/{newnum}", path, count=1)
                    newids = object_ids(newpath, query, id_patterns, None, id_query_names)
                    if not newids:
                        continue
                    add(TestCase(template(newpath, id_patterns), r["method"],
                                 base_url + newpath + suffix,
                                 atk, victim, "id_probe", list(newids), scope),
                        ("id_probe", r["method"], newpath, query, atk))

            # 3) method_swap：写型探测，副作用由 run.py 二次确认
            add(TestCase(endpoint, "DELETE", base_url + path + suffix,
                         atk, victim, "method_swap", list(ids), scope,
                         setup=setup, teardown=teardown),
                ("method_swap", "DELETE", path, query, atk))

        if len(cases) >= max_cases:
            break

    # ---- 写型重放：受害者的写请求模板 -> 攻击者身份 ----
    for r in records:
        if (r["account"] != victim
                or r["method"] not in ("POST", "PUT", "PATCH")
                or not (200 <= (r["status"] or 0) < 300)):
            continue
        path, query = split_query(r["path"])
        if not has_object_ref(path, query, id_patterns, None, id_query_names):
            continue
        tpl_body = r.get("req_body_template")
        if tpl_body is None:
            continue
        suffix = f"?{query}" if query else ""
        ids = object_ids(path, query, id_patterns, None, id_query_names)
        endpoint = template(path, id_patterns)
        verify_tpl = r.get("verify_path") or path
        enum_field = r.get("enum_field")
        enum_values = list(r.get("enum_values") or [])
        for atk in attackers:
            verify_path = verify_tpl.replace("{nonce}", "")
            if enum_field and len(enum_values) >= 2:
                # 枚举型：目标值要到运行时看受害者当前状态才能定（翻转）
                add(TestCase(endpoint, r["method"], base_url + path + suffix,
                             atk, victim, "write_replay", list(ids),
                             _scope(tenants, victim, atk),
                             verify_url=base_url + verify_path,
                             body_template=tpl_body,
                             enum_field=enum_field,
                             enum_values=enum_values),
                    ("write_replay", r["method"], path, query, atk))
                continue
            # 每次运行唯一：否则上一轮写入的标记会让"pre 里没有"这一条失败
            marker = f"BOLA-{uuid.uuid4().hex[:12]}"
            body = _render(tpl_body, marker)
            add(TestCase(endpoint, r["method"], base_url + path + suffix,
                         atk, victim, "write_replay", list(ids),
                         _scope(tenants, victim, atk),
                         body=json.dumps(body, ensure_ascii=False),
                         verify_url=base_url + verify_path,
                         marker=marker,
                         verify_login=bool(r.get("verify_login")),
                         restore_body=r.get("restore"),
                         restore_as=r.get("restore_as", "attacker")),
                ("write_replay", r["method"], path, query, atk))

    return cases


def render_body(obj, mapping: dict[str, str]):
    """渲染请求体模板：把 {nonce} / {enum} 等占位符换成具体值。"""
    if isinstance(obj, dict):
        return {k: render_body(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render_body(v, mapping) for v in obj]
    if isinstance(obj, str):
        for k, v in mapping.items():
            obj = obj.replace("{%s}" % k, v)
        return obj
    return obj


def _render(obj, marker: str):
    """把请求体模板里的 {nonce} 换成具体标记。"""
    return render_body(obj, {"nonce": marker})


def _render_str(tpl: str, marker: str) -> str:
    return tpl.replace("{nonce}", marker)


def dig(obj, dotted: str | None):
    """按点号路径取值（用于复读时比对 status 这类嵌套字段）。"""
    if not dotted:
        return None
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def run_side_effect(base_url: str, token: str, spec: dict | None) -> bool:
    """以指定身份执行 setup / teardown（跨接口组合的前置与清理动作）。"""
    if not spec:
        return False
    try:
        kw = {}
        if spec.get("json") is not None:
            kw["json"] = spec["json"]
        httpx.request(spec.get("method", "GET").upper(), base_url + spec["path"],
                      headers={"Authorization": f"Bearer {token}", **DEFAULT_HEADERS},
                      timeout=20, **kw)
        return True
    except Exception:
        return False


def send(case: TestCase, token: str, timeout: float = 10.0) -> dict:
    h = {"Authorization": f"Bearer {token}", **DEFAULT_HEADERS}
    t0 = time.time()
    try:
        kw = {}
        if case.body is not None:
            kw["content"] = case.body
            h["Content-Type"] = "application/json"
        r = httpx.request(case.method, case.url, headers=h, timeout=timeout, **kw)
        ct = r.headers.get("content-type", "")
        try:
            body = r.json()
        except Exception:
            from .textract import as_text
            body = as_text(r.content, ct)[:8000]
        return {"status": r.status_code, "body": body, "elapsed": time.time() - t0}
    except Exception as e:
        return {"status": -1, "body": None, "elapsed": time.time() - t0, "error": type(e).__name__}
