"""pilot 编排器：采集 -> API 恢复 -> 语义推断 -> 重放 -> 判定 -> 实例级指标。

用法：
    python -m pipeline.run --system mock
    python -m pipeline.run --system crapi --skip-crawl    # 复用已有抓包
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import judge as J
from .config import DATA, DEFAULT_HEADERS, SENSITIVE_FIELDS, SYSTEMS
from .crawl import crawl, login
from .evaluate import evaluate, load_jsonl, report
from .infer import infer_endpoints, infer_owner_fields
from .jsapi import extract_dir, merge_with_capture
from .replay import build_cases, dig, load_capture, render_body, run_side_effect, send
from .seed import seed_details, seed_writes


def _bench_path(rel: str) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else Path(__file__).resolve().parent.parent / p


def _tpl(path: str, patterns=None) -> str:
    from .ids import template
    return template(path, patterns)


def reset_system(system: dict) -> None:
    r = system.get("reset")
    if not r:
        return
    try:
        httpx.request(r["method"], system["base_url"].rstrip("/") + r["path"], timeout=10)
    except Exception:
        pass


def _owns_path(url: str, attacker: str, owners: dict) -> bool:
    """请求 URL 里的对象标识是否属于攻击者自己。

    写型响应常常不返回对象正文（204 或只回状态），拿不到身份标识，只能靠
    推断出的 owner 值判断。宁可漏掉一条"自己改自己"的判定，也不要把它记成越权：
    这类用例本来就不是 BOLA 测试，误判会污染 self_read_alerts 这一披露指标。
    """
    own = (owners.get(attacker) or {}).get("owner_values") or {}
    want = {str(v) for vs in own.values() for v in vs}
    if not want:
        return False
    segs = [s for s in url.split("?")[0].split("/") if s]
    return any(s in want for s in segs)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", default="mock")
    ap.add_argument("--skip-crawl", action="store_true")
    ap.add_argument("--headless", default="true")
    # 判定准则：evidence = 结构化归属证据（默认）；similarity = CN03 风格字符串相似度（消融）
    ap.add_argument("--judge", choices=["evidence", "similarity"], default="evidence")
    # 消融专用：给相似度基线"空壳不算泄露"的优待（默认给，忠实复现基线时关掉）
    # 消融专用：R2-a 只认 owner 键名、不比对值（历史实现，在 clean 对照上稳定误报）
    ap.add_argument("--owner-key-only", action="store_true",
                    help="消融：R2-a 只检查 owner 键名，不比对值（复现历史失败模式）")
    ap.add_argument("--sim-empty-guard", action="store_true", default=True)
    ap.add_argument("--no-sim-empty-guard", dest="sim_empty_guard",
                    action="store_false",
                    help="消融：不排除空壳，忠实复现 CN03 一类做法")
    ap.add_argument("--sim-threshold", type=float, default=0.90)
    # 关掉可见性抑制，模拟"没有公开资源模型"的检测器（CN03 一类）
    ap.add_argument("--no-public-suppression", action="store_true")
    # 消融：写型只看"请求被接受"（2xx），不做副作用二次确认
    ap.add_argument("--no-write-check", action="store_true")
    # 消融：只用抓包，不做 AST / 常量表恢复（前端语义值多少）
    ap.add_argument("--no-ast", action="store_true")
    # 消融：不做 owner/身份字段推断，改用人工配置（自动化值多少）
    ap.add_argument("--no-infer-owner", action="store_true")
    # 配合 --no-infer-owner：模拟"只知道账号名/邮箱、不知道数据库内部主键"的操作员
    ap.add_argument("--naive-owner", action="store_true")
    # 消融结果单独落目录，避免覆盖默认结果
    ap.add_argument("--tag", default="")
    args = ap.parse_args()

    system = SYSTEMS[args.system]
    sid = system["id"]
    print(f"\n=== [{sid}] {system['name']}")

    raw = DATA / "raw" / sid
    raw.mkdir(parents=True, exist_ok=True)
    cap = raw / "capture.jsonl"
    out = raw / "ablation" / args.tag if args.tag else raw
    out.mkdir(parents=True, exist_ok=True)

    reset_system(system)

    # ---- Phase 3.1 采集 ----
    if system.get("crawl", True) is False:
        # API-only 系统（如 VAmPI）：没有前端 bundle，capture 全部由种子路由生成
        cap.write_text("")
        (raw / "js").mkdir(exist_ok=True)
        print("  [crawl] API-only：跳过浏览器，capture 由种子路由补齐")
    elif not args.skip_crawl or not cap.exists():
        crawl(system, raw, headless=args.headless.lower() != "false")
    else:
        print(f"  [crawl] reuse {cap}")

    # ---- Phase 3.1b 种子路由：把受害者自己的对象实例逐个取一遍 ----
    if system.get("detail_seeds"):
        try:
            n = seed_details(system, cap)
            print(f"  [seed] +{n} detail records -> {cap.name}")
        except Exception as e:
            print(f"  [seed] skip: {type(e).__name__}: {e}")
    if system.get("write_seeds"):
        try:
            n = seed_writes(system, cap)
            print(f"  [seed] +{n} write records -> {cap.name}")
        except Exception as e:
            print(f"  [seed] write skip: {type(e).__name__}: {e}")

    # ---- Phase 3.2 API 恢复 ----
    if args.no_ast:
        # 消融：不读前端 bundle，只把抓到的流量当成端点清单
        js = {"endpoints": [], "routes": [], "static": []}
        print("  [jsapi] 消融：跳过 AST/常量表，只用抓包")
    else:
        js = extract_dir(raw / "js")
    merged = merge_with_capture(js, cap, system.get("id_patterns"))
    st = merged["stats"]
    print(f"  [jsapi] routes={len(js['routes'])} ast={len(js['endpoints'])} "
          f"static={st['static']} captured={st['captured']} "
          f"confirmed={st['static_confirmed']} static_only={st['static_only']} "
          f"unobserved_with_ref={st['unobserved_with_ref']}")
    unseen = [e for e in merged["endpoints"] if "capture" not in e["sources"]]
    for ep in unseen[:10]:
        print(f"          [unseen] {(','.join(ep['methods']) or 'ANY'):5s} {ep['template']}")
    if len(unseen) > 10:
        print(f"          [unseen] ... 其余 {len(unseen) - 10} 条见 endpoints.json")

    # ---- Phase 3.3 语义推断 ----
    victims = system.get("victims") or [system["victim"]]
    accounts = list(system["accounts"])
    if args.no_infer_owner:
        # 消融：人工配置。把配置里已声明的账号属性当作 owner/身份来源，
        # 不从响应里推断任何东西 —— 这是现有工具要求用户手工填的那部分。
        naive = bool(args.naive_owner)
        owners = {v: _manual_owner(system, v, naive) for v in victims}
        all_identity = {n: _manual_identity(system, n, naive) for n in accounts}
        print("  [infer] 消融：人工配置 owner/身份字段，不做自动推断")
    else:
        owners = {v: infer_owner_fields(cap, v) for v in victims}
        all_identity = {n: infer_owner_fields(cap, n).get("identity_values", {})
                        for n in accounts}
    owner = owners[system["victim"]]
    # 人工配置成本：对照 研究方案 §3.4 的口径 —— "需要人工标注归属的端点数"。
    # −Owner 时每个带对象引用的端点都要人写一句"这个对象属于谁"；自动推断时为 0。
    ep_with_ref = sum(1 for e in merged["endpoints"]
                      if re.search(r"\{\w+\}", e["template"]))
    manual_ep = ep_with_ref if args.no_infer_owner else 0
    print(f"  [infer] 人工配置端点：{manual_ep}/{len(merged['endpoints'])}"
          f"（带对象引用 {ep_with_ref} 条）")

    def _others(atk: str) -> dict:
        """除攻击者本人之外的所有已知身份标识。

        实例级标注下，被访问对象的属主未必是配置里的 victim —— crAPI 的
        订单 8 属于 bob，carol 读它就应判定为越权。只比对 victim 的身份
        会漏报，所以这里比对"非攻击者"的身份集合。
        """
        own = all_identity.get(atk, {})
        out: dict[str, list] = {}
        for acct, ident in all_identity.items():
            if acct == atk:
                continue
            for k, vals in ident.items():
                out.setdefault(k, []).extend(v for v in vals if v not in own.get(k, []))
        return out

    atk_identity = {a: all_identity.get(a, {}) for a in accounts}
    atk_others = {a: _others(a) for a in accounts}
    print(f"  [infer] victims={victims} owner_keys={owner['owner_keys']} "
          f"identity={list(owner.get('identity_values', {}))} "
          f"sensitive={owner['sensitive_fields']}")
    eps = infer_endpoints(js, cap)
    (raw / "endpoints.json").write_text(
        json.dumps({"ast": js, "inventory": merged["endpoints"],
                    "inventory_stats": st, "inferred": eps, "owner": owners},
                   ensure_ascii=False, indent=2),
        encoding="utf-8")

    # ---- Phase 4 重放 ----
    tokens = {n: login(system["base_url"], system["login"], a)
              for n, a in system["accounts"].items()}
    victim_ids = {v: system["accounts"][v].get("id") or _victim_id_from_capture(cap, v)
                  for v in victims}
    tenants = {n: a.get("tenant", "") for n, a in system["accounts"].items()}
    records = load_capture(cap)

    # 每个账号轮流当受害者：单受害者设计下，bob/carol 的对象永远测不到
    raw_cases = []
    seed_stats: dict = {}
    for v in victims:
        raw_cases += build_cases(records, v, [a for a in accounts if a != v],
                                 system["base_url"], tenants=tenants,
                                 deltas=system.get("probe_deltas"),
                                 id_patterns=system.get("id_patterns"),
                                 id_query_names=system.get("id_query_names"),
                                 identity_values=all_identity,
                                 stats=seed_stats)
    if seed_stats.get("seeds_rejected_not_owned"):
        # 抓包里"受害者读到的其实是别人的对象"不能当种子，否则会生成
        # "属主删自己的对象"的伪越权用例（见 replay._response_belongs_to_victim）
        print(f"  [replay] 丢弃 {seed_stats['seeds_rejected_not_owned']} 条非本人对象的读种子")
    cases, seen = [], set()
    for c in raw_cases:
        # 去重键必须带 victim 与 object_ids：批量/导出场景的 URL 完全相同，
        # 只有"受害者的对象集合"能区分两个不同实例
        key = (c.variant, c.method, c.url, c.attacker, c.victim, tuple(c.object_ids))
        if key in seen:
            continue
        seen.add(key)
        cases.append(c)
    print(f"  [replay] {len(cases)} test cases (victims={len(victims)})")

    results: list[dict] = []
    patterns = system.get("id_patterns")
    public = {_tpl(p, patterns) for p in system.get("public_paths", [])}
    public_hits = 0
    suppress_public = not args.no_public_suppression
    print(f"  [judge] criterion={args.judge}"
          + (f"(threshold={args.sim_threshold:.2f})" if args.judge == "similarity" else "")
          + f" public_suppression={'on' if suppress_public else 'off'}")

    baseline_cache: dict[tuple[str, str], tuple[int | None, object]] = {}

    def _baseline_body(r) -> object:
        """与 send() 同一套响应解析：JSON 优先，非 JSON 走 textract。

        直接用 r.json() 会在 CSV/PDF 响应上抛异常并把 baseline 记成 None，
        于是导出类实例全部变成 no_baseline —— 这是消融框架的缺陷，不是判据缺陷。
        """
        ct = r.headers.get("content-type", "")
        try:
            return r.json()
        except Exception:
            from .textract import as_text
            return as_text(r.content, ct)[:8000]

    def _victim_baseline(c) -> tuple[int | None, object]:
        """受害者自己访问同一 URL 的响应，作为相似度比较的参照。

        必须在 setup 状态**仍然有效时**调用：软删除类实例的正文只在
        "已删除"状态下可见，若在 teardown 之后才取参照，受害者自己也会看到
        空容器，参照就退化成空壳，真漏洞被判成漏报。
        """
        key = (c.url, c.victim)
        if key not in baseline_cache:
            try:
                kw = {}
                if c.body is not None:
                    kw["content"] = c.body
                    kw["headers_extra"] = {"Content-Type": "application/json"}
                r = httpx.request(c.method, c.url,
                                  headers={"Authorization": f"Bearer {tokens[c.victim]}",
                                           **DEFAULT_HEADERS,
                                           **kw.pop("headers_extra", {})},
                                  timeout=10, **kw)
                baseline_cache[key] = (r.status_code, _baseline_body(r))
            except Exception:
                baseline_cache[key] = (None, None)
        return baseline_cache[key]

    # 先跑读型（无副作用）
    for c in [x for x in cases if x.variant in ("id_swap", "id_probe")]:
        # L3 跨接口组合：攻击前先以受害者身份把对象推进到"只有组合后才可见"的状态
        if c.setup:
            run_side_effect(system["base_url"], tokens[c.victim], c.setup)
        resp = send(c, tokens[c.attacker])
        if args.judge == "similarity":
            # 参照必须在 teardown 之前取（见 _victim_baseline 的注释）
            base_status, base_body = _victim_baseline(c)
        if c.teardown:
            run_side_effect(system["base_url"], tokens[c.victim], c.teardown)
        own = owners[c.victim]
        if args.judge == "similarity":
            vuln, reason = J.judge_read_similarity(resp, base_body, args.sim_threshold,
                                                   empty_guard=args.sim_empty_guard)
        else:
            base_status, base_body = None, None
            vuln, reason = J.judge_read(
                resp, victim_ids[c.victim], own["owner_keys"], own["owner_values"],
                identity_values=atk_others.get(c.attacker, {}),
                attacker_values=atk_identity.get(c.attacker, {}),
                owner_key_only=args.owner_key_only,
            )
        if vuln and suppress_public and _tpl(urlparse(c.url).path, patterns) in public:
            # 公开资源（社区帖子）：读到作者身份是设计行为，不算 BOLA
            vuln, reason = False, "public_resource"
            public_hits += 1
        results.append({**c.__dict__, "status": resp["status"],
                        "baseline_status": base_status,
                        "vuln": vuln, "reason": reason})

    # 写型重放：攻击者写 + 受害者复读，确认副作用
    write_cases = [x for x in cases if x.variant == "write_replay"]
    write_confirmed = 0
    for c in write_cases:
        vh = {"Authorization": f"Bearer {tokens[c.victim]}", **DEFAULT_HEADERS}
        try:
            pre = httpx.get(c.verify_url, headers=vh, timeout=10).json()
        except Exception:
            pre = None

        enum_before = None
        if c.enum_field:
            # 枚举型：写前先看受害者当前值，攻击者写"另一个合法值"
            enum_before = dig(pre, c.enum_field)
            target = next((v for v in (c.enum_values or []) if str(v) != str(enum_before)), None)
            if target is None:
                continue
            c.body = json.dumps(render_body(c.body_template or {}, {"enum": target}),
                                ensure_ascii=False)

        wr = send(c, tokens[c.attacker])
        try:
            post = httpx.get(c.verify_url, headers=vh, timeout=10).json()
        except Exception:
            post = None

        if args.no_write_check:
            # 消融：2xx = 越权成功。这正是很多工具的做法，也是误报的来源
            confirmed = 200 <= wr["status"] < 300
            reason = (f"write_accepted({wr['status']})" if confirmed
                      else f"write_rejected({wr['status']})")
        elif c.verify_login:
            newpw = (json.loads(c.body) if c.body else {}).get("password")
            confirmed = bool(newpw) and _login_ok(system, c.victim, newpw)
            reason = "login_with_new_password_ok" if confirmed else "login_with_new_password_failed"
        elif c.enum_field:
            enum_after = dig(post, c.enum_field)
            confirmed = (str(enum_after) == str(target) and str(enum_after) != str(enum_before))
            reason = (f"enum_flip:{enum_before}->{enum_after}" if confirmed
                      else f"no_enum_change({enum_before}->{enum_after},status={wr['status']})")
        else:
            confirmed = bool(c.marker and c.marker in str(post) and c.marker not in str(pre))
            reason = "side_effect_confirmed" if confirmed else f"no_side_effect(status={wr['status']})"

        # 清理必须独立于判据：即使不做副作用校验，也要把状态改回去
        if c.verify_login:
            orig = system["accounts"][c.victim]["password"]
            try:
                httpx.request(c.method, c.url,
                              headers={"Authorization": f"Bearer {tokens[c.victim]}",
                                       **DEFAULT_HEADERS},
                              json={"password": orig}, timeout=10)
            except Exception:
                pass
            if not _login_ok(system, c.victim, orig):
                print(f"  [warn] {c.victim} 原密码恢复失败，后续运行可能登录不上")
        elif c.enum_field:
            # 以受害者身份把字段改回原值，保证复跑口径一致
            try:
                httpx.request(c.method, c.url, headers=vh, timeout=10,
                              json=render_body(c.body_template or {}, {"enum": enum_before}))
            except Exception:
                pass

        # 写测试必须有清理：不还原就会把"攻击者自己"的邮箱/资料改掉，
        # 下一轮的身份证据对不上，公开资源抑制会莫名失效
        if c.restore_body:
            who = c.attacker if c.restore_as == "attacker" else c.victim
            acct = {k: str(v) for k, v in system["accounts"][who].items()}
            body = render_body(c.restore_body, {**acct, "victim": who})
            try:
                httpx.request(c.method, c.url,
                              headers={"Authorization": f"Bearer {tokens[who]}",
                                       **DEFAULT_HEADERS},
                              json=body, timeout=10)
            except Exception:
                pass

        write_confirmed += int(confirmed)
        # R0 写型版：攻击者改的若是自己的对象，副作用确认当然成立，但那不是越权。
        # 判据是"请求路径里的对象标识属于攻击者自己"——写型响应往往不返回对象正文，
        # 拿不到身份标识，只能靠归属映射判断。
        # 同上：`--owner-key-only` 复现的历史实现没有 R0，写型也不能替它挡
        self_object = (False if args.owner_key_only
                       else _owns_path(c.url, c.attacker, owners))
        vuln = confirmed and not self_object
        if vuln and suppress_public and _tpl(urlparse(c.url).path, patterns) in public:
            vuln, reason = False, "public_resource"
            public_hits += 1
        if self_object:
            reason = "self_object"
        results.append({**c.__dict__, "status": wr["status"],
                        "vuln": vuln, "reason": reason,
                        "write_confirmed": confirmed})

    if write_cases:
        label = "accepted" if args.no_write_check else "side_effect"
        print(f"  [writereplay] {len(write_cases)} cases, {label}={write_confirmed}")
    if public_hits:
        print(f"  [judge] public_resource 抑制 {public_hits} 条（可见性由配置声明）")

    # 再跑写型（每条后 reset，避免前一条的副作用污染后一条）
    for c in [x for x in cases if x.variant == "method_swap"]:
        pre = httpx.get(c.url, headers={"Authorization": f"Bearer {tokens[c.victim]}",
                                        **DEFAULT_HEADERS}, timeout=10)
        if pre.status_code != 200:
            continue
        wr = send(c, tokens[c.attacker])
        post = httpx.get(c.url, headers={"Authorization": f"Bearer {tokens[c.victim]}",
                                         **DEFAULT_HEADERS}, timeout=10)
        vuln, reason = J.judge_write(pre.status_code, wr["status"], post.status_code)
        results.append({**c.__dict__, "status": wr["status"],
                        "vuln": vuln, "reason": reason,
                        "pre_status": pre.status_code, "post_status": post.status_code})
        reset_system(system)

    (out / "results.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in results), encoding="utf-8")

    # ---- Phase 6 指标（对象实例级） ----
    labels = load_jsonl(_bench_path(system["labels"]))
    noref = load_jsonl(_bench_path(system["labels"].replace(".jsonl", ".noref.jsonl")))
    res = evaluate(results, labels, noref)

    print("\n  ---- 检出 ----")
    for r in results:
        if not r.get("vuln"):
            continue
        ids = ",".join(str(x) for x in r.get("object_ids") or [])
        print(f"  [VULN] {r['method']:6s} {r['endpoint']:44s} ids={ids:8s} "
              f"via={r['variant']:11s} {r['reason']}")

    print("\n  ---- 指标（对象实例级） ----")
    for line in report(res):
        print(line)

    # 与端点清单同口径：按路径模板去重（清单不区分方法）
    tested_endpoints = {r["endpoint"] for r in results}
    summary = {"system": sid, **res,
               "inventory_endpoints": len(merged["endpoints"]),
               "unobserved_endpoints": len(unseen),
               "endpoints_tested": len(tested_endpoints),
               "owner_inference": "manual" if args.no_infer_owner else "auto",
               "endpoints_with_ref": ep_with_ref,
               "manually_annotated_endpoints": manual_ep,
               "manual_config_ratio": (round(manual_ep / len(merged["endpoints"]), 3)
                                       if merged["endpoints"] else 0.0),
               "static_recovery": not args.no_ast,
               "judge": args.judge,
               "similarity_threshold": (args.sim_threshold
                                        if args.judge == "similarity" else None),
               "sim_empty_guard": (args.sim_empty_guard
                                   if args.judge == "similarity" else None),
               "owner_key_only": args.owner_key_only,
               "public_suppression": suppress_public,
               "write_check": not args.no_write_check,
               "tag": args.tag or None,
               "detections": [r for r in results if r.get("vuln")]}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    print(f"\n  -> {out/'summary.json'}")


def _manual_owner(system: dict, victim: str, naive: bool = False) -> dict:
    """人工配置的 owner 信息：owner 键名用静态表，值取账号声明的 id。

    这是"−Owner"消融的输入：一个真实用户会怎么写配置，这里就怎么写。
    """
    acct = system["accounts"][victim]
    # naive：只用账号名当 owner 值（不知道数据库内部主键）
    oid = (acct.get("username") if naive else (acct.get("id") or acct.get("username")))
    from .config import OWNER_KEYS
    return {
        "owner_keys": sorted(OWNER_KEYS),
        "owner_values": {k: [oid] for k in OWNER_KEYS},
        "identity_values": _manual_identity(system, victim, naive),
        # 没有自动推断时，敏感字段表同样要人给；这里用全局默认表模拟
        "sensitive_fields": sorted(SENSITIVE_FIELDS),
    }


def _manual_identity(system: dict, name: str, naive: bool = False) -> dict:
    """人工配置的身份标识：账号里声明了什么就用什么。

    naive=True 时不使用内部主键 id —— 真实操作员通常只知道账号名和邮箱。
    """
    acct = system["accounts"][name]
    out: dict[str, list] = {}
    keys = ("username", "email", "phone", "number") if naive else ("id", "username", "email", "phone", "number")
    for k in keys:
        v = acct.get(k)
        if v:
            out.setdefault(k, []).append(v)
    return out


def _login_ok(system: dict, username: str, password: str) -> bool:
    """尝试登录；注意 VAmPI 密码错误也返回 200，必须看 token 是否存在。"""
    acct = {**system["accounts"][username], "password": password}
    try:
        return bool(login(system["base_url"], system["login"], acct))
    except Exception:
        return False


def _victim_id_from_capture(cap: Path, victim: str):
    with cap.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["account"] == victim and isinstance(r.get("resp_body"), dict):
                for k in ("id", "user_id", "uid"):
                    if k in r["resp_body"]:
                        return r["resp_body"][k]
    return None


if __name__ == "__main__":
    main()
