"""种子路由：把"受害者自己的对象"逐个取一遍，补出 UI 没触发的详情接口。

UI 爬虫只能看到用户点到的对象（crAPI 上只点到订单 7），同一个详情接口的
其它实例因此永远进不了测试集。这里按 `config.detail_seeds` 声明"从哪个
列表接口取 id、拼到哪个详情模板上"，用**受害者自己的凭据**把全部实例取
一遍，结果并入 capture.jsonl（`source="seed"`）。

这一步不越权：所有请求都用受害者自己的 token，只是补齐基线。真正的越权
发生在 replay 阶段。

## L1/L2 场景（标识在路径里）

    "detail_seeds": [
        {"path": "/workshop/api/shop/orders/{id}",
         "from": "/workshop/api/shop/orders/all",
         "ids_path": "orders[].id"},
    ]

## L3 场景（标识不在路径里，或需要跨接口组合）

    # 批量读：标识放在请求体里，一次带多个对象
    {"path": "/api/orders/batch", "method": "POST",
     "from": "/api/users/{uid}/orders", "ids_path": "[].id",
     "group": 2, "body_ids_key": "ids"}

    # 导出：标识是逗号分隔的查询值，响应是 CSV 而不是 JSON
    {"path": "/api/orders/export",
     "from": "/api/users/{uid}/orders", "ids_path": "[].id",
     "group": 2, "query_ids_key": "ids"}

    # 派生标识：filename = "report_<id>"，要先从另一个接口拿到 id
    {"path": "/workshop/api/mechanic/download_report",
     "from": "/workshop/api/mechanic/service_requests", "ids_path": "[].id",
     "query_ids_key": "filename", "query_value_template": "report_{id}"}

    # 跨接口组合：受害者先软删除，攻击者才能读到回收站里的内容
    {"path": "/api/documents/{uuid}/trash",
     "from": "/api/documents", "ids_path": "[].id",
     "setup":    {"method": "DELETE", "path": "/api/documents/{uuid}"},
     "teardown": {"method": "PATCH", "path": "/api/documents/{uuid}",
                  "json": {"deleted": False}}}

`ids_path` 是极简路径表达式：`a[].b` 表示 body["a"] 的每个元素的 "b" 字段，
`[].b` 表示 body 本身是数组。故意不引入 jsonpath 依赖。

有些列表接口本身要带受试者标识（如"按 VIN 查我的维修请求"），用
`id_sources` 先解析这些标识：

    "id_sources": {
        "vin":  {"from": "/vehicle/vehicles", "ids_path": "[].vin"},
        "uuid": {"from": "/vehicle/vehicles", "ids_path": "[].uuid"},
    },
    "detail_seeds": [
        {"path": "/merchant/service_requests/{vin}", ...},
        {"path": "/mechanic/service_request/{serviceId}",
         "from": "/merchant/service_requests/{vin}",
         "ids_path": "service_requests[].id"},
    ]

`from` 里的占位符由 `id_sources` 填充，`path` 里的占位符由本次取到的 id 填充。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from .config import DEFAULT_HEADERS
from .crawl import login

PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def extract_ids(body: Any, expr: str) -> list[str]:
    """按极简路径表达式从响应体里取标量 id，保序去重。"""
    nodes: list[Any] = [body]
    for raw in expr.split("."):
        name = raw[:-2] if raw.endswith("[]") else raw
        iterate = raw.endswith("[]")
        nxt: list[Any] = []
        for node in nodes:
            if name:
                if not isinstance(node, dict):
                    continue
                node = node.get(name)
            if iterate:
                if isinstance(node, list):
                    nxt.extend(node)
            elif node is not None:
                nxt.append(node)
        nodes = nxt

    out: list[str] = []
    for n in nodes:
        if isinstance(n, (str, int)) and str(n) not in out:
            out.append(str(n))
    return out


def _fill(tpl: str, oid: str | None = None, subject: dict[str, str] | None = None) -> str:
    """替换模板占位符。给了 oid 就全替换成 oid，否则用 subject 里的映射。"""
    def repl(m: re.Match) -> str:
        if oid is not None:
            return oid
        return str((subject or {}).get(m.group(1), m.group(0)))
    return PLACEHOLDER_RE.sub(repl, tpl)


def resolve_sources(system: dict, victim: str) -> dict[str, str]:
    """按 `id_sources` 取受试者自己的标识（vin / uuid / ...），供 `from` 模板使用。"""
    specs = system.get("id_sources") or {}
    if not specs:
        return {}
    base = system["base_url"].rstrip("/")
    token = login(base, system["login"], system["accounts"][victim])
    h = {"Authorization": f"Bearer {token}", **DEFAULT_HEADERS}
    out: dict[str, str] = {}
    for name, spec in specs.items():
        try:
            r = httpx.get(base + spec["from"], headers=h, timeout=20)
            ids = extract_ids(r.json(), spec["ids_path"])
        except Exception as e:
            print(f"  [seed] {victim} id_source {name} 失败: {type(e).__name__}")
            continue
        if ids:
            out[name] = ids[0]
    return out


def _dig(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _apply_where(body, where: dict, account: dict):
    """按 `where` 过滤列表项（例如只保留 author.email == 本账号的帖子）。"""
    if not where or not isinstance(body, dict):
        return body
    items = body.get(where["list"])
    if not isinstance(items, list):
        return body
    want = where["value"].format(**account)
    kept = [it for it in items if str(_dig(it, where["field"])) == want]
    return {**body, where["list"]: kept}


def _chunks(ids: list[str], group: int) -> list[list[str]]:
    group = max(1, int(group or 1))
    return [ids[i:i + group] for i in range(0, len(ids), group)]


def _response_body(r: httpx.Response):
    """保留 JSON，其次保留纯文本（CSV / PDF 抽取后的文本）。"""
    try:
        return r.json()
    except Exception:
        pass
    text = r.text
    if text and text.lstrip().startswith("%PDF"):
        from .textract import pdf_text
        return pdf_text(r.content)
    return text[:4000]


def _request_spec(base: str, spec: dict, h: dict, chunk: list[str], subject: dict) -> tuple[str, Any, int, Any]:
    """按 spec 发一次请求，返回 (path, req_body, status, resp_body)。

    三种标识落点：
      路径占位符（默认）      path 里已有 {uuid} 等
      body_ids_key            标识放进请求体
      query_ids_key           标识放进查询参数（可用 query_value_template 派生）
    """
    path = spec["path"]
    body = None
    params = None
    if spec.get("body_ids_key"):
        body = {spec["body_ids_key"]: [int(x) if x.isdigit() else x for x in chunk]}
        # 路径里若还有占位符（少见），用第一个标识填上
        if PLACEHOLDER_RE.search(path):
            path = _fill(path, chunk[0])
    elif spec.get("query_ids_key"):
        tpl = spec.get("query_value_template")
        if tpl:
            values = [tpl.format(id=x) for x in chunk]
        else:
            values = chunk
        params = {spec["query_ids_key"]: ",".join(values)}
        if PLACEHOLDER_RE.search(path):
            path = _fill(path, chunk[0])
    else:
        path = _fill(path, chunk[0])

    method = spec.get("method", "GET").upper()
    kw: dict[str, Any] = {}
    if body is not None:
        kw["json"] = body
    if params is not None:
        kw["params"] = params
        # 查询型标识必须写回 path，否则抓包里看不到它，
        # 重放层的 has_object_ref 闸门会把整个 L3 场景挡掉
        path = path + "?" + urlencode(params)
    r = httpx.request(method, base + path, headers=h, timeout=30, **kw)
    return path, body, r.status_code, _response_body(r)


def _run_side_effect(base: str, h: dict, spec: dict | None, chunk: list[str]) -> dict | None:
    """执行 setup / teardown，并把解析后的具体路径写回记录（供重放后清理）。"""
    if not spec:
        return None
    path = _fill(spec["path"], chunk[0])
    kw: dict[str, Any] = {}
    if spec.get("json") is not None:
        kw["json"] = spec["json"]
    try:
        httpx.request(spec.get("method", "GET").upper(), base + path,
                      headers=h, timeout=20, **kw)
    except Exception:
        return None
    return {"method": spec.get("method", "GET").upper(), "path": path, "json": spec.get("json")}


def seed_details(system: dict, cap: Path) -> int:
    """抓取受害者的全部对象实例，幂等：先删旧 seed 记录再追加。"""
    specs = system.get("detail_seeds") or []
    rows = [json.loads(line) for line in cap.open(encoding="utf-8") if line.strip()] if cap.exists() else []
    rows = [r for r in rows if r.get("source") != "seed"]
    if not specs:
        _write(cap, rows)
        return 0

    base = system["base_url"].rstrip("/")
    victims = system.get("victims") or [system["victim"]]

    added = 0
    for victim in victims:
        token = login(base, system["login"], system["accounts"][victim])
        h = {"Authorization": f"Bearer {token}", **DEFAULT_HEADERS}
        subject = resolve_sources(system, victim)
        for spec in specs:
            src = _fill(spec["from"], subject=subject)
            try:
                r = httpx.get(base + src, headers=h, timeout=20)
                body = _apply_where(r.json(), spec.get("where"), system["accounts"][victim])
                ids = extract_ids(body, spec["ids_path"])
            except Exception as e:
                print(f"  [seed] {victim} {src} 取 id 失败: {type(e).__name__}: {e}")
                continue
            if not ids:
                print(f"  [seed] {victim} {src} 没有取到 id（ids_path={spec['ids_path']}）")
                continue
            if spec.get("limit"):
                ids = ids[:int(spec["limit"])]
            if spec.get("index") is not None:
                # 只取指定下标：同一个端点既需要"已被软删除"的对象，
                # 也需要"未删除的空容器"，两者是不同的实例键
                idx = int(spec["index"])
                ids = ids[idx:idx + 1] if idx < len(ids) else []
            for chunk in _chunks(ids, spec.get("group", 1)):
                setup = _run_side_effect(base, h, spec.get("setup"), chunk)
                try:
                    path, req_body, status, resp_body = _request_spec(
                        base, spec, h, chunk, subject)
                except Exception as e:
                    print(f"  [seed] {victim} {spec['path']} 请求失败: {type(e).__name__}: {e}")
                    continue
                teardown = _run_side_effect(base, h, spec.get("teardown"), chunk)
                rows.append({
                    "account": victim,
                    "method": spec.get("method", "GET").upper(),
                    "url": base + path,
                    "path": path,
                    "status": status,
                    "req_headers": {"Authorization": "Bearer <victim>"},
                    "req_body": req_body,
                    "resp_body": resp_body,
                    "resource_type": "seed",
                    "source": "seed",
                    "l3_kind": spec.get("kind"),
                    "setup": setup,
                    "teardown": teardown,
                    "ts": time.time(),
                })
                added += 1
            n_req = len(_chunks(ids, spec.get("group", 1)))
            print(f"  [seed] {victim} {spec.get('method','GET')} {spec['path']} <- "
                  f"{len(ids)} 个标识 / {n_req} 次请求")

    _write(cap, rows)
    return added


def _render(obj, mapping: dict[str, str]):
    """把 dict/list/str 里的 `{name}` 换成 mapping 中的值（用于请求体模板）。"""
    if isinstance(obj, dict):
        return {k: _render(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render(v, mapping) for v in obj]
    if isinstance(obj, str):
        return PLACEHOLDER_RE.sub(lambda m: mapping.get(m.group(1), m.group(0)), obj)
    return obj


def seed_writes(system: dict, cap: Path) -> int:
    """用受害者自己的凭据执行写请求，把"写请求模板"记进 capture。

    只记录、不越权：真正的写型越权发生在 replay 阶段（攻击者身份重放同一模板）。
    记 `req_body_template`（带 `{nonce}`）而不是只记具体请求体，重放时才能
    生成每次唯一的标记，用"受害者侧复读能否看到该标记"确认副作用。

    枚举型字段（如 `status`）塞不进 nonce：模板里写 `{enum}`，种子里先读受害
    者当前值、写成另一个合法值，重放阶段再翻转一次并比对复读结果。
    """
    specs = system.get("write_seeds") or []
    if not specs:
        return 0
    rows = [json.loads(line) for line in cap.open(encoding="utf-8") if line.strip()] if cap.exists() else []
    rows = [r for r in rows if r.get("source") != "wseed"]

    base = system["base_url"].rstrip("/")
    victims = system.get("victims") or [system["victim"]]
    added = 0
    for victim in victims:
        token = login(base, system["login"], system["accounts"][victim])
        h = {"Authorization": f"Bearer {token}", **DEFAULT_HEADERS}
        subject = resolve_sources(system, victim)
        for spec in specs:
            src = _fill(spec["from"], subject=subject)
            try:
                r = httpx.get(base + src, headers=h, timeout=20)
                body = _apply_where(r.json(), spec.get("where"), system["accounts"][victim])
                ids = extract_ids(body, spec["ids_path"])
            except Exception as e:
                print(f"  [seed] {victim} 写种子 {src} 取 id 失败: {type(e).__name__}")
                continue
            if not ids:
                print(f"  [seed] {victim} 写种子 {src} 没有取到 id")
                continue
            for oid in ids:
                path = _fill(spec["path"], oid)
                verify_path = _fill(spec["verify"], oid)
                marker = f"BASELINE-{victim}"
                enum_field = spec.get("enum_field")
                enum_values = list(spec.get("enum_values") or [])
                # 幂等：受害者侧已经能看到基线标记，就不再重复写
                try:
                    pre = httpx.get(base + verify_path, headers=h, timeout=20)
                    pre_body = pre.json()
                except Exception:
                    pre_body = None
                if spec.get("verify_login"):
                    # 密码类写操作：种子里先改一次、验证能登录、立刻改回，
                    # 既证明模板可用，又不破坏账号（否则下一轮登录全失败）
                    orig = system["accounts"][victim]["password"]
                    payload = _render(spec["json"], {"nonce": marker, "victim": victim})
                    try:
                        rr = httpx.request(spec["method"], base + path, headers=h,
                                           json=payload, timeout=20)
                        status = rr.status_code
                        try:
                            resp_body = rr.json()
                        except Exception:
                            resp_body = rr.text[:2000]
                    except Exception as e:
                        print(f"  [seed] {victim} 写种子 {path} 失败: {type(e).__name__}")
                        continue
                    # 立即恢复原密码
                    httpx.request(spec["method"], base + path, headers=h,
                                  json={"password": orig}, timeout=20)
                    rows.append({
                        "account": victim, "method": spec["method"], "url": base + path,
                        "path": path, "status": status,
                        "req_headers": {"Authorization": "Bearer <victim>"},
                        "req_body": payload, "req_body_template": spec["json"],
                        "verify_path": verify_path, "resp_body": resp_body,
                        "resource_type": "write_seed", "source": "wseed",
                        "verify_login": True, "ts": time.time(),
                    })
                    added += 1
                    print(f"  [seed] {victim} {spec['method']} {spec['path']} <- 1 个实例（已改回）")
                    continue

                if enum_field and len(enum_values) >= 2:
                    cur = _dig(pre_body, enum_field)
                    target = next((v for v in enum_values if str(v) != str(cur)), None)
                    if target is None:
                        print(f"  [seed] {victim} 写种子 {path} 无可翻转取值")
                        continue
                    payload = _render(spec["json"], {"enum": target, "victim": victim})
                else:
                    payload = _render(spec["json"], {"nonce": marker, "victim": victim})

                if not enum_field and marker in str(pre_body):
                    status, resp_body = pre.status_code, pre_body
                else:
                    try:
                        rr = httpx.request(spec["method"], base + path, headers=h,
                                           json=payload, timeout=20)
                        status = rr.status_code
                        try:
                            resp_body = rr.json()
                        except Exception:
                            resp_body = rr.text[:2000]
                    except Exception as e:
                        print(f"  [seed] {victim} 写种子 {path} 失败: {type(e).__name__}")
                        continue

                # 有些写操作（改自己的邮箱）会污染后续身份比对，种子里写完立刻还原
                if spec.get("restore"):
                    body = _render(spec["restore"], {"nonce": marker, "victim": victim,
                                                     **system["accounts"][victim]})
                    try:
                        httpx.request(spec["method"], base + path, headers=h,
                                      json=body, timeout=20)
                    except Exception:
                        pass

                rows.append({
                    "account": victim,
                    "method": spec["method"],
                    "url": base + path,
                    "path": path,
                    "status": status,
                    "req_headers": {"Authorization": "Bearer <victim>"},
                    "req_body": payload,
                    "req_body_template": spec["json"],
                    "verify_path": verify_path,
                    "resp_body": resp_body,
                    "resource_type": "write_seed",
                    "source": "wseed",
                    "enum_field": enum_field,
                    "enum_values": enum_values,
                    "restore": spec.get("restore"),
                    "restore_as": spec.get("restore_as", "attacker"),
                    "ts": time.time(),
                })
                added += 1
            print(f"  [seed] {victim} {spec['method']} {spec['path']} <- {len(ids)} 个实例")
    _write(cap, rows)
    return added


def _write(cap: Path, rows: list[dict]) -> None:
    cap.parent.mkdir(parents=True, exist_ok=True)
    with cap.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
