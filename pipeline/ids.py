"""对象标识抽取与路径模板归一化。

标注单位是 `(method, path_template, victim_object_ids)`，而不是端点。
同一个 `/workshop/api/shop/orders/{id}` 对订单 6 是漏洞、对订单 8 不是，
"这个端点有没有漏洞"本身就没有唯一答案。因此流水线每一层都必须能
把一次具体请求还原成"对象实例键"：

    采集 -> 重放 -> 判定 -> 指标匹配
    统一用 case_key(method, path, query) 生成同一个键。

标识出现的四种位置（对照 §II-D 范围声明）：

    路径段         /api/orders/1002
    查询参数       ?id=7 / ?ids=1001,1002 / ?filename=report_6
    请求体字段     {"ids": [1001, 1002]}
    自然键         /books/v1/alice1-notebook（由 config.id_patterns 声明）

前两种与自然键由 `object_ids` 处理；请求体由 `body_object_ids` 处理。
后者是 L3 的核心：标识不在 URL 里，只看路径模板的检测器会整类漏掉。

已知简化：除"带 id 语义"的查询参数外，其余查询参数（offset/status/...）
在模板化时被丢弃。对 BOLA 测试这是可接受的，写进 Threats to Validity。
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
UUID_SEG = re.compile(UUID_RE, re.I)
NUM_SEG = re.compile(r"^\d+$")

# 内置的标识形态；额外形态由各系统在 config 里声明：
#   "id_patterns": [("vin", "^[A-HJ-NPR-Z0-9]{17}$")]
BUILTIN_PATTERNS: tuple[tuple[str, str], ...] = (("id", r"^\d+$"), ("uuid", UUID_RE))

# 查询参数名：id / user_id / orderId / uuid / no / code / sn / key / report_id
ID_QUERY = re.compile(r"(^|_)(id|uid|uuid|gid|no|code|sn|key)$|(Id|ID|Uuid|UUID)$")
# 复数形式：?ids=1001,1002 —— 一个参数携带多个对象标识（批量/导出场景）
ID_QUERY_LIST = re.compile(r"(^|_)ids$|Ids$")

# 请求体里表示"对象标识"的键名（比查询参数宽一档：body 里的 `user` 常常是 id）
ID_BODY = re.compile(r"(^|_)(id|ids|uid|uuid|gid|no|code|sn|key|user|owner)$|(Id|ID|Ids|Uuid|UUID)$")

_BLANK = ("", "null", "undefined", "none")


def split_query(target: str) -> tuple[str, str]:
    """把 URL 或 path 拆成 (path, query)。绝对 URL 只保留 path。"""
    if not target:
        return "", ""
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return parts.path or "/", parts.query
    if "?" in target:
        p, q = target.split("?", 1)
        return p, q
    return target, ""


def _patterns(extra=None) -> list[tuple[str, re.Pattern]]:
    out = [(name, re.compile(rx, re.I if name == "uuid" else 0)) for name, rx in BUILTIN_PATTERNS]
    out += [(name, re.compile(rx)) for name, rx in (extra or ())]
    return out


def token_kind(seg: str, patterns=None) -> str | None:
    """返回该路径段的标识类型（id / uuid / vin / ...），不是标识则 None。"""
    for name, rx in _patterns(patterns):
        if rx.match(seg):
            return name
    return None


def is_object_token(seg: str, patterns=None) -> bool:
    return token_kind(seg, patterns) is not None


def template(path: str, patterns=None) -> str:
    """把具体路径归一化成模板。

    /api/orders/1002            -> /api/orders/{id}
    /vehicle/4af8...-.../location -> /vehicle/{uuid}/location

    对已经是模板的字符串是幂等的（`{id}` 不会被二次替换）。
    """
    path, _ = split_query(path)
    out = []
    for seg in path.split("/"):
        kind = token_kind(seg, patterns)
        out.append(f"{{{kind}}}" if kind else seg)
    t = "/".join(out)
    if t != "/":
        t = t.rstrip("/")
    return t or "/"


def _id_query_name(key: str, names=None) -> bool:
    return bool(ID_QUERY.search(key) or ID_QUERY_LIST.search(key)
                or (names and key in names))


def _split_values(value: str) -> list[str]:
    """`1001,1002` -> ['1001','1002']；单值原样返回。"""
    parts = [x.strip() for x in value.split(",")]
    return [x for x in parts if x and x.lower() not in _BLANK]


def _scalars(value) -> list[str]:
    """把请求体里某个键的值摊平成标量列表（支持标量 / 数组 / 逗号串）。"""
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for v in value:
            out.extend(_scalars(v))
        return out
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (str, int, float)):
        s = str(value)
        if s.lower() in _BLANK:
            return []
        return _split_values(s) if isinstance(value, str) else [s]
    return []


def object_ids(path: str, query: str = "", patterns=None, body=None,
               id_query_names=None) -> list[str]:
    """按出现顺序收集请求里引用的对象标识。

    路径段里所有纯数字 / UUID / 系统声明的自然键都算；查询参数只看名字带
    id 语义的（可用 `id_query_names` 补充，如 crAPI 的 `filename`）；
    给了 `body` 时再看请求体里 id 语义键的值（L3：批量接口）。
    """
    p, q = split_query(path)
    if query:
        q = f"{q}&{query}" if q else query
    ids = [seg for seg in p.split("/") if is_object_token(seg, patterns)]
    for k, v in parse_qsl(q, keep_blank_values=False):
        if v and _id_query_name(k, id_query_names):
            ids.extend(_split_values(v))
    if body is not None:
        ids.extend(body_object_ids(body, patterns, id_query_names))
    return ids


def body_object_ids(body, patterns=None, id_query_names=None) -> list[str]:
    """从请求体里按 id 语义键名抽取对象标识（L3 批量接口）。

    {"ids": [1001, 1002]}          -> ['1001','1002']
    {"order_id": 7}                -> ['7']
    {"documents": [{"id": "..."}]} -> ['...']（递归下钻）

    只按**键名**判断，不看值形态：请求体里的 `amount: 599` 不能被误当标识。
    """
    out: list[str] = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _id_query_name(k, id_query_names) or ID_BODY.search(k):
                    out.extend(_scalars(v))
                else:
                    walk(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                walk(v)

    walk(body)
    return out


def has_object_ref(path: str, query: str = "", patterns=None, body=None,
                   id_query_names=None) -> bool:
    """请求里是否真的引用了一个对象标识。

    没有对象标识的请求（`/api/me`、`/community/posts/recent`）换 token
    重放只会拿到攻击者自己的数据，不能证明 BOLA。这是误报的第一道闸门。
    """
    return bool(object_ids(path, query, patterns, body, id_query_names))


def case_key(method: str, path: str, query: str = "",
             patterns=None) -> tuple[str, str, tuple[str, ...]]:
    """对象实例键：方法 + 路径模板 + 具体对象标识。"""
    return (method.upper(), template(path, patterns),
            tuple(object_ids(path, query, patterns)))


def key_of(record: dict) -> tuple[str, str, tuple[str, ...]]:
    """从标注或测试结果里取对象实例键。"""
    return (
        str(record.get("method", "")).upper(),
        str(record.get("path") or record.get("endpoint") or ""),
        tuple(str(x) for x in (record.get("object_ids") or [])),
    )


def fmt_key(key: tuple[str, str, tuple[str, ...]], width: int = 46) -> str:
    method, tpl, ids = key
    return f"{method:6s} {tpl:{width}s} ids={','.join(ids) or '-'}"
