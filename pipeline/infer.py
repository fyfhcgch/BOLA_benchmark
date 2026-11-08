"""语义推断层：参数分类 + owner 字段自动推断。

这是本方案相对现有工作的核心增量之一：
现有方法需要人工告诉工具"这个接口属于谁、角色怎么配"，
这里改为从响应 JSON 里自动找出 owner 关系。
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .config import IDENTITY_KEYS, OWNER_KEYS, SENSITIVE_FIELDS

ID_NAME_RE = re.compile(r"(^|_)(id|uid|uuid|gid|no|code|sn|key)$|Id$|ID$", re.I)
NUM_RE = re.compile(r"^\d{1,10}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{16,64}$", re.I)


def classify_param(name: str, observed: list[str] | None = None) -> dict:
    kind = "unknown"
    if observed:
        sample = next((v for v in observed if v), "")
        if NUM_RE.match(sample):
            kind = "numeric"
        elif UUID_RE.match(sample):
            kind = "uuid"
        elif HEX_RE.match(sample):
            kind = "hex"
        else:
            kind = "string"
    return {
        "name": name,
        "is_object_ref": bool(ID_NAME_RE.search(name or "")),
        "kind": kind,
        "enum_risk": "high" if kind == "numeric" else ("medium" if kind in ("uuid", "hex") else "low"),
    }


def _flatten(obj, prefix="") -> dict:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            out.update(_flatten(v, f"{prefix}[{i}]."))
    else:
        out[prefix.rstrip(".")] = obj
    return out


def _identity_canon(leaf: str) -> str | None:
    """`user_email` / `owner_number` 这类带前缀的身份字段归一成 `email` / `number`。

    返回 None 表示不是身份字段。归一化是必需的：不归一，`user_email` 会被当成
    一个独立的键，身份集合里就没有 `email`，下游的 R2-b 找不到受害者邮箱。
    """
    low = leaf.lower()
    if low in IDENTITY_KEYS:
        return low
    for k in IDENTITY_KEYS:
        if low.endswith(k):
            return k
    return None


def _is_identity_key(leaf: str) -> bool:
    return _identity_canon(leaf) is not None


def _sole_identity(flat: dict) -> dict[str, str]:
    """返回该响应里"只出现一个值"的身份字段。

    判据是**基数为一**，不是"路径里没有数字"：crAPI 的
    `/community/api/v2/community/posts/recent` 没有对象标识，却一次列出 7 个
    作者的邮箱，不能说明调用者是谁；而 `/identity/api/v2/user/dashboard` 只有
    调用者自己的邮箱。反过来，`/api/users/2/orders` 虽然路径带标识，但两条订单
    都属于同一个人，基数也是一，同样可用——只要后续再核对它是否等于本人身份。
    """
    grouped: dict[str, set] = {}
    for k, v in flat.items():
        leaf = k.split(".")[-1].split("[")[-1]
        canon = _identity_canon(leaf)
        if not canon or not isinstance(v, (str, int)):
            continue
        sv = str(v)
        if len(sv) < 5:      # 空串、短数字不是身份标识
            continue
        grouped.setdefault(canon, set()).add(sv)
    return {k: next(iter(vs)) for k, vs in grouped.items() if len(vs) == 1}


def infer_owner_fields(capture_path: Path, victim: str) -> dict:
    """从受害者的响应里推断 owner 字段名与其值。

    三步，顺序不能颠倒：

    1. **确定本人身份**：只认"某个身份字段在该响应里基数为 1"的响应。一个响应
       只点名一个人，那这个人就是调用者。列表类响应（社区帖子列表、维修工列表）
       一次点名多个主体，全部排除。
    2. **筛可信的 owner 值**：只从"响应里出现本人身份标识"的响应里收 owner 值。
       带对象标识的端点可能跨用户（靶场本来就允许），必须先核对身份。
    3. 响应里完全没有身份字段时（如纯 API 靶场），owner 值全部收集——不能因为
       推断不出身份就把证据丢光。

    为什么必须这么做：mock 的抓包语料里 bob 能读 alice 的订单。若不加区分，
    `user_id=1` 会被记成 bob 的归属值（`owner_values` 变成 `[1, 2]`），alice 的
    邮箱也会混进 bob 的身份集合；判据随即把"属主读自己的对象"判成越权
    （实测 9 条）。这是**推断层被越权探测污染**，不是判据本身的问题。
    """
    keys = Counter()
    values: dict[str, set] = {}
    sensitive_hits: set[str] = set()
    rows: list[dict] = []
    sole: dict[str, Counter] = {}

    with capture_path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["account"] != victim:
                continue
            body = r.get("resp_body")
            if not isinstance(body, (dict, list)):
                continue
            rows.append(r)
            for canon, val in _sole_identity(_flatten(body)).items():
                sole.setdefault(canon, Counter())[val] += 1

    identity: dict[str, set] = {}
    for canon, c in sole.items():
        top = max(c.values())
        identity[canon] = {v for v, n in c.items() if n == top}
    identity_source = "sole_identity" if identity else "none"
    own_ids = {v for vs in identity.values() for v in vs}

    for r in rows:
        flat = _flatten(r.get("resp_body"))
        leaves = {k.split(".")[-1].split("[")[-1]: v for k, v in flat.items()}
        id_leaves = [k for k in leaves if _is_identity_key(k)]
        has_ident = any(str(leaves[k]) in own_ids for k in id_leaves)
        trusted = has_ident or not id_leaves
        for k, v in flat.items():
            leaf = k.split(".")[-1].split("[")[-1]
            if leaf in OWNER_KEYS and trusted and v is not None:
                keys[leaf] += 1
                values.setdefault(leaf, set()).add(v)
            if leaf.lower() in SENSITIVE_FIELDS:
                sensitive_hits.add(leaf)

    return {
        "owner_keys": [k for k, _ in keys.most_common()],
        "owner_values": {k: sorted(v, key=str) for k, v in values.items()},
        "identity_values": {k: sorted(v) for k, v in identity.items()},
        "sensitive_fields": sorted(sensitive_hits),
        "identity_source": identity_source,
    }


def infer_endpoints(js_info: dict, capture_path: Path) -> list[dict]:
    """合并 AST 结果与抓包观测，产出带语义标签的端点清单。"""
    observed: dict[tuple[str, str], list[str]] = {}
    with capture_path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            path = re.sub(r"/\d+", "/{id}", r["path"].split("?")[0])
            segs = [s for s in r["path"].split("?")[0].split("/") if s]
            for s in segs:
                if s.isdigit():
                    observed.setdefault((r["method"], path), []).append(s)

    out = []
    for ep in js_info.get("endpoints", []):
        params = [classify_param(p, observed.get((ep["method"], ep["template"]))) for p in ep["params"]]
        out.append({
            "method": ep["method"],
            "template": ep["template"],
            "params": params,
            "source": "ast",
        })
    return out


if __name__ == "__main__":
    import sys
    cap = Path(sys.argv[1] if len(sys.argv) > 1 else "results/raw/mock/capture.jsonl")
    print(json.dumps(infer_owner_fields(cap, "alice"), ensure_ascii=False, indent=2))
