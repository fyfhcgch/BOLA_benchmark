"""API 恢复层：从打包后的前端 JS 中提取 API 调用点与路由表。

三路来源（对照 研究方案 §2 Phase 3.2）：
  1. source map —— 若存在 .map，还原原始路径（这里只记录，不做完整还原）
  2. AST        —— 解析调用表达式，得到 URL 模板 + 参数名
  3. 路由表     —— 解析 Vue Router / React Router 的 path 定义

不依赖 Node，纯 Python（esprima）。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

try:
    import esprima
except ImportError:  # pragma: no cover
    esprima = None

# 常见 HTTP 客户端封装名
CLIENT_OBJECTS = {"axios", "http", "api", "request", "service", "req", "$", "instance", "client"}
METHOD_PROPS = {
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
    "del": "DELETE", "patch": "PATCH", "request": "GET", "ajax": "GET",
    "head": "HEAD", "options": "OPTIONS",
}


# --------------------------------------------------------------------------- #
# URL 参数解析
# --------------------------------------------------------------------------- #

def _literal(node) -> str | None:
    if node is None:
        return None
    t = getattr(node, "type", None)
    if t == "Literal" and isinstance(getattr(node, "value", None), str):
        return node.value
    return None


def _expr_name(node) -> str | None:
    """把表达式节点变成一个参数名，如 `${orderId}` -> orderId"""
    t = getattr(node, "type", None)
    if t == "Identifier":
        return node.name
    if t == "MemberExpression":
        obj = _expr_name(node.object)
        prop = node.property.name if getattr(node, "computed", False) is False else _expr_name(node.property)
        return f"{obj}.{prop}" if obj and prop else None
    if t == "CallExpression":
        return "expr"
    if t == "Literal":
        return None
    return "expr"


def url_template(node) -> tuple[str | None, list[str]]:
    """把 URL 参数节点转成 '/api/orders/{orderId}' 形式。"""
    if node is None:
        return None, []
    t = getattr(node, "type", None)

    if t == "Literal":
        v = getattr(node, "value", None)
        return (v, []) if isinstance(v, str) else (None, [])

    if t == "TemplateLiteral":
        out, params = [], []
        quasis = list(node.quasis)
        exprs = list(node.expressions)
        for i, q in enumerate(quasis):
            raw = q.value.raw if hasattr(q.value, "raw") else str(q.value)
            out.append(raw)
            if i < len(exprs):
                name = _expr_name(exprs[i]) or f"p{i}"
                params.append(name)
                out.append("{" + name + "}")
        return "".join(out), params

    if t == "BinaryExpression" and getattr(node, "operator", None) == "+":
        left, lp = url_template(node.left)
        right, rp = url_template(node.right)
        if left is not None and right is not None:
            return left + right, lp + rp
        # 左侧是字符串、右侧是变量
        if left is not None:
            name = _expr_name(node.right) or "p"
            return left + "{" + name + "}", lp + [name]
        if right is not None:
            name = _expr_name(node.left) or "p"
            return "{" + name + "}" + right, lp + [name]
    return None, []


# --------------------------------------------------------------------------- #
# AST 遍历
# --------------------------------------------------------------------------- #

class _Walker:
    def __init__(self):
        self.apis: list[dict] = []
        self.routes: list[dict] = []

    def walk(self, node, depth=0):
        if node is None or depth > 400:
            return
        t = getattr(node, "type", None)
        if t == "CallExpression":
            self._maybe_api(node)
        if t == "ObjectExpression":
            self._maybe_route(node)
        for key, val in vars(node).items() if hasattr(node, "__dict__") else []:
            if isinstance(val, list):
                for item in val:
                    if hasattr(item, "type"):
                        self.walk(item, depth + 1)
            elif hasattr(val, "type"):
                self.walk(val, depth + 1)

    def _maybe_api(self, node):
        callee = node.callee
        method, url_node = None, None
        ct = getattr(callee, "type", None)

        if ct == "MemberExpression":
            prop = getattr(callee.property, "name", None)
            obj_name = getattr(callee.object, "name", None) or ""
            if prop in METHOD_PROPS and (obj_name in CLIENT_OBJECTS or obj_name.endswith("Api")):
                method = METHOD_PROPS[prop]
                url_node = node.arguments[0] if node.arguments else None
        elif ct == "Identifier" and callee.name == "fetch":
            method = "GET"
            url_node = node.arguments[0] if node.arguments else None
            if len(node.arguments) > 1:
                method = self._fetch_method(node.arguments[1]) or "GET"

        if not method or url_node is None:
            return
        tpl, params = url_template(url_node)
        if not tpl or not tpl.startswith("/") and "://" not in tpl:
            return
        path = urlparse(tpl).path if "://" in tpl else tpl.split("?")[0]
        self.apis.append({
            "method": method,
            "template": path,
            "raw": tpl,
            "params": params,
        })

    @staticmethod
    def _fetch_method(opts):
        try:
            if getattr(opts, "type", None) != "ObjectExpression":
                return None
            for p in opts.properties:
                if getattr(p.key, "name", None) == "method":
                    return (p.value.value or "").upper() or None
        except Exception:
            return None
        return None

    def _maybe_route(self, node):
        keys = {getattr(p.key, "name", None) for p in node.properties}
        if "path" in keys and ("component" in keys or "element" in keys):
            for p in node.properties:
                if getattr(p.key, "name", None) == "path":
                    v = getattr(p.value, "value", None)
                    if isinstance(v, str) and v.startswith("/"):
                        self.routes.append({"path": v})


# --------------------------------------------------------------------------- #
# 对外接口
# --------------------------------------------------------------------------- #

def _normalize(path: str) -> str:
    """把 /api/orders/1001 -> /api/orders/{id}；仅用于匹配，不改原始模板。"""
    return re.sub(r"/\d+", "/{id}", re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27,}", "/{uuid}", path))


CALL_RE = re.compile(
    r"""\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]{3,160})["'`]"""
)
FETCH_RE = re.compile(r"""fetch\s*\(\s*["'`]([^"'`]{3,160})["'`]""")

# 常量表分支：现代 SPA 常把接口写成一张字面量表，例如
#   GET_ORDER: "api/shop/orders/<orderId>"
# 这类字面量既没有调用点（不可执行上下文），也不带 HTTP 方法，
# 但能覆盖"UI 从未触发"的接口，所以单独作为一路来源。
CONST_URL_RE = re.compile(r"""["'`](api/[A-Za-z0-9_\-./<>{}:]{2,160})["'`]""")
ANGLE_PARAM_RE = re.compile(r"<([A-Za-z_][A-Za-z0-9_]*)>")


def _regex_const_table(src: str) -> list[dict]:
    """提取 `"api/..."` 形式的常量路径，`<orderId>` 归一成 `{orderId}`。"""
    out: list[dict] = []
    for m in CONST_URL_RE.finditer(src):
        raw = m.group(1)
        path = "/" + raw.lstrip("/")
        path = ANGLE_PARAM_RE.sub(r"{\1}", path)
        out.append({
            "method": "ANY",
            "template": path,
            "raw": raw,
            "params": re.findall(r"\{([^}]+)\}", path),
            "source": "const",
        })
    return out


def _segment_list(path: str) -> list[str]:
    return [s for s in path.split("?")[0].split("/") if s]


def _template_has_ref(tpl: str) -> bool:
    """模板里是否还有占位符段（说明该接口带对象引用）。"""
    return any(_is_placeholder(seg) for seg in _segment_list(tpl))


def _is_placeholder(seg: str) -> bool:
    return (seg.startswith("{") and seg.endswith("}")) or (
        seg.startswith("<") and seg.endswith(">"))


def suffix_match(static_tpl: str, captured_tpl: str) -> int | None:
    """静态模板是否是抓包模板的后缀（占位符互相通配）。

    返回匹配到的段数（越大越具体），不匹配返回 None。
    `api/shop/orders/<orderId>` 与 `/workshop/api/shop/orders/{id}`
    在段级别对齐，从而解决"静态路径缺服务前缀"的问题。
    """
    a, b = _segment_list(static_tpl), _segment_list(captured_tpl)
    if not a or len(a) > len(b):
        return None
    for x, y in zip(a, b[-len(a):]):
        if x == y:
            continue
        if _is_placeholder(x) and _is_placeholder(y):
            continue
        return None
    return len(a)


def _regex_extract(src: str) -> list[dict]:
    """现代打包产物（ES2015+ / 压缩）esprima 解析不了时的降级路径。

    只能捕获"字符串字面量形式"的 URL；由常量拼接出来的 URL 抓不到，
    这类情况必须依赖抓包（这也是本文的一个实证发现）。
    """
    out = []
    for m in CALL_RE.finditer(src):
        method = METHOD_PROPS.get(m.group(1).lower(), "GET")
        url = m.group(2)
        if url.startswith("/") or url.startswith("http"):
            out.append({"method": method, "template": url.split("?")[0], "raw": url, "params": []})
    for m in FETCH_RE.finditer(src):
        url = m.group(1)
        if url.startswith("/") or url.startswith("http"):
            out.append({"method": "GET", "template": url.split("?")[0], "raw": url, "params": []})
    return out


def extract_from_file(path: Path) -> dict:
    src = path.read_text(encoding="utf-8", errors="ignore")
    w = _Walker()
    parsed = False
    if esprima is not None:
        try:
            tree = esprima.parseScript(src, {"tolerant": True, "loc": True})
            w.walk(tree)
            parsed = True
        except Exception:
            parsed = False
    if not parsed:
        w.apis = _regex_extract(src)

    # 去重（同 method + template 只留一条），合并参数
    merged: dict[tuple[str, str], dict] = {}
    for a in w.apis:
        key = (a["method"], _normalize(a["template"]))
        if key in merged:
            merged[key]["params"] = sorted(set(merged[key]["params"]) | set(a["params"]))
        else:
            merged[key] = dict(a, params=list(a["params"]))

    # 常量表分支与调用点分支互不替代：前者补广度，后者给方法
    static = _regex_const_table(src)

    return {
        "file": str(path),
        "endpoints": list(merged.values()),
        "static": static,
        "routes": w.routes,
    }


def merge_with_capture(js_info: dict, capture_path: Path, id_patterns=None) -> dict:
    """把"抓包观测 / AST 调用点 / 常量表"三路来源合并成一份端点清单。

    合并按**最长后缀**做，因为常量表里的路径往往缺少服务前缀：

        api/shop/orders/<orderId>  ->  /workshop/api/shop/orders/{id}

    返回的 stats 直接回答一个问题：静态常量表补出了多少"UI 从未触发"的接口。
    """
    from .ids import template as path_template

    observed: dict[str, dict] = {}
    with capture_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            tpl = path_template(r["path"].split("?")[0], id_patterns)
            ent = observed.setdefault(tpl, {"template": tpl, "methods": set(), "sources": set()})
            ent["methods"].add(r["method"].upper())
            ent["sources"].add("capture")

    inventory = [dict(e, methods=sorted(e["methods"]), sources=sorted(e["sources"]))
                 for e in observed.values()]

    def _best(tpl: str) -> tuple[dict | None, int]:
        best, best_score = None, (0, 0)
        for ent in inventory:
            n = suffix_match(tpl, ent["template"])
            if n is None:
                continue
            a = _segment_list(tpl)
            b = _segment_list(ent["template"])
            literal = sum(1 for x, y in zip(a, b[-len(a):]) if x == y)
            score = (n, literal)
            if score > best_score:
                best, best_score = ent, score
        return best, best_score[0]

    # AST 调用点：有方法，可能来自未被 UI 触发的代码路径
    for ep in js_info.get("endpoints", []):
        tpl = path_template(ep["template"], id_patterns)
        ent, _ = _best(tpl)
        if ent is None:
            ent = {"template": tpl, "methods": [], "sources": []}
            inventory.append(ent)
        if ep["method"] not in ent["methods"]:
            ent["methods"].append(ep["method"])
        ent["methods"].sort()
        if "ast" not in ent["sources"]:
            ent["sources"].append("ast")

    # 常量表：只有路径，没有方法
    confirmed = 0
    for st in js_info.get("static", []):
        ent, _ = _best(st["template"])
        if ent is not None:
            confirmed += 1
            ent.setdefault("static_template", st["template"])
            if "static" not in ent["sources"]:
                ent["sources"].append("static")
        else:
            inventory.append({
                "template": st["template"], "methods": [],
                "sources": ["static"], "static_template": st["template"],
            })

    static_total = len(js_info.get("static", []))
    captured = [e for e in inventory if "capture" in e["sources"]]
    unobserved = [e for e in inventory if "capture" not in e["sources"]]
    # 未触发接口里有多少是"带对象引用"的（理论上可测 BOLA，但缺对象实例）
    unseen_ref = [e for e in unobserved if _template_has_ref(e["template"])]
    return {
        "endpoints": inventory,
        "stats": {
            "captured": len(captured),
            "static": static_total,
            "static_confirmed": confirmed,
            "static_only": static_total - confirmed,
            "inventory": len(inventory),
            "unobserved": len(unobserved),
            "unobserved_with_ref": len(unseen_ref),
        },
    }


def extract_dir(jsdir: Path) -> dict:
    """扫描目录下全部 bundle，按方法+模板去重。"""
    out = {"endpoints": [], "routes": [], "static": []}
    seen = set()
    seen_static = set()
    for f in sorted(jsdir.glob("*.js")):
        try:
            r = extract_from_file(f)
        except Exception as e:
            print(f"  [jsapi] skip {f.name}: {type(e).__name__}: {e}")
            continue
        for ep in r["endpoints"]:
            key = (ep["method"], _normalize(ep["template"]))
            if key in seen:
                continue
            seen.add(key)
            out["endpoints"].append(ep)
        for st in r["static"]:
            key = _normalize(st["template"])
            if key in seen_static:
                continue
            seen_static.add(key)
            out["static"].append(st)
        out["routes"].extend(r["routes"])
    return out


if __name__ == "__main__":
    import sys
    d = Path(sys.argv[1] if len(sys.argv) > 1 else "results/raw/mock/js")
    print(json.dumps(extract_dir(d), ensure_ascii=False, indent=2))
