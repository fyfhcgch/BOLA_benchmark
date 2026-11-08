"""
Mock 靶场：一个刻意带有 BOLA 漏洞的最小 Web 应用。

设计目标（与真实靶场对齐）：
  * 多用户 + 多对象，对象带 owner 字段 -> 支持"从响应反推对象归属"
  * 同时包含 读型 BOLA / 写型 BOLA / 嵌套资源 / 安全接口 / 公开接口
  * 包含 L3 场景：批量读取、导出、软删除（标识不在路径里，或需要跨接口组合）
  * 前端是一个带 JS bundle 的 SPA -> 支持"从前端恢复 API"
  * 提供 /api/debug/reset -> 支持实验可重复

## 整系统 clean control（`MOCK_POLICY=secure`）

`systems/clean/app.py` 用**同一个文件**、同一份种子数据、同一个前端 bundle，
只把环境变量 `MOCK_POLICY` 切成 `secure`。差异点全部集中在 `_owner_ok()`：
`secure` 时每个 ★ 标记处都补上归属校验，`vulnerable` 时保持原样。

这样"漏洞系统 vs 无漏洞系统"的对照是**受控**的：路由表、响应字段、对象标识、
前端调用点完全一致，唯一变量是授权判定。clean 系统上任何告警都是误报，
这正是 §VI 里"整系统 clean control"要量化的量（当前 FP=0 即零误报）。

漏洞清单（`MOCK_POLICY=vulnerable`，与 bench/labels/mock.jsonl 一一对应）：
  GET    /api/orders/{id}            读型 BOLA（缺 owner 校验）
  GET    /api/users/{uid}/orders     嵌套资源 BOLA
  DELETE /api/orders/{id}            写型 BOLA（硬删除，受害者复读变 404）
  PATCH  /api/orders/{id}            写型 BOLA（改内容，用于 PATCH 模板）
  POST   /api/orders/batch           L3 批量读：标识在**请求体**里，缺 owner 校验
  GET    /api/orders/export?ids=...  L3 导出：标识是**逗号分隔的查询值**，缺 owner 校验
  DELETE /api/documents/{uuid}       L3 软删除：标记 deleted 而不真删，缺 owner 校验
  GET    /api/documents/{uuid}/trash L3 回收站读：删除后才可见，缺 owner 校验
                                     （必须先 DELETE 再 GET，是真正的跨接口组合）
  GET    /api/mechanic 侧无此路由，见 crAPI
安全接口：
  GET    /api/profile/{uid}         校验 owner，403
  GET    /api/orders/{id}/items     校验 owner，403
  GET    /api/documents/{uuid}      校验 owner，403（正常分支）
  PATCH  /api/documents/{uuid}      只允许属主改 deleted 标记，403
  GET    /api/products              公开数据，不涉及对象
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# 授权策略开关：vulnerable = 保留 BOLA；secure = 每个入口都校验归属。
# clean 对照系统不复制代码，只切这个变量 —— 保证两组之间只差策略。
POLICY = os.environ.get("MOCK_POLICY", "vulnerable")
SECURE = POLICY == "secure"

TOKENS: dict[str, str] = {}          # token -> username
USERS = {
    "alice": {"id": 1, "password": "alice123", "email": "alice@example.com", "phone": "13800000001"},
    "bob":   {"id": 2, "password": "bob123",   "email": "bob@example.com",   "phone": "13800000002"},
    "carol": {"id": 3, "password": "carol123", "email": "carol@example.com", "phone": "13800000003"},
}

SEED_ORDERS = [
    {"id": 1001, "user_id": 1, "user_email": "alice@example.com", "item": "机械键盘", "amount": 599,  "note": "ALICE-ONLY-1001"},
    {"id": 1002, "user_id": 1, "user_email": "alice@example.com", "item": "显示器",   "amount": 1899, "note": "ALICE-ONLY-1002"},
    {"id": 1003, "user_id": 2, "user_email": "bob@example.com",   "item": "鼠标",     "amount": 199,  "note": "BOB-ONLY-1003"},
    {"id": 1004, "user_id": 2, "user_email": "bob@example.com",   "item": "耳机",     "amount": 899,  "note": "BOB-ONLY-1004"},
    {"id": 1005, "user_id": 3, "user_email": "carol@example.com", "item": "摄像头",   "amount": 459,  "note": "CAROL-ONLY-1005"},
]

# 文档用 UUID 作标识：软删除场景的对象不应能被数字枚举，
# 否则 id_probe 会把"枚举命中"混进来，掩盖"跨接口组合"这一难点。
SEED_DOCUMENTS = [
    {"id": "a1b2c3d4-0001-4000-8000-000000000001", "user_id": 1,
     "owner_email": "alice@example.com", "title": "alice 的合同", "body": "ALICE-DOC-SECRET", "deleted": False},
    {"id": "a1b2c3d4-0002-4000-8000-000000000002", "user_id": 1,
     "owner_email": "alice@example.com", "title": "alice 的发票", "body": "ALICE-DOC-SECRET-2", "deleted": False},
    {"id": "b1b2c3d4-0003-4000-8000-000000000003", "user_id": 2,
     "owner_email": "bob@example.com", "title": "bob 的合同", "body": "BOB-DOC-SECRET", "deleted": False},
    {"id": "b1b2c3d4-0004-4000-8000-000000000004", "user_id": 2,
     "owner_email": "bob@example.com", "title": "bob 的发票", "body": "BOB-DOC-SECRET-2", "deleted": False},
    {"id": "c1b2c3d4-0005-4000-8000-000000000005", "user_id": 3,
     "owner_email": "carol@example.com", "title": "carol 的合同", "body": "CAROL-DOC-SECRET", "deleted": False},
]

ORDERS: list[dict] = []
DOCUMENTS: list[dict] = []
LOCK = threading.Lock()


def reset() -> None:
    global ORDERS, DOCUMENTS
    with LOCK:
        ORDERS = [dict(o) for o in SEED_ORDERS]
        DOCUMENTS = [dict(d) for d in SEED_DOCUMENTS]


reset()

INDEX_HTML = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><title>MockShop</title></head>
<body>
  <h1>MockShop</h1>
  <nav>
    <a href="/orders">我的订单</a> |
    <a href="/profile">我的资料</a> |
    <a href="/documents">我的文档</a> |
    <a href="/products">商品</a>
  </nav>
  <div id="app">loading...</div>
  <script src="/static/app.js"></script>
</body></html>"""

APP_JS = r"""
// 一个刻意写得"像真实项目"的前端 bundle：
// 里面混合了模板字符串、字符串拼接、fetch 与 axios 风格封装，
// 用于验证 pipeline/jsapi.py 的 AST 提取能力。
// 注意 L3 场景的调用点：批量与导出的标识**不在路径里**，
// 只看路径模板的检测器会整类漏掉它们。
const api = {
  get: (url) => fetch(url, {headers: {Authorization: 'Bearer ' + (localStorage.token || '')}}),
  del: (url) => fetch(url, {method: 'DELETE', headers: {Authorization: 'Bearer ' + (localStorage.token || '')}}),
};

async function loadOrders() {
  const me = await (await api.get('/api/me')).json();
  const orderId = new URLSearchParams(location.search).get('id') || 1001;
  await api.get(`/api/orders/${orderId}`);
  await api.get('/api/users/' + me.id + '/orders');
  await api.get(`/api/orders/${orderId}/items`);
}

async function loadProfile() {
  const me = await (await api.get('/api/me')).json();
  await api.get(`/api/profile/${me.id}`);
}

// L3：批量读取，对象标识放在请求体里
async function loadBatch(ids) {
  await fetch('/api/orders/batch', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + (localStorage.token || '')},
    body: JSON.stringify({ids}),
  });
}

// 批量读取的安全对照：请求体结构相同，服务端只返回自己的对象
async function loadBatchMine(ids) {
  await fetch('/api/orders/batch/mine', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + (localStorage.token || '')},
    body: JSON.stringify({ids}),
  });
}

// L3：导出，标识是逗号分隔的查询值
async function exportOrders(ids) {
  await api.get('/api/orders/export?ids=' + ids.join(','));
}

// 导出的安全对照：同一导出形态，服务端按归属过滤
async function exportMyOrders(ids) {
  await api.get('/api/orders/export/mine?ids=' + ids.join(','));
}

// L3：软删除 + 回收站（必须先 DELETE 才能读到内容）
async function loadDocuments() {
  const me = await (await api.get('/api/me')).json();
  const list = await (await api.get(`/api/documents?user=${me.id}`)).json();
  for (const d of list) {
    await api.get(`/api/documents/${d.id}`);
  }
  await api.del(`/api/documents/${list[0].id}`);
  await api.get(`/api/documents/${list[0].id}/trash`);
}

async function loadProducts() {
  await api.get('/api/products');
}

const routes = [
  {path: '/orders',  component: 'OrderList'},
  {path: '/orders/:id', component: 'OrderDetail'},
  {path: '/profile/:id', component: 'Profile'},
  {path: '/documents', component: 'DocumentList'},
  {path: '/products', component: 'ProductList'},
];

document.addEventListener('DOMContentLoaded', () => {
  const p = location.pathname;
  if (p.startsWith('/orders')) loadOrders();
  else if (p.startsWith('/profile')) loadProfile();
  else if (p.startsWith('/documents')) loadDocuments();
  else if (p.startsWith('/products')) loadProducts();
});
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ---------- helpers ----------
    def _drain_body(self):
        """把还没读走的请求体读掉，再回响应。

        keep-alive 下 401/403 提前返回时请求体还留在连接里，下一条请求的请求行
        会被残留 body 前缀污染成 `{"note":...}GET /...` → 501。重放型扫描器
        （ZAP Access Control）把 501 当"没命中拒绝判据"→ 把失败重放误判成
        授权成功（实测 msgs 183/202/216，/items 端点全是这种 501 假 200）。
        真实生产服务器（gunicorn 等）会正确处理，这是我们 mock 的 HTTP 层缺陷。
        """
        n = int(self.headers.get("Content-Length") or 0)
        got = getattr(self, "_consumed", 0)
        if n and n > got:
            try:
                self.rfile.read(n - got)
            except Exception:
                pass
        self._consumed = 0

    def _send(self, code: int, payload, ctype="application/json; charset=utf-8", extra=None):
        self._drain_body()
        body = payload if isinstance(payload, bytes) else (
            payload.encode() if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False).encode()
        )
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        self._consumed = n
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _user(self):
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            name = TOKENS.get(auth[7:])
            if name:
                return USERS[name]
        return None

    def log_message(self, *a):  # 静音
        pass

    @staticmethod
    def _doc(doc_id: str):
        return next((x for x in DOCUMENTS if x["id"] == doc_id), None)

    @staticmethod
    def _deny(u, obj, key: str = "user_id") -> bool:
        """该请求是否应被拒。

        `vulnerable` 策略下永远返回 False（保留漏洞）；`secure` 策略下
        对象不属于调用者就返回 True。所有 ★ 标记处只调这一个函数，
        因此两组系统之间的差异可以被逐点核对，不存在"顺手多改一处"。
        """
        if not SECURE:
            return False
        return str(obj.get(key)) != str(u["id"])

    # ---------- routing ----------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/orders", "/profile", "/documents", "/products"):
            return self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript; charset=utf-8")

        u = self._user()
        if not u and path.startswith("/api/"):
            return self._send(401, {"error": "unauthorized"})

        if path == "/api/me":
            return self._send(200, {"id": u["id"], "username": self._username(u), "email": u["email"]})

        if path == "/api/products":
            return self._send(200, [{"id": 1, "name": "键盘"}, {"id": 2, "name": "鼠标"}])

        # ---- L3 导出：标识是逗号分隔的查询值，且不在路径里 ----
        # ★ 漏洞：只按 ids 拼结果，完全不校验这些订单是否属于调用者
        if path in ("/api/orders/export", "/api/orders/export/mine"):
            raw = (query.get("ids") or [""])[0]
            ids = [x for x in raw.split(",") if x.strip()]
            if not ids:
                return self._send(400, {"error": "ids required"})
            rows = [o for o in ORDERS if str(o["id"]) in ids]
            if path.endswith("/mine") or SECURE:
                # ✅ 安全：同一导出形态，但按归属过滤（请求体/查询结构与漏洞版完全相同）
                rows = [o for o in rows if o["user_id"] == u["id"]]
            lines = ["id,user_email,item,amount,note"]
            lines += [f"{o['id']},{o['user_email']},{o['item']},{o['amount']},{o['note']}" for o in rows]
            # 导出是文本而不是 JSON：归属证据要能从 CSV 里读出来
            return self._send(200, "\n".join(lines), "text/csv; charset=utf-8")

        if path == "/api/documents":
            return self._send(200, [d for d in DOCUMENTS if d["user_id"] == u["id"] and not d["deleted"]])

        parts = [p for p in path.split("/") if p]

        # /api/orders/{id}
        if len(parts) == 3 and parts[:2] == ["api", "orders"]:
            if not parts[2].isdigit():
                return self._send(404, {"error": "no route"})
            oid = int(parts[2])
            o = next((x for x in ORDERS if x["id"] == oid), None)
            if not o:
                return self._send(404, {"error": "not found"})
            # ★ 漏洞：没有校验 o["user_id"] == u["id"]
            if self._deny(u, o):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, o)

        # /api/orders/{id}/items
        if len(parts) == 4 and parts[:2] == ["api", "orders"] and parts[3] == "items":
            if not parts[2].isdigit():
                return self._send(404, {"error": "no route"})
            oid = int(parts[2])
            o = next((x for x in ORDERS if x["id"] == oid), None)
            if not o:
                return self._send(404, {"error": "not found"})
            # ✅ 安全：校验了归属
            if o["user_id"] != u["id"]:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, [{"sku": "SKU-1", "qty": 1}])

        # /api/users/{uid}/orders
        if len(parts) == 4 and parts[:2] == ["api", "users"] and parts[3] == "orders":
            if not parts[2].isdigit():
                return self._send(404, {"error": "no route"})
            uid = int(parts[2])
            # ★ 漏洞：直接按路径里的 uid 返回，不校验是否等于当前用户
            if SECURE and str(uid) != str(u["id"]):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, [x for x in ORDERS if x["user_id"] == uid])

        # /api/profile/{uid}
        if len(parts) == 3 and parts[:2] == ["api", "profile"]:
            if not parts[2].isdigit():
                return self._send(404, {"error": "no route"})
            uid = int(parts[2])
            if uid != u["id"]:
                return self._send(403, {"error": "forbidden"})   # ✅ 安全
            return self._send(200, {"id": u["id"], "email": u["email"], "phone": u["phone"]})

        # /api/documents/{uuid}/trash：回收站读，只有软删除之后才有内容
        if len(parts) == 4 and parts[:2] == ["api", "documents"] and parts[3] == "trash":
            d = self._doc(parts[2])
            if not d:
                return self._send(404, {"error": "not found"})
            if not d["deleted"]:
                # 未删除的对象不在回收站：空容器，不是漏洞（no_owner_evidence 对照）
                return self._send(200, {"trash": []})
            # ★ 漏洞（L3）：回收站分支不校验归属，软删除后正文照样返回。
            # 必须先 DELETE 再 GET 才看得到 —— 单步检测器整类漏掉。
            if self._deny(u, d):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, d)

        # /api/documents/{uuid}
        if len(parts) == 3 and parts[:2] == ["api", "documents"]:
            d = self._doc(parts[2])
            if not d:
                return self._send(404, {"error": "not found"})
            # ✅ 安全：校验归属（正常分支与 include_deleted 分支都不放松）
            if d["user_id"] != u["id"]:
                return self._send(403, {"error": "forbidden"})
            if d["deleted"]:
                return self._send(404, {"error": "not found"})
            return self._send(200, d)

        return self._send(404, {"error": "no route"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/login":
            b = self._body()
            name = b.get("username", "")
            pwd = b.get("password", "")
            u = USERS.get(name)
            if not u or u["password"] != pwd:
                return self._send(401, {"error": "bad credentials"})
            token = f"tok-{name}-{u['id']}"
            TOKENS[token] = name
            return self._send(200, {"token": token, "id": u["id"], "username": name})
        if path == "/api/debug/reset":
            reset()
            return self._send(200, {"ok": True})

        u = self._user()
        if not u:
            return self._send(401, {"error": "unauthorized"})

        # ---- L3 批量读：标识在请求体里 ----
        # ★ 漏洞：按请求体里的 ids 批量返回，不校验归属
        if path == "/api/orders/batch":
            ids = [str(x) for x in (self._body().get("ids") or [])]
            rows = [o for o in ORDERS if str(o["id"]) in ids]
            if SECURE:
                rows = [o for o in rows if o["user_id"] == u["id"]]
            return self._send(200, {"orders": rows})

        # 批量读取的安全对照：同一个批量形态，但只返回调用者自己的对象。
        # 两者请求体结构完全相同，只有"响应里出现了谁的身份"能区分。
        if path == "/api/orders/batch/mine":
            ids = [str(x) for x in (self._body().get("ids") or [])]
            rows = [o for o in ORDERS if str(o["id"]) in ids and o["user_id"] == u["id"]]
            return self._send(200, {"orders": rows})

        return self._send(404, {"error": "no route"})

    def do_PATCH(self):
        path = urlparse(self.path).path
        u = self._user()
        if not u:
            return self._send(401, {"error": "unauthorized"})
        parts = [p for p in path.split("/") if p]

        # 恢复软删除标记：只允许属主（用于测试后清理，不构成漏洞）
        if len(parts) == 3 and parts[:2] == ["api", "documents"]:
            d = self._doc(parts[2])
            if not d:
                return self._send(404, {"error": "not found"})
            if d["user_id"] != u["id"]:
                return self._send(403, {"error": "forbidden"})
            b = self._body()
            if "deleted" in b:
                d["deleted"] = bool(b["deleted"])
            return self._send(200, d)

        if len(parts) == 3 and parts[:2] == ["api", "orders"]:
            oid = int(parts[2])
            b = self._body()
            with LOCK:
                o = next((x for x in ORDERS if x["id"] == oid), None)
                if not o:
                    return self._send(404, {"error": "not found"})
                # ★ 漏洞：修改时不校验归属
                if self._deny(u, o):
                    return self._send(403, {"error": "forbidden"})
                if "note" in b:
                    o["note"] = str(b["note"])
            return self._send(200, o)
        return self._send(404, {"error": "no route"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        u = self._user()
        if not u:
            return self._send(401, {"error": "unauthorized"})
        parts = [p for p in path.split("/") if p]

        # ---- L3 软删除：只把 deleted 置真，不真删 ----
        # ★ 漏洞：不校验归属；受害者之后正常读会 404（副作用可确认），
        # 但 ?include_deleted=true 分支仍把正文吐给任何人
        if len(parts) == 3 and parts[:2] == ["api", "documents"]:
            with LOCK:
                d = self._doc(parts[2])
                if not d:
                    return self._send(404, {"error": "not found"})
                if self._deny(u, d):
                    return self._send(403, {"error": "forbidden"})
                d["deleted"] = True
            return self._send(200, {"id": d["id"], "deleted": True})

        if len(parts) == 3 and parts[:2] == ["api", "orders"]:
            oid = int(parts[2])
            with LOCK:
                o = next((x for x in ORDERS if x["id"] == oid), None)
                if not o:
                    return self._send(404, {"error": "not found"})
                # ★ 漏洞：删除时不校验归属
                if self._deny(u, o):
                    return self._send(403, {"error": "forbidden"})
                ORDERS.remove(o)
            return self._send(204, b"")
        return self._send(404, {"error": "no route"})

    @staticmethod
    def _username(u):
        return next((k for k, v in USERS.items() if v["id"] == u["id"]), "?")


def main(host="127.0.0.1", port=8765):
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"[mock] listening on http://{host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
