"""靶场与账户配置。

新增一个系统只需要：
  1. 在 systems/ 下放 docker-compose.yml + seed.py
  2. 在 SYSTEMS 里加一条
  3. 在 bench/labels/<id>.jsonl 写标注
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "refs"
DATA = ROOT / "results"
BENCH = ROOT / "bench"


def _base_url(default: str) -> str:
    return os.environ.get("BOLA_BASE_URL", default)


SYSTEMS: dict[str, dict] = {
    "mock": {
        "id": "mock",
        "name": "MockShop (self-hosted lab)",
        "base_url": _base_url("http://127.0.0.1:8765"),
        "login": {
            "method": "POST",
            "path": "/api/login",
            "json": {"username": "{username}", "password": "{password}"},
            "token_field": "token",
        },
        "accounts": {
            # id 是系统内部主键（响应里的 user_id），手工配置 owner 时需要它
            "alice": {"id": 1, "username": "alice", "password": "alice123", "role": "user", "tenant": "t1"},
            "bob":   {"id": 2, "username": "bob",   "password": "bob123",   "role": "user", "tenant": "t1"},
            "carol": {"id": 3, "username": "carol", "password": "carol123", "role": "user", "tenant": "t2"},
        },
        "victim": "alice",
        "victims": ["alice", "bob", "carol"],   # 每个账号轮流当受害者
        "attackers": ["bob", "carol"],
        "seed_routes": ["/orders?id=1002", "/profile", "/products"],
        # 每个账号从自己的对象进入，否则 bob/carol 的详情页永远采不到
        "seed_routes_by_account": {
            "alice": ["/orders?id=1002", "/profile", "/products"],
            "bob":   ["/orders?id=1003", "/orders?id=1004", "/profile", "/products"],
            "carol": ["/orders?id=1005", "/profile", "/products"],
        },
        # 写型种子：PATCH 自己的订单，记录带 {nonce} 的请求体模板，
        # 供 replay 阶段换成攻击者身份重放（mock 的 PATCH 不校验归属 -> 真 BOLA）
        "id_sources": {
            "uid": {"from": "/api/me", "ids_path": "id"},
        },
        # L3 种子：标识不在路径里（请求体 / 逗号分隔查询值），
        # 或需要跨接口组合（先软删除再读回收站）才能触发。
        # `setup` / `teardown` 由采集与重放两侧各执行一次，保证可重复。
        "detail_seeds": [
            # 文档详情：UUID 标识 + 正常分支（安全对照，owner_check）
            {"path": "/api/documents/{uuid}",
             "from": "/api/documents",
             "ids_path": "[].id"},
            # L3 批量读：本账号全部订单 id 一次放进请求体
            {"path": "/api/orders/batch",
             "method": "POST",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "body_ids_key": "ids",
             "kind": "batch_read"},
            # 同一批量形态的安全对照：服务端按归属过滤，只返回自己的对象
            {"path": "/api/orders/batch/mine",
             "method": "POST",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "body_ids_key": "ids",
             "kind": "batch_read"},
            # L3 导出：标识是逗号分隔的查询值，响应是 CSV 而不是 JSON
            {"path": "/api/orders/export",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "query_ids_key": "ids"},
            # 同一导出形态的安全对照：服务端按归属过滤，只导出自己的行
            {"path": "/api/orders/export/mine",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "query_ids_key": "ids"},
            # L3 软删除：跨接口组合 —— 受害者先删，攻击者再读回收站
            {"path": "/api/documents/{uuid}/trash",
             "from": "/api/documents",
             "ids_path": "[].id",
             "index": 0,
             "setup": {"method": "DELETE", "path": "/api/documents/{uuid}"},
             "teardown": {"method": "PATCH", "path": "/api/documents/{uuid}",
                          "json": {"deleted": False}},
             "kind": "soft_delete"},
            # 同一回收站端点的空容器对照：文档没被删除时回收站是空的。
            # 与上一条同模板、不同对象 -> 两个不同的实例键，指标能分开算。
            {"path": "/api/documents/{uuid}/trash",
             "from": "/api/documents",
             "ids_path": "[].id",
             "index": 1,
             "kind": "trash_empty"},
        ],
        "write_seeds": [
            {"method": "PATCH",
             "path": "/api/orders/{id}",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "json": {"note": "BOLA-PROBE-{nonce}"},
             "verify": "/api/orders/{id}"},
        ],
        "labels": "bench/labels/mock.jsonl",
        "reset": {"method": "POST", "path": "/api/debug/reset"},
    },
    # 整系统 clean control：与 mock 是**同一个应用**（systems/mock/app.py），
    # 只把 MOCK_POLICY 切成 secure。路由/响应/前端/对象全部同构，
    # 唯一变量是授权判定，所以"零误报"这句话可归因（见 systems/clean/app.py）。
    "clean": {
        "id": "clean",
        "name": "MockShop-secure (clean control)",
        "base_url": _base_url("http://127.0.0.1:8766"),
        "login": {
            "method": "POST",
            "path": "/api/login",
            "json": {"username": "{username}", "password": "{password}"},
            "token_field": "token",
        },
        "accounts": {
            "alice": {"id": 1, "username": "alice", "password": "alice123", "role": "user", "tenant": "t1"},
            "bob":   {"id": 2, "username": "bob",   "password": "bob123",   "role": "user", "tenant": "t1"},
            "carol": {"id": 3, "username": "carol", "password": "carol123", "role": "user", "tenant": "t2"},
        },
        "victim": "alice",
        "victims": ["alice", "bob", "carol"],
        "attackers": ["bob", "carol"],
        # 与 mock 完全相同的入口：前端 bundle 与种子路由一致，差异只在服务端
        "seed_routes": ["/orders?id=1002", "/profile", "/products"],
        "seed_routes_by_account": {
            "alice": ["/orders?id=1002", "/profile", "/products"],
            "bob":   ["/orders?id=1003", "/orders?id=1004", "/profile", "/products"],
            "carol": ["/orders?id=1005", "/profile", "/products"],
        },
        "id_sources": {
            "uid": {"from": "/api/me", "ids_path": "id"},
        },
        "detail_seeds": [
            {"path": "/api/documents/{uuid}",
             "from": "/api/documents",
             "ids_path": "[].id"},
            {"path": "/api/orders/batch",
             "method": "POST",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "body_ids_key": "ids",
             "kind": "batch_read"},
            {"path": "/api/orders/batch/mine",
             "method": "POST",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "body_ids_key": "ids",
             "kind": "batch_read"},
            {"path": "/api/orders/export",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "query_ids_key": "ids"},
            {"path": "/api/orders/export/mine",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "group": 2,
             "query_ids_key": "ids"},
            {"path": "/api/documents/{uuid}/trash",
             "from": "/api/documents",
             "ids_path": "[].id",
             "index": 0,
             "setup": {"method": "DELETE", "path": "/api/documents/{uuid}"},
             "teardown": {"method": "PATCH", "path": "/api/documents/{uuid}",
                          "json": {"deleted": False}},
             "kind": "soft_delete"},
            {"path": "/api/documents/{uuid}/trash",
             "from": "/api/documents",
             "ids_path": "[].id",
             "index": 1,
             "kind": "trash_empty"},
        ],
        "write_seeds": [
            {"method": "PATCH",
             "path": "/api/orders/{id}",
             "from": "/api/users/{uid}/orders",
             "ids_path": "[].id",
             "json": {"note": "BOLA-PROBE-{nonce}"},
             "verify": "/api/orders/{id}"},
        ],
        "labels": "bench/labels/clean.jsonl",
        "reset": {"method": "POST", "path": "/api/debug/reset"},
    },
    # OWASP crAPI（docker compose 部署，需先跑 systems/crapi/seed.py）
    "crapi": {
        "id": "crapi",
        "name": "OWASP crAPI",
        "base_url": _base_url("http://127.0.0.1:8888"),
        "login": {
            "method": "POST",
            "path": "/identity/api/auth/login",
            "json": {"email": "{email}", "password": "{password}"},
            "token_field": "token",
        },
        "accounts": {
            "alice": {"username": "alice", "email": "alice@example.com", "password": "Alice@12345", "role": "user", "tenant": "t1"},
            "bob":   {"username": "bob",   "email": "bob@example.com",   "password": "Bob@12345",   "role": "user", "tenant": "t1"},
            "carol": {"username": "carol", "email": "carol@example.com", "password": "Carol@12345", "role": "user", "tenant": "t2"},
        },
        "victim": "alice",
        "victims": ["alice", "bob", "carol"],   # 每个账号轮流当受害者
        "attackers": ["bob", "carol"],
        "seed_routes": [
            "/dashboard", "/orders", "/my-profile", "/forum",
            "/shop", "/past-orders", "/contact-mechanic",
        ],
        "ui_login": {
            "path": "/login",
            "email_selector": "#basic_email",
            "password_selector": "#basic_password",
            "submit": "button[type=submit]",
            "wait_ms": 3000,
            "success_path": "/login",
        },
        # UI 只点到订单 7；这里按列表接口把受害者的全部对象实例补一遍
        "detail_seeds": [
            {"path": "/workshop/api/shop/orders/{id}",
             "from": "/workshop/api/shop/orders/all",
             "ids_path": "orders[].id"},
            {"path": "/identity/api/v2/vehicle/{uuid}/location",
             "from": "/identity/api/v2/vehicle/vehicles",
             "ids_path": "[].uuid"},
            {"path": "/workshop/api/merchant/service_requests/{vin}",
             "from": "/identity/api/v2/vehicle/vehicles",
             "ids_path": "[].vin"},
            # 按 VIN 取到"我的维修请求 id"，再补 mechanic 侧的详情与评论
            {"path": "/workshop/api/mechanic/service_request/{serviceId}",
             "from": "/workshop/api/merchant/service_requests/{vin}",
             "ids_path": "service_requests[].id"},
            {"path": "/workshop/api/mechanic/service_request/{serviceId}/comment",
             "from": "/workshop/api/merchant/service_requests/{vin}",
             "ids_path": "service_requests[].id"},
            # 社区帖子 id 是 22 位 NanoID，从 recent 列表取
            {"path": "/community/api/v2/community/posts/{postId}",
             "from": "/community/api/v2/community/posts/recent",
             "ids_path": "posts[].id",
             # recent 返回全站帖子，只取本账号发的（受害者自己的对象）
             "where": {"list": "posts", "field": "author.email", "value": "{email}"}},
            # ---- L3：报表下载（标识由上一跳派生，响应是 PDF） ----
            # ★ 漏洞：任意登录用户按 filename 就能下到他人报表（PDF 里有车主邮箱/手机号）
            {"path": "/workshop/api/mechanic/download_report",
             "from": "/workshop/api/merchant/service_requests/{vin}",
             "ids_path": "service_requests[].id",
             "query_ids_key": "filename",
             "query_value_template": "report_{id}",
             "index": 0,
             "kind": "export"},
            # mechanic 报表元数据：标识是查询参数 report_id（由上一跳的 serviceId 得到）
            # ★ 漏洞：不校验归属，响应里带车主 email/number
            {"path": "/workshop/api/mechanic/mechanic_report",
             "from": "/workshop/api/merchant/service_requests/{vin}",
             "ids_path": "service_requests[].id",
             "query_ids_key": "report_id",
             "index": 0,
             "kind": "query_ref"},
        ],
        # `from` 模板里要用的受试者标识
        "id_sources": {
            "vin": {"from": "/identity/api/v2/vehicle/vehicles", "ids_path": "[].vin"},
            "uuid": {"from": "/identity/api/v2/vehicle/vehicles", "ids_path": "[].uuid"},
            "uid": {"from": "/identity/api/v2/user/dashboard", "ids_path": "id"},
        },
        # 除数字 / UUID 之外的标识形态（F2：非数字自然标识）
        "id_patterns": [
            ("vin", r"^[A-HJ-NPR-Z0-9]{17}$"),
            ("postId", r"^[A-Za-z0-9_-]{20,24}$"),
        ],
        # 查询参数名不在内置 id 语义表里、但确实引用对象的：导出接口的 filename
        "id_query_names": ["filename", "report_id"],
        # 写型种子：用受害者自己的凭据写入，记录带 {nonce} 的请求体模板，
        # replay 阶段换成攻击者身份重放，再以受害者身份复读确认副作用。
        "write_seeds": [
            {"method": "POST",
             "path": "/community/api/v2/community/posts/{postId}/comment",
             "from": "/community/api/v2/community/posts/recent",
             "ids_path": "posts[].id",
             "where": {"list": "posts", "field": "author.email", "value": "{email}"},
             "json": {"content": "BOLA-PROBE-{nonce}"},
             "verify": "/community/api/v2/community/posts/{postId}"},
            # PUT + 枚举字段：status 不能塞 nonce，改成"读当前值 -> 写另一个合法值 -> 复读比对"
            # 前端把该接口放在 mechanic 面板，但服务端不校验角色与归属 -> 任意登录用户可改他人状态
            {"method": "PUT",
             "path": "/workshop/api/mechanic/service_request/{serviceId}",
             "from": "/workshop/api/merchant/service_requests/{vin}",
             "ids_path": "service_requests[].id",
             "json": {"status": "{enum}"},
             "verify": "/workshop/api/mechanic/service_request/{serviceId}",
             "enum_field": "status",
             "enum_values": ["pending", "completed"]},
        ],
        # 公开资源：社区帖子对所有登录用户可见，读到作者 email 不算越权。
        # 资源可见性是**策略输入**，不能从"匿名能否读"推断（见 pilot_findings §7.1）。
        "public_paths": [
            "/community/api/v2/community/posts/{postId}",
            "/community/api/v2/community/posts/{postId}/comment",
        ],
        # 部署相关标识（uuid）的刷新来源，见 bench/sync_ids.py
        "vehicle_list": "/identity/api/v2/vehicle/vehicles",
        "labels": "bench/labels/crapi.jsonl",
        "reset": None,
    },
    # VAmPI：Flask + SQLite，纯 API（没有前端 bundle），对象标识是字符串
    # 三处泛化点：换栈（Python/Flask）、换标识形态（书名/用户名）、换认证（JWT）
    "vampi": {
        "id": "vampi",
        "name": "VAmPI (Flask, API-only)",
        "base_url": _base_url("http://127.0.0.1:5002"),
        "login": {
            "method": "POST",
            "path": "/users/v1/login",
            "json": {"username": "{username}", "password": "{password}"},
            "token_field": "auth_token",
        },
        "accounts": {
            "alice1": {"id": "alice1", "username": "alice1", "password": "Alice@12345",
                       "email": "alice1@example.com", "role": "user", "tenant": "t1"},
            "bob2":   {"id": "bob2", "username": "bob2", "password": "Bob@12345",
                       "email": "bob2@example.com", "role": "user", "tenant": "t1"},
            "carol3": {"id": "carol3", "username": "carol3", "password": "Carol@12345",
                       "email": "carol3@example.com", "role": "user", "tenant": "t2"},
        },
        "victim": "alice1",
        "victims": ["alice1", "bob2", "carol3"],
        "attackers": ["bob2", "carol3"],
        # 纯 API：没有 SPA 可点，capture 由 detail_seeds / write_seeds 生成
        "crawl": False,
        "seed_routes": [],
        # 非数字标识：书名是自然键，用户名是自然键。两条规则都不匹配路由段
        # （v1 只有 1 个字母，password/email 没有数字）
        "id_patterns": [
            ("bookTitle", r"^[a-z0-9]+-notebook$"),
            ("username", r"^[a-z]{3,}[0-9]{1,3}$"),
        ],
        "id_sources": {
            "username": {"from": "/me", "ids_path": "data.username"},
        },
        "detail_seeds": [
            # 列出全部书（不含 secret），只取本账号的，再读详情
            {"path": "/books/v1/{bookTitle}",
             "from": "/books/v1",
             "ids_path": "Books[].book_title",
             "where": {"list": "Books", "field": "user", "value": "{username}"}},
            # 用户资料：路径里是用户名，属于"公开可见"（列表接口也返回 email）
            {"path": "/users/v1/{username}",
             "from": "/users/v1",
             "ids_path": "users[].username",
             "where": {"list": "users", "field": "username", "value": "{username}"}},
        ],
        "write_seeds": [
            # 真 BOLA：改他人密码（路径 username 决定目标，服务端不校验）
            {"method": "PUT",
             "path": "/users/v1/{username}/password",
             "from": "/me",
             "ids_path": "data.username",
             "json": {"password": "Bola-{nonce}!A1"},
             "verify": "/me",
             "verify_login": True},
            # 安全对照：路径里也有 username，但服务端忽略它、只改调用者自己的邮箱
            {"method": "PUT",
             "path": "/users/v1/{username}/email",
             "from": "/me",
             "ids_path": "data.username",
             "json": {"email": "bola-{nonce}@example.com"},
             "verify": "/users/v1/{username}",
             # 该接口只改调用者自己的邮箱；种子里写完立刻还原，避免污染身份比对
             "restore": {"email": "{email}"}},
        ],
        # 用户列表本来就返回 email，所以单个资料页是公开信息
        "public_paths": ["/users/v1/{username}"],
        # VAmPI 的用户资料页**匿名真实可读**（实测 200），"公开"包含匿名；
        # 其余系统（crAPI community 等）匿名 401，公开仅指已认证用户。
        "public_anon": True,
        "labels": "bench/labels/vampi.jsonl",
        # 重置/重建由 systems/vampi/reset.sh 负责（它还会注册账号、加书）
        "reset": None,
    },
}

# 敏感字段：判定"是否泄露了他人私有数据"
SENSITIVE_FIELDS = {
    "email", "phone", "mobile", "address", "id_card", "real_name", "realname",
    "order_no", "amount", "balance", "card_no", "note", "birthday", "ssn",
    # VAmPI 的书本详情把 secret 直接返回；密码类泄露也算敏感
    "secret", "password",
}

# owner 字段：用来推断"这个对象属于谁"
# 身份标识字段：值本身就能唯一标识一个主体（crAPI 的订单里是嵌套的 user.email）
IDENTITY_KEYS = {"email", "username", "number", "phone", "mobile"}

OWNER_KEYS = {
    "user_id", "userId", "uid", "owner", "owner_id", "ownerId",
    "create_by", "createBy", "created_by", "createdBy", "tenant_id", "tenantId",
}

# 参数名启发式
ID_PARAM_RE = r"(^|_)(id|uid|uuid|gid|no|code|sn|key)$|Id$|ID$"

# id_probe 的偏移量：太小覆盖不到旁路对象，太大浪费请求。
# 本地靶场可以放宽，正式实验按 systems 覆盖。
DEFAULT_PROBE_DELTAS = (-2, -1, 1, 2, 3, 4, 5, 10)

DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "User-Agent": "BOLA-bench-pilot/0.1",
}
