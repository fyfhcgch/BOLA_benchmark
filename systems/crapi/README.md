# OWASP crAPI 靶场

真实微服务靶场（Java/Go + React 前端），BOLA 是其设计目标之一。

## 1. 部署

```bash
cd systems/crapi
docker compose up -d          # 首次会拉 ~3 GB 镜像
docker compose ps             # 等到全部 healthy（约 1–2 分钟）
```

端口：

| 服务 | 地址 |
|---|---|
| Web 前端 | http://127.0.0.1:8888 |
| Mailhog（收邮件） | http://127.0.0.1:8025 |

## 2. 种子数据

```bash
python systems/crapi/seed.py
```

脚本做的事（幂等，可重复执行）：

1. 注册 alice / bob / carol
2. 从 Mailhog 解析每个账号收到的 VIN + pincode，调用 `add_vehicle` 添加车辆
3. 每个账号创建 2 笔订单
4. 每个账号发 1 条社区帖子（已有则跳过）
5. 每个账号提 1 条维修服务请求（`contact_mechanic`，按 VIN 可查）

写型模板不在这里造：`pipeline/seed.py` 的 `seed_writes` 会以受害者身份

* 在自己的帖子上写一条评论（`POST`，请求体带 `{nonce}`）；
* 把自己的维修请求状态翻转一次（`PUT`，`status` 是枚举值，塞不进 nonce，
  改用"读当前值 → 写另一个合法值 → 受害者复读比对"）。

两条模板都记进 capture，供攻击者重放。

账号：

| 账号 | 邮箱 | 密码 |
|---|---|---|
| alice | alice@example.com | Alice@12345 |
| bob | bob@example.com | Bob@12345 |
| carol | carol@example.com | Carol@12345 |

## 3. 跑检测

```bash
python -m pipeline.run --system crapi
```

预期输出：

```
[crawl] UI login -> /dashboard (ok)
[crawl] 108 records
[seed] alice /workshop/api/shop/orders/{id} <- 2 个实例
[seed] alice /identity/api/v2/vehicle/{uuid}/location <- 1 个实例
[seed] alice /workshop/api/merchant/service_requests/{vin} <- 1 个实例
[seed] alice /workshop/api/mechanic/service_request/{serviceId} <- 1 个实例
[seed] alice /workshop/api/mechanic/service_request/{serviceId}/comment <- 1 个实例
[seed] alice /community/api/v2/community/posts/{postId} <- 1 个实例
[seed] alice POST /community/api/v2/community/posts/{postId}/comment <- 1 个实例
[seed] alice PUT /workshop/api/mechanic/service_request/{serviceId} <- 1 个实例
[jsapi] routes=0 ast=0 static=41 captured=18 confirmed=16 static_only=25 unobserved_with_ref=0
[infer] victims=['alice','bob','carol'] owner_keys=['owner'] identity=['email', 'number']
[VULN] GET /workshop/api/shop/orders/{id} ids=7 via=id_swap leak:amount,email|email:alice@exam
[VULN] GET /identity/api/v2/vehicle/{uuid}/location ids=... via=id_swap leak:email|email:alice@exam
[VULN] GET /workshop/api/merchant/service_requests/{vin} ids=... via=id_swap leak:email|email:alice@exam
[VULN] GET /workshop/api/mechanic/service_request/{id} ids=6 via=id_swap leak:email|email:alice@exam
[VULN] PUT /workshop/api/mechanic/service_request/{id} ids=6 via=write_replay enum_flip:pending->completed
[writereplay] 12 cases, side_effect=12
[judge] public_resource 抑制 12 条（可见性由配置声明）
labels=33 tested=33 uncovered=0 (coverage=1.000)
TP=18 FP=0 FN=0 TN=15
```

## 3.1 全量重置后必须刷新部署相关标识

`vehicle.uuid` / `vin`、社区帖子 `postId`、维修请求 `serviceId` 在
`docker compose down -v` 后都会重新生成或重排，标注里硬编码的值会失效。
重置后跑一次（`reset.sh` 已自动调用）：

```bash
python bench/sync_ids.py --system crapi
```

## 4. 全量重置

```bash
bash systems/crapi/reset.sh
```

删卷重建 + 重新灌种子数据。**写型测试之间必须重置**，否则订单被删后后续测试全部 404。

## 5. 这个靶场的坑（都已在代码里处理）

| 现象 | 原因 | 处理 |
|---|---|---|
| 注入 `localStorage.token` 后仍跳 /login | React 应用在初始化时才写入 token，注入无效 | `config.py` 里配 `ui_login`，走真实表单登录 |
| `add_vehicle` 返回 400 | 字段名是 `vin` 不是 `carId` | 已修正 |
| 打包产物 1.6 MB，esprima 解析报 `Unexpected token ILLEGAL` | 现代 ES2015+ 语法 | `jsapi.py` 降级到正则提取（crAPI 上仍为 0，见下） |
| 静态提取到 0 个端点 | crAPI 的 API 路径写在常量表里，没有可执行调用点 | 增加常量表分支，41 条候选，见 `docs/pilot_findings.md` §3 |
| 读他人社区帖子被判误报 | 帖子是公开内容，作者 email 可见是设计行为 | `public_paths` 声明可见性，判定输出 `public_resource` |
| 改他人维修请求状态 | 前端把它放在 mechanic 面板，但服务端不校验角色与归属 | `write_seeds` 翻转 `status`，受害者复读确认后判 VULN |
| 无对象引用的端点被误判 | 换 token 重放 `dashboard` / `posts/recent` 只会拿到攻击者自己的数据 | `replay.has_object_ref()` 闸门过滤 |
| 订单 id 是全局自增，跨用户可见 | crAPI 的设计 | 正常，正是漏洞所在 |
