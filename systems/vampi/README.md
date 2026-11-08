# VAmPI 靶场（换栈对照）

Flask + SQLite + connexion（OpenAPI 3）写的 OWASP API Top 10 靶场。选它做第二个
真实系统，是为了验证三处泛化：**换语言/框架**（Python/Flask）、**换标识形态**
（书名、用户名等自然键，而不是自增数字 / UUID）、**纯 API 无前端**（没有 bundle
可爬，只能靠种子路由构造 capture）。

## 1. 部署

```bash
cd systems/vampi
docker compose up -d
docker compose ps        # 等容器起来（约 3–5 秒）
```

| 服务 | 地址 |
|---|---|
| VAmPI（vulnerable=1） | http://127.0.0.1:5002 |

配置里只起 vulnerable 实例。上游 `docker-compose.yaml` 还有一个 `vulnerable=0`
的 secure 实例（5001），留作"同一份代码、不同开关"的对照，本 pilot 不需要，
要手工对照时把 compose 里那段加回来即可。

## 2. 种子数据

```bash
python3 systems/vampi/seed.py
```

脚本做的事：

1. `GET /createdb` 重建 SQLite（会清空所有账号）
2. 注册 `alice1` / `bob2` / `carol3`
3. 每个账号 `POST /books/v1` 添加一本 `<username>-notebook`，`secret` 为
   `SECRET-<USERNAME>-BOOK`

书名是**全局唯一**的自然键，所以三个账号必须用不同书名。`pipeline/config.py`
的 `id_patterns` 里声明了 `^[a-z0-9]+-notebook$`，模板化时才认得出这段路径是
对象标识。

账号：

| 账号 | 邮箱 | 密码 |
|---|---|---|
| alice1 | alice1@example.com | Alice@12345 |
| bob2 | bob2@example.com | Bob@12345 |
| carol3 | carol3@example.com | Carol@12345 |

## 3. 跑检测

```bash
python -m pipeline.run --system vampi
```

预期输出：

```
[crawl] API-only：跳过浏览器，capture 由种子路由补齐
[infer] victims=['alice1', 'bob2', 'carol3'] owner_keys=['owner'] identity=['username', 'email'] sensitive=['email', 'secret']
[replay] 36 test cases (victims=3)
[writereplay] 12 cases, side_effect=6
[judge] public_resource 抑制 6 条（可见性由配置声明）
[VULN] GET /books/v1/{bookTitle} ids=alice1-notebook via=id_swap leak:secret|username:alice1
[VULN] PUT /users/v1/{username}/password ids=alice1 via=write_replay login_with_new_password_ok
labels=12  tested=12  uncovered=0  (coverage=1.000)
TP=6  FP=0  FN=0  TN=6
Precision=1.000  Recall=1.000  Recall(strict)=1.000  F1=1.000
```

连跑 3 次结果一致，账号密码与邮箱都会还原。

## 4. 标注内容

`bench/labels/vampi.jsonl`（12 条实例）分四组，每组 3 个账号各一条：

| 接口 | 类型 | 判定 | 设计意图 |
|---|---|---|---|
| `GET /books/v1/{bookTitle}` | 读 | VULN | 不校验归属，任意登录用户按书名可读他人 `secret` 与 `owner` |
| `PUT /users/v1/{username}/password` | 写 | VULN | 路径 `username` 决定目标，不校验是否为调用者；受害者能用新密码登录 |
| `PUT /users/v1/{username}/email` | 写 | 安全对照 | **路径形态一样**，但服务端忽略 `username`，只改调用者自己的邮箱 |
| `GET /users/v1/{username}` | 读 | 安全对照 | 用户列表 `GET /users/v1` 本来就返回 email，单个资料页属公开信息 |

`bench/labels/vampi.noref.jsonl`（4 条）是无对象引用的对照组：`/books/v1`、
`/users/v1`、`/users/v1/_debug`、`/me`。其中 `_debug` 是"过度数据暴露"（返回
明文密码），但**不是对象级越权**，正好检验"有敏感字段 ≠ 有 BOLA"。

## 5. 这个靶场的坑（都已在代码里处理）

| 现象 | 原因 | 处理 |
|---|---|---|
| 登录失败也返回 200 | VAmPI 用 body 里的 `{"status":"fail"}` 表示失败 | `login()` 取 `auth_token`；写型副作用用 `_login_ok()` 判断 token 是否存在，不看状态码 |
| `/createdb` 后所有账号消失 | 它 `drop_all + create_all` | 配置里 `reset: None`，重置由 `seed.py` 负责（重建 + 注册 + 加书） |
| 爬不到任何接口 | 纯 API，没有前端 bundle | `crawl: False`，capture 全部由 `detail_seeds` / `write_seeds` 生成 |
| 改自己邮箱导致后续判定错乱 | 该接口只改调用者，种子里写一次就污染了身份比对 | `write_seeds.restore` 写后立刻还原；replay 侧 `restore_body` 再兜一次 |
| 密码写完下一轮登录不上 | 改密码是破坏性的 | 种子里"改 → 验证能登录 → 立刻改回"；重放里用受害者 token 改回原密码 |
| 只有"数字/UUID"才被当对象 | 书名、用户名都不匹配默认规则 | `config.id_patterns` 声明两条形态，而不是改代码硬编码 |

## 6. 全量重置

```bash
bash systems/vampi/reset.sh
```

`docker compose down -v` → `up -d` → 等就绪 → `seed.py`。SQLite 在容器内，
不删容器卷就清不干净。
