"""基线 1：OWASP ZAP 的 Access Control 插件（全流程无头，不用点 GUI）。

ZAP 的 accessControl 插件做的事：把站点树里的每个 URL 节点，分别以「各个用户 +
未认证」的身份重放，用 context 里配置的**授权判据**判断这次响应算不算"被授权"，
再对照该 (用户, 节点) 的**访问规则**（ALLOWED / DENIED）；两者矛盾就报
`Access Control Issue - Improper Authorization / Authentication` 告警。
它就是本文要对比的「多身份重放 + 授权矩阵」这一类工业实现（AuthMatrix /
Autorize 是同一族的交互式版本），因此必须有。

## 为什么必须往 context 文件里注入规则（论文里要写这条）

accessControl 插件**没有任何设置授权规则的 API**：`accessControl` 前缀下只有
`scan` / `writeHTMLreport` 两个 action 和 `getScanStatus` / `getScanProgress`
两个 view。官方 API 描述自己写明：

> [This assumes the Access Control rules were previously established via ZAP gui
>  and the necessary Context exported/imported.]

也就是说，**规则只能靠人工在 GUI 里点，或者导入手改过的 context 文件**。
更麻烦的是：没有规则的节点判据结果是 `UNKNOWN`，`UNKNOWN` **不产告警也不产判定**，
所以"没配规则"和"配了规则但没发现漏洞"在报告上长得一模一样（都是零告警）。
我们第一次跑就是被这个坑到：扫描 FINISHED、19 行节点、三列角色，告警 0 条。

本脚本的做法：`exportContext` → 在 `<context>` 里插入 `<accessControl>` 规则块 →
`removeContext` → `importContext`，规则串格式（从插件 jar 反查确认）：

    `userId`RULE`base64(nodeName)`escapedURI`

`nodeName` 不是路径最后一段，而是 ZAP 站点树自己的叶子名，带方法前缀、查询参数名
和请求体结构，例如 `GET:me` / `GET:export(ids)` / `PATCH:1001()({note})` /
`POST:batch()({ids:[{}..]})`。写错一个字符不会报错，只会静默变成"无规则"。
所以节点名一律**从 ZAP 自己的站点树里读**（scripts/dump_nodes.js），
注入完再用 scripts/dump_rules.js 逐条 `getDefinedRule()` 核对回来。

## 公平性口径（写进论文，不许美化也不许抹黑）

1. **URL 集合与我们流水线完全相同**：种子节点全部来自 `results/raw/<sys>/capture.jsonl`
   里受害者的抓包记录，不做人工整理、不额外补 URL。
2. **授权矩阵按工具设计意图机械注入**：给 ZAP 一份 per-URL × per-user 的 ALLOWED/DENIED
   矩阵。这属于该工具**设计上就要求人工提供**的输入（等价于在 GUI 里逐条点），
   因此是**对基线最有利**的配置。矩阵的生成规则（`build_matrix`）只用「端点是不是
   公开」「实例属主是谁」这两条策略事实，不使用「这个实例有没有漏洞」这个答案。
   任何漏检都必须归因于判据/机制，不能归因于配置缺失。
3. **未认证列同样给规则**：公开端点（登录、列表里的公开资源）匿名 ALLOWED，其余 DENIED。
   不给匿名规则的话 ZAP 那一列全是 UNKNOWN，等于偷偷砍掉它一半的判定面。
4. **告警只算 Access Control 类**：被动规则（Server 头、CSP 之类）与 RQ1 无关，
   分开统计，绝不混进 P/R/F1。
5. 命中与否由 `pipeline.evaluate` 的同一套匹配键判定，ZAP 报什么就记什么。

## 这个基线会破坏靶场状态（也是发现之一）

accessControl 是**真实重放**：它会把站点树里的 DELETE / PATCH / PUT 节点用每个身份
各发一遍，而且**没有任何 dry-run / 只测不改的开关**。我们的写型实例（软删除、改备注、
改他人密码）跑一遍就被改掉了，跨接口组合（先 DELETE 再读回收站）的顺序也完全由
ZAP 自己的树遍历顺序决定，不由测试脚本决定。所以：跑前跑后各重置一次 fixture，
并把这条写进 §IV-D 与 Threats to Validity。

跑法（需要先起 ZAP daemon 与靶场）：

    docker run -d --name zap --network host \\
        -v "$PWD/baselines/zap/scripts:/zap/scripts:ro" \\
        ghcr.io/zaproxy/zaproxy:stable \\
        zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=bolabench \\
        -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

    .venv/bin/python baselines/zap_access_control.py --system mock
    .venv/bin/python baselines/zap_access_control.py --system crapi --skip-feed

`/zap/scripts` 必须挂载：靶场用 Bearer token，ZAP 内置会话管理只认 cookie 或响应头，
取不到 JSON 体里的 token，所以要用脚本型会话管理。accessControl 本身是 alpha 插件，
镜像默认不带，脚本会自动 `installAddon`（需联网，约 30 s；**容器重启即丢**）。

输出 `baselines/zap/<system>/`：
  capture-nodes.tsv        ZAP 站点树里该 context 的真实 (nodeName, method, URI)
  policy.csv               我们注入的授权矩阵（含每行的策略来源，可审计）
  rules-check.tsv          注入后逐条核对 ZAP 是否真的认了这条规则
  ac-matrix.csv            ZAP 报告里的 节点 × 身份 → Authorized?/判定 矩阵
  alerts.jsonl             ZAP 的**全部**告警（含被动规则，原样保留）
  zap-access-control.html  ZAP 原生报告（原始产物，便于复核）
  summary.json             诊断 + 只用 Access Control 类告警算的 P/R/F1
"""

from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.config import BENCH, DEFAULT_HEADERS, SYSTEMS  # noqa: E402
from pipeline.evaluate import evaluate, load_jsonl  # noqa: E402
from pipeline.ids import (body_object_ids, object_ids, split_query,  # noqa: E402
                          template)

ZAP_API = "http://127.0.0.1:8090"
ZAP_PROXY = "http://127.0.0.1:8080"
KEY = "bolabench"
CONTAINER = "zap"
UNAUTH_USER_ID = -1          # ContextAccessRulesManager.UNAUTHENTICATED_USER_ID
ANON = "<< Unauthenticated >>"
AC_NAME = "zap-access-control"

# 「这次响应算不算未被授权」的判据。ZAP 的 BasicAuthorizationDetectionMethod 里
# statusCode 的语义是**等于该码即未授权**（不是"这个码算允许"），写反了整份报告就废。
# 三个靶场的拒绝响应形态是实测出来的（匿名/跨用户各发一遍看返回码与体）：
#   mock/clean : 401 {"error": "unauthorized"}，403 {"error": "forbidden"}
#   crAPI      : 401 {"error":"Unauthorized"}（community）；workshop 侧基本不拦
#   VAmPI      : 401 {"detail": "No authorization token provided", ...}
# 状态码只写一个（插件的限制），剩下的靠 bodyRegex 用 OR 兜住。
AUTHZ: dict[str, dict] = {
    "mock":  {"statusCode": "401",
              "bodyRegex": r"(?i)unauthorized|forbidden",
              "headerRegex": "",
              "loggedIn": r'"(?:auth_)?token"',
              "loggedOut": r"(?i)unauthorized|forbidden|no authorization token|invalid token"},
    "clean": {"statusCode": "401",
              "bodyRegex": r"(?i)unauthorized|forbidden",
              "headerRegex": "",
              "loggedIn": r'"(?:auth_)?token"',
              "loggedOut": r"(?i)unauthorized|forbidden|no authorization token|invalid token"},
    "crapi": {"statusCode": "401",
              "bodyRegex": r"(?i)unauthorized|forbidden|not authorized|permission denied",
              "headerRegex": "",
              "loggedIn": r'"(?:auth_)?token"',
              "loggedOut": r"(?i)unauthorized|forbidden|no authorization token|invalid token"},
    "vampi": {"statusCode": "401",
              "bodyRegex": r"(?i)unauthorized|forbidden|no authorization token|invalid token",
              "headerRegex": "",
              "loggedIn": r'"(?:auth_)?token"',
              "loggedOut": r"(?i)unauthorized|forbidden|no authorization token|invalid token"},
}


# --------------------------------------------------------------------------- API

def _enc(q: dict) -> str:
    # ZAP 的 API 解析器不认 urlencode 默认的 `+`（空格），必须用 %20；
    # 引擎名 "ECMAScript : Graal.js" 里带空格和冒号，踩过这个坑。
    return urllib.parse.urlencode(q, quote_via=urllib.parse.quote)


def api(component: str, kind: str, action: str, **params) -> dict:
    q = {"apikey": KEY, **params}
    url = f"{ZAP_API}/JSON/{component}/{kind}/{action}/?{_enc(q)}"
    r = httpx.get(url, timeout=300)
    try:
        d = r.json()
    except Exception:
        d = None
    # ZAP 的参数错误也返回 HTTP 200 + {"code": ...}，不检查就会静默配置失败；
    # 反过来 4xx 的响应体里也有可读的错误码，别把它压成一句 HTTPStatusError。
    if isinstance(d, dict) and d.get("code"):
        raise RuntimeError(f"{component}/{kind}/{action}: {d.get('code')} "
                           f"{d.get('message')} (HTTP {r.status_code})")
    r.raise_for_status()
    return d if d is not None else {"raw": r.text}


def docker(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, **kw)


def run_script(name: str, src: Path, out_file: str,
               stdin_pair: tuple[str, str] | None = None) -> str:
    """在容器里跑一个 standalone 脚本并把它的落盘输出读回来。

    踩过的坑：Graal standalone 只执行**顶层代码**（包在 function run() 里不执行），
    而且 print/System.out 不进 ZAP 日志，只能写文件再 cat。
    stdin_pair = (宿主机路径, 容器内路径)：容器里没有宿主机的 /tmp/opencode，
    docker cp 必须拷到一个已存在的容器目录。
    """
    if not src.exists():
        raise FileNotFoundError(f"脚本不在挂载目录里：{src}")
    ensure_script(name)
    if stdin_pair:
        host, remote = stdin_pair
        r = docker(["cp", host, f"{CONTAINER}:{remote}"])
        if r.returncode != 0:
            raise RuntimeError(f"docker cp 进容器失败: {r.stderr.strip()}")
    api("script", "action", "runStandAloneScript", scriptName=name)
    r = docker(["exec", CONTAINER, "cat", out_file])
    if r.returncode != 0:
        raise RuntimeError(f"读回 {out_file} 失败: {r.stderr.strip()}")
    return r.stdout


def ensure_script(name: str) -> None:
    """加载 standalone 诊断脚本。

    ZAP 的 load 对同名脚本报 400 already_exists，而脚本内容是从磁盘**缓存**进内存的：
    改了挂载目录里的 .js 不重新 reload 是不会生效的。所以存在就 reload。
    """
    existing = [x["name"] for x in api("script", "view", "listScripts").get("listScripts", [])]
    if name in existing:
        # 没有 script/action/reload 这个 action（400 bad_action），而 ZAP 缓存的是
        # 加载那一刻的文件内容 —— 改了 .js 必须先 remove 再 load 才生效。
        api("script", "action", "remove", scriptName=name)
    api("script", "action", "load", scriptName=name, scriptType="standalone",
        scriptEngine="ECMAScript : Graal.js", fileName=f"/zap/scripts/{name}.js",
        charset="UTF-8", scriptDescription="BOLA bench diagnostics")


def wait_scan(context_id: str, timeout: float = 1800) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        # 响应键就是视图名本身（getScanStatus），不是 scanStatus —— 写错会永远轮询
        st = api("accessControl", "view", "getScanStatus", contextId=context_id)
        prog = api("accessControl", "view", "getScanProgress", contextId=context_id)
        status = st.get("getScanStatus")
        if status in ("FINISHED", "COMPLETED") or prog.get("getScanProgress") == "100":
            return {"status": status, "progress": prog.get("getScanProgress")}
        time.sleep(3)
    raise TimeoutError(f"access control scan did not finish in {timeout}s")


# ------------------------------------------------------------------- 靶场侧辅助

def login_body(cfg: dict, who: dict) -> dict:
    lg = cfg["login"]
    s = json.dumps(lg["json"])
    for k in ("username", "password", "email"):
        s = s.replace("{" + k + "}", str(who.get(k, "")))
    return json.loads(s)


def reset_fixture(system_id: str, cfg: dict) -> str:
    """把靶场打回初始状态。ZAP 的 AC 扫描会真的执行 DELETE/PATCH，跑完必须重置。"""
    rs = cfg.get("reset")
    if not rs:
        return "no-reset-endpoint（crAPI/VAmPI 需要重跑 seed 脚本，见 systems/*/seed.py）"
    try:
        httpx.request(rs["method"], cfg["base_url"] + rs["path"], timeout=30)
        return "reset"
    except Exception as exc:
        return f"reset-failed:{type(exc).__name__}"


def feed_proxy(system_id: str, cfg: dict, accounts: list[str]) \
        -> tuple[int, set[tuple[str, str]]]:
    """把**全部账号**抓包里的请求**匿名**通过 ZAP 代理重放一遍，建立站点树。

    为什么要灌全部账号而不只受害者的：accessControl 只能重放站点树里已有的节点，
    节点集合直接决定 coverage。只灌 alice 时，bob/carol 名下的对象实例根本不在
    树里，ZAP 连"被测"的机会都没有——那是拿覆盖缺口去评它的检出力，不公平。
    灌全量后，节点集合与我们流水线的输入集合相同（同一份 capture.jsonl）。

    必须匿名发：accessControl 重放时复用站点树里**存下来的那条消息**，
    种子请求自带的 Authorization 会被原样带上（"未认证"列也拿到 200）。
    """
    base = cfg["base_url"]
    cap = ROOT / "results" / "raw" / system_id / "capture.jsonl"
    if not cap.exists():
        raise FileNotFoundError(f"缺少抓包文件：{cap}")
    seen: set[tuple[str, str]] = set()
    n = 0
    for line in open(cap, encoding="utf-8"):
        rec = json.loads(line)
        if rec.get("account") not in accounts:
            continue
        key = (rec["method"], rec["path"])
        if key in seen:
            continue
        seen.add(key)
        body = rec.get("req_body") if isinstance(rec.get("req_body"), (dict, list)) else None
        try:
            httpx.request(rec["method"], base + rec["path"], headers=dict(DEFAULT_HEADERS),
                          json=body, proxy=ZAP_PROXY, timeout=60, follow_redirects=False)
            n += 1
        except Exception as exc:
            print(f"  [feed] 跳过 {rec['method']} {rec['path']}: {type(exc).__name__}")
    # 静态首页：只是为了建主机节点；它不进 seeded，矩阵里保持 UNKNOWN
    try:
        httpx.get(base + "/", headers=DEFAULT_HEADERS, proxy=ZAP_PROXY, timeout=30)
    except Exception:
        pass
    return n, seen


def parse_nodes(dump: str, ctx_name: str) -> list[dict]:
    """从 dump_nodes.js 的输出里取本 context 的 (nodeName, method, uri, 请求体)。

    请求体是节点里**存下来的那条消息**的 body（base64 传回）：L3 批量端点的
    对象标识只在体里，规则匹配必须要它。注意 ZAP 每个节点只存一条消息，
    同 URI 不同体的请求会塌成同一个节点（写进论文的已知局限）。
    """
    nodes: list[dict] = []
    inside = False
    for line in dump.splitlines():
        if line.startswith("--- context "):
            inside = f" {ctx_name} " in line
            continue
        if inside and line.startswith("CTX|"):
            parts = line.split("|", 4)
            name, method, uri = parts[1], parts[2], parts[3]
            body = None
            if len(parts) > 4 and parts[4]:
                try:
                    body = json.loads(base64.b64decode(parts[4]).decode("utf-8"))
                except Exception:
                    body = None
            if uri:
                nodes.append({"node_name": name, "method": method, "uri": uri,
                              "body": body})
    return nodes


# ------------------------------------------------------------------- 授权矩阵

def build_matrix(nodes: list[dict], labels: list[dict], noref: list[dict],
                 cfg: dict, victim: str, attackers: list[str],
                 seeded: set[tuple[str, str]]) -> list[dict]:
    """按「端点公开性 + 实例属主」两条策略事实，为每个节点 × 每个身份生成规则。

    只用策略、不用答案：
      - 公开端点（登录、`public_paths`、标注里写明"公开"的无对象引用端点）
        -> 所有身份（含匿名）ALLOWED
      - 无对象引用的私有端点（`/api/me`、`/api/profile` 这类"只返回自己"的）
        -> 已认证身份 ALL 都 ALLOWED、匿名 DENIED。
        这里**不能**给攻击者写 DENIED：它们本来就不引用他人对象，写了就是
        拿策略输入去造误报（bob 读 /api/me 拿到的是 bob 自己，天经地义）。
      - 引用了对象标识的实例
        -> 属主 ALLOWED，其余已认证身份 DENIED，匿名 DENIED。
        注意 DENIED 是「bob 不应该能读 alice 的订单 1001」这条**策略**，
        不是「这个实例有漏洞」这个**结论**：漏洞与否要靠 ZAP 自己去重放发现。
      - 其余一律**不写规则**（UNKNOWN）：
        * ZAP 自己从 URL 层级推出来的容器节点（`/`、`/api`、`/api/documents`）：
          它们没有唯一的授权语义（`/` 是公开首页，`/api/documents` 只是前缀）。
          硬写一条策略就是拿输入去制造误报/漏报，宁可留 UNKNOWN。
        * 有对象标识但**没有标注**的实例：属主是谁不可确定（我们没有 ground truth），
          同样留 UNKNOWN，不猜。
        ZAP 对 UNKNOWN 既不产判定也不产告警——这正好等于"该工具在缺少
        人工逐条配置时什么都测不出来"，是它设计上的真实行为。
    """
    pat = cfg.get("id_patterns")
    iqn = cfg.get("id_query_names")
    lab: dict[tuple[str, str, tuple[str, ...]], dict] = {}
    for l in labels:
        lab[(l["method"], l["path"], tuple(str(x) for x in (l.get("object_ids") or [])))] = l
    noref_keys = {(n["method"], n["path"]) for n in noref}
    noref_public = {(n["method"], n["path"]) for n in noref
                    if "公开" in (n.get("note") or "")}
    login_tpl = template(cfg["base_url"] + cfg["login"]["path"], pat)
    public_tpl = {template(p, pat) for p in cfg.get("public_paths", [])}

    rows: list[dict] = []
    for nd in nodes:
        path, query = split_query(nd["uri"])
        tpl = template(path, pat)
        ids = object_ids(path, query, pat, body=nd.get("body"), id_query_names=iqn)
        key = (nd["method"], tpl, tuple(ids))
        label = lab.get(key)
        # 无对象引用的端点：所有已认证身份都允许（读的是自己的东西）
        authenticated = {u: "ALLOWED" for u in [victim, *attackers]}

        if (nd["method"], path) not in seeded:
            policy, src = {u: "UNKNOWN" for u in [*authenticated, ANON]}, "unseeded-container-node"
        elif tpl == login_tpl:
            # 登录页/登录接口：唯一的真·匿名公开端点
            policy = {u: "ALLOWED" for u in [*authenticated, ANON]}
            src = "public-endpoint"
        elif (nd["method"], tpl) in noref_public or tpl in public_tpl:
            # "公开"的默认语义是**任意已认证用户**可读（社区帖、商品列表）：
            # 匿名访问实测 401，给 anon 写 ALLOWED 就是拿错误策略造误报
            # （crAPI community 的 FP 全部来自这里——anon 401 vs 假 ALLOWED）。
            # 例外：靶场 profile 这类**匿名真实可读**的端点（实测 200），由
            # cfg["public_anon"] 声明——这是策略输入的一部分，与授权检测判据
            # （401=未授权）一样属于工具配置，不是拿测试结论改答案。
            policy = {u: "ALLOWED" for u in authenticated}
            policy[ANON] = "ALLOWED" if cfg.get("public_anon") else "DENIED"
            src = "public-endpoint"
        elif not ids:
            # 无对象引用：策略只能写到"角色"粒度
            policy = dict(authenticated)
            policy[ANON] = "DENIED"
            src = "noref-role-only" if (nd["method"], tpl) in noref_keys else "no-object-ref"
        elif label is None:
            policy, src = {u: "UNKNOWN" for u in [*authenticated, ANON]}, "unlabeled-instance"
        else:
            owner = label["victim"]
            policy = {u: ("ALLOWED" if u == owner else "DENIED") for u in authenticated}
            policy[ANON] = "DENIED"
            src = "labeled-instance"
            # 社区帖这类"对所有登录用户公开"的实例，攻击者也该是 ALLOWED
            if label.get("visibility") == "public":
                for u in authenticated:
                    policy[u] = "ALLOWED"
                src = "labeled-instance-public-visibility"

        for who, rule in policy.items():
            rows.append({"method": nd["method"], "node_name": nd["node_name"],
                         "uri": nd["uri"], "template": tpl,
                         "object_ids": "|".join(ids),
                         "user": who, "rule": rule, "policy_source": src,
                         "label_vulnerable": "" if label is None else
                         ("yes" if label.get("vulnerable") else "no")})
    return rows


def rule_string(user_id: int, rule: str, node_name: str, uri: str) -> str:
    """`userId`RULE`base64(nodeName)`escapedURI —— 从插件 jar 里 importSerializedRule
    的实现反查确认（split 限 4 段，nodeName 走 Base64.getDecoder，URI 用
    new URI(str, true) 即 escaped 形式）。"""
    b64 = base64.b64encode(node_name.encode("utf-8")).decode("ascii")
    return f"{user_id}`{rule}`{b64}`{uri}"


def inject_rules(ctx_name: str, cid: str, rules: list[str]) -> dict:
    """导出 context -> 插入 <accessControl> -> 删掉 -> 导入。

    `Context.isInContext()` 判的是**作用域正则**（javap 确认走 isInScope(URI)），
    不是 context id 的标记位，所以删掉再导入不会让站点树里的节点跟丢。
    """
    work = Path("/tmp/opencode")
    work.mkdir(parents=True, exist_ok=True)
    # 参数名踩过坑：不是 fileName / dir，是 context/action/exportContext?contextFile=
    remote = f"/tmp/bola-{ctx_name}.context"
    api("context", "action", "exportContext", contextName=ctx_name, contextFile=remote)
    got = docker(["cp", f"{CONTAINER}:{remote}", str(work / "ctx_export.context")])
    if got.returncode != 0:
        raise RuntimeError(f"导出 context 失败: {got.stderr.strip()}")
    text = (work / "ctx_export.context").read_text(encoding="utf-8")
    if "<accessControl>" in text:
        raise RuntimeError("导出的 context 已经带 accessControl 块，先确认没有重复注入")
    block = ("        <accessControl>\n            <rules>\n"
             + "".join(f"                <rule>{html.escape(r)}</rule>\n" for r in rules)
             + "            </rules>\n        </accessControl>\n    </context>")
    edited = text.replace("    </context>", block, 1)
    if edited == text:
        raise RuntimeError("没找到 </context>，无法注入规则块")
    (work / "ctx_injected.context").write_text(edited, encoding="utf-8")
    if docker(["cp", str(work / "ctx_injected.context"), f"{CONTAINER}:{remote}"]).returncode:
        raise RuntimeError("把改好的 context 拷回容器失败")
    api("context", "action", "removeContext", contextName=ctx_name)
    # importContext 只要 contextFile：名字与用户 id 都由文件里的值原样恢复，
    # 返回体里直接给新 contextId。
    imported = api("context", "action", "importContext", contextFile=remote)
    new_cid = str(imported["contextId"])
    return {"old_context_id": cid, "context_id": new_cid,
            "exported_bytes": len(text), "rules_injected": len(rules)}


def check_rules(cid: str, matrix: list[dict], uid_of: dict[str, int],
                out_dir: Path) -> dict:
    """逐条问 ZAP「这个 (用户, 节点) 你认的是哪条规则」，核对注入是否真生效。"""
    lines = [f"CTX\t{cid}"]
    for r in matrix:
        uid = UNAUTH_USER_ID if r["user"] == ANON else uid_of[r["user"]]
        lines.append(f"RULE\t{uid}\t{r['node_name']}\t{r['uri']}")
    local = Path("/tmp/opencode/zap_rules_in.tsv")
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = run_script("dump_rules", ROOT / "baselines" / "zap" / "scripts" / "dump_rules.js",
                     "/tmp/zap_rules_out.tsv",
                     stdin_pair=(str(local), "/tmp/zap_rules_in.tsv"))
    (out_dir / "rules-check.tsv").write_text(out, encoding="utf-8")
    tally: dict[str, int] = {}
    for ln in out.splitlines():
        p = ln.split("|")
        if p[0] == "RULE":
            tally[p[2]] = tally.get(p[2], 0) + 1
    return tally


# ------------------------------------------------------------------- 报告解析

def parse_report(text: str) -> tuple[list[dict], list[str]]:
    """把 ZAP 的 Access Control HTML 报告拆成 节点 × 身份 → 判定 的表。

    表头是 `Method | URL | (Authorized? | Access Control) × 身份`。
    这个矩阵比告警更有用：告警只看得到"矛盾的那些格"，矩阵看得到
    覆盖了多少节点、有多少格因为没规则而落进 UNKNOWN。
    """
    m = re.search(r"<tbody>(.*?)</tbody>", text, re.S)
    if not m:
        return [], []
    head = re.search(r"<thead>(.*?)</thead>", text, re.S)
    users = re.findall(r"<th colspan=\"\d+\">(.*?)</th>", head.group(1)) if head else []
    users = [html.unescape(re.sub(r"<[^>]+>", "", u)).strip() for u in users]
    rows = []
    for tr in re.findall(r"<tr>(.*?)</tr>", m.group(1), re.S):
        td = [html.unescape(re.sub(r"<[^>]+>", "", c)).strip()
              for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        if len(td) < 2 + 2 * max(len(users), 1):
            continue
        # 报告里会重复一行表头（Method/URL），别把它当成数据行写进 CSV
        if td[0].lower() == "method" or td[1].lower() == "url":
            continue
        cell, i = {"method": td[0], "url": td[1]}, 2
        cell["cells"] = {}
        for u in users:
            cell["cells"][u] = {"authorized": td[i], "result": td[i + 1]}
            i += 2
        rows.append(cell)
    return rows, users


# ------------------------------------------------------------------- 告警 -> 结果

def alert_user(alert: dict) -> str:
    """从告警文案里把「这次是拿谁的身份重放的」读出来。

    Improper Authentication = 未认证那一列；Improper Authorization 的
    attack/other 字段里带 `Accessed as user: bob`。
    """
    blob = (alert.get("attack") or "") + (alert.get("other") or "")
    if "Improper Authentication" in (alert.get("name") or "") or "unauthenticated" in blob:
        return ANON
    m = re.search(r"Accessed as user\s*:\s*([^\s<\n]+)", blob)
    return m.group(1) if m else ""


def pull_message(alert: dict) -> tuple[str, dict | None]:
    """取告警对应的那条消息的请求体：L3 的批量/导出端点，标识在**请求体**里，
    只看 URL 会退化成"端点级"匹配，必须把体里的 id 也拿回来才可比。"""
    for field in ("messageId", "sourceMessageId"):
        mid = alert.get(field)
        if mid in (None, "", 0, "0"):
            continue
        try:
            d = api("core", "view", "message", id=str(mid))
        except Exception:
            continue
        msg = d.get("message") or {}
        body = msg.get("requestBody")
        parsed = None
        if body:
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = None
        return msg.get("requestHeader") or "", parsed
    return "", None


# ------------------------------------------------------------------------ 主流程

def run(system_id: str, victim: str, attackers: list[str],
        skip_feed: bool = False) -> dict:
    cfg = SYSTEMS[system_id]
    base = cfg["base_url"]
    acc = cfg["accounts"]
    out_dir = ROOT / "baselines" / "zap" / system_id
    out_dir.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []

    # 0) accessControl 是 alpha 插件，镜像里默认不带；装了才有 /JSON/accessControl
    installed = [a["id"] for a in
                 api("autoupdate", "view", "installedAddons").get("installedAddons", [])]
    if "accessControl" not in installed:
        print("  [zap] 安装 accessControl 插件（alpha，需联网，约 30 s；容器重启即丢）")
        api("autoupdate", "action", "installAddon", id="accessControl")
        for _ in range(60):
            time.sleep(2)
            ids = [a["id"] for a in api("autoupdate", "view",
                                        "installedAddons").get("installedAddons", [])]
            if "accessControl" in ids:
                break
        else:
            raise RuntimeError("accessControl 插件安装失败（离线环境需预装）")

    # 0.1) 代理端口（容器里默认只开 API 端口）
    srv = api("network", "view", "getLocalServers").get("getLocalServers", [])
    if not any(int(s["port"]) == 8080 for s in srv):
        api("network", "action", "addLocalServer", address="0.0.0.0", port="8080",
            api="false", proxy="true")
        time.sleep(3)

    # 0.2) 每轮开一个全新 session：站点树、历史、告警、context 全部清零。
    #      不清的话上一轮扫描写回站点树的消息（带某个身份的 token）会被这一轮
    #      的 cloneRequest() 继承，"未认证"列静默变成已认证；旧告警也会被
    #      core/view/alerts 一起读出来，混进这一轮的 P/R/F1。
    try:
        api("core", "action", "newSession",
            name=f"bola-{system_id}-{int(time.time())}", overwrite="true")
        notes.append("newSession：每轮从空站点树/空告警开始")
    except Exception as exc:
        notes.append(f"newSession-failed:{type(exc).__name__}（可能混入上一轮残留）")

    before_reset = reset_fixture(system_id, cfg)   # 跑前先干净（有 reset 端点的系统）

    # 0.3) 清掉 session_token 脚本存在 JVM 全局的旧 token：靶场重置后 token 可能
    #      换新（crAPI/VAmPI 是按次签发的 JWT），上一轮的残留身份绝不能带进本轮。
    run_script("clear_tokens", ROOT / "baselines" / "zap" / "scripts" / "clear_tokens.js",
               "/tmp/clear_tokens_result.txt")
    # 会话脚本的诊断日志也每轮清零：它记录「每个回调看到的身份与 token」，
    # 是判断串号的第一手证据，跨轮混在一起就看不出本轮的问题了。
    docker(["exec", CONTAINER, "rm", "-f", "/tmp/session_token_debug.log"])

    # 1) context：只把该靶场主机纳入
    ctx_name = f"bola-{system_id}"
    for old in api("context", "view", "contextList").get("contextList", []):
        if old.startswith("bola-"):
            api("context", "action", "removeContext", contextName=old)
    api("context", "action", "newContext", contextName=ctx_name)
    # context id 会变化（删掉旧的再建，id 不一定回到 1），必须按名字查回真实 id，
    # 否则后续所有调用都报 context_not_found。
    cid = str(api("context", "view", "context", contextName=ctx_name)["context"]["id"])
    u = urllib.parse.urlparse(base)
    api("context", "action", "includeInContext", contextName=ctx_name,
        regex=f"{u.scheme}://{u.netloc}.*")
    api("context", "action", "setContextInScope", contextName=ctx_name,
        booleanInScope="true")

    # 2) 认证：JSON 登录 + 脚本型会话（token 在登录响应体里）
    # jsonBasedAuthentication 只认 {%username%}/{%password%} 两个占位符；
    # crAPI 用 email 登录，{email} 必须映射到 {%username%}（凭据里 username 就填
    # email，见下面 creds 的构造）。写成 {%email%} 不会被替换——实测登录请求
    # 原样发出 `{"email": "{%email%}"}`，crAPI 回 "Given Email is not registered!"，
    # 所有用户都拿不到 token，replay 全变匿名（第一轮 crAPI 结果因此作废）。
    uses_email_login = "{email}" in json.dumps(cfg["login"]["json"])
    body = json.dumps(cfg["login"]["json"]).replace("{username}", "{%username%}") \
                                            .replace("{password}", "{%password%}") \
                                            .replace("{email}", "{%username%}")
    # 编码层次：ZAP 先把 authMethodConfigParams 解码一次，再把它当 kvp 解码第二次。
    # 所以这里只需要 urlencode 一层，`api()` 再 urlencode 一层正好凑够两层；
    # 多编一层会让 `{%username%}` 变成 `%username%`，第二次解码时报 Illegal hex characters。
    api("authentication", "action", "setAuthenticationMethod", contextId=cid,
        authMethodName="jsonBasedAuthentication",
        authMethodConfigParams=urllib.parse.urlencode(
            {"loginUrl": base + cfg["login"]["path"], "loginRequestData": body}))
    script_name = "session_token"
    existing = [x["name"] for x in api("script", "view", "listScripts").get("listScripts", [])]
    if script_name in existing:
        api("script", "action", "remove", scriptName=script_name)
    api("script", "action", "load", scriptName=script_name, scriptType="session",
        scriptEngine="ECMAScript : Graal.js", fileName=f"/zap/scripts/{script_name}.js",
        charset="UTF-8", scriptDescription="Bearer token from login JSON body")
    # session 型脚本不可 enable（enableable:false），配进 context 即生效
    api("sessionManagement", "action", "setSessionManagementMethod", contextId=cid,
        methodName="scriptBasedSessionManagement",
        methodConfigParams=_enc({"scriptName": script_name}))

    az = AUTHZ[system_id]
    api("authorization", "action", "setBasicAuthorizationDetectionMethod", contextId=cid,
        headerRegex=az["headerRegex"], bodyRegex=az["bodyRegex"],
        statusCode=az["statusCode"], logicalOperator="OR")
    # 登录态指示器：不设会被判"全都没登录"。用能同时覆盖 mock/clean/crAPI（"token"）
    # 与 VAmPI（"auth_token"）的正则，而不是 \Q"token"\E 这种字面量（后者对 VAmPI 失效）。
    api("authentication", "action", "setLoggedInIndicator", contextId=cid,
        loggedInIndicatorRegex=az["loggedIn"])
    api("authentication", "action", "setLoggedOutIndicator", contextId=cid,
        loggedOutIndicatorRegex=az["loggedOut"])

    # 3) 用户：受害者 + 全部攻击者。
#    不能用 usersList 读回 id：removeContext 不清 ZAP 的用户存储，usersList 对
#    新建 context 也会吐出历史僵尸用户（同名不同 id，实测攒出 3 组 alice/bob），
#    dict 推导"同名后者胜"会选错 id，规则/扫描/凭据各引用一组。newUser 的响应
#    里直接带 userId，从那里拿才是确定性的。
    names = [victim, *attackers]
    uid_of: dict[str, str] = {}
    for who in names:
        r = api("users", "action", "newUser", contextId=cid, name=acc[who]["username"])
        uid_of[acc[who]["username"]] = str(r["userId"])
    for who in names:
        # 登录体用 email 的系统（crAPI）：凭据的 username 必须填 email，
        # 否则 {%username%} 替换出来的是 "alice"，登录必败（见上面 uses_email_login）。
        username = acc[who]["email"] if uses_email_login else acc[who].get("username", "")
        creds = {"username": username, "password": acc[who]["password"]}
        if "email" in acc[who]:
            creds["email"] = acc[who]["email"]
        api("users", "action", "setAuthenticationCredentials", contextId=cid,
            userId=uid_of[acc[who]["username"]], authCredentialsConfigParams=_enc(creds))
        api("users", "action", "setUserEnabled", contextId=cid,
            userId=uid_of[acc[who]["username"]], enabled="true")

    # 4) 灌种子（匿名，走代理；**全部账号**，见 feed_proxy 注释）
    if skip_feed:
        fed, seeded = 0, set()
        notes.append("skip-feed：复用上一次灌进去的站点树")
    else:
        fed, seeded = feed_proxy(system_id, cfg, names)

    urls = api("context", "view", "urls", contextName=ctx_name).get("urls", [])
    nodes = parse_nodes(
        run_script("dump_nodes", ROOT / "baselines" / "zap" / "scripts" / "dump_nodes.js",
                   "/tmp/nodes.txt"),
        ctx_name)
    (out_dir / "capture-nodes.tsv").write_text(
        "\n".join(["node_name\tmethod\turi"] +
                  [f"{n['node_name']}\t{n['method']}\t{n['uri']}" for n in nodes]) + "\n",
        encoding="utf-8")

    # 5) 授权矩阵 -> 注入
    labels = load_jsonl(BENCH / "labels" / f"{system_id}.jsonl")
    noref = load_jsonl(BENCH / "labels" / f"{system_id}.noref.jsonl")
    matrix = build_matrix(nodes, labels, noref, cfg, victim, attackers, seeded)
    with open(out_dir / "policy.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(matrix[0].keys()))
        w.writeheader()
        w.writerows(matrix)
    # UNKNOWN 的节点**不注入规则**：策略不可确定的容器节点 / 无标注实例一律留给 ZAP 的
    # INHERIT（= 不产判定、不产告警），而不是猜一个属主去制造误报。
    ruled = [r for r in matrix if r["rule"] in ("ALLOWED", "DENIED")]
    rules = [rule_string(UNAUTH_USER_ID if r["user"] == ANON else uid_of[r["user"]],
                         r["rule"], r["node_name"], r["uri"]) for r in ruled]
    injected = inject_rules(ctx_name, cid, rules)
    cid = injected["context_id"]
    # 规则串里引用的是**导出前**的用户 id；importContext 按文件原样恢复（User.decode
    # 直接用文件里的 id）。但 removeContext **不清** ZAP 的用户存储，usersList 会把
    # 历史僵尸用户一起吐出来（实测一个 context 里攒出 3 组同名 alice/bob，id 分别
    # 0/1、232/233、533/534）——dict 推导"同名后者胜"可能选中僵尸 id，让核对/扫描
    # 引用到没有授权规则覆盖的用户。这里只认导出前记录的那组 (id -> name)，
    # 其余全部忽略；如果导入后 id 对不上（理论上不会），直接报错终止。
    pre_uid = dict(uid_of)                      # 注规则用的 name -> id
    by_id = {int(x["id"]): x["name"] for x in
             api("users", "view", "usersList", contextId=cid).get("usersList", [])}
    restored = {name: str(i) for i, name in by_id.items() if str(i) in set(pre_uid.values())}
    if restored != pre_uid:
        raise RuntimeError(f"导入后用户 id 与规则不一致：规则用 {pre_uid}，实际 {restored}")
    uid_of = restored
    rules_check = check_rules(cid, ruled, uid_of, out_dir)
    unresolved = {k: v for k, v in rules_check.items()
                  if k not in ("ALLOWED", "DENIED")}
    if unresolved:
        notes.append(f"规则核对异常：{unresolved}")

    # 6) 扫描：userId 传**所有要被重放的身份**（不是"以谁扫描"），逗号分隔；
    #    scanAsUnAuthUser 再追加未认证那一列。
    #    alertRiskLevel 必须传整数：插件用 params.optInt(..., RISK_HIGH)，
    #    传 "Medium" 会静默回落到 HIGH。
    scan_users = ",".join(str(uid_of[acc[w]["username"]]) for w in names)
    api("accessControl", "action", "scan", contextId=cid, userId=scan_users,
        scanAsUnAuthUser="true", raiseAlert="true", alertRiskLevel="2")
    scan = wait_scan(cid)

    # 7) 原生 HTML 报告：写到容器 /tmp（必然可写）再拷出。
    #    不能写 `-v` 挂进来的目录：root 属主时容器用户写不进（500 Permission denied）。
    remote_report = f"/tmp/zap-ac-{system_id}.html"
    api("accessControl", "action", "writeHTMLreport", contextId=cid, fileName=remote_report)
    local = Path("/tmp/opencode/zap-report.html")
    got_report = docker(["cp", f"{CONTAINER}:{remote_report}", str(local)]).returncode == 0
    matrix_rows: list[dict] = []
    matrix_users: list[str] = []
    if got_report:
        text = local.read_text(encoding="utf-8", errors="replace")
        (out_dir / "zap-access-control.html").write_text(text, encoding="utf-8")
        matrix_rows, matrix_users = parse_report(text)
        with open(out_dir / "ac-matrix.csv", "w", newline="", encoding="utf-8") as f:
            cols = ["method", "url"] + [f"{u}::authorized" for u in matrix_users] \
                                  + [f"{u}::result" for u in matrix_users]
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in matrix_rows:
                flat = {"method": r["method"], "url": r["url"]}
                for k, v in r["cells"].items():
                    flat[f"{k}::authorized"] = v["authorized"]
                    flat[f"{k}::result"] = v["result"]
                w.writerow(flat)

    # 8) 告警：Access Control 类才算 RQ1 的判定，被动规则分开统计
    ver = api("core", "view", "version").get("version")
    alerts = api("core", "view", "alerts", baseurl=base, start="0", count="5000")
    rows = []
    for al in alerts.get("alerts", []):
        body = al.get("requestBody")
        rows.append({
            "tool": AC_NAME, "zap_version": ver, "system": system_id,
            "victim": victim, "users_scanned": names,
            "url": al.get("url"), "method": al.get("method"),
            "name": al.get("name"), "risk": al.get("risk"),
            "confidence": al.get("confidence"), "node": al.get("nodeName"),
            "attack": (al.get("attack") or "")[:200],
            "other": (al.get("other") or "")[:200],
            "evidence": (al.get("evidence") or "")[:200],
            "cweid": al.get("cweid"), "wascid": al.get("wascid"),
            "messageId": al.get("messageId"), "sourceMessageId": al.get("sourceMessageId"),
        })
    with open(out_dir / "alerts.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # AC 告警里只有 **Improper Authorization** 是授权判定；Improper Authentication
    # 是会话健康信号（重放后掉线/401），ZAP 对匿名列大量误发——它不是"发现越权"，
    # 进打分只会把"会话没保住"计成检测。匿名重放本来就预期 401。
    ac_all = [r for r in rows if "Access Control" in (r.get("name") or "")]
    ac_rows = [r for r in ac_all if "Improper Authorization" in (r.get("name") or "")]
    pat, iqn = cfg.get("id_patterns"), cfg.get("id_query_names")

    # ------------------------------------------------------------------ 打分
    # 关键口径：results 必须覆盖 ZAP **实际评估过的每一个 (节点 × 身份) 格**，
    # 不能只放告警。只放告警会让 `tested` 退化成"有告警的标注"，FN 恒为空、
    # Recall 恒为 1.0 —— 那是把"没测出来"从分母里偷偷删掉，对谁都不公平。
    # 矩阵（HTML 报告）里每个格都有 Valid/Invalid/Unknown 三种结果：
    #   Unknown        -> 没规则/没评估，不算 tested（coverage 的真实边界）
    #   Valid/Invalid  -> 测过了；vuln = ZAP 是否为这个 (url, 身份) 发了 AC 告警
    def node_body_of(m: str, u: str):
        for nd in nodes:
            if nd["method"] == m and nd["uri"] == u:
                return nd.get("body")
        return None

    flagged = {(r["method"], r["url"], alert_user(r)) for r in ac_rows}
    results = []
    seen: set = set()

    def add_result(m: str, u: str, body, attacker: str, hdr: str = "") -> None:
        path, query = split_query(u)
        ids = object_ids(path, query, pat, body=body, id_query_names=iqn)
        key = (template(path, pat), m, tuple(ids), attacker)
        if key in seen:
            return
        seen.add(key)
        results.append({
            "endpoint": template(path, pat), "method": m, "url": u,
            "request_header": hdr, "attacker": attacker, "victim": victim,
            "object_ids": ids,
            # ZAP 判"授权有问题"（发了 AC 告警）才算它认为有漏洞
            "vuln": (m, u, attacker) in flagged,
            "tool": AC_NAME, "variant": "zap-access-control",
        })

    for row in matrix_rows:
        m, u = row["method"], row["url"]
        for user, cell in row["cells"].items():
            if cell["result"] == "Unknown":
                continue
            add_result(m, u, node_body_of(m, u), user)

    # 矩阵没覆盖到的告警（如 gate violation：节点没规则但 ZAP 也发了
    # Improper Authentication）也要进来，否则会漏记 gate 违规。
    for r in ac_rows:
        au = alert_user(r)
        path, query = split_query(r["url"] or "")
        key = (template(path, pat), r["method"],
               tuple(object_ids(path, query, pat, id_query_names=iqn)), au)
        if key in seen:
            continue
        hdr, msg_body = pull_message(r)
        add_result(r["method"], r["url"], msg_body, au, hdr)

    score = evaluate(results, labels, noref) if results else {}
    if score:
        score.pop("self_read_alert_records", None)

    # 9) 矩阵统计：ZAP 到底判了多少格、多少格落进 UNKNOWN
    cells = [(u, c["result"]) for r in matrix_rows for u, c in r["cells"].items()]
    by_user: dict[str, dict[str, int]] = {}
    for uname, res in cells:
        d = by_user.setdefault(uname, {})
        d[res] = d.get(res, 0) + 1

    after_reset = reset_fixture(system_id, cfg)
    info = {
        "system": system_id, "victim": victim, "attackers": attackers,
        "zap_version": ver, "context": ctx_name, "context_id": cid,
        "user_ids": uid_of, "seeded_urls": fed, "urls_in_context": len(urls),
        "site_nodes": len(nodes), "rules_injected": len(rules),
        "rules_check": rules_check, "injected": injected,
        "scan": scan, "by_user_results": by_user,
        "alerts_total": len(rows),
        # ac_alerts = 全部 Access Control 告警（含 Improper Authentication，
        # 它只进诊断不进打分）；ac_authz_alerts = 进打分的授权判定告警。
        "ac_alerts": len(ac_all), "ac_authz_alerts": len(ac_rows),
        "ac_alerts_by_name": {},
        "passive_alerts": len(rows) - len(ac_all),
        "report_saved": got_report,
        # reset_fixture 对 crAPI/VAmPI 没有 reset 端点，返回 no-reset-endpoint；
        # 不能硬编码 "reset"——那会把"状态可能被本轮扫描改过"伪装成"已重置"。
        "fixture_before": before_reset, "fixture_after": after_reset,
        # 仓库内的相对路径：绝对路径在公开仓库里既泄露本地用户名，换台机器也没有意义
        "notes": notes, "score": score,
        "out": str(out_dir.relative_to(ROOT)) if out_dir.is_relative_to(ROOT)
        else str(out_dir),
    }
    for r in ac_all:
        k = r["name"] or "?"
        info["ac_alerts_by_name"][k] = info["ac_alerts_by_name"].get(k, 0) + 1
    (out_dir / "summary.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", default="mock")
    ap.add_argument("--victim", default=None)
    ap.add_argument("--attackers", default=None,
                    help="逗号分隔，默认取配置里除受害者外的全部攻击者")
    ap.add_argument("--skip-feed", action="store_true",
                    help="复用上一次灌进站点树的种子（靶场状态没变时省时间）")
    args = ap.parse_args()
    cfg = SYSTEMS[args.system]
    victim = args.victim or cfg["victim"]
    attackers = (args.attackers.split(",") if args.attackers
                 else [a for a in cfg["attackers"] if a != victim])
    info = run(args.system, victim, attackers, skip_feed=args.skip_feed)
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
