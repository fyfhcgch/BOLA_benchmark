"""AI 辅助二次标注：按 `docs/labeling_spec.md` 对 107 条盲标卷做黑盒复核。

纪律（写进论文的口径）：
  * 只读 `results/relabel/blind_sheet.jsonl` 与 `docs/labeling_spec.md`；
    **不读** `bench/labels/*.jsonl`、`docs/pilot_findings.md`、靶场源码里的漏洞清单。
  * 判定全部来自对活靶场的 HTTP 行为：读型看响应是否出现受害者身份标识，
    写型看受害者复读是否观察到攻击者写入的副作用（删除看 200 -> 404）。
  * 写型测试一律**做恢复**：PATCH 备注写回原值、PUT 状态写回原值、
    改密/改邮箱后用新凭据把原值改回去。mock 结束时调用 /api/debug/reset。

四阶段（顺序不可换，否则会自己破坏后续用例的状态）：
  1. 读型（GET；POST /batch 与 /export 语义上是读）
  2. 写型（PATCH / PUT，带恢复）
  3. 删除（DELETE）
  4. 软删除后的 trash 复读（依赖第 3 阶段真的删掉了）

用法：
    .venv/bin/python bench/ai_relabel.py
    .venv/bin/python bench/metrics.py --answers results/relabel/answers_assistant.jsonl
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.config import DEFAULT_HEADERS, SYSTEMS  # noqa: E402
from pipeline.crawl import login  # noqa: E402

OUT = ROOT / "results" / "relabel"
SHEET = OUT / "blind_sheet.jsonl"

PUBLIC_PATHS = {
    # 规范 3.3：所有登录用户本就可见、读到作者身份是设计行为
    "crapi": ("/community/",),
    # VAmPI 的用户列表/资料页按规范属于公开资源
    "vampi": ("/users/v1/{username}",),
}


# --------------------------------------------------------------------------- #
# 基础设施
# --------------------------------------------------------------------------- #

class Ctx:
    def __init__(self, system: str):
        self.system = system
        cfg = SYSTEMS[system]
        self.base = cfg["base_url"].rstrip("/")
        self.login_cfg = cfg["login"]
        self.accounts = cfg["accounts"]
        self.tokens: dict[str, str] = {}
        self.client = httpx.Client(timeout=30, follow_redirects=False)

    def token(self, name: str) -> str:
        if name not in self.tokens:
            self.tokens[name] = login(self.base, self.login_cfg, self.accounts[name])
        return self.tokens[name]

    def fresh_token(self, name: str) -> str:
        self.tokens.pop(name, None)
        return self.token(name)

    def request(self, attacker: str, method: str, path: str,
                body: dict | None = None, token: str | None = None):
        headers = {"Authorization": f"Bearer {token or self.token(attacker)}",
                   **DEFAULT_HEADERS}
        return self.client.request(method, self.base + path, headers=headers,
                                   json=body, timeout=30)

    def attacker_for(self, victim: str) -> str:
        for name in sorted(self.accounts):
            if name != victim:
                return name
        raise ValueError("没有第二个账号可当攻击者")


def markers(system: str, victim: str) -> list[str]:
    """受害者的强身份标识（规范 3.1：email / username / phone / number）。"""
    accounts = SYSTEMS[system]["accounts"]
    acct = accounts[victim]
    out = []
    for key in ("email", "username", "phone", "number"):
        v = acct.get(key)
        if v:
            out.append(str(v))
    # mock / crAPI 的号码没有写进 config，按账号顺序稳定派生（1 -> 13800000001）
    if system in ("mock", "crapi") and "phone" not in acct:
        out.append(f"1380000000{list(accounts).index(victim) + 1}")
    return sorted(set(out), key=len, reverse=True)


def hit_markers(text: str, marks: list[str]) -> list[str]:
    if not text:
        return []
    return [m for m in marks if m in text]


def is_public(system: str, method: str, template: str) -> bool:
    if method != "GET" and "/comment" in template:
        # 公开帖子下评论同样是设计允许的（规范 3.3 第 2 类）
        return any(p.startswith("/community/") for p in PUBLIC_PATHS.get(system, ()))
    return any(template.startswith(p) or template == p
               for p in PUBLIC_PATHS.get(system, ()))


def text_of(resp: httpx.Response) -> str:
    try:
        return resp.text
    except Exception:
        return resp.content.decode("latin-1", "ignore")


def pdf_text(resp: httpx.Response) -> str:
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as fh:
        fh.write(resp.content)
        fh.flush()
        try:
            return subprocess.run(["pdftotext", fh.name, "-"],
                                  capture_output=True, text=True, timeout=20).stdout
        except Exception:
            return text_of(resp)


def difficulty(entry: dict) -> str:
    p, m = entry["path"], entry["method"]
    ids = " ".join(entry.get("object_ids") or [])
    if any(k in p for k in ("/batch", "/export", "/trash",
                            "download_report", "mechanic_report")):
        return "L3"
    if m == "POST" and "/comment" in p:
        return "L3"
    if any(k in p for k in ("{uuid}", "{vin}", "{postId}", "{bookTitle}", "{username}")):
        return "L2"
    if ids and any(not i.isdigit() for i in ids):
        return "L2"
    if "/comment" in p:
        return "L2"
    return "L1"


# --------------------------------------------------------------------------- #
# 判定
# --------------------------------------------------------------------------- #

def judge_read(ctx: Ctx, entry: dict, resp: httpx.Response, *,
               text: str | None = None, marks: list[str] | None = None) -> dict:
    victim = entry["victim"]
    marks = marks if marks is not None else markers(ctx.system, victim)
    body = text if text is not None else text_of(resp)
    found = hit_markers(body, marks)
    public = is_public(ctx.system, entry["method"], entry["path"])

    if resp.status_code == 405:
        return _ans(False, "method_not_allowed", f"HTTP 405（方法不允许）")
    if resp.status_code in (401, 403):
        return _ans(False, "owner_check", f"HTTP {resp.status_code}（正确校验归属）")
    if resp.status_code == 404:
        return _ans(None, None, f"HTTP 404（对象不可见/不存在）", uncertain=True)
    if not (200 <= resp.status_code < 300):
        return _ans(None, None, f"HTTP {resp.status_code}，无法判定", uncertain=True)

    if public:
        return _ans(False, "public_resource",
                    f"公开资源（路径 {entry['path']} 对所有登录用户可见）")
    if found:
        return _ans(True, None,
                    f"HTTP {resp.status_code}，响应出现受害者标识 {found}")
    # 200 但无归属证据
    filtered = any(k in entry["path"] for k in ("/mine",))
    kind = "owner_check" if filtered else "no_owner_evidence"
    return _ans(False, kind, f"HTTP {resp.status_code}，无受害者身份标识（空/已过滤）")


def _ans(vulnerable, control_kind, note, uncertain=False) -> dict:
    return {"vulnerable": vulnerable, "control_kind": control_kind,
            "uncertain": uncertain, "note": note}


# --------------------------------------------------------------------------- #
# 各系统：读
# --------------------------------------------------------------------------- #

def read_mock(ctx: Ctx, entry: dict) -> dict:
    victim = entry["victim"]
    atk = ctx.attacker_for(victim)
    body = None
    if entry["method"] == "POST":
        ids = [int(x) for x in entry["object_ids"]]
        body = {"ids": ids}
    resp = ctx.request(atk, entry["method"], entry["request_path"], body=body)
    ans = judge_read(ctx, entry, resp)
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "body": text_of(resp)[:400]}
    return ans


def read_crapi(ctx: Ctx, entry: dict) -> dict:
    victim = entry["victim"]
    atk = ctx.attacker_for(victim)
    resp = ctx.request(atk, "GET", entry["request_path"])
    if "download_report" in entry["path"]:
        text = pdf_text(resp)
        ans = judge_read(ctx, entry, resp, text=text,
                         marks=markers(ctx.system, victim))
        ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                           "pdf_text": text[:800]}
        return ans
    ans = judge_read(ctx, entry, resp)
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "body": text_of(resp)[:600]}
    return ans


def read_vampi(ctx: Ctx, entry: dict) -> dict:
    victim = entry["victim"]
    atk = ctx.attacker_for(victim)
    resp = ctx.request(atk, "GET", entry["request_path"])
    ans = judge_read(ctx, entry, resp)
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "body": text_of(resp)[:400]}
    return ans


# --------------------------------------------------------------------------- #
# 各系统：写（全部带恢复）
# --------------------------------------------------------------------------- #

def write_mock(ctx: Ctx, entry: dict) -> dict:
    """PATCH /api/orders/{id}：写唯一 nonce，受害者复读，再写回原值。"""
    victim, oid = entry["victim"], entry["object_ids"][0]
    atk = ctx.attacker_for(victim)
    nonce = f"AI-RELABEL-{int(time.time())}-{entry['id']}"

    before = ctx.request(victim, "GET", f"/api/orders/{oid}", token=ctx.token(victim))
    original = before.json().get("note") if before.status_code == 200 else None

    resp = ctx.request(atk, "PATCH", entry["request_path"], body={"note": nonce})
    after = ctx.request(victim, "GET", f"/api/orders/{oid}", token=ctx.token(victim))
    seen = after.json().get("note") if after.status_code == 200 else None

    if 200 <= resp.status_code < 300 and seen == nonce:
        ans = _ans(True, None, f"攻击者 PATCH 2xx，受害者复读到 nonce（订单 {oid}）")
    elif resp.status_code in (401, 403):
        ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
    elif resp.status_code == 405:
        ans = _ans(False, "method_not_allowed", "HTTP 405")
    else:
        ans = _ans(False, "ignored_identifier",
                   f"HTTP {resp.status_code}，受害者复读 note={seen!r}（未变）")

    # 恢复
    if original is not None:
        ctx.request(victim, "PATCH", f"/api/orders/{oid}", body={"note": original},
                    token=ctx.token(victim))
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "victim_read": seen, "original": original}
    return ans


def write_crapi(ctx: Ctx, entry: dict) -> dict:
    """PUT /workshop/api/mechanic/service_request/{id}：改 status 再改回。"""
    victim, sid = entry["victim"], entry["object_ids"][0]
    atk = ctx.attacker_for(victim)
    url = entry["request_path"]

    before = ctx.request(victim, "GET", url, token=ctx.token(victim))
    old = before.json().get("status") if before.status_code == 200 else None
    # crAPI 的 status 是自由字符串，seed 里出现过 pending / completed / inprogress
    candidate = ("inprogress", "pending", "completed")
    new = next(c for c in candidate if c != old)

    resp = ctx.request(atk, "PUT", url, body={"status": new})
    after = ctx.request(victim, "GET", url, token=ctx.token(victim))
    seen = after.json().get("status") if after.status_code == 200 else None

    if 200 <= resp.status_code < 300 and seen == new:
        ans = _ans(True, None, f"攻击者 PUT 2xx，受害者复读 status={new}（原 {old}）")
    elif resp.status_code in (401, 403):
        ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
    elif resp.status_code == 405:
        ans = _ans(False, "method_not_allowed", "HTTP 405")
    else:
        ans = _ans(False, "ignored_identifier",
                   f"HTTP {resp.status_code}，受害者复读 status={seen!r}（未变）")

    if old is not None:
        ctx.request(victim, "PUT", url, body={"status": old}, token=ctx.token(victim))
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "victim_read": seen, "original": old,
                       "body": text_of(resp)[:200]}
    return ans


def write_vampi(ctx: Ctx, entry: dict) -> dict:
    victim = entry["victim"]
    atk = ctx.attacker_for(victim)
    kind = "password" if entry["path"].endswith("/password") else "email"
    stamp = int(time.time())
    old_cfg = ctx.accounts[victim]
    atk_cfg = ctx.accounts[atk]

    if kind == "password":
        new_pw = f"AiRelabel-{stamp}!A1"
        resp = ctx.request(atk, "PUT", entry["request_path"], body={"password": new_pw})
        # 受害者能否用新密码登录 -> 凭据真的被改了
        victim_changed = _try_login(ctx, victim, new_pw)
        attacker_changed = _try_login(ctx, atk, new_pw)
        if victim_changed:
            ans = _ans(True, None, "攻击者改密 2xx，受害者用新密码登录成功")
            _restore_password(ctx, victim, new_pw, old_cfg["password"])
        elif attacker_changed:
            ans = _ans(False, "ignored_identifier",
                       "改的是调用者自己的密码，路径里的 username 被忽略")
            _restore_password(ctx, atk, new_pw, atk_cfg["password"])
        elif resp.status_code in (401, 403):
            ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
        else:
            ans = _ans(None, None, f"HTTP {resp.status_code}，改密后无法判定", uncertain=True)
        ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                           "victim_changed": victim_changed,
                           "attacker_changed": attacker_changed}
        return ans

    # email
    new_mail = f"ai-relabel-{stamp}@example.com"
    before_v = ctx.request(victim, "GET", f"/users/v1/{victim}",
                           token=ctx.token(victim))
    before_a = ctx.request(atk, "GET", f"/users/v1/{atk}", token=ctx.token(atk))
    resp = ctx.request(atk, "PUT", entry["request_path"], body={"email": new_mail})
    after_v = ctx.request(victim, "GET", f"/users/v1/{victim}",
                          token=ctx.token(victim))
    after_a = ctx.request(atk, "GET", f"/users/v1/{atk}", token=ctx.token(atk))
    v_mail = after_v.json().get("email") if after_v.status_code == 200 else None
    a_mail = after_a.json().get("email") if after_a.status_code == 200 else None

    if v_mail == new_mail:
        ans = _ans(True, None, "受害者邮箱被改成攻击者提交的值")
        ctx.request(victim, "PUT", f"/users/v1/{victim}/email",
                    body={"email": old_cfg["email"]}, token=ctx.token(victim))
    elif a_mail == new_mail:
        ans = _ans(False, "ignored_identifier",
                   "改的是调用者自己的邮箱，路径里的 username 被忽略")
        ctx.request(atk, "PUT", f"/users/v1/{atk}/email",
                    body={"email": atk_cfg["email"]}, token=ctx.token(atk))
    elif resp.status_code in (401, 403):
        ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
    else:
        ans = _ans(None, None, f"HTTP {resp.status_code}，邮箱归属不明", uncertain=True)
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "victim_email": v_mail, "attacker_email": a_mail,
                       "victim_before": before_v.text[:120],
                       "attacker_before": before_a.text[:120]}
    return ans


def _try_login(ctx: Ctx, name: str, password: str) -> bool:
    acct = dict(ctx.accounts[name])
    acct["password"] = password
    try:
        login(ctx.base, ctx.login_cfg, acct)
        return True
    except Exception:
        return False


def _restore_password(ctx: Ctx, name: str, current: str, original: str) -> None:
    """用当前密码换 token，再把密码改回原值。"""
    acct = dict(ctx.accounts[name])
    acct["password"] = current
    try:
        tok = login(ctx.base, ctx.login_cfg, acct)
    except Exception:
        return
    ctx.request(name, "PUT", f"/users/v1/{name}/password",
                body={"password": original}, token=tok)
    ctx.tokens.pop(name, None)


def write_crapi_comment(ctx: Ctx, entry: dict) -> dict:
    """社区帖子是公开资源：任意登录用户可读可评（规范 3.3 第 2 类）。

    仍然真实发一条带 nonce 的评论并复读，确认"写确实成功"，但判定为
    `public_resource`——它检验的是判据能否把"公开可写"与 BOLA 分开。
    """
    victim, pid = entry["victim"], entry["object_ids"][0]
    atk = ctx.attacker_for(victim)
    nonce = f"AI-RELABEL-COMMENT-{entry['id']}"
    resp = ctx.request(atk, "POST", entry["request_path"], body={"content": nonce})
    post_path = (entry["request_path"].rsplit("/comment", 1)[0]
                 if entry["request_path"].endswith("/comment") else entry["request_path"])
    listing = ctx.request(atk, "GET", post_path)
    seen = nonce in text_of(listing) if listing.status_code == 200 else False
    if 200 <= resp.status_code < 300:
        ans = _ans(False, "public_resource",
                   f"公开帖子：攻击者评论 2xx 且复读可见 nonce（{seen}），按规范不算 BOLA")
    else:
        ans = _ans(False, "public_resource",
                   f"公开帖子，POST {resp.status_code}；按规范不算 BOLA")
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "nonce_visible": seen,
                       "post": text_of(ctx.request(atk, "GET", entry["request_path"]))[:400]}
    return ans


# --------------------------------------------------------------------------- #
# 删除（含受害者复读）
# --------------------------------------------------------------------------- #

def delete_mock_order(ctx: Ctx, entry: dict) -> dict:
    victim, oid = entry["victim"], entry["object_ids"][0]
    atk = ctx.attacker_for(victim)
    resp = ctx.request(atk, "DELETE", entry["request_path"])
    after = ctx.request(victim, "GET", f"/api/orders/{oid}", token=ctx.token(victim))
    if 200 <= resp.status_code < 300 and after.status_code == 404:
        ans = _ans(True, None, "攻击者 DELETE 2xx，受害者复读 200 -> 404")
    elif resp.status_code in (401, 403):
        ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
    elif resp.status_code == 405:
        ans = _ans(False, "method_not_allowed", "HTTP 405")
    else:
        ans = _ans(False, "ignored_identifier",
                   f"DELETE {resp.status_code}，受害者复读仍为 {after.status_code}")
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "victim_after": after.status_code}
    return ans


def delete_mock_doc(ctx: Ctx, entry: dict) -> dict:
    victim, uuid = entry["victim"], entry["object_ids"][0]
    atk = ctx.attacker_for(victim)
    resp = ctx.request(atk, "DELETE", entry["request_path"])
    after = ctx.request(victim, "GET", entry["request_path"], token=ctx.token(victim))
    if 200 <= resp.status_code < 300 and after.status_code == 404:
        ans = _ans(True, None, "攻击者 DELETE 2xx，受害者复读 200 -> 404（软删除）")
    elif resp.status_code in (401, 403):
        ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
    else:
        ans = _ans(False, "ignored_identifier",
                   f"DELETE {resp.status_code}，受害者复读仍为 {after.status_code}")
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "victim_after": after.status_code}
    return ans


def delete_crapi(ctx: Ctx, entry: dict) -> dict:
    victim = entry["victim"]
    atk = ctx.attacker_for(victim)
    resp = ctx.request(atk, "DELETE", entry["request_path"])
    after = ctx.request(victim, "GET", entry["request_path"], token=ctx.token(victim))
    if 200 <= resp.status_code < 300 and after.status_code == 404:
        ans = _ans(True, None, "攻击者 DELETE 2xx，受害者复读 200 -> 404")
    elif resp.status_code in (401, 403):
        ans = _ans(False, "owner_check", f"HTTP {resp.status_code}")
    elif resp.status_code == 405:
        ans = _ans(False, "method_not_allowed", "HTTP 405（方法不允许）")
    else:
        ans = _ans(None, None,
                   f"DELETE {resp.status_code}，受害者复读 {after.status_code}",
                   uncertain=True)
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "victim_after": after.status_code,
                       "body": text_of(resp)[:200]}
    return ans


def trash_mock(ctx: Ctx, entry: dict) -> dict:
    """软删除后的 trash 复读：删除动作由同一攻击者在上一步完成。"""
    victim = entry["victim"]
    atk = ctx.attacker_for(victim)
    resp = ctx.request(atk, "GET", entry["request_path"])
    ans = judge_read(ctx, entry, resp)
    ans["evidence"] = {"attacker": atk, "status": resp.status_code,
                       "body": text_of(resp)[:400]}
    return ans


# --------------------------------------------------------------------------- #
# 调度
# --------------------------------------------------------------------------- #

READ = {"mock": read_mock, "clean": read_mock,
        "crapi": read_crapi, "vampi": read_vampi}


def phase_of(entry: dict) -> int:
    m, p = entry["method"], entry["path"]
    if p.endswith("/trash"):
        return 3
    if m == "DELETE":
        return 2
    if m in ("PATCH", "PUT"):
        return 1
    if m == "POST" and "/comment" in p:
        return 1
    return 0


def run(entries: list[dict]) -> list[dict]:
    results: dict[str, dict] = {}
    ctxs: dict[str, Ctx] = {}
    for entry in entries:
        ctxs.setdefault(entry["system"], Ctx(entry["system"]))

    for phase in (0, 1, 2, 3):
        batch = [e for e in entries if phase_of(e) == phase]
        print(f"[phase {phase}] {len(batch)} 条")
        for e in batch:
            ctx = ctxs[e["system"]]
            try:
                if phase == 0:
                    ans = READ[e["system"]](ctx, e)
                elif phase == 1:
                    if e["method"] == "PATCH":
                        ans = write_mock(ctx, e)
                    elif e["method"] == "POST" and "/comment" in e["path"]:
                        ans = write_crapi_comment(ctx, e)
                    elif e["system"] == "crapi":
                        ans = write_crapi(ctx, e)
                    else:
                        ans = write_vampi(ctx, e)
                elif phase == 2:
                    if e["system"] == "mock":
                        ans = (delete_mock_doc(ctx, e) if "/documents/" in e["path"]
                               else delete_mock_order(ctx, e))
                    else:
                        ans = delete_crapi(ctx, e)
                else:
                    ans = trash_mock(ctx, e)
            except Exception as exc:  # 单条失败不拖垮全卷
                ans = _ans(None, None, f"{type(exc).__name__}: {exc}", uncertain=True)
            ans["id"] = e["id"]
            ans["seq"] = e["seq"]
            ans["difficulty"] = difficulty(e)
            ans["probe"] = {"system": e["system"], "method": e["method"],
                            "path": e["path"], "object_ids": e["object_ids"],
                            "victim": e["victim"]}
            results[e["id"]] = ans
            v = ans["vulnerable"]
            tag = "V" if v is True else ("S" if v is False else "?")
            print(f"  {e['seq']:3d} {e['id']:12s} {tag}  {ans['note'][:80]}")

    # mock 收尾：把靶场数据恢复成初始状态
    if "mock" in ctxs:
        try:
            ctxs["mock"].request(sorted(ctxs["mock"].accounts)[0], "POST", "/api/debug/reset")
            print("[reset] mock 已恢复初始数据")
        except Exception as exc:
            print(f"[reset] mock 恢复失败：{exc}")

    return [results[e["id"]] for e in entries]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AI 辅助二次标注（黑盒复核）")
    ap.add_argument("--sheet", default=str(SHEET))
    ap.add_argument("--out", default=str(OUT / "answers_assistant.jsonl"))
    ap.add_argument("--evidence", default=str(OUT / "evidence_assistant.jsonl"))
    args = ap.parse_args(argv)

    entries = [json.loads(l) for l in
               Path(args.sheet).read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"载入盲标卷 {len(entries)} 条")

    answers = run(entries)
    Path(args.out).write_text(
        "\n".join(json.dumps(a, ensure_ascii=False) for a in answers) + "\n",
        encoding="utf-8")
    Path(args.evidence).write_text(
        "\n".join(json.dumps(a, ensure_ascii=False) for a in answers) + "\n",
        encoding="utf-8")

    nv = sum(1 for a in answers if a["vulnerable"] is True)
    ns = sum(1 for a in answers if a["vulnerable"] is False)
    nu = sum(1 for a in answers if a["uncertain"] or a["vulnerable"] is None)
    print(f"\n总结：vuln {nv} / safe {ns} / 判不准 {nu}  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())