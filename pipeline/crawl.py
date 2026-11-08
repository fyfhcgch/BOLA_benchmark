"""采集层：用 Playwright 驱动真实浏览器，捕获 XHR/fetch 与 JS bundle。

设计要点（对照 研究方案 §2 Phase 3.1）：
  * 只抓 /api 或 XHR 类型响应，避免把图片/CSS 塞进结果
  * 页面加载后还要"交互"（滚轮、点击导航），否则漏掉懒加载接口
  * JS bundle 单独落盘，交给 jsapi.py 做 AST 分析
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from playwright.sync_api import sync_playwright

from .config import DEFAULT_HEADERS, DATA


def login(base_url: str, login_cfg: dict, account: dict) -> str:
    url = base_url.rstrip("/") + login_cfg["path"]
    payload = {
        k: v.format(**account) if isinstance(v, str) else v
        for k, v in login_cfg["json"].items()
    }
    r = httpx.request(login_cfg["method"], url, json=payload, timeout=15,
                      headers={"Content-Type": "application/json", **DEFAULT_HEADERS})
    r.raise_for_status()
    token = r.json()[login_cfg["token_field"]]
    return token


def _chrome_path() -> str | None:
    """Playwright 版本与本地缓存不一致时，直接指定可执行文件。"""
    env = os.environ.get("BOLA_CHROME")
    if env:
        return env
    base = Path.home() / ".cache/ms-playwright"
    cands = sorted(base.glob("chromium-*/chrome-linux64/chrome"))
    return str(cands[-1]) if cands else None


def crawl(system: dict, outdir: Path | None = None, headless: bool = True) -> Path:
    """返回 capture 文件路径。"""
    sid = system["id"]
    outdir = outdir or (DATA / "raw" / sid)
    outdir.mkdir(parents=True, exist_ok=True)
    jsdir = outdir / "js"
    jsdir.mkdir(exist_ok=True)

    records: list[dict] = []
    base = system["base_url"].rstrip("/")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, executable_path=_chrome_path())
        for name, acct in system["accounts"].items():
            token = login(base, system["login"], acct)
            ctx = browser.new_context()
            if not system.get("ui_login"):
                ctx.add_init_script(
                    f"localStorage.setItem('token', {json.dumps(token)});"
                    f"localStorage.setItem('auth_token', {json.dumps(token)});"
                )
            page = ctx.new_page()

            def on_response(resp):
                try:
                    req = resp.request
                    if req.resource_type not in ("xhr", "fetch"):
                        return
                    if urlparse(req.url).netloc != urlparse(base).netloc:
                        # 第三方请求（地图、埋点）不是被测系统的攻击面
                        return
                    ct = (resp.headers or {}).get("content-type", "")
                    body = None
                    if "json" in ct:
                        try:
                            body = resp.json()
                        except Exception:
                            body = resp.text()[:2000]
                    records.append({
                        "account": name,
                        "method": req.method,
                        "url": req.url,
                        "path": urlparse(req.url).path + (("?" + urlparse(req.url).query) if urlparse(req.url).query else ""),
                        "status": resp.status,
                        "req_headers": dict(req.headers),
                        "req_body": req.post_data,
                        "resp_body": body,
                        "resource_type": req.resource_type,
                        "ts": time.time(),
                    })
                except Exception:
                    pass

            page.on("response", on_response)

            if system.get("ui_login"):
                if not _ui_login(page, base, system["ui_login"], acct):
                    print(f"  [crawl] {name}: UI 登录失败，跳过")
                    ctx.close()
                    continue

            routes = system.get("seed_routes_by_account", {}).get(name) or system["seed_routes"]
            for route in routes:
                url = base + route
                try:
                    page.goto(url, wait_until="networkidle", timeout=30000)
                    page.mouse.wheel(0, 1200)
                    page.wait_for_timeout(400)
                    _interact(page)
                except Exception as e:
                    print(f"  [crawl] {name} {route} -> {type(e).__name__}: {e}")

            # 保存本次加载到的 JS bundle
            for resp in list(page.context.pages):
                pass

            ctx.close()
            print(f"  [crawl] {name}: captured")

        # 单独再抓一次 JS：用 http 直取页面引用的 script
        browser.close()

    # 抓 JS bundle（简化版：从首页 HTML 里解析 script src）
    _download_bundles(base, jsdir)

    cap = outdir / "capture.jsonl"
    with cap.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"  [crawl] {len(records)} records -> {cap}")
    return cap


DANGER_RE = re.compile(r"log\s*out|sign\s*out|注销|删除|delete|remove|pay|buy now", re.I)


def _interact(page, max_clicks: int = 6) -> None:
    """页面加载后点击若干可点元素 —— 大量接口只在交互之后才被调用。"""
    clicked = 0
    try:
        handles = page.query_selector_all("a, button, [role=button], .card, tr")
    except Exception:
        return
    for h in handles:
        if clicked >= max_clicks:
            break
        try:
            if not h.is_visible():
                continue
            text = (h.inner_text() or "").strip()
            if not text or DANGER_RE.search(text):
                continue
            h.click(timeout=1200)
            page.wait_for_timeout(350)
            clicked += 1
            try:
                page.go_back(timeout=1500)
                page.wait_for_timeout(200)
            except Exception:
                pass
        except Exception:
            continue


def _ui_login(page, base: str, cfg: dict, acct: dict) -> bool:
    """真实 SPA 往往不认注入的 localStorage token，必须走一次表单登录。"""
    try:
        page.goto(base + cfg.get("path", "/login"), wait_until="networkidle", timeout=30000)
        page.fill(cfg.get("email_selector", "input[type=email]"),
                  acct.get("email") or acct["username"])
        page.fill(cfg.get("password_selector", "input[type=password]"), acct["password"])
        page.click(cfg.get("submit", "button[type=submit]"))
        page.wait_for_timeout(cfg.get("wait_ms", 2500))
        ok = cfg.get("success_path", "/login") not in urlparse(page.url).path
        print(f"  [crawl] UI login -> {urlparse(page.url).path} ({'ok' if ok else 'FAILED'})")
        return ok
    except Exception as e:
        print(f"  [crawl] UI login error: {type(e).__name__}: {e}")
        return False


def _download_bundles(base: str, jsdir: Path) -> None:
    try:
        html = httpx.get(base + "/", timeout=10).text
    except Exception:
        return
    import re
    for src in re.findall(r'<script[^>]+src="([^"]+)"', html):
        url = src if src.startswith("http") else base + ("" if src.startswith("/") else "/") + src
        name = urlparse(url).path.strip("/").replace("/", "_") or "bundle.js"
        try:
            r = httpx.get(url, timeout=10)
            if r.status_code == 200:
                (jsdir / name).write_text(r.text, encoding="utf-8", errors="ignore")
                print(f"  [crawl] bundle -> {name} ({len(r.text)} bytes)")
        except Exception:
            continue


if __name__ == "__main__":
    from .config import SYSTEMS
    crawl(SYSTEMS["mock"])
