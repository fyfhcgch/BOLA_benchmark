"""crAPI 种子数据脚本。

做五件事（幂等，可重复执行）：
  1. 注册 3 个账号（已存在则跳过）
  2. 从 Mailhog 读取每个账号收到的 VIN / pincode，添加车辆
  3. 每个账号下 2 笔订单
  4. 每个账号发 1 条社区帖子
  5. 每个账号提 1 条维修服务请求（按 VIN 可查，用于测 BOLA）

用法：
    python systems/crapi/seed.py [--base http://127.0.0.1:8888] [--mailhog http://127.0.0.1:8025]
"""

from __future__ import annotations

import argparse
import json
import quopri
import re
import sys
import time

import httpx

ACCOUNTS = {
    "alice": {"name": "Alice", "email": "alice@example.com", "number": "13800000001", "password": "Alice@12345"},
    "bob":   {"name": "Bob",   "email": "bob@example.com",   "number": "13800000002", "password": "Bob@12345"},
    "carol": {"name": "Carol", "email": "carol@example.com", "number": "13800000003", "password": "Carol@12345"},
}


def signup(base: str, a: dict) -> None:
    r = httpx.post(f"{base}/identity/api/auth/signup", json={
        "name": a["name"], "email": a["email"], "number": a["number"], "password": a["password"],
    }, timeout=20)
    msg = r.text[:80]
    print(f"  signup {a['name']:6s} {r.status_code} {msg}")


def login(base: str, a: dict) -> str:
    r = httpx.post(f"{base}/identity/api/auth/login",
                   json={"email": a["email"], "password": a["password"]}, timeout=20)
    r.raise_for_status()
    return r.json()["token"]


def _decode(raw_msg: str) -> str:
    try:
        head, body = raw_msg.split("\r\n\r\n", 1)
    except ValueError:
        return raw_msg
    return quopri.decodestring(body.encode()).decode("utf-8", "ignore")


def fetch_vehicle_credentials(mailhog: str, email: str, retries: int = 10) -> tuple[str, str] | None:
    user = email.split("@")[0]
    for _ in range(retries):
        try:
            d = httpx.get(f"{mailhog}/api/v2/messages?limit=100", timeout=15).json()
        except Exception:
            d = {"items": []}
        for m in d.get("items", []):
            if m["To"][0]["Mailbox"] != user:
                continue
            txt = _decode(m["Raw"]["Data"])
            vin = re.search(r"VIN:\s*.*?>([A-Z0-9]{10,20})<", txt)
            pin = re.search(r"Pincode:\s*.*?>(\d{3,8})<", txt)
            if vin and pin:
                return vin.group(1), pin.group(1)
        time.sleep(1)
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8888")
    ap.add_argument("--mailhog", default="http://127.0.0.1:8025")
    args = ap.parse_args()
    base, mailhog = args.base, args.mailhog

    print("[seed] 1/5 注册账号")
    for a in ACCOUNTS.values():
        signup(base, a)
    time.sleep(2)

    print("[seed] 2/5 添加车辆")
    tokens = {}
    vins: dict[str, str] = {}
    for key, a in ACCOUNTS.items():
        tok = login(base, a)
        tokens[key] = tok
        h = {"Authorization": f"Bearer {tok}"}
        cred = fetch_vehicle_credentials(mailhog, a["email"])
        if not cred:
            print(f"  {key}: 未找到 VIN/pincode，跳过")
            continue
        vin, pin = cred
        vins[key] = vin
        r = httpx.post(f"{base}/identity/api/v2/vehicle/add_vehicle",
                       json={"vin": vin, "pincode": pin}, headers=h, timeout=20)
        print(f"  {key}: add_vehicle {r.status_code} {vin}")

    print("[seed] 3/5 创建订单")
    products = httpx.get(f"{base}/workshop/api/shop/products",
                         headers={"Authorization": f"Bearer {tokens['alice']}"}, timeout=20).json()["products"]
    pid = products[0]["id"]
    for key, tok in tokens.items():
        h = {"Authorization": f"Bearer {tok}"}
        have = httpx.get(f"{base}/workshop/api/shop/orders/all", headers=h, timeout=20).json().get("count", 0)
        if have >= 2:
            print(f"  {key}: 已有 {have} 笔订单，跳过")
            continue
        for qty in (1, 2):
            r = httpx.post(f"{base}/workshop/api/shop/orders",
                           json={"product_id": pid, "quantity": qty}, headers=h, timeout=20)
            print(f"  {key}: order qty={qty} -> {r.status_code}")

    print("[seed] 4/5 发布社区帖子")
    for key, tok in tokens.items():
        h = {"Authorization": f"Bearer {tok}"}
        try:
            posts = httpx.get(f"{base}/community/api/v2/community/posts/recent",
                              headers=h, timeout=20).json().get("posts", [])
        except Exception:
            posts = []
        mine = [p for p in posts if p.get("author", {}).get("email") == ACCOUNTS[key]["email"]]
        if mine:
            print(f"  {key}: 已有 {len(mine)} 条帖子，跳过")
            continue
        r = httpx.post(f"{base}/community/api/v2/community/posts",
                       json={"title": f"{key} 的第一条帖子", "content": f"SECRET-{key.upper()}-POST"},
                       headers=h, timeout=20)
        print(f"  {key}: post -> {r.status_code}")

    print("[seed] 5/5 创建维修服务请求")
    # workshop 容器会回调这个地址；主机侧发起请求时只有容器名可达
    mechanic_api = "http://crapi-workshop:8000/workshop/api/mechanic/receive_report"
    for key, tok in tokens.items():
        vin = vins.get(key)
        if not vin:
            continue
        h = {"Authorization": f"Bearer {tok}"}
        try:
            have = httpx.get(f"{base}/workshop/api/merchant/service_requests/{vin}",
                             headers=h, timeout=20).json().get("count", 0)
        except Exception:
            have = 0
        if have:
            print(f"  {key}: 已有 {have} 条服务请求，跳过")
            continue
        r = httpx.post(f"{base}/workshop/api/merchant/contact_mechanic",
                       json={"mechanic_code": "TRAC_JHN",
                             "problem_details": f"SECRET-{key.upper()}-SR 刹车异响",
                             "vin": vin, "mechanic_api": mechanic_api,
                             "repeat_request_if_failed": False, "number_of_repeats": 1},
                       headers=h, timeout=40)
        print(f"  {key}: service_request -> {r.status_code}")

    print("[seed] done")
    json.dump({k: {"email": v["email"], "password": v["password"]} for k, v in ACCOUNTS.items()},
              sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
