"""VAmPI 种子：重建库 -> 注册三个账号 -> 每人一本带 secret 的书。

VAmPI 的书名是**全局唯一**的自然键，所以每个账号用不同的书名
（`<username>-notebook`）。`id_patterns` 里声明了这个形态，模板化时才认得出
它是对象标识，而不是普通路径段。
"""

from __future__ import annotations

import json
import sys
import time

import httpx

BASE = "http://127.0.0.1:5002"
ACCOUNTS = {
    "alice1": "Alice@12345",
    "bob2": "Bob@12345",
    "carol3": "Carol@12345",
}


def main() -> None:
    # 1) 清库并重建（VAmPI 自带 /createdb）
    for _ in range(20):
        try:
            r = httpx.get(f"{BASE}/createdb", timeout=5)
            if r.status_code == 200:
                print("[seed] 1/3 数据库已重建")
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        sys.exit("[seed] VAmPI 未就绪，请先 docker compose up -d")

    # 2) 注册
    for name, pw in ACCOUNTS.items():
        r = httpx.post(f"{BASE}/users/v1/register",
                       json={"username": name, "password": pw, "email": f"{name}@example.com"},
                       timeout=10)
        print(f"[seed] 2/3 注册 {name}: {r.status_code} {r.text[:60]}")

    # 3) 每账号一本自己的书
    tokens = {}
    for name, pw in ACCOUNTS.items():
        r = httpx.post(f"{BASE}/users/v1/login",
                       json={"username": name, "password": pw}, timeout=10)
        tokens[name] = r.json()["auth_token"]
        r = httpx.post(f"{BASE}/books/v1",
                       json={"book_title": f"{name}-notebook",
                             "secret": f"SECRET-{name.upper()}-BOOK"},
                       headers={"Authorization": f"Bearer {tokens[name]}"}, timeout=10)
        print(f"[seed] 3/3 {name} 添加书本: {r.status_code} {r.text[:60]}")

    print("[seed] done")
    print(json.dumps({k: {"username": k, "password": v} for k, v in ACCOUNTS.items()},
                     indent=2))


if __name__ == "__main__":
    main()
