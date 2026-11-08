"""刷新"部署相关"的对象标识（车辆 uuid/vin、帖子 id、维修请求 id）。

crAPI 的 vehicle.uuid / vin、community post id、workshop service_request id
在 `docker compose down -v` 之后都会变（或按新顺序重建）。把具体值硬编码进
labels 会让全量重置后的实验对不上。这个脚本登录每个账号，按各自的列表接口
读回当前值，只改 `object_ids` 与 `request_path`，不改语义。

用法：
    python bench/sync_ids.py --system crapi
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.config import DEFAULT_HEADERS, SYSTEMS  # noqa: E402
from pipeline.crawl import login  # noqa: E402


def _kind_for(path: str) -> str | None:
    """标注模板 -> 需要刷新的标识类型。"""
    if "/workshop/api/mechanic/service_request/" in path:
        return "serviceId"
    for kind in ("uuid", "vin", "postId"):
        if f"{{{kind}}}" in path:
            return kind
    return None


def _placeholder_for(kind: str) -> str:
    # 数字 id 在模板里统一是 {id}
    return "{id}" if kind == "serviceId" else f"{{{kind}}}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", default="crapi")
    ap.add_argument("--labels", default=None)
    args = ap.parse_args()

    system = SYSTEMS[args.system]
    list_path = system.get("vehicle_list")
    if not list_path:
        print(f"[sync] {args.system} 未配置 vehicle_list，无事可做")
        return

    base = system["base_url"].rstrip("/")
    id_of: dict[str, dict[str, str]] = {}
    for name, acct in system["accounts"].items():
        try:
            tok = login(base, system["login"], acct)
            h = {"Authorization": f"Bearer {tok}", **DEFAULT_HEADERS}
            items = httpx.get(base + list_path, headers=h, timeout=20).json()
        except Exception as e:
            print(f"[sync] {name}: {type(e).__name__}: {e}")
            continue
        if not (isinstance(items, list) and items):
            continue
        cur = {
            "uuid": items[0].get("uuid", ""),
            "vin": items[0].get("vin", ""),
        }
        # 帖子：取本账号发的第一条
        try:
            posts = httpx.get(base + "/community/api/v2/community/posts/recent",
                              headers=h, timeout=20).json().get("posts", [])
            mine = [p for p in posts if p.get("author", {}).get("email") == acct.get("email")]
            if mine:
                cur["postId"] = mine[0]["id"]
        except Exception:
            pass
        # 维修请求：按 VIN 查自己的列表
        try:
            if cur["vin"]:
                sr = httpx.get(base + f"/workshop/api/merchant/service_requests/{cur['vin']}",
                               headers=h, timeout=20).json().get("service_requests", [])
                if sr:
                    cur["serviceId"] = str(sr[0]["id"])
        except Exception:
            pass
        id_of[name] = cur

    print("[sync] 当前标识:", json.dumps(id_of, ensure_ascii=False))

    path = Path(args.labels) if args.labels else ROOT / system["labels"]
    rows = [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]
    changed = 0
    for d in rows:
        kind = _kind_for(d.get("path", ""))
        if not kind:
            continue
        oid = (id_of.get(d.get("victim")) or {}).get(kind)
        if not oid:
            continue
        if d.get("object_ids") != [oid]:
            d["object_ids"] = [oid]
            d["request_path"] = d["path"].replace(_placeholder_for(kind), oid)
            changed += 1

    with path.open("w", encoding="utf-8") as f:
        for d in rows:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    print(f"[sync] {path}: {len(rows)} 条标注，更新 {changed} 条")


if __name__ == "__main__":
    main()
