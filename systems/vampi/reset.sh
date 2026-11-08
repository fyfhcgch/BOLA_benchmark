#!/usr/bin/env bash
# 重建 VAmPI 容器与数据（SQLite 在容器内，down -v 才会清空）
set -euo pipefail
cd "$(dirname "$0")"

echo "[reset] down -v"
docker compose down -v
echo "[reset] up -d"
docker compose up -d
for i in $(seq 1 30); do
  if curl -sf -m 2 http://127.0.0.1:5002/ >/dev/null 2>&1; then break; fi
  sleep 1
done
echo "[reset] seed"
python3 seed.py
