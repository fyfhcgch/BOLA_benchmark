#!/usr/bin/env bash
# 全量重置 crAPI：删卷 -> 重建 -> 等待 healthy -> 灌种子
set -euo pipefail
cd "$(dirname "$0")"

echo "[reset] down -v"
docker compose down -v

echo "[reset] up -d"
docker compose up -d

echo "[reset] 等待 healthy（最多 180s）"
for i in $(seq 1 60); do
  unhealthy=$(docker compose ps --format '{{.Status}}' | grep -vc 'healthy' || true)
  if [ "$unhealthy" -eq 0 ]; then break; fi
  sleep 3
done
docker compose ps --format 'table {{.Name}}\t{{.Status}}'

echo "[reset] seed"
python3 ../../systems/crapi/seed.py

# vehicle.uuid 会重新生成，标注里的 uuid 必须跟着刷新
echo "[reset] sync ids"
python3 ../../bench/sync_ids.py --system crapi || echo "[reset] sync_ids 失败，请手动执行"
