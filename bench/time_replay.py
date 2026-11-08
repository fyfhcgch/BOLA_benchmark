"""测量四个系统的全量重放耗时（论文 §III 与 §VI 的开销数字）。

用法：
    python bench/time_replay.py

做法：对每个系统以 `--skip-crawl --tag timing` 跑一遍默认判据，用 wall-clock 计时，
读取 `summary.json` 的 `tests_total`，然后**删掉** timing 目录（它是临时产物，
不能留在 `results/raw/*/ablation/` 里污染消融表）。

输出 `results/processed/timing.json`，供 `paper/gen_tables.py` 生成正文宏。
计时含 Python 进程启动与靶场重置，是“一个人在自己的笔记本上跑一遍”的真实耗时。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results" / "raw"
OUT = ROOT / "results" / "processed" / "timing.json"

SYSTEMS = ["mock", "clean", "crapi", "vampi"]


def main() -> None:
    py = sys.executable
    rows = []
    for sid in SYSTEMS:
        tag_dir = RAW / sid / "ablation" / "timing"
        t0 = time.perf_counter()
        proc = subprocess.run(
            [py, "-m", "pipeline.run", "--system", sid, "--skip-crawl", "--tag", "timing"],
            cwd=ROOT, capture_output=True, text=True,
        )
        elapsed = time.perf_counter() - t0
        if proc.returncode != 0:
            raise SystemExit(f"[{sid}] 重放失败：\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
        summary = json.loads((tag_dir / "summary.json").read_text(encoding="utf-8"))
        rows.append({
            "system": sid,
            "seconds": round(elapsed, 2),
            "tests_total": summary["tests_total"],
        })
        print(f"[{sid}] {elapsed:.2f} s, {summary['tests_total']} 用例")
        shutil.rmtree(tag_dir, ignore_errors=True)

    doc = {
        "source": "bench/time_replay.py（wall-clock，含进程启动与靶场重置）",
        "rows": rows,
        "tests_total": sum(r["tests_total"] for r in rows),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n-> {OUT}")


if __name__ == "__main__":
    main()
