"""整系统 clean control：与 mock **同一个应用**，只把授权策略切到 secure。

为什么这样搭：如果另写一个"安全版应用"，漏洞系统与对照系统会在路由表、
响应字段、前端调用点、对象标识形态上全都不同，那么"检测器在 clean 系统上
零误报"这句话就无法归因 —— 它可能只是因为两者长得不像。

这里复用 `systems/mock/app.py` 的同一份代码与同一份种子数据：

    MOCK_POLICY=vulnerable  ->  systems/mock   （端口 8765）
    MOCK_POLICY=secure      ->  systems/clean  （端口 8766）

两者唯一的差异是 `Handler._deny()` 的返回值。这条差异可以逐点核对：
`grep -n "_deny" systems/mock/app.py` 数出来的每一处，就是 clean 版
比 mock 版多做的唯一一件事。

标注口径：clean 系统**没有漏洞标注**。`bench/labels/clean.jsonl` 是空文件
（只有注释行），所有实例都通过 `bench/labels/clean.noref.jsonl` 之外的方式
进入指标 —— 更准确地说，clean 系统的全部端点都按"应当零告警"来评：
任何告警都是 FP，没有任何告警时 precision 记为 1.000（分母为 0 的约定）。

用法：
    MOCK_POLICY=secure .venv/bin/python systems/clean/app.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# 必须在 import mock 之前设置：app.py 在模块加载时就读取 MOCK_POLICY
os.environ.setdefault("MOCK_POLICY", "secure")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mock.app import main  # noqa: E402

PORT = int(os.environ.get("CLEAN_PORT", "8766"))

if __name__ == "__main__":
    main(host="127.0.0.1", port=PORT)
