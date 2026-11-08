# 靶场镜像 digest（论文结果对应的版本）

`docker-compose.yml` 为了方便部署用的是 `latest` 标签，标签会随上游更新而漂移。
**论文里的数字对应的是下表中这些 digest**，复现时请按 digest 拉取，否则对象标识
（crAPI 的 UUID / VIN / NanoID、VAmPI 的 book title）会重新生成，标注与结果不再可比。

生成方式（在本机运行中的容器上执行）：

```bash
docker inspect -f '{{.Image}}' <container>
docker image inspect -f '{{join .RepoDigests " "}}' <image-id>
```

## crAPI（镜像构建于 2025-09-22）

| 服务 | 镜像 | digest |
|---|---|---|
| identity | `crapi/crapi-identity` | `sha256:5d1db5b3ba8e02bc68711ec6fc4e35ed7cd8b87e63785ece9e7ff5b5e36c5260` |
| community | `crapi/crapi-community` | `sha256:8ba0c7eda86ae065a673f1fa554d0109a24f25c5a8d65097ae024e5ee715c54e` |
| web | `crapi/crapi-web` | `sha256:b27d246c646bd33898e7d1d2095b6e7576c0993a7b81a73aa7386929493d7151` |
| workshop | `crapi/crapi-workshop` | `sha256:d4d2d94d35a31e211b04d5a771881f5ae13e358e8fa0804463ae3bace05dd815` |
| chatbot | `crapi/crapi-chatbot` | `sha256:36d274d54182a8baddba7ede17282035bb43ab9cb9cf87927e1fe7109901e0aa` |
| gateway | `crapi/gateway-service` | `sha256:97dade9daf0e758547b1686e2d3303c8c9b79838167f728a9211f0ee1f4622b0` |

## VAmPI（镜像构建于 2026-04-07）

| 服务 | 镜像 | digest |
|---|---|---|
| vampi | `erev0s/vampi` | `sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12` |

## 与标注指纹的关系

两项指纹必须**成对引用**：

| 指纹 | 位置 |
|---|---|
| 标注 | `results/processed/bench_manifest.json`（`bench/labels/*.jsonl` 逐文件 sha256） |
| 环境 | 本文件（镜像 digest） |

只给其一，复现出来的数字不可比。
