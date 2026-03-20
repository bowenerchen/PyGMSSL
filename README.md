# GMSSL（国密 Python 实现与互操作测试）

本仓库包含 **pygmssl**（Python 国密算法库）及 **tests-api**（与 **eet** 的交叉验证脚本与结果）。

## 文档入口（推荐从这里进）

**[docs/README.md](docs/README.md)** — 统一文档中心，按类浏览：

| 类别 | 说明 |
|------|------|
| [算法说明](docs/algorithms/sm2.md) | SM2 / SM3 / SM4 / SM9 / ZUC 等 |
| [使用指南](docs/usage/getting_started.md) | 安装、哈希、对称/非对称、证书等 |
| [Cookbook（可复制示例）](docs/cookbook/README.md) | 面向 `gmssl.hazmat` 的逐算法代码片段 |
| [测试与 eet 互操作](docs/testing/README.md) | 用例 ID、API 评审摘要、SM2 fixture 说明 |
| [架构](docs/architecture.md) | 模块与设计理念 |

## 代码与脚本

| 目录 | 说明 |
|------|------|
| [pygmssl/](pygmssl/README.md) | Python 包源码、`pip install -e pygmssl` |
| [tests-api/](tests-api/README.md) | eet 对照脚本、`shell/run_all.sh`、fixture |

## 上游与许可

算法实现对照 **GmSSL 3.1.1**；上游：<https://github.com/guanzhi/GmSSL>。各子项目许可证见其各自目录。
