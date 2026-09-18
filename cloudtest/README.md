# cloudtest：在真实 AWS SEV-SNP TEE 上跑 tee-web3-accounts

在 AWS `eu-west-1` 起一台 AMD SEV-SNP 机密计算实例，把交叉编译好的静态二进制传上去，
在实例回环地址上跑完整业务流，采集 TEE 证据、审计落盘数据与日志、验证三条启动护栏，
再把结果拉回本地做独立的密码学验签。

## 架构

```
cloudtest/
├── config.py          配置（region / user 标签 / 实例类型 / 测试助记词）
├── aws.py             幂等 ensure 原语 + 启动 + 按标签查找/删除（不构造 boto3 client，可单测）
├── create.py          模块一：ensure 基础设施 → 启动实例 → 写 hosts.json（覆盖写入）
├── delete.py          模块二：按双标签查找并终止实例（绝不读 hosts.json，支持 --dry-run）
├── delete_infra.py    独立工具：按双标签拆掉网络基础设施（VPC/子网/IGW/安全组/密钥对）
├── run.sh             编排器：build / create / test / delete / delete-infra / 全流程
├── lib.sh             SSH/rsync/日志等公共函数
├── remote/run-all.sh  在实例上执行的套件（证据采集、起服务、护栏验证、打包结果）
├── remote/check.py    在实例上跑接口与数据审计（只用标准库，不依赖 secp256k1）
├── tests/test_unit.py 本地单元测试（内存 fake EC2，不需要 boto3，不碰真实云）
├── hosts.json         生成的实例信息临时文件（gitignored）
└── logs/<时间戳>/      每次运行的日志与拉回的远端结果（gitignored）
```

## 使用

```bash
./setup.sh                  # 创建 .venv 并装 boto3（只需一次）
./run.sh                    # 全流程：create → test → delete（测试失败也会清理机器）
./run.sh build              # 交叉编译 linux/amd64 静态二进制
./run.sh create             # 只创建（幂等：基础设施不重复建，hosts.json 覆盖写入）
./run.sh test               # 只测试（依赖 hosts.json 提供实例地址）
./run.sh delete             # 只终止实例
./run.sh delete --dry-run   # 列出会终止的实例，不删
./run.sh delete-infra       # 只拆网络基础设施（少用，见下）
KEEP_INSTANCE=true ./run.sh # 全流程但保留机器，便于手工排查
```

注意：`./run.sh create` 会**留着机器**（供后续 `./run.sh test` 使用），只有全流程
`./run.sh` 才会自动清理。全流程在中断（Ctrl-C / 崩溃）时也会通过 trap 回收实例。

## 远端套件做了什么

1. **采集 TEE 证据** → `tee-evidence.txt`：虚拟化类型、CPU 的 `sev*` 特性、
   `/dev/sev-guest` 是否存在、`dmesg` 里 SEV/SNP/CCP 的记录。这是「确实跑在机密
   计算实例上」的原始凭据，会随结果一起拉回本地。
2. **起服务**：助记词写进 `0400` 文件、走 `TEE_MNEMONIC_FILE` 注入（不进环境变量），
   数据文件与监听地址都在实例的私有目录 / 回环地址上。
3. **接口与数据审计**（`remote/check.py`，31 项断言）：
   - 三个接口的正路径与失败路径；
   - 索引 0 的地址等于**公开已知值**（Hardhat 测试助记词的派生地址，本地硬编码，
     不从服务端读回来当期望值）；
   - 签名格式（`0x` + 130 位小写十六进制、`v ∈ {27,28}`）与 RFC 6979 确定性；
   - 「密码错误」与「索引不存在」响应体完全相同；
   - 账户库权限必须是 `0600`，字段集合必须**精确**等于预期（多一个字段就失败），
     且不得出现 `priv` / `secret` / `mnemonic` / `seed` 之类字段或明文密码；
   - 服务日志里不得出现助记词、密码或助记词字段名。
4. **启动护栏**：换错助记词、没配助记词、助记词校验和错误 —— 三种都必须拒绝启动，
   且日志要指明原因。
5. **本地独立验签**：实例上没有 secp256k1 库，所以密码学验证在本地做。套件产出
   `signature.json`（哈希 + 签名 + 服务端返回的地址 + 公开已知地址），编排器用
   `wallet.RecoverAddress` 重新派生期望地址并验签，形成三方一致。

## 安全与幂等

- **幂等 ensure**：VPC、子网、互联网网关、路由、安全组、密钥对全部「先查后建」，
  重复执行 create 不会产生重复资源，全部资源都带 `tee-web3-accounts=true` 和
  `user=<配置值>` 双标签。
- **严格按标签删除**：delete 只按两个标签查找（服务端过滤后本地再逐台复核标签），
  并且 user 值必须等于配置的 `TEE_ACCOUNTS_USER`；任何不带完整双标签的机器绝不动。
  delete 从不读 hosts.json，即使临时文件丢了也能精确清掉自己创建的机器。
- **只开放 22 端口**：安全组只放行 SSH，服务只在实例回环地址上监听，业务端口不暴露公网。
- **中断也会清理**：全流程装了 `trap ... EXIT INT TERM`，即使 Ctrl-C 或崩溃发生在
  test 之前，也会回收本轮启动的实例，避免持续计费。`KEEP_INSTANCE=true` 可跳过。
- **delete_infra 是独立、少用的工具**：同样只按双标签查找、本地逐条复核，但拆的是
  网络基础设施（不拆不花钱，所以默认留着以便重跑收敛）。只在想彻底重置区域或轮换
  密钥对时才用，且永远先跑 `--dry-run`。

## 配置

复制 `.env.example` 为 `.env` 并填入 AWS 凭证和 `TEE_ACCOUNTS_USER`；其余都有默认值。

| 变量 | 默认 | 说明 |
|---|---|---|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | 无 | 必填（不填则创建/删除直接失败） |
| `TEE_ACCOUNTS_USER` | **无，必填** | 实例 user 标签值，删除时精确匹配它。这是区分不同操作员机器**唯一**的边界，必须每人一个唯一值，绝不共享默认值 |
| `TEE_ACCOUNTS_REGION` | `eu-west-1` | 唯一允许启动的区域（爱尔兰），勿改 |
| `TEE_ACCOUNTS_INSTANCE_TYPE` | `m6a.large` | 必须是 AMD 系列（m6a/c6a/r6a） |

`TEE_ACCOUNTS_USER` 未设置时 shell 层和 Python 层都会直接失败退出（不会退回任何默认值）。

## 关于区域与实例类型

AWS 的 SEV-SNP 支持 AMD 实例（m6a/c6a/r6a）。代码默认固定在 **eu-west-1**（运营
规定：只允许在此区域启停服务器）；若该区域尚未开放 `AmdSevSnp=enabled`，
`run_instances` 会直接返回错误，create 步骤会明确失败并提示，不会悄悄起一台普通实例。

## 测试用的助记词

远端套件用的是 Hardhat / Anvil 的公开测试助记词
`test test test test test test test test test test test junk`，它的派生地址是公开
已知的（见根目录 README 的表格），所以断言可以独立对码。这个值**故意硬编码**在
`config.py` 里，就是为了让真实助记词没有机会经由配置文件流到测试实例上。

## 单元测试

```bash
./setup.sh
python3 -m unittest discover -s tests -v
```

覆盖：ensure 幂等、SEV-SNP 启动参数与双标签、安全组只开 22 端口、按标签精确删除、
delete 不依赖 hosts.json、delete_infra 只拆自己带双标签的资源（别人的 / 缺标签的 /
无标签的必须存活）、`TEE_ACCOUNTS_USER` 缺失时直接失败、`check.py` 必须硬编码公开
地址而不是自证。

## 真实运行前置条件

1. `./setup.sh` 创建 `.venv` 并装好 boto3
2. `.env` 填入有 `ec2:*` 权限的凭证，以及唯一的 `TEE_ACCOUNTS_USER`
3. `./run.sh build` 成功（本地交叉编译 linux/amd64，纯静态、无运行时依赖）
4. 目标区域有 SEV-SNP 实例配额

执行 `./run.sh` 时，远端套件会 `apt-get install ca-certificates curl`（`check.py`
只用 Python 标准库，不需要 pip 装包）。运行结果以 `logs/<时间戳>/` 保留在本地。
