"""cloudtest 的唯一配置来源。

值从环境变量读取（先加载同目录的 .env），并带安全默认值，保证 Python 步骤与 shell
编排器永远看到同一套配置。user 标签和 region 是两个绝不能漂移的值：机器在哪个
region 创建就在哪个 region 删除，且始终按同一对标签匹配。
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path

# cloudtest 唯一允许创建机器的区域：eu-west-1（爱尔兰）。运维规定，勿改。
DEFAULT_REGION = "eu-west-1"

# 标记 cloudtest 拥有的一切资源；删除时两个标签必须同时匹配。
TAG_OWNER = "tee-web3-accounts"
TAG_OWNER_VALUE = "true"
TAG_USER = "user"

# 远端测试使用的助记词。**故意硬编码成公开的测试助记词**，原因有两条：
#   1. 它的派生地址是公开已知的（见 README），远端脚本才能独立对码验证；
#   2. 让真实助记词没有机会经由配置文件流到实例上。
# 这里的助记词是 Hardhat / Anvil 的公开默认值，人人皆知，不可用于任何真实资产。
TEST_MNEMONIC = "test test test test test test test test test test test junk"

ENV_FILE = Path(__file__).with_name(".env")


def load_env() -> None:
    """把 .env 里的 KEY=VALUE 读进 os.environ（不覆盖已有值）。"""
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@dataclass(frozen=True)
class Config:
    # user 是必填项：它是区分不同操作员机器的**唯一**边界，必须显式设置，
    # 绝不提供默认值。
    user: str
    region: str = DEFAULT_REGION
    instance_type: str = "m6a.large"  # 必须是 AMD 系列：m6a / c6a / r6a
    ami_filter: str = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
    mnemonic: str = TEST_MNEMONIC

    @property
    def key_name(self) -> str:
        return f"tee-web3-accounts-{self.user}"

    @property
    def name_prefix(self) -> str:
        return f"tee-web3-accounts-{self.user}"

    @property
    def tag_owner(self) -> str:
        return TAG_OWNER

    @property
    def tag_owner_value(self) -> str:
        return TAG_OWNER_VALUE

    @property
    def tag_user(self) -> str:
        return TAG_USER

    def tags(self, name: str = "") -> list[dict]:
        tags = [
            {"Key": TAG_OWNER, "Value": TAG_OWNER_VALUE},
            {"Key": TAG_USER, "Value": self.user},
        ]
        if name:
            tags.append({"Key": "Name", "Value": name})
        return tags


def load() -> Config:
    load_env()
    user = os.environ.get("TEE_ACCOUNTS_USER", "").strip()
    if not user:
        sys.exit(
            "TEE_ACCOUNTS_USER 是必填项（填一个只属于你的唯一值，比如你的名字）；"
            "缺少它时 cloudtest 拒绝运行"
        )
    return Config(
        user=user,
        region=os.environ.get("TEE_ACCOUNTS_REGION", DEFAULT_REGION),
        instance_type=os.environ.get("TEE_ACCOUNTS_INSTANCE_TYPE", "m6a.large"),
        ami_filter=os.environ.get(
            "TEE_ACCOUNTS_AMI_FILTER",
            "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
        ),
    )
