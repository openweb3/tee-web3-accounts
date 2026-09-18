#!/usr/bin/env python3
"""创建 cloudtest 的 TEE 实例（生命周期第一步）。

幂等：每件基础设施都是 ensure（先查后建），实例信息写入 hosts.json（覆盖写入）。

    python3 create.py

没有 AWS 凭证时会在构造 client 时直接失败；本脚本只创建、从不删除任何东西。
"""

import json
import subprocess
import sys
import time
from pathlib import Path

from aws import (
    ensure_igw,
    ensure_key,
    ensure_sg,
    ensure_subnet,
    ensure_vpc,
    latest_ami,
    launch,
    wait_running,
)
from config import load

HERE = Path(__file__).resolve().parent
HOSTS_FILE = HERE / "hosts.json"
KEY_FILE = HERE / "ssh-key.pem"


def boto3_client(cfg):
    try:
        import boto3
    except ImportError:
        sys.exit("没有安装 boto3；先执行 ./setup.sh")
    return boto3.client("ec2", region_name=cfg.region)


def ensure_local_key() -> None:
    if KEY_FILE.exists():
        return
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(KEY_FILE)], check=True
    )


def main() -> None:
    cfg = load()
    ensure_local_key()
    ec2 = boto3_client(cfg)

    print(f"==> 在 {cfg.region} 上收敛基础设施（user 标签: {cfg.user}）")
    vpc_id = ensure_vpc(ec2, cfg)
    subnet_id = ensure_subnet(ec2, cfg, vpc_id)
    ensure_igw(ec2, cfg, vpc_id)
    sg_id = ensure_sg(ec2, cfg, vpc_id)
    ensure_key(ec2, cfg, public_key=KEY_FILE.with_suffix(".pem.pub").read_text().strip())

    ami = latest_ami(ec2, cfg)
    print(f"==> 启动 {cfg.instance_type}（AMI {ami}），AmdSevSnp=enabled")
    inst = launch(ec2, cfg, ami, vpc_id, subnet_id, sg_id)
    inst = wait_running(ec2, inst["InstanceId"])

    entry = {
        "instance_id": inst["InstanceId"],
        "public_ip": inst.get("PublicIpAddress", ""),
        "region": cfg.region,
        "instance_type": cfg.instance_type,
        "user_tag": cfg.user,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    HOSTS_FILE.write_text(json.dumps(entry, indent=2) + "\n")
    print(f"==> 实例 {entry['instance_id']} 已就绪，地址 {entry['public_ip']}")
    print(f"==> 已写入 {HOSTS_FILE}")


if __name__ == "__main__":
    main()
