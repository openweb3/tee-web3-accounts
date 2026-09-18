#!/usr/bin/env python3
"""删除 cloudtest 的 TEE 实例（生命周期最后一步）。

删除**从不读 hosts.json**。实例只按两个 cloudtest 标签查找
（tee-web3-accounts=true 且 user=<配置的用户>），每个匹配结果都在本地复核，
任何不带完整双标签的机器都不会被碰。

    python3 delete.py            终止所有匹配实例
    python3 delete.py --dry-run  只列出会删除什么，不删
"""

import sys

from aws import find_by_tags, terminate
from config import load


def boto3_client(cfg):
    try:
        import boto3
    except ImportError:
        sys.exit("没有安装 boto3；先执行 ./setup.sh")
    return boto3.client("ec2", region_name=cfg.region)


def main() -> None:
    dry_run = "--dry-run" in sys.argv[1:]
    cfg = load()

    ec2 = boto3_client(cfg)
    found = find_by_tags(ec2, cfg)
    if not found:
        print(
            f"==> {cfg.region} 下没有实例带 tag:{cfg.tag_owner}="
            f"{cfg.tag_owner_value} 且 tag:{cfg.tag_user}={cfg.user}"
        )
        return

    for inst in found:
        print(
            f"    {inst['InstanceId']}  {inst['State']['Name']}  "
            f"{inst.get('PublicIpAddress', '-')}"
        )
    if dry_run:
        print(f"==> dry-run: 会终止 {len(found)} 台实例")
        return

    ids = [i["InstanceId"] for i in found]
    print(f"==> 正在终止 {len(ids)} 台实例")
    terminate(ec2, ids)
    print(f"==> 已终止: {', '.join(ids)}")


if __name__ == "__main__":
    main()
