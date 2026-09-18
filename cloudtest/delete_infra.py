#!/usr/bin/env python3
"""拆掉 cloudtest 的网络基础设施（VPC / 子网 / 互联网网关 / 安全组 / 密钥对）。

**这是少用的破坏性工具。** 正常生命周期（create → test → delete）只终止实例，
把（不花钱的）网络脚手架留着，让重跑收敛而不是重建。只有想彻底重置某区域、或者
轮换密钥对时才需要它。

安全性与 delete.py 完全一致：
  * 每个资源都只按两个 cloudtest 标签发现（tee-web3-accounts=true 且 user=<配置用户>），
    并在本地逐条复核；
  * 作用范围限定在 cfg.region，其他区域不可达；
  * 缺少完整双标签的东西一律不动；
  * 永远先跑 --dry-run。

    python3 delete_infra.py            拆掉带标签的基础设施
    python3 delete_infra.py --dry-run  只列出会拆掉什么
"""

import sys

from aws import terminate_infra
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
    summary = terminate_infra(ec2, cfg, dry_run=dry_run)

    print(f"==> region {cfg.region}，user 标签 {cfg.user}")
    for kind, ids in summary.items():
        if ids:
            print(f"    {kind}: {', '.join(ids)}")
    if dry_run:
        print("==> dry-run: 什么都没删")
    else:
        print("==> 上面列出的资源已拆除")


if __name__ == "__main__":
    main()
