"""cloudtest 用的幂等 AWS EC2 原语。

每个 ensure_* 遵循同一份契约：先按 cloudtest 的双标签查找资源；找到就原样返回，
没找到才创建并打上同一对标签。因此重复执行 create.py 只会收敛到已有环境，不会
产生重复资源。

所有函数都要求调用方传入 ec2 client，自己从不构造 client —— 这样单元测试可以用
内存 fake 驱动完全相同的代码路径，不需要 AWS 凭证，也绝不会触达真实云。
"""

from __future__ import annotations

import time

from config import Config

CANONICAL_OWNER = "099720109477"  # Ubuntu 官方 AMI 的 owner 账号


def tag_filters(cfg: Config) -> list[dict]:
    return [
        {"Name": f"tag:{cfg.tag_owner}", "Values": [cfg.tag_owner_value]},
        {"Name": f"tag:{cfg.tag_user}", "Values": [cfg.user]},
    ]


def ensure_vpc(ec2, cfg: Config) -> str:
    vpcs = ec2.describe_vpcs(Filters=tag_filters(cfg))["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    ec2.create_tags(Resources=[vpc["VpcId"]], Tags=cfg.tags(name=cfg.name_prefix))
    return vpc["VpcId"]


def ensure_subnet(ec2, cfg: Config, vpc_id: str) -> str:
    subnets = ec2.describe_subnets(
        Filters=tag_filters(cfg) + [{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"]
    if subnets:
        return subnets[0]["SubnetId"]
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=az
    )["Subnet"]
    ec2.create_tags(Resources=[subnet["SubnetId"]], Tags=cfg.tags())
    ec2.modify_subnet_attribute(
        SubnetId=subnet["SubnetId"], MapPublicIpOnLaunch={"Value": True}
    )
    return subnet["SubnetId"]


def ensure_igw(ec2, cfg: Config, vpc_id: str) -> str:
    igws = ec2.describe_internet_gateways(
        Filters=tag_filters(cfg)
        + [{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    )["InternetGateways"]
    if igws:
        return igws[0]["InternetGatewayId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]
    ec2.create_tags(Resources=[igw["InternetGatewayId"]], Tags=cfg.tags())
    ec2.attach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
    # VPC 的主路由表需要一条指向网关的默认路由。
    rts = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "association.main", "Values": ["true"]},
        ]
    )["RouteTables"]
    rt_id = rts[0]["RouteTableId"]
    routes = [r.get("DestinationCidrBlock") for r in rts[0].get("Routes", [])]
    if "0.0.0.0/0" not in routes:
        ec2.create_route(
            RouteTableId=rt_id,
            DestinationCidrBlock="0.0.0.0/0",
            # 必须传 IGW 的 id 字符串；传整个 dict 会被真实 AWS 以
            # ParamValidationError 拒绝。
            GatewayId=igw["InternetGatewayId"],
        )
    return igw


def ensure_sg(ec2, cfg: Config, vpc_id: str) -> str:
    sgs = ec2.describe_security_groups(
        Filters=tag_filters(cfg) + [{"Name": "vpc-id", "Values": [vpc_id]}]
    )["SecurityGroups"]
    if sgs:
        return sgs[0]["GroupId"]
    sg_id = ec2.create_security_group(
        GroupName=f"{cfg.name_prefix}-sg",
        Description="tee-web3-accounts cloudtest: SSH only",
        VpcId=vpc_id,
    )["GroupId"]
    ec2.create_tags(Resources=[sg_id], Tags=cfg.tags())
    # 只放行 22 端口：服务本身只在实例回环地址上监听，业务端口不暴露公网。
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    return sg_id


def ensure_key(ec2, cfg: Config, public_key: str) -> str:
    """本地公钥在 AWS 上不存在时导入它。"""
    keys = ec2.describe_key_pairs(
        Filters=[{"Name": "key-name", "Values": [cfg.key_name]}]
    )["KeyPairs"]
    if keys:
        return keys[0]["KeyName"]
    ec2.import_key_pair(
        KeyName=cfg.key_name,
        PublicKeyMaterial=public_key,
        # 密钥对也打上和其他资源一样的双标签，delete_infra 才能用同一条规则
        # 发现并清理它。
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": cfg.tags()}],
    )
    return cfg.key_name


def latest_ami(ec2, cfg: Config) -> str:
    images = ec2.describe_images(
        Owners=[CANONICAL_OWNER],
        Filters=[
            {"Name": "name", "Values": [cfg.ami_filter]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise RuntimeError(f"没有匹配 {cfg.ami_filter!r} 的 AMI")
    images.sort(key=lambda i: i["CreationDate"])
    return images[-1]["ImageId"]


def launch(ec2, cfg: Config, ami_id: str, vpc_id: str, subnet_id: str, sg_id: str) -> dict:
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=cfg.instance_type,
        KeyName=cfg.key_name,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[
            {
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": [sg_id],
            }
        ],
        # 打开 AMD SEV-SNP。区域不支持时 AWS 会直接拒绝这次调用，create
        # 步骤会明确失败，而不是悄悄起一台普通实例。
        CpuOptions={"AmdSevSnp": "enabled"},
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": cfg.tags(name=cfg.name_prefix)}
        ],
    )
    return resp["Instances"][0]


def wait_running(ec2, instance_id: str, timeout: int = 300) -> dict:
    """轮询到实例 running 且拿到公网 IP 为止。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]
        state = inst["State"]["Name"]
        if state == "running":
            ip = inst.get("PublicIpAddress")
            if ip:
                return inst
        if state in ("terminated", "shutting-down"):
            raise RuntimeError(f"实例 {instance_id} 进入了状态 {state}")
        time.sleep(5)
    raise TimeoutError(f"实例 {instance_id} 在 {timeout}s 内没有进入 running")


def find_by_tags(ec2, cfg: Config) -> list[dict]:
    """携带完整双标签、且未终止的实例。

    服务端过滤只是性能提示；返回结果里的标签会被本地再核对一遍，因此一个过期或
    意外变宽的 describe 结果不可能扩大匹配集合。
    """
    resp = ec2.describe_instances(
        Filters=tag_filters(cfg)
        + [
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"],
            }
        ]
    )
    found = []
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            if (
                tags.get(cfg.tag_owner) == cfg.tag_owner_value
                and tags.get(cfg.tag_user) == cfg.user
            ):
                found.append(inst)
    return found


def terminate(ec2, instance_ids: list[str]) -> None:
    if instance_ids:
        ec2.terminate_instances(InstanceIds=instance_ids)


def wait_terminated(ec2, instance_ids: list[str], timeout: int = 360) -> None:
    """轮询到所有实例彻底 terminated 为止。

    AWS 的实例终止是异步的：在实例完全消失之前，它的 ENI 会一直占着安全组、子网
    和 VPC。delete_infra 必须在这里等，否则后续的删除会中途失败，留下它本该拆掉的
    脚手架。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = ec2.describe_instances(InstanceIds=instance_ids)
        states = [
            i["State"]["Name"]
            for r in resp.get("Reservations", [])
            for i in r.get("Instances", [])
        ]
        if not states or not ({s for s in states} - {"terminated", "shutting-down"}):
            return
        time.sleep(5)
    raise TimeoutError(f"实例在 {timeout}s 内没有终止完成")


def _delete_with_retry(func, attempts: int = 8, delay: int = 5, **kwargs):
    """重试删除调用，吸收刚终止实例导致的瞬时依赖错误（ENI / 安全组仍被占用）。"""
    for n in range(attempts):
        try:
            func(**kwargs)
            return
        except Exception:
            if n == attempts - 1:
                raise
            time.sleep(delay)


def _tagged(items: list[dict], cfg: Config) -> list[dict]:
    """只保留同时带两个 cloudtest 标签的条目，并在本地复核。

    服务端过滤是性能提示，真正防止「过期或意外变宽的 describe 扩大匹配集合」的是
    这次本地复核。与 find_by_tags 对应，用于非实例资源。
    """
    out = []
    for it in items:
        tags = {t["Key"]: t["Value"] for t in it.get("Tags", [])}
        if (
            tags.get(cfg.tag_owner) == cfg.tag_owner_value
            and tags.get(cfg.tag_user) == cfg.user
        ):
            out.append(it)
    return out


def find_vpcs_by_tags(ec2, cfg: Config) -> list[dict]:
    return _tagged(ec2.describe_vpcs(Filters=tag_filters(cfg)).get("Vpcs", []), cfg)


def find_subnets_by_tags(ec2, cfg: Config) -> list[dict]:
    return _tagged(ec2.describe_subnets(Filters=tag_filters(cfg)).get("Subnets", []), cfg)


def find_igws_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_internet_gateways(Filters=tag_filters(cfg))
    return _tagged(resp.get("InternetGateways", []), cfg)


def find_sgs_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_security_groups(Filters=tag_filters(cfg))
    return _tagged(resp.get("SecurityGroups", []), cfg)


def find_keys_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_key_pairs(Filters=tag_filters(cfg))
    return _tagged(resp.get("KeyPairs", []), cfg)


def terminate_infra(ec2, cfg: Config, dry_run: bool = False) -> dict:
    """拆掉本 region / 本 user 下所有带 cloudtest 标签的资源。

    发现完全靠那两个标签（并在本地复核），拆除按依赖顺序进行，因此 AWS 会接受每一次
    删除。任何缺少完整双标签的东西都不会被碰；client 被限定在 cfg.region，其他区域
    根本不可达。传 dry_run 只列出不删除。

    这是 delete.py 那种「删除实例」之外的、少用的破坏性工具：正常生命周期只终止实例，
    把（不花钱的）网络脚手架留着，让重跑能收敛。
    """
    insts = find_by_tags(ec2, cfg)
    vpcs = find_vpcs_by_tags(ec2, cfg)
    subnets = find_subnets_by_tags(ec2, cfg)
    igws = find_igws_by_tags(ec2, cfg)
    sgs = find_sgs_by_tags(ec2, cfg)
    keys = find_keys_by_tags(ec2, cfg)

    summary = {
        "instances": [i["InstanceId"] for i in insts],
        "vpcs": [v["VpcId"] for v in vpcs],
        "subnets": [s["SubnetId"] for s in subnets],
        "igws": [g["InternetGatewayId"] for g in igws],
        "security_groups": [g["GroupId"] for g in sgs],
        "key_pairs": [k["KeyName"] for k in keys],
    }
    if dry_run:
        return summary

    # 1. 先删实例，子网和 VPC 才有可能被释放。
    if insts:
        terminate(ec2, summary["instances"])
        # 等 ENI 释放，否则下面几步会以 DependencyViolation 失败并漏掉脚手架。
        wait_terminated(ec2, summary["instances"])
    # 2. 摘掉并删除互联网网关。
    for g in igws:
        for a in g.get("Attachments", []):
            try:
                ec2.detach_internet_gateway(
                    InternetGatewayId=g["InternetGatewayId"], VpcId=a["VpcId"]
                )
            except Exception:
                pass
        _delete_with_retry(
            ec2.delete_internet_gateway, InternetGatewayId=g["InternetGatewayId"]
        )
    # 3. 安全组。
    for g in sgs:
        _delete_with_retry(ec2.delete_security_group, GroupId=g["GroupId"])
    # 4. 子网。
    for s in subnets:
        _delete_with_retry(ec2.delete_subnet, SubnetId=s["SubnetId"])
    # 5. VPC（自动创建的主路由表随 VPC 一起消失）。
    for v in vpcs:
        _delete_with_retry(ec2.delete_vpc, VpcId=v["VpcId"])
    # 6. 密钥对（按名字识别，名字里嵌了 user 标签，别人的密钥不可能匹配）。
    for k in keys:
        ec2.delete_key_pair(KeyName=k["KeyName"])
    return summary
