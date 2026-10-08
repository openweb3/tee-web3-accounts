"""cloudtest 的本地单元测试。不需要 boto3、不碰网络：用一个内存里的 fake EC2
client 驱动与真实 client 完全相同的 aws.py 代码路径。

运行:  python3 -m unittest discover -s tests -v   （在 cloudtest 目录下）
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aws
import config as config_mod
from config import Config


def tags_dict(tags):
    return {t["Key"]: t["Value"] for t in (tags or [])}


class FakeEC2:
    """内存版 boto3 ec2 client，形状与真实 API 一致。"""

    def __init__(self):
        self.vpcs, self.subnets, self.igws, self.rts = [], [], [], []
        self.sgs, self.keys, self.images = [], [], []
        self.instances, self.next_id = [], 1
        self.last_run_instances = None

    # -- 通用 ---------------------------------------------------------------
    def _match(self, tags, attrs, filters):
        for f in filters:
            name, values = f["Name"], f["Values"]
            if name.startswith("tag:"):
                if tags.get(name[4:]) not in values:
                    return False
            elif attrs.get(name) not in values:
                return False
        return True

    def _tag(self, resource_id, tags, stores):
        for store in stores:
            for r in store:
                if (
                    r.get("VpcId") == resource_id
                    or r.get("SubnetId") == resource_id
                    or r.get("InternetGatewayId") == resource_id
                    or r.get("GroupId") == resource_id
                    or r.get("InstanceId") == resource_id
                ):
                    r.setdefault("Tags", []).extend(tags)
                    return
        raise KeyError(f"unknown resource {resource_id}")

    # -- VPC ----------------------------------------------------------------
    def describe_vpcs(self, Filters=None):
        return {
            "Vpcs": [
                v
                for v in self.vpcs
                if self._match(tags_dict(v.get("Tags")), {"vpc-id": v["VpcId"]}, Filters or [])
            ]
        }

    def create_vpc(self, CidrBlock):
        vpc = {"VpcId": f"vpc-{len(self.vpcs) + 1}", "CidrBlock": CidrBlock, "Tags": []}
        self.vpcs.append(vpc)
        # AWS 会为 VPC 自动创建主路由表。
        self.rts.append(
            {
                "RouteTableId": f"rt-{len(self.rts) + 1}",
                "VpcId": vpc["VpcId"],
                "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": CidrBlock}],
            }
        )
        return {"Vpc": vpc}

    def create_tags(self, Resources, Tags):
        for rid in Resources:
            self._tag(rid, Tags, (self.vpcs, self.subnets, self.igws, self.sgs, self.instances))

    # -- 子网 ----------------------------------------------------------------
    def describe_subnets(self, Filters=None):
        return {
            "Subnets": [
                s
                for s in self.subnets
                if self._match(
                    tags_dict(s.get("Tags")),
                    {"vpc-id": s["VpcId"], "subnet-id": s["SubnetId"]},
                    Filters or [],
                )
            ]
        }

    def create_subnet(self, VpcId, CidrBlock, AvailabilityZone):
        sn = {
            "SubnetId": f"subnet-{len(self.subnets) + 1}",
            "VpcId": VpcId,
            "CidrBlock": CidrBlock,
            "AvailabilityZone": AvailabilityZone,
            "Tags": [],
        }
        self.subnets.append(sn)
        return {"Subnet": sn}

    def modify_subnet_attribute(self, SubnetId, MapPublicIpOnLaunch):
        pass

    def describe_availability_zones(self):
        return {"AvailabilityZones": [{"ZoneName": "eu-west-1a"}]}

    # -- 互联网网关 -----------------------------------------------------------
    def describe_internet_gateways(self, Filters=None):
        def attrs(g):
            return {
                "vpc-id": g["Attachments"][0]["VpcId"] if g["Attachments"] else None,
                "internet-gateway-id": g["InternetGatewayId"],
            }

        return {
            "InternetGateways": [
                g for g in self.igws if self._match(tags_dict(g.get("Tags")), attrs(g), Filters or [])
            ]
        }

    def create_internet_gateway(self):
        igw = {"InternetGatewayId": f"igw-{len(self.igws) + 1}", "Attachments": [], "Tags": []}
        self.igws.append(igw)
        return {"InternetGateway": igw}

    def attach_internet_gateway(self, InternetGatewayId, VpcId):
        next(
            g for g in self.igws if g["InternetGatewayId"] == InternetGatewayId
        )["Attachments"].append({"VpcId": VpcId})

    def describe_route_tables(self, Filters=None):
        def attrs(rt):
            return {
                "vpc-id": rt["VpcId"],
                "association.main": "true" if any(a.get("Main") for a in rt["Associations"]) else "false",
            }

        return {"RouteTables": [rt for rt in self.rts if self._match({}, attrs(rt), Filters or [])]}

    def create_route(self, RouteTableId, DestinationCidrBlock, GatewayId):
        rt = next(r for r in self.rts if r["RouteTableId"] == RouteTableId)
        rt["Routes"].append({"DestinationCidrBlock": DestinationCidrBlock, "GatewayId": GatewayId})
        self.last_create_route = {"RouteTableId": RouteTableId, "GatewayId": GatewayId}

    # -- 安全组 --------------------------------------------------------------
    def describe_security_groups(self, Filters=None):
        return {
            "SecurityGroups": [
                g
                for g in self.sgs
                if self._match(
                    tags_dict(g.get("Tags")), {"vpc-id": g["VpcId"], "group-id": g["GroupId"]}, Filters or []
                )
            ]
        }

    def create_security_group(self, GroupName, Description, VpcId):
        sg = {
            "GroupId": f"sg-{len(self.sgs) + 1}",
            "VpcId": VpcId,
            "GroupName": GroupName,
            "Description": Description,
            "Tags": [],
        }
        self.sgs.append(sg)
        self.last_ingress = None
        return {"GroupId": sg["GroupId"]}

    def authorize_security_group_ingress(self, GroupId, IpPermissions):
        self.last_ingress = {"GroupId": GroupId, "IpPermissions": IpPermissions}

    # -- 密钥对 --------------------------------------------------------------
    def describe_key_pairs(self, Filters=None):
        return {
            "KeyPairs": [
                k for k in self.keys if self._match(tags_dict(k.get("Tags")), {"key-name": k["KeyName"]}, Filters or [])
            ]
        }

    def import_key_pair(self, KeyName, PublicKeyMaterial, TagSpecifications=None):
        tags = []
        for spec in TagSpecifications or []:
            tags.extend(spec.get("Tags", []))
        self.keys.append({"KeyName": KeyName, "KeyPairId": f"key-{len(self.keys) + 1}", "Tags": tags})
        return {"KeyName": KeyName}

    # -- 镜像 ----------------------------------------------------------------
    def describe_images(self, Owners, Filters):
        return {
            "Images": [i for i in self.images if i.get("Architecture") == "x86_64" and i.get("State") == "available"]
        }

    # -- 实例 ----------------------------------------------------------------
    def add_instance(self, tag_map, state="running", public_ip=None):
        inst = {
            "InstanceId": f"i-{self.next_id}",
            "State": {"Name": state},
            "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
            "PublicIpAddress": public_ip,
        }
        self.next_id += 1
        self.instances.append(inst)
        return inst

    def run_instances(self, **kwargs):
        self.last_run_instances = kwargs
        tags = []
        for spec in kwargs.get("TagSpecifications", []):
            tags.extend(spec.get("Tags", []))
        inst = {"InstanceId": f"i-{self.next_id}", "State": {"Name": "pending"}, "Tags": tags}
        self.next_id += 1
        self.instances.append(inst)
        return {"Instances": [inst]}

    def describe_instances(self, InstanceIds=None, Filters=None):
        pool = [i for i in self.instances if InstanceIds is None or i["InstanceId"] in InstanceIds]
        if Filters is not None:
            pool = [
                i
                for i in pool
                if self._match(
                    tags_dict(i.get("Tags")),
                    {"instance-state-name": i["State"]["Name"], "instance-id": i["InstanceId"]},
                    Filters,
                )
            ]
        return {"Reservations": [{"Instances": pool}]}

    def terminate_instances(self, InstanceIds):
        for i in self.instances:
            if i["InstanceId"] in InstanceIds:
                i["State"]["Name"] = "terminated"

    # -- 基础设施辅助（delete_infra 测试用） ---------------------------------
    def add_vpc(self, tag_map, cidr="10.0.0.0/16"):
        vpc = {
            "VpcId": f"vpc-{len(self.vpcs) + 1}",
            "CidrBlock": cidr,
            "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
        }
        self.vpcs.append(vpc)
        self.rts.append(
            {
                "RouteTableId": f"rt-{len(self.rts) + 1}",
                "VpcId": vpc["VpcId"],
                "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": cidr}],
            }
        )
        return vpc

    def add_subnet(self, tag_map, vpc_id=None, cidr="10.0.1.0/24"):
        vid = vpc_id or (self.vpcs[-1]["VpcId"] if self.vpcs else "vpc-1")
        sn = {
            "SubnetId": f"subnet-{len(self.subnets) + 1}",
            "VpcId": vid,
            "CidrBlock": cidr,
            "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
        }
        self.subnets.append(sn)
        return sn

    def add_igw(self, tag_map, attachments=None):
        igw = {
            "InternetGatewayId": f"igw-{len(self.igws) + 1}",
            "Attachments": attachments or [],
            "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
        }
        self.igws.append(igw)
        return igw

    def add_sg(self, tag_map, vpc_id=None):
        vid = vpc_id or (self.vpcs[-1]["VpcId"] if self.vpcs else "vpc-1")
        sg = {
            "GroupId": f"sg-{len(self.sgs) + 1}",
            "VpcId": vid,
            "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
        }
        self.sgs.append(sg)
        return sg

    def add_key(self, name, tag_map=None):
        key = {
            "KeyName": name,
            "KeyPairId": f"key-{len(self.keys) + 1}",
            "Tags": [{"Key": k, "Value": v} for k, v in (tag_map or {}).items()],
        }
        self.keys.append(key)
        return key

    def delete_vpc(self, VpcId):
        self.vpcs = [v for v in self.vpcs if v["VpcId"] != VpcId]

    def delete_subnet(self, SubnetId):
        self.subnets = [s for s in self.subnets if s["SubnetId"] != SubnetId]

    def delete_internet_gateway(self, InternetGatewayId):
        self.igws = [g for g in self.igws if g["InternetGatewayId"] != InternetGatewayId]

    def detach_internet_gateway(self, InternetGatewayId, VpcId):
        for g in self.igws:
            if g["InternetGatewayId"] == InternetGatewayId:
                g["Attachments"] = [a for a in g["Attachments"] if a.get("VpcId") != VpcId]

    def delete_security_group(self, GroupId):
        self.sgs = [g for g in self.sgs if g["GroupId"] != GroupId]

    def delete_key_pair(self, KeyName):
        self.keys = [k for k in self.keys if k["KeyName"] != KeyName]


OWNER = "tee-web3-accounts"


class EnsureIdempotencyTest(unittest.TestCase):
    def test_vpc_ensure_creates_once(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        first = aws.ensure_vpc(fake, cfg)
        second = aws.ensure_vpc(fake, cfg)
        self.assertEqual(first, second)
        self.assertEqual(len(fake.vpcs), 1)
        tags = tags_dict(fake.vpcs[0]["Tags"])
        self.assertEqual(tags[OWNER], "true")
        self.assertEqual(tags["user"], "xinghao")

    def test_infra_ensure_is_idempotent_end_to_end(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        vpc = aws.ensure_vpc(fake, cfg)
        s1 = aws.ensure_subnet(fake, cfg, vpc)
        aws.ensure_igw(fake, cfg, vpc)
        g1 = aws.ensure_sg(fake, cfg, vpc)
        k1 = aws.ensure_key(fake, cfg, "ssh-ed25519 AAA test")
        s2 = aws.ensure_subnet(fake, cfg, vpc)
        aws.ensure_igw(fake, cfg, vpc)
        g2 = aws.ensure_sg(fake, cfg, vpc)
        k2 = aws.ensure_key(fake, cfg, "ssh-ed25519 AAA test")
        self.assertEqual((s1, g1, k1), (s2, g2, k2))
        self.assertEqual(len(fake.subnets), 1)
        self.assertEqual(len(fake.sgs), 1)
        self.assertEqual(len(fake.keys), 1)

    def test_igw_route_is_created_once(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        vpc = aws.ensure_vpc(fake, cfg)
        aws.ensure_igw(fake, cfg, vpc)
        aws.ensure_igw(fake, cfg, vpc)
        default = [r for r in fake.rts[0]["Routes"] if r["DestinationCidrBlock"] == "0.0.0.0/0"]
        self.assertEqual(len(default), 1)
        # GatewayId 必须是 IGW 的 id 字符串而不是整个 dict：传 dict 会被真实 AWS
        # 以 ParamValidationError 拒绝。
        self.assertIsInstance(fake.last_create_route["GatewayId"], str)
        self.assertTrue(fake.last_create_route["GatewayId"].startswith("igw-"))


class LaunchTest(unittest.TestCase):
    def test_launch_enables_sevsnp_and_both_tags(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        aws.launch(fake, cfg, "ami-1", "vpc-1", "subnet-1", "sg-1")
        kwargs = fake.last_run_instances
        self.assertEqual(kwargs["CpuOptions"], {"AmdSevSnp": "enabled"})
        tags = kwargs["TagSpecifications"][0]["Tags"]
        self.assertIn({"Key": OWNER, "Value": "true"}, tags)
        self.assertIn({"Key": "user", "Value": "xinghao"}, tags)

    def test_wait_running_returns_public_ip(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        inst = fake.add_instance({OWNER: "true", "user": "xinghao"}, public_ip="1.2.3.4")
        got = aws.wait_running(fake, inst["InstanceId"], timeout=1)
        self.assertEqual(got["PublicIpAddress"], "1.2.3.4")

    def test_security_group_opens_only_ssh(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        vpc = aws.ensure_vpc(fake, cfg)
        aws.ensure_sg(fake, cfg, vpc)
        permissions = fake.last_ingress["IpPermissions"]
        self.assertEqual(len(permissions), 1)
        self.assertEqual(permissions[0]["FromPort"], 22)
        self.assertEqual(permissions[0]["ToPort"], 22)
        self.assertEqual(permissions[0]["IpProtocol"], "tcp")


class DeleteSafetyTest(unittest.TestCase):
    def setUp(self):
        self.fake, self.cfg = FakeEC2(), Config(user="xinghao")
        self.fake.add_instance({OWNER: "true", "user": "xinghao"}, "running", "1.0.0.1")
        self.fake.add_instance({OWNER: "true", "user": "someone-else"}, "running", "1.0.0.2")
        self.fake.add_instance({OWNER: "true"}, "running", "1.0.0.3")
        self.fake.add_instance({"user": "xinghao"}, "running", "1.0.0.4")
        self.fake.add_instance({OWNER: "true", "user": "xinghao"}, "terminated")

    def test_find_by_tags_only_matching_running(self):
        found = aws.find_by_tags(self.fake, self.cfg)
        self.assertEqual([i["InstanceId"] for i in found], ["i-1"])

    def test_delete_only_targets_matching_instances(self):
        ids = [i["InstanceId"] for i in aws.find_by_tags(self.fake, self.cfg)]
        self.assertEqual(ids, ["i-1"])
        aws.terminate(self.fake, ids)
        states = {i["InstanceId"]: i["State"]["Name"] for i in self.fake.instances}
        self.assertEqual(states["i-1"], "terminated")
        for other in ("i-2", "i-3", "i-4"):
            self.assertEqual(states[other], "running")


class DeleteInfraSafetyTest(unittest.TestCase):
    def setUp(self):
        self.fake, self.cfg = FakeEC2(), Config(user="xinghao")
        self.fake.add_vpc({OWNER: "true", "user": "xinghao"})
        self.fake.add_subnet({OWNER: "true", "user": "xinghao"})
        self.fake.add_igw({OWNER: "true", "user": "xinghao"}, attachments=[{"VpcId": "vpc-1"}])
        self.fake.add_sg({OWNER: "true", "user": "xinghao"})
        self.fake.add_key("tee-web3-accounts-xinghao", {OWNER: "true", "user": "xinghao"})
        self.owned_inst = self.fake.add_instance({OWNER: "true", "user": "xinghao"}, "running", "1.0.0.1")
        # 别人的 / 缺标签的：必须存活
        self.fake.add_vpc({OWNER: "true", "user": "someone-else"})
        self.fake.add_vpc({"user": "xinghao"})
        self.fake.add_vpc({})
        self.fake.add_key("tee-web3-accounts-someone-else", {OWNER: "true", "user": "someone-else"})

    def test_dry_run_lists_only_owned(self):
        summary = aws.terminate_infra(self.fake, self.cfg, dry_run=True)
        self.assertEqual(summary["vpcs"], ["vpc-1"])
        self.assertEqual(summary["subnets"], ["subnet-1"])
        self.assertEqual(summary["igws"], ["igw-1"])
        self.assertEqual(summary["security_groups"], ["sg-1"])
        self.assertEqual(summary["key_pairs"], ["tee-web3-accounts-xinghao"])
        self.assertEqual(summary["instances"], [self.owned_inst["InstanceId"]])
        # dry-run 什么都不动
        self.assertEqual(len(self.fake.vpcs), 4)

    def test_delete_removes_only_owned(self):
        aws.terminate_infra(self.fake, self.cfg, dry_run=False)
        vpc_ids = {v["VpcId"] for v in self.fake.vpcs}
        self.assertNotIn("vpc-1", vpc_ids)  # 自己的被删
        self.assertIn("vpc-2", vpc_ids)  # 别人的保留
        self.assertIn("vpc-3", vpc_ids)  # 缺 owner 标签的保留
        self.assertIn("vpc-4", vpc_ids)  # 无标签的保留
        self.assertNotIn("subnet-1", {s["SubnetId"] for s in self.fake.subnets})
        self.assertNotIn("igw-1", {g["InternetGatewayId"] for g in self.fake.igws})
        self.assertNotIn("sg-1", {g["GroupId"] for g in self.fake.sgs})
        key_names = {k["KeyName"] for k in self.fake.keys}
        self.assertNotIn("tee-web3-accounts-xinghao", key_names)
        self.assertIn("tee-web3-accounts-someone-else", key_names)
        states = {i["InstanceId"]: i["State"]["Name"] for i in self.fake.instances}
        self.assertEqual(states[self.owned_inst["InstanceId"]], "terminated")


class WaitTerminatedTest(unittest.TestCase):
    def test_wait_terminated_blocks_until_all_terminated(self):
        fake, cfg = FakeEC2(), Config(user="xinghao")
        ids = [
            fake.add_instance({OWNER: "true", "user": "xinghao"}, "running")["InstanceId"],
            fake.add_instance({OWNER: "true", "user": "xinghao"}, "running")["InstanceId"],
        ]
        original = aws.time.sleep
        calls = {"n": 0}

        def fake_sleep(_):
            calls["n"] += 1
            if calls["n"] == 1:  # 第一次轮询还看到 running，第二次已经 terminated
                for i in fake.instances:
                    if i["State"]["Name"] == "running":
                        i["State"]["Name"] = "terminated"

        aws.time.sleep = fake_sleep
        try:
            aws.wait_terminated(fake, ids, timeout=30)  # 不该抛异常
        finally:
            aws.time.sleep = original


class ConfigTest(unittest.TestCase):
    def setUp(self):
        # 把 load_env 指向一个不存在的文件，让这些用例是封闭的：开发机上真实的
        # cloudtest/.env（确实会设置 TEE_ACCOUNTS_USER）不该决定它们是否通过。
        self._saved = config_mod.ENV_FILE
        config_mod.ENV_FILE = Path("/nonexistent/.env")

    def tearDown(self):
        config_mod.ENV_FILE = self._saved

    def test_env_overrides_defaults(self):
        os.environ["TEE_ACCOUNTS_USER"] = "alice"
        try:
            cfg = config_mod.load()
            self.assertEqual(cfg.user, "alice")
            # 运维规定：eu-west-1（爱尔兰）是唯一允许的区域。
            self.assertEqual(cfg.region, "eu-west-1")
            self.assertEqual(cfg.instance_type, "m6a.large")
        finally:
            del os.environ["TEE_ACCOUNTS_USER"]

    def test_load_requires_user(self):
        os.environ.pop("TEE_ACCOUNTS_USER", None)
        with self.assertRaises(SystemExit):
            config_mod.load()

    def test_test_mnemonic_is_the_public_hardhat_one(self):
        """远端脚本与 README 都依赖这个助记词及其公开地址，改动必须同步别处。"""
        self.assertEqual(
            config_mod.TEST_MNEMONIC,
            "test test test test test test test test test test test junk",
        )


class StructureTest(unittest.TestCase):
    def test_delete_never_depends_on_hosts_file(self):
        source = Path(__file__).resolve().parent.parent.joinpath("delete.py").read_text()
        self.assertNotIn("HOSTS_FILE", source)
        self.assertNotIn("open(", source)

    def test_remote_check_hardcodes_the_public_addresses(self):
        """check.py 必须独立硬编码公开已知地址，不能从服务端读回来当期望值，
        否则断言就是自证。"""
        source = Path(__file__).resolve().parent.parent.joinpath("remote/check.py").read_text()
        self.assertIn("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", source)


if __name__ == "__main__":
    unittest.main()
