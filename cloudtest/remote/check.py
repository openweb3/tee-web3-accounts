#!/usr/bin/env python3
"""cloudtest 的接口与数据审计（在实例上跑，只用标准库）。

对 127.0.0.1 上的服务打完整业务流，逐条断言，并把原始响应留给本地复核：
签名本身不在这里做密码学验证（实例上没有 secp256k1 库），而是连同哈希和期望地址
一起写进 signature.json，由本地编排器用 Go 侧的 wallet.RecoverAddress 独立验签。

    python3 check.py --base-url http://127.0.0.1:8080 \
        --data-file <accounts.json> --log-file <tee.log> --results <dir>
"""

import argparse
import json
import os
import stat
import sys
import urllib.error
import urllib.request

# 测试助记词在 m/44'/60'/0'/0/{i} 下的公开已知地址（Hardhat / Anvil 默认账户）。
EXPECTED_ADDRESSES = [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
]

PASSWORD = "correct horse battery staple"
HASH = "0x" + "11" * 32

# 账户库文件允许出现的字段名（精确集合，多一个都不行）。
FILE_KEYS = {"version", "next_index", "accounts"}
ACCOUNT_KEYS = {"index", "address", "password_hash", "created_at"}
HASH_KEYS = {"algorithm", "time", "memory_kib", "threads", "salt", "key"}
FORBIDDEN_SUBSTRINGS = ("priv", "secret", "mnemonic", "seed")

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"    ok: {message}")
    else:
        print(f"    FAIL: {message}")
        failures.append(message)


def call(base_url: str, method: str, path: str, body: dict | None = None):
    """发一次请求，返回 (状态码, 解析后的 JSON 或原始文本)。"""
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        status = exc.code
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def save(results: str, name: str, payload) -> None:
    path = os.path.join(results, name)
    with open(path, "w") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--data-file", required=True)
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--mnemonic-file", required=True)
    parser.add_argument("--results", required=True)
    args = parser.parse_args()

    # --- 接口 ---
    print("==> 健康检查")
    status, payload = call(args.base_url, "GET", "/healthz")
    check(status == 200 and payload == {"status": "ok"}, f"/healthz 返回 200 {payload}")
    save(args.results, "healthz.json", payload)

    print("==> 创建账户")
    status, created = call(args.base_url, "POST", "/v1/accounts", {"password": PASSWORD})
    check(status == 201, f"创建账户状态码 201（实际 {status}）")
    check(created.get("index") == 0, f"首个账户索引为 0（实际 {created.get('index')}）")
    check(
        created.get("address") == EXPECTED_ADDRESSES[0],
        f"索引 0 的地址等于公开已知值（实际 {created.get('address')}）",
    )
    check(
        created.get("path") == "m/44'/60'/0'/0/0",
        f"返回的派生路径正确（实际 {created.get('path')}）",
    )
    check(
        set(created) == {"index", "path", "address"},
        f"创建响应恰好只有 index/path/address（实际 {sorted(created)}）",
    )
    save(args.results, "create.json", {"status": status, "body": created})

    print("==> 查询地址")
    status, fetched = call(args.base_url, "GET", "/v1/accounts/0")
    check(status == 200, f"查询状态码 200（实际 {status}）")
    check(
        fetched.get("address") == EXPECTED_ADDRESSES[0],
        "查询返回的地址与创建时一致",
    )
    save(args.results, "get.json", {"status": status, "body": fetched})

    status, _ = call(args.base_url, "GET", "/v1/accounts/7")
    check(status == 404, f"越界索引返回 404（实际 {status}）")

    print("==> 签名")
    status, signed = call(
        args.base_url,
        "POST",
        "/v1/sign",
        {"index": 0, "password": PASSWORD, "hash": HASH},
    )
    check(status == 200, f"签名状态码 200（实际 {status}）")
    signature = signed.get("signature", "")
    check(
        isinstance(signature, str)
        and signature.startswith("0x")
        and len(signature) == 132,
        f"签名是 0x + 130 位十六进制（实际长度 {len(signature)}）",
    )
    check(
        signature == signature.lower(),
        "签名使用小写十六进制",
    )
    check(
        signed.get("address") == EXPECTED_ADDRESSES[0],
        f"签名响应的地址正确（实际 {signed.get('address')}）",
    )
    check(signed.get("hash") == HASH, "签名响应回显了同一个哈希")
    if len(signature) == 132:
        recovery = int(signature[-2:], 16)
        check(recovery in (27, 28), f"v 是 27/28（实际 {recovery}）")
    save(args.results, "sign.json", {"status": status, "body": signed})

    print("==> 签名确定性")
    _, again = call(
        args.base_url,
        "POST",
        "/v1/sign",
        {"index": 0, "password": PASSWORD, "hash": HASH},
    )
    check(again.get("signature") == signature, "同输入两次签名结果一致（RFC 6979）")

    print("==> 密码与索引的失败路径")
    wrong_password = call(
        args.base_url,
        "POST",
        "/v1/sign",
        {"index": 0, "password": "definitely-wrong", "hash": HASH},
    )
    check(wrong_password[0] == 401, f"密码错误返回 401（实际 {wrong_password[0]}）")

    missing_index = call(
        args.base_url,
        "POST",
        "/v1/sign",
        {"index": 9, "password": "definitely-wrong", "hash": HASH},
    )
    check(missing_index[0] == 401, f"索引不存在返回 401（实际 {missing_index[0]}）")
    check(
        wrong_password[1] == missing_index[1],
        "「密码错误」与「索引不存在」的响应体完全相同，不泄露索引是否存在",
    )
    save(
        args.results,
        "failure-auth.json",
        {"wrong_password": wrong_password, "missing_index": missing_index},
    )

    # --- 数据审计 ---
    print("==> 账户库审计")
    mode = stat.S_IMODE(os.stat(args.data_file).st_mode)
    check(mode == 0o600, f"账户库权限是 0600（实际 {oct(mode)}）")

    with open(args.data_file) as handle:
        raw = handle.read()
    store = json.loads(raw)
    check(set(store) == FILE_KEYS, f"账户库顶层字段恰好是 {sorted(FILE_KEYS)}（实际 {sorted(store)}）")
    check(store.get("next_index") == 1, "next_index 与已创建账户数一致")
    check(len(store.get("accounts", [])) == 1, "只落了 1 个账户")

    for account in store.get("accounts", []):
        check(
            set(account) == ACCOUNT_KEYS,
            f"账户记录字段恰好是 {sorted(ACCOUNT_KEYS)}（实际 {sorted(account)}）",
        )
        check(
            set(account.get("password_hash", {})) == HASH_KEYS,
            "密码验证子字段符合预期",
        )
        check(
            not any(bad in json.dumps(account).lower() for bad in FORBIDDEN_SUBSTRINGS),
            "账户记录里没有 priv/secret/mnemonic/seed 之类的字段",
        )
        check(
            PASSWORD not in json.dumps(account),
            "账户库里没有明文密码",
        )
        check(
            account.get("password_hash", {}).get("algorithm") == "argon2id",
            "密码验证子用的是 argon2id",
        )

    # --- 日志审计 ---
    print("==> 日志审计")
    with open(args.log_file, errors="replace") as handle:
        server_log = handle.read()
    with open(args.mnemonic_file) as handle:
        mnemonic = handle.read().strip()
    check(mnemonic not in server_log, "服务日志里没有出现助记词")
    check("mnemonic" not in server_log.lower(), "服务日志里没有提到助记词字段名")
    check(PASSWORD not in server_log, "服务日志里没有出现密码")

    # 交给本地做密码学验签。
    save(
        args.results,
        "signature.json",
        {
            "index": 0,
            "hash": HASH,
            "address": signed.get("address"),
            "signature": signature,
            "expected_addresses": EXPECTED_ADDRESSES,
        },
    )

    print()
    if failures:
        print(f"==> {len(failures)} 项断言失败")
        return 1
    print("==> 全部断言通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
