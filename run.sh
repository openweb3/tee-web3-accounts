#!/usr/bin/env bash
# tee-web3-accounts 的构建 / 测试 / 本地开发入口。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${ROOT}/bin/tee"
LINUX_BIN="${ROOT}/bin/tee.linux-amd64"

# 本地开发专用的测试助记词（Hardhat 的公开助记词，人人皆知，绝不可用于生产）。
# 生产环境必须用 TEE_MNEMONIC_FILE 指向一个权限收紧的真实助记词文件。
DEV_MNEMONIC="${DEV_MNEMONIC:-test test test test test test test test test test test junk}"

usage() {
	cat <<'EOF'
用法: ./run.sh <命令>

  build        编译本机平台的二进制到 bin/tee
  build-linux  交叉编译 linux/amd64 静态二进制到 bin/tee.linux-amd64（给 cloudtest 用）
  test         go vet + go test ./...
  e2e          只跑端到端测试（编译真实二进制、起进程、打全套接口）
  dev          用测试助记词在本地前台起服务
  fmt          gofmt 格式化全部包
EOF
}

cmd_build() {
	mkdir -p "${ROOT}/bin"
	go build -trimpath -ldflags "-s -w" -o "${BIN}" ./cmd/tee
	echo "已编译: ${BIN}"
}

cmd_build_linux() {
	mkdir -p "${ROOT}/bin"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags "-s -w" -o "${LINUX_BIN}" ./cmd/tee
	echo "已编译: ${LINUX_BIN}（静态链接，可直接拷进 TEE 实例）"
}

cmd_test() {
	go vet ./...
	go test ./...
}

cmd_e2e() {
	go test ./internal/e2e/ -v
}

cmd_dev() {
	cmd_build
	export TEE_MNEMONIC="${TEE_MNEMONIC:-${DEV_MNEMONIC}}"
	export TEE_DATA_FILE="${TEE_DATA_FILE:-${ROOT}/data/accounts.json}"
	export TEE_LISTEN_ADDR="${TEE_LISTEN_ADDR:-127.0.0.1:8080}"
	echo "TEE_DATA_FILE=${TEE_DATA_FILE}"
	echo "TEE_LISTEN_ADDR=${TEE_LISTEN_ADDR}"
	exec "${BIN}"
}

case "${1:-}" in
build) cmd_build ;;
build-linux) cmd_build_linux ;;
test) cmd_test ;;
e2e) cmd_e2e ;;
dev) cmd_dev ;;
fmt) go fmt ./... ;;
*) usage; exit 1 ;;
esac
