#!/bin/bash
# tee-web3-accounts cloudtest 编排器。
#
#   ./run.sh                    全流程：create → test → delete
#   ./run.sh build              交叉编译 linux/amd64 静态二进制
#   ./run.sh create             收敛基础设施 + 起实例 + 写 hosts.json
#   ./run.sh test               上传、跑远端套件、把日志与结果拉回本地并独立验签
#   ./run.sh delete             按标签终止实例（从不读 hosts.json）
#   ./run.sh delete --dry-run   只列出匹配的实例，不删
#   ./run.sh delete-infra       拆掉带标签的**网络基础设施**（少用，见 delete_infra.py）
#   ./run.sh delete-infra --dry-run  列出会拆掉什么
#
# 每一步都写进 logs/<时间戳>/；测试失败也会清理机器，除非 KEEP_INSTANCE=true。
set -u
set -o pipefail
cd "$(dirname "$0")"
# shellcheck disable=SC1091
. ./lib.sh

load_env
setup_logs
log "cloudtest 开始（user=${TEE_ACCOUNTS_USER}, region=${TEE_ACCOUNTS_REGION:-eu-west-1}）"

cmd="${1:-all}"

build() {
  local out="bin"
  mkdir -p "$out"
  log "交叉编译 linux/amd64 静态二进制"
  # cloudtest 就在仓库根目录下，所以仓库根是 ..
  (cd .. && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o "cloudtest/$out/tee" ./cmd/tee) \
    || { log "编译失败"; exit 1; }
  log "已编译: $(ls "$out")"
}

create() {
  log "步骤: create"
  "$PY" create.py | tee -a "$LOG_DIR/run.log"
}

# verify_signature 用本地的 Go 侧代码对远端产出的签名做真正的密码学验签。
# 实例上只做格式与确定性检查，因为那里没有 secp256k1 库。
verify_signature() {
  local artifact="$LOG_DIR/tee-accounts-results/signature.json"
  if [ ! -f "$artifact" ]; then
    log "没有拉回 signature.json，跳过本地验签"
    return 1
  fi
  log "步骤: 本地独立验签"
  (cd .. && TEE_CLOUDTEST_SIGNATURE="$artifact" \
    go test ./internal/e2e/ -run TestVerifyPulledSignature -count=1 -v) \
    | tee -a "$LOG_DIR/run.log"
}

test() {
  [ -f "$HOSTS_FILE" ] || { log "没有 $HOSTS_FILE；先执行 ./run.sh create"; exit 1; }
  local ip rem
  ip="$(host_field public_ip)"
  log "步骤: test（实例 $ip）"
  [ -x bin/tee ] || build

  log "等待 $ip 的 ssh"
  wait_ssh "$ip" || { log "ssh 连不上 $ip"; exit 1; }
  # SEV-SNP 实例启动较慢：端口可能已经接受 TCP 连接但 sshd 还没起来，第一次
  # banner 交互也可能超时。用真实命令探测（最多约 5 分钟），别让套件败在启动竞态上。
  for _ in $(seq 1 60); do
    remote_exec "$ip" true 2>/dev/null && break
    sleep 5
  done
  remote_exec "$ip" true || { log "ssh 始终没有响应"; exit 1; }

  remote_exec "$ip" "command -v rsync >/dev/null || sudo apt-get install -y -qq rsync" \
    || { log "无法在 $ip 上准备 rsync"; exit 1; }
  rem="$(remote_exec "$ip" 'echo $HOME' | tr -d '\r')"
  [ -n "$rem" ] || { log "拿不到远端 HOME"; exit 1; }

  log "上传二进制与远端脚本"
  remote_exec "$ip" "mkdir -p $rem/tee-accounts-test"
  remote_push "$ip" bin/tee            "$rem/tee-accounts-test/tee"
  remote_push "$ip" remote/run-all.sh  "$rem/tee-accounts-test/run-all.sh"
  remote_push "$ip" remote/check.py    "$rem/tee-accounts-test/check.py"
  remote_exec "$ip" "chmod +x $rem/tee-accounts-test/tee $rem/tee-accounts-test/run-all.sh"

  # 助记词由 config.py 统一提供（公开的测试助记词），不让它散落在多个脚本里。
  local mnemonic
  mnemonic="$("$PY" -c 'import config; print(config.TEST_MNEMONIC)')"

  log "在实例上跑远端套件"
  local remote_status=0
  remote_exec "$ip" "TEE_TEST_MNEMONIC='$mnemonic' bash $rem/tee-accounts-test/run-all.sh" \
    | tee "$LOG_DIR/remote.log" || remote_status=1

  log "把结果拉回本地"
  remote_pull "$ip" "$rem/tee-accounts-results.tar.gz" "$LOG_DIR/results.tar.gz"
  (cd "$LOG_DIR" && tar xzf results.tar.gz && rm -f results.tar.gz)
  log "结果保存在 $LOG_DIR"

  [ "$remote_status" -eq 0 ] || { log "远端套件失败（见 $LOG_DIR/remote.log）"; return 1; }
  verify_signature || { log "本地验签失败"; return 1; }
  return 0
}

delete() { # delete [--dry-run]
  log "步骤: delete"
  "$PY" delete.py "$@" | tee -a "$LOG_DIR/run.log"
}

delete_infra() { # delete_infra [--dry-run]
  log "步骤: delete-infra（网络基础设施拆除，少用的破坏性操作）"
  "$PY" delete_infra.py "$@" | tee -a "$LOG_DIR/run.log"
}

# 全流程的自动清理：如果已经起了实例，但运行被中断（Ctrl-C、崩溃、ssh 卡住），
# 就把这一轮留下的机器终止掉，避免持续计费。KEEP_INSTANCE=true 时跳过；显式
# delete 已经跑过时也跳过，防止重复终止。
cleanup() {
  local rc=$?
  if [ "${KEEP_INSTANCE:-false}" != "true" ] && [ "${INSTANCES_DELETED:-0}" != "1" ]; then
    log "cleanup: 终止本轮留下的实例"
    delete || true
  fi
  exit "$rc"
}

status=0
case "$cmd" in
  build) build; status=$? ;;
  create) create; status=$? ;;
  test) test; status=$? ;;
  delete) shift; delete "$@"; status=$? ;;
  all|"")
    trap cleanup EXIT INT TERM
    # create 失败也可能留下刚建好的脚手架（VPC / 安全组 / 密钥对），一并拆掉，
    # 绝不留半成品基础设施。
    create || { log "CREATE 失败（见 $LOG_DIR）"; delete_infra || true; exit 1; }
    test || { log "TEST 失败（见 $LOG_DIR）"; status=1; }
    if [ "${KEEP_INSTANCE:-false}" = "true" ]; then
      log "KEEP_INSTANCE=true: 跳过 delete"
    else
      if delete; then
        INSTANCES_DELETED=1
      else
        log "DELETE 失败（见 $LOG_DIR）"; status=1
      fi
    fi
    ;;
  delete-infra) shift; delete_infra "$@"; status=$? ;;
  *) echo "用法: $0 [build|create|test|delete|delete --dry-run|delete-infra|delete-infra --dry-run|all]"; exit 1 ;;
esac

log "结束；日志在 $LOG_DIR"
exit "$status"
