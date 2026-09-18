#!/bin/bash
# cloudtest 套件，在实例上执行。
#
# 采集 TEE 证据、起服务、走完整业务流、审计落盘数据与日志，再验证「换错助记词 /
# 没配助记词 / 助记词校验和错误」三条启动护栏，最后把所有产物打包成
# ~/tee-accounts-results.tar.gz 让编排器拉回本地。
#
# 服务只在实例回环地址上监听；安全组只放行 22 端口。
set -u

cd "$HOME/tee-accounts-test" || exit 1

RESULTS="$HOME/tee-accounts-results"
WORK="$HOME/tee-accounts-work"
PORT="${TEE_ACCOUNTS_PORT:-8080}"
BASE="http://127.0.0.1:$PORT"
STATUS=0

rm -rf "$RESULTS" "$WORK"
mkdir -p "$RESULTS"
mkdir -p "$WORK"
chmod 700 "$WORK"

fail() {
  echo "!! $*"
  STATUS=1
}

if [ -z "${TEE_TEST_MNEMONIC:-}" ]; then
  echo "!! 缺少 TEE_TEST_MNEMONIC（由编排器从 cloudtest/config.py 传入）"
  exit 1
fi

echo "==> 采集 TEE 证据"
{
  echo "--- 内核 ---"
  uname -a
  echo
  echo "--- 虚拟化类型 ---"
  systemd-detect-virt 2>&1
  echo
  echo "--- CPU 的 sev 特性 ---"
  grep -o -m1 -E 'sev[a-z_]*' /proc/cpuinfo | sort -u || echo "(无)"
  echo
  echo "--- /dev/sev-guest ---"
  ls -l /dev/sev-guest 2>&1 || echo "(不存在)"
  echo
  echo "--- dmesg 里的 SEV/SNP/CCP 记录 ---"
  sudo dmesg 2>/dev/null | grep -i -E 'sev|snp|ccp' | head -60 || echo "(无)"
} >"$RESULTS/tee-evidence.txt" 2>&1
cat "$RESULTS/tee-evidence.txt"

echo "==> 安装系统依赖"
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null

# 助记词写进权限收紧的文件，走 TEE_MNEMONIC_FILE 而不是环境变量。
printf '%s' "$TEE_TEST_MNEMONIC" >"$WORK/mnemonic.txt"
chmod 400 "$WORK/mnemonic.txt"

echo "==> 启动服务（127.0.0.1:$PORT）"
TEE_MNEMONIC_FILE="$WORK/mnemonic.txt" \
  TEE_DATA_FILE="$WORK/accounts.json" \
  TEE_LISTEN_ADDR="127.0.0.1:$PORT" \
  ./tee >"$RESULTS/tee.log" 2>&1 &
TEE_PID=$!

READY=0
for _ in $(seq 1 100); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then READY=1; break; fi
  sleep 0.2
done
if [ "$READY" != "1" ]; then
  echo "!! 服务没能在 20s 内就绪:"
  cat "$RESULTS/tee.log"
  exit 1
fi

echo "==> 跑接口与数据审计"
python3 check.py \
  --base-url "$BASE" \
  --data-file "$WORK/accounts.json" \
  --log-file "$RESULTS/tee.log" \
  --mnemonic-file "$WORK/mnemonic.txt" \
  --results "$RESULTS" || fail "接口/数据审计断言失败"

echo "==> 关闭服务并确认优雅退出"
kill -TERM "$TEE_PID" 2>/dev/null
for _ in $(seq 1 50); do
  kill -0 "$TEE_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$TEE_PID" 2>/dev/null; then
  fail "服务没有响应 SIGTERM"
  kill -9 "$TEE_PID" 2>/dev/null
fi
grep -q "优雅关闭" "$RESULTS/tee.log" || fail "日志里没有优雅关闭的痕迹"

# --- 启动护栏：三条都必须拒绝启动 ---
echo "==> 护栏 1/3：换错助记词必须拒绝启动"
OTHER_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
printf '%s' "$OTHER_MNEMONIC" >"$WORK/mnemonic-other.txt"
chmod 400 "$WORK/mnemonic-other.txt"

TEE_MNEMONIC_FILE="$WORK/mnemonic-other.txt" \
  TEE_DATA_FILE="$WORK/accounts.json" \
  TEE_LISTEN_ADDR="127.0.0.1:$((PORT + 1))" \
  ./tee >"$RESULTS/guard-mismatch.log" 2>&1
GUARD_RC=$?
[ "$GUARD_RC" -ne 0 ] || fail "换了助记词竟然启动成功"
grep -q "助记词" "$RESULTS/guard-mismatch.log" || fail "护栏日志没有指出是助记词问题"

echo "==> 护栏 2/3：没配助记词必须拒绝启动"
env -u TEE_MNEMONIC -u TEE_MNEMONIC_FILE \
  TEE_DATA_FILE="$WORK/accounts-fresh.json" \
  TEE_LISTEN_ADDR="127.0.0.1:$((PORT + 2))" \
  ./tee >"$RESULTS/guard-missing.log" 2>&1
GUARD_RC=$?
[ "$GUARD_RC" -ne 0 ] || fail "没配助记词竟然启动成功"
grep -q "TEE_MNEMONIC" "$RESULTS/guard-missing.log" || fail "护栏日志没有指明缺少哪个配置"

echo "==> 护栏 3/3：助记词校验和错误必须拒绝启动"
BROKEN_MNEMONIC="${TEE_TEST_MNEMONIC%junk}zoo"
printf '%s' "$BROKEN_MNEMONIC" >"$WORK/mnemonic-broken.txt"
chmod 400 "$WORK/mnemonic-broken.txt"
TEE_MNEMONIC_FILE="$WORK/mnemonic-broken.txt" \
  TEE_DATA_FILE="$WORK/accounts-fresh.json" \
  TEE_LISTEN_ADDR="127.0.0.1:$((PORT + 3))" \
  ./tee >"$RESULTS/guard-checksum.log" 2>&1
GUARD_RC=$?
[ "$GUARD_RC" -ne 0 ] || fail "非法助记词竟然启动成功"
grep -q "校验和" "$RESULTS/guard-checksum.log" || fail "护栏日志没有指出是校验和问题"

echo "==> 打包结果"
cp "$WORK/accounts.json" "$RESULTS/accounts.json"
chmod 644 "$RESULTS"/*
tar czf "$HOME/tee-accounts-results.tar.gz" -C "$HOME" tee-accounts-results

if [ "$STATUS" -eq 0 ]; then
  echo "==> 远端套件全部通过"
else
  echo "==> 远端套件有失败项"
fi
exit "$STATUS"
