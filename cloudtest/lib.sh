#!/bin/bash
# cloudtest 编排器的公共函数。由 run.sh source。
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS_FILE="$SCRIPT_DIR/hosts.json"
LOG_DIR=""

# 优先用项目自带的 venv（./setup.sh 创建），这样 Python 步骤一定有 boto3，
# 不受 PATH 上是哪个解释器影响；没有就退回 python3。
if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
  PY="$SCRIPT_DIR/.venv/bin/python3"
else
  PY=python3
fi

load_env() {
  if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/.env"
    set +a
  fi
  if [ -z "${TEE_ACCOUNTS_USER:-}" ]; then
    echo "error: TEE_ACCOUNTS_USER 是必填项（填一个只属于你的唯一值）；拒绝运行" >&2
    exit 1
  fi
}

setup_logs() {
  LOG_DIR="$SCRIPT_DIR/logs/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$LOG_DIR"
}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_DIR/run.log"; }

host_field() { # host_field public_ip
  "$PY" -c "import json; print(json.load(open('$HOSTS_FILE'))['$1'])"
}

wait_ssh() { # wait_ssh ip [attempts]
  local ip="$1" tries="${2:-120}"
  for _ in $(seq 1 "$tries"); do
    (echo > "/dev/tcp/$ip/22") 2>/dev/null && return 0
    sleep 2
  done
  return 1
}

SSH_OPTS=(-i "$SCRIPT_DIR/ssh-key.pem" -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR)

# 上传优先用较新的 rsync：macOS 自带 openrsync（rsync 2.6.9 协议）只支持 -z，
# 而 Homebrew rsync 3.x 与远端 Ubuntu 24.04 的 rsync(3.2) 都支持协议 31+，
# -zz（zstd）压缩更快更好。拿不到就退回 -z。
RSYNC=rsync
for cand in /opt/homebrew/bin/rsync /usr/local/bin/rsync rsync; do
  if command -v "$cand" >/dev/null 2>&1; then RSYNC="$cand"; break; fi
done
if "$RSYNC" --version 2>/dev/null | grep -q 'protocol version 3[0-9]'; then
  RSYNC_COMPRESS=(-zz)
else
  RSYNC_COMPRESS=(-z)
fi

remote_exec() { # remote_exec ip command...
  local ip="$1"; shift
  ssh "${SSH_OPTS[@]}" "ubuntu@$ip" "$@"
}

remote_push() { # remote_push ip local remote
  "$RSYNC" -av "${RSYNC_COMPRESS[@]}" --progress \
    -e "ssh ${SSH_OPTS[*]}" "$2" "ubuntu@$1:$3" || exit 1
}

remote_pull() { # remote_pull ip remote local
  "$RSYNC" -av "${RSYNC_COMPRESS[@]}" --progress \
    -e "ssh ${SSH_OPTS[*]}" "ubuntu@$1:$2" "$3" || exit 1
}
