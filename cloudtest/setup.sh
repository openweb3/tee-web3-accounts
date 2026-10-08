#!/bin/bash
# 创建 cloudtest 的 venv 并装好 boto3（只需跑一次）：
#   ./setup.sh
set -eu
cd "$(dirname "$0")"
if [ ! -x ".venv/bin/python" ]; then
  python3 -m venv .venv
fi
# 有些基础解释器建出来的 venv 没有 pip，显式引导一次。
if [ ! -x ".venv/bin/pip" ] && [ ! -x ".venv/bin/pip3" ]; then
  .venv/bin/python -m ensurepip --default-pip >/dev/null
fi
.venv/bin/python -m pip install --quiet --upgrade boto3
echo "==> boto3 就绪: $("$PWD/.venv/bin/python" -c 'import boto3; print(boto3.__version__)')"
