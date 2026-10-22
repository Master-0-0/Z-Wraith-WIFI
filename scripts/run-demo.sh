#!/usr/bin/env bash
# 以演示模式启动 Wraith（无需 root、无需无线网卡）
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${WRAITH_PORT:-8787}"
HOST="${WRAITH_HOST:-127.0.0.1}"

if [[ -x .venv/bin/python ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

echo
echo "  Wraith · 演示模式"
echo "  控制台：http://${HOST}:${PORT}"
echo "  API 文档：http://${HOST}:${PORT}/docs"
echo "  仅限授权测试"
echo

exec "$PY" -m wraith web --demo --host "$HOST" --port "$PORT" --open "$@"
