#!/usr/bin/env bash
# 以实机模式启动 Wraith（必须由 root 运行）
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${WRAITH_PORT:-8787}"
HOST="${WRAITH_HOST:-127.0.0.1}"
IFACE="${WRAITH_IFACE:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "  [!] 实机模式需要 root，请使用：sudo -E $0" >&2
  exit 1
fi

if [[ -x .venv/bin/python ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$(command -v python3)"
fi

echo
echo "  Wraith · 实机模式（会发送真实无线帧）"
echo "  控制台：http://${HOST}:${PORT}"
echo "  启动后请在「设置 → 授权门禁」输入 AUTHORIZED 完成授权"
echo

ARGS=(-m wraith web --live --host "$HOST" --port "$PORT" --open)
if [[ -n "$IFACE" ]]; then
  ARGS+=(--iface "$IFACE")
fi

exec "$PY" "${ARGS[@]}" "$@"
