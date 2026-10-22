#!/usr/bin/env bash
# 重启 Wraith 实机 Web 服务（需要 root；会先停止 8787 上的旧进程）
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ROOT="/home/kali/桌面/ wifi"
cd "$ROOT"

PORT="${WRAITH_PORT:-8787}"
IFACE="${WRAITH_IFACE:-wlan0}"
PY="$ROOT/.venv/bin/python"
LOG="$ROOT/data/run/web.log"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "需要 root：请用 sudo $0" >&2
  exit 1
fi

mkdir -p "$ROOT/data/run"

mapfile -t pids < <(pgrep -f "python -m wraith web .*--port ${PORT}" || true)
if ((${#pids[@]})); then
  echo "停止旧服务：${pids[*]}"
  kill "${pids[@]}" 2>/dev/null || true
  for _ in $(seq 1 40); do
    ss -ltn 2>/dev/null | grep -q ":${PORT} " || break
    sleep 0.25
  done
fi

if ss -ltn 2>/dev/null | grep -q ":${PORT} "; then
  echo "端口 ${PORT} 仍被占用，未启动新服务" >&2
  exit 1
fi

setsid nohup "$PY" -m wraith web --live --port "$PORT" --iface "$IFACE" \
  >"$LOG" 2>&1 </dev/null &
echo "新服务 PID：$!"

for _ in $(seq 1 40); do
  if curl -fsS -m 1 "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
    echo "服务已就绪：http://127.0.0.1:${PORT}/"
    exit 0
  fi
  sleep 0.25
done

echo "健康检查失败，请查看 $LOG" >&2
exit 1
