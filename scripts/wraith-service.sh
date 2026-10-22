#!/usr/bin/env bash
# Wraith Web 服务管理脚本：启动 / 停止 / 重启 / 状态 / 日志
#
# 默认以后台方式启动演示模式，健康检查通过后返回。
# 实机模式必须由 root 运行，且启动后仍需在控制台完成授权。
#
# 状态文件：data/run/wraith-web.pid、data/run/wraith-web.state
# 日志文件：data/run/wraith-web.log
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "$ROOT" || exit 2

usage() {
  cat <<'EOF'
用法：
  ./scripts/wraith-service.sh start   [--demo|--live] [--host H] [--port P] [--iface IF] [--open] [--foreground]
  ./scripts/wraith-service.sh stop
  ./scripts/wraith-service.sh restart [同上]
  ./scripts/wraith-service.sh status
  ./scripts/wraith-service.sh logs    [--lines N]

命令：
  start    后台启动 Web 控制台（健康检查通过后返回）
  stop     停止后台服务（SIGTERM，超时后 SIGKILL）
  restart  重启（默认沿用上次的模式/地址/端口/网卡）
  status   查看运行状态（运行中返回 0，已停止返回 3）
  logs     跟踪日志（默认显示末尾 200 行）

选项：
  --demo            演示模式（默认，不需要 root）
  --live            实机模式（需要 root；启动后仍需在设置中授权）
  --host HOST       监听地址（默认 127.0.0.1）
  --port, -p PORT   监听端口（默认 8787）
  --iface, -i IF    无线网卡（实机模式）
  --open            启动后打开浏览器
  --foreground, -f  前台运行（仅 start/restart；Ctrl+C 退出）
  --lines, -n N     logs 显示的行数（默认 200）
  --timeout SEC     启动健康检查超时（默认 20 秒）
  -h, --help        显示帮助

环境变量：
  WRAITH_MODE / WRAITH_HOST / WRAITH_PORT / WRAITH_IFACE
  WRAITH_DATA_DIR / WRAITH_RUN_DIR / WRAITH_PIDFILE / WRAITH_STATE / WRAITH_LOG

默认路径：
  状态：data/run/wraith-web.pid、data/run/wraith-web.state
  日志：data/run/wraith-web.log

示例：
  ./scripts/wraith-service.sh start
  ./scripts/wraith-service.sh status
  sudo -E ./scripts/wraith-service.sh start --live --iface wlan0
  ./scripts/wraith-service.sh restart
  ./scripts/wraith-service.sh stop
EOF
}

# ---------------------------------------------------------------- 颜色
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_CYAN=""
fi

err()  { printf '%s[!]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }

# ---------------------------------------------------------------- 参数
COMMAND="${1:-}"
if [[ -z "$COMMAND" ]]; then
  usage >&2
  exit 2
fi
case "$COMMAND" in
  -h|--help) usage; exit 0 ;;
  start|stop|restart|status|logs) ;;
  *)
    err "未知命令：$COMMAND"
    usage >&2
    exit 2
    ;;
esac
shift

MODE="${WRAITH_MODE:-demo}"
HOST="${WRAITH_HOST:-127.0.0.1}"
PORT="${WRAITH_PORT:-8787}"
IFACE="${WRAITH_IFACE:-}"
MODE_SET=0
HOST_SET=0
PORT_SET=0
IFACE_SET=0
[[ -n "${WRAITH_MODE:-}" ]] && MODE_SET=1
[[ -n "${WRAITH_HOST:-}" ]] && HOST_SET=1
[[ -n "${WRAITH_PORT:-}" ]] && PORT_SET=1
[[ -n "${WRAITH_IFACE:-}" ]] && IFACE_SET=1

OPEN=0
FOREGROUND=0
START_TIMEOUT=20
STOP_TIMEOUT=15
LOG_LINES=200

while (($#)); do
  case "$1" in
    --demo) MODE="demo"; MODE_SET=1 ;;
    --live) MODE="live"; MODE_SET=1 ;;
    --mode) MODE="${2:-}"; MODE_SET=1; shift ;;
    --mode=*) MODE="${1#*=}"; MODE_SET=1 ;;
    --host) HOST="${2:-}"; HOST_SET=1; shift ;;
    --host=*) HOST="${1#*=}"; HOST_SET=1 ;;
    --port|-p) PORT="${2:-}"; PORT_SET=1; shift ;;
    --port=*) PORT="${1#*=}"; PORT_SET=1 ;;
    --iface|-i) IFACE="${2:-}"; IFACE_SET=1; shift ;;
    --iface=*) IFACE="${1#*=}"; IFACE_SET=1 ;;
    --open) OPEN=1 ;;
    --foreground|-f) FOREGROUND=1 ;;
    --lines|-n) LOG_LINES="${2:-}"; shift ;;
    --timeout) START_TIMEOUT="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      err "未知参数：$1"
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$MODE" != "demo" && "$MODE" != "live" ]]; then
  err "模式只能是 demo 或 live：$MODE"
  exit 2
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  err "端口无效：$PORT"
  exit 2
fi
if ! [[ "$START_TIMEOUT" =~ ^[0-9]+$ ]] || ((START_TIMEOUT < 1)); then
  err "启动超时无效：$START_TIMEOUT"
  exit 2
fi
if ! [[ "$LOG_LINES" =~ ^[0-9]+$ ]] || ((LOG_LINES < 1)); then
  err "日志行数无效：$LOG_LINES"
  exit 2
fi

# ---------------------------------------------------------------- 路径
DATA_DIR="${WRAITH_DATA_DIR:-$ROOT/data}"
RUN_DIR="${WRAITH_RUN_DIR:-$DATA_DIR/run}"
PID_FILE="${WRAITH_PIDFILE:-$RUN_DIR/wraith-web.pid}"
STATE_FILE="${WRAITH_STATE:-$RUN_DIR/wraith-web.state}"
LOG_FILE="${WRAITH_LOG:-$RUN_DIR/wraith-web.log}"
LOG_EXPLICIT=0
[[ -n "${WRAITH_LOG:-}" ]] && LOG_EXPLICIT=1

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi

has() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- 基础工具
health_host() {
  case "$1" in
    0.0.0.0|::|"[::]"|"") printf '127.0.0.1' ;;
    *:*) printf '[%s]' "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}

health_ok() {
  local host=$1 port=$2 url
  url="http://$(health_host "$host"):${port}/api/health"
  if has curl; then
    curl -fsS --max-time 2 "$url" >/dev/null 2>&1
    return $?
  fi
  if [[ -z "$PY" || ! -x "$PY" ]]; then
    return 1
  fi
  "$PY" - "$url" <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen(sys.argv[1], timeout=2) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

port_busy() {
  local port=$1
  if has ss; then
    ss -ltn 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p {found=1} END {exit(found ? 0 : 1)}'
    return $?
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null || return 1
  exec 3>&-
  return 0
}

is_wraith_pid() {
  local pid=$1 cmd
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  # 不依赖 kill -0：普通用户无法向 root 进程发信号，但 /proc 仍可读。
  [[ -d "/proc/$pid" ]] || return 1
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" || return 1
  [[ "$cmd" == *"wraith"* && "$cmd" == *"web"* ]]
}

# 成功时输出 PID；未运行返回 1；PID 文件不可读返回 2
running_pid() {
  local pid=""
  if [[ -e "$PID_FILE" && ! -r "$PID_FILE" ]]; then
    return 2
  fi
  if [[ -r "$PID_FILE" ]]; then
    IFS= read -r pid < "$PID_FILE" || true
  fi
  pid="${pid//[!0-9]/}"
  if [[ -n "$pid" ]] && is_wraith_pid "$pid"; then
    printf '%s' "$pid"
    return 0
  fi
  if [[ -n "$pid" || -e "$PID_FILE" ]]; then
    rm -f "$PID_FILE" 2>/dev/null || true
  fi
  return 1
}

state_get() {
  [[ -r "$STATE_FILE" ]] || return 0
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$STATE_FILE" 2>/dev/null
}

write_state() {
  local pid=$1
  {
    printf 'PID=%s\n' "$pid"
    printf 'MODE=%s\n' "$MODE"
    printf 'HOST=%s\n' "$HOST"
    printf 'PORT=%s\n' "$PORT"
    printf 'IFACE=%s\n' "$IFACE"
    printf 'LOG=%s\n' "$LOG_FILE"
    printf 'STARTED=%s\n' "$(date -Is 2>/dev/null || date)"
  } > "$STATE_FILE" 2>/dev/null || true
  chmod 600 "$STATE_FILE" 2>/dev/null || true
}

pid_arg() {
  local pid=$1 want=$2
  local -a argv=()
  mapfile -t argv < <(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null)
  local i
  for ((i = 0; i < ${#argv[@]}; i++)); do
    case "${argv[i]}" in
      --port|-p)
        if [[ "$want" == "port" ]]; then printf '%s' "${argv[i+1]:-}"; return 0; fi
        ;;
      --host)
        if [[ "$want" == "host" ]]; then printf '%s' "${argv[i+1]:-}"; return 0; fi
        ;;
      --iface|-i)
        if [[ "$want" == "iface" ]]; then printf '%s' "${argv[i+1]:-}"; return 0; fi
        ;;
      --demo)
        if [[ "$want" == "mode" ]]; then printf 'demo'; return 0; fi
        ;;
      --live)
        if [[ "$want" == "mode" ]]; then printf 'live'; return 0; fi
        ;;
    esac
  done
  return 0
}

pid_exe() {
  local pid=$1
  local -a argv=()
  mapfile -d '' -t argv < "/proc/$pid/cmdline" 2>/dev/null || return 0
  printf '%s' "${argv[0]:-}"
}

# 查找不由本脚本管理（没有 PID 文件）的 Wraith Web 实例；按端口匹配。
find_unmanaged_pid() {
  local want_port=$1 pid cmd port exe
  has pgrep || return 1
  while read -r pid cmd; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    is_wraith_pid "$pid" || continue
    # 只接受 python -m wraith web / .../wraith web，避免误伤 grep 或 shell 包装进程。
    exe="$(pid_exe "$pid")"
    [[ "$exe" == *python* || "$exe" == *wraith || "$exe" == */env ]] || continue
    [[ "$cmd" == *" -m wraith web"* || "$cmd" == *"/wraith web"* ]] || continue
    port="$(pid_arg "$pid" port)"
    [[ -z "$port" ]] && port=8787
    if [[ "$port" == "$want_port" ]]; then
      printf '%s' "$pid"
      return 0
    fi
  done < <(pgrep -af -- "wraith web" 2>/dev/null || true)
  return 1
}

# ---------------------------------------------------------------- 启动前检查
prepare_runtime() {
  if ! mkdir -p "$RUN_DIR" 2>/dev/null; then
    err "无法创建运行目录：$RUN_DIR"
    return 1
  fi
  if [[ ! -w "$RUN_DIR" ]]; then
    err "运行目录不可写：$RUN_DIR（检查权限，或使用 sudo）"
    return 1
  fi
  return 0
}

resolve_log_for_start() {
  if [[ -e "$LOG_FILE" && ! -w "$LOG_FILE" ]]; then
    if ((LOG_EXPLICIT)); then
      err "日志文件不可写：$LOG_FILE"
      err "请改用可写路径：WRAITH_LOG=/path/to/web.log $0 start"
      return 1
    fi
    local alt="$RUN_DIR/wraith-web-$(id -un).log"
    warn "默认日志不可写，改用：$alt"
    LOG_FILE="$alt"
  fi
  if [[ -e "$LOG_FILE" && ! -w "$LOG_FILE" ]]; then
    err "日志文件不可写：$LOG_FILE"
    err "请检查目录权限，或用 WRAITH_LOG 指定可写文件"
    return 1
  fi
  return 0
}

preflight_start() {
  if [[ -z "$PY" || ! -x "$PY" ]]; then
    err "未找到 Python 解释器；请先运行 ./install.sh"
    return 1
  fi
  if ! "$PY" -c 'import wraith' >/dev/null 2>&1; then
    err "无法导入 wraith；请先运行 ./install.sh 或 $PY -m pip install -e ."
    return 1
  fi
  if ! "$PY" -c 'import fastapi, uvicorn, jinja2, pydantic, httpx' >/dev/null 2>&1; then
    err "Python 依赖不完整；请运行 ./scripts/check-deps.sh 或 $PY -m pip install -e ."
    return 1
  fi

  if [[ "$MODE" == "live" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
      err "实机模式需要 root：sudo -E $0 start --live [--iface wlan0]"
      return 1
    fi
    if [[ -n "$IFACE" && ! -d "/sys/class/net/$IFACE" ]]; then
      err "无线网卡不存在：$IFACE"
      return 1
    fi
  else
    if [[ "$(id -u)" -eq 0 ]]; then
      warn "演示模式不需要 root；以 root 运行会在 data/ 下生成 root 所有的文件"
    fi
  fi

  if [[ -e "$PID_FILE" && ! -r "$PID_FILE" ]]; then
    err "PID 文件不可读（可能由其他用户创建）：$PID_FILE"
    err "请尝试：sudo -E $0 $COMMAND"
    return 1
  fi
  if [[ -e "$LOG_FILE" && ! -w "$LOG_FILE" ]]; then
    err "日志文件不可写（可能由其他用户创建）：$LOG_FILE"
    err "请尝试：sudo -E $0 $COMMAND，或设置 WRAITH_LOG 指向可写文件"
    return 1
  fi
  return 0
}

rotate_log() {
  [[ -f "$LOG_FILE" ]] || return 0
  local size
  size="$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)"
  if [[ "$size" =~ ^[0-9]+$ ]] && ((size > 10485760)); then
    mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  fi
}

print_runtime() {
  local hh
  hh="$(health_host "$HOST")"
  printf '  模式：%s\n' "$MODE"
  printf '  地址：%s\n' "${C_CYAN}http://${hh}:${PORT}/${C_RESET}"
  printf '  API 文档：http://%s:%s/docs\n' "$hh" "$PORT"
  printf '  日志：%s\n' "$LOG_FILE"
  printf '  停止：%s stop\n' "$0"
  if [[ "$MODE" == "live" ]]; then
    printf '  %s授权：打开控制台 → 设置 → 授权门禁，输入 AUTHORIZED%s\n' "$C_YELLOW" "$C_RESET"
  fi
}

# ---------------------------------------------------------------- 命令实现
start_service() {
  if ! prepare_runtime; then
    return 1
  fi

  local pid rc
  if pid="$(running_pid)"; then
    info "Wraith 已在运行（PID $pid），不重复启动"
    print_runtime
    return 0
  else
    rc=$?
    if ((rc == 2)); then
      err "PID 文件不可读（可能由其他用户创建）：$PID_FILE"
      err "请尝试：sudo -E $0 start"
      return 1
    fi
  fi

  local unmanaged
  if port_busy "$PORT"; then
    unmanaged="$(find_unmanaged_pid "$PORT")"
    if [[ -n "$unmanaged" ]]; then
      info "端口 $PORT 上已有 Wraith 实例（PID $unmanaged，未托管），不重复启动"
      local m h
      m="$(pid_arg "$unmanaged" mode)"
      [[ -n "$m" ]] && MODE="$m"
      h="$(pid_arg "$unmanaged" host)"
      [[ -n "$h" ]] && HOST="$h"
      printf '  模式：%s\n' "$MODE"
      printf '  地址：http://%s:%s/\n' "$(health_host "$HOST")" "$PORT"
      printf '  提示：该实例可能由其他方式启动；stop 可按端口停止，或用 --port 启动其他实例\n'
      return 0
    fi
    err "端口 $PORT 已被占用，无法启动"
    if has ss; then
      ss -ltnp 2>/dev/null | awk -v p=":${PORT}\$" '$4 ~ p' >&2 || true
    fi
    return 1
  fi

  if ! resolve_log_for_start; then
    return 1
  fi
  if ! preflight_start; then
    return 1
  fi

  local -a args=(-m wraith web --host "$HOST" --port "$PORT")
  if [[ "$MODE" == "live" ]]; then
    args+=(--live)
  else
    args+=(--demo)
  fi
  [[ -n "$IFACE" ]] && args+=(--iface "$IFACE")
  ((OPEN)) && args+=(--open)

  if ((FOREGROUND)); then
    info "前台启动 Wraith（$MODE 模式）..."
    print_runtime
    exec "$PY" "${args[@]}"
  fi

  rotate_log
  info "后台启动 Wraith（$MODE 模式）..."
  nohup "$PY" "${args[@]}" >> "$LOG_FILE" 2>&1 < /dev/null &
  pid=$!
  printf '%s\n' "$pid" > "$PID_FILE"
  chmod 600 "$PID_FILE" 2>/dev/null || true
  write_state "$pid"

  local i
  for ((i = 0; i < START_TIMEOUT * 4; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      err "服务进程已退出，启动失败。日志末尾："
      tail -n 30 "$LOG_FILE" >&2 2>/dev/null || true
      rm -f "$PID_FILE" "$STATE_FILE"
      return 1
    fi
    if health_ok "$HOST" "$PORT"; then
      ok "Wraith 已启动（PID $pid）"
      print_runtime
      return 0
    fi
    sleep 0.25
  done

  err "健康检查超时（${START_TIMEOUT}s）。日志末尾："
  tail -n 30 "$LOG_FILE" >&2 2>/dev/null || true
  kill -TERM "$pid" 2>/dev/null || true
  sleep 1
  kill -KILL "$pid" 2>/dev/null || true
  rm -f "$PID_FILE" "$STATE_FILE"
  return 1
}

stop_service() {
  local quiet=${1:-0}
  local pid rc unmanaged=0 state_port
  if ! pid="$(running_pid)"; then
    rc=$?
    if ((rc == 2)); then
      err "PID 文件不可读（可能由其他用户创建）：$PID_FILE"
      err "请尝试：sudo -E $0 stop"
      return 1
    fi
    state_port="$(state_get PORT)"
    [[ -z "$state_port" ]] && state_port="$PORT"
    pid="$(find_unmanaged_pid "$state_port")"
    if [[ -z "$pid" && "$state_port" != "$PORT" ]]; then
      pid="$(find_unmanaged_pid "$PORT")"
    fi
    if [[ -z "$pid" ]]; then
      ((quiet)) || info "Wraith 未运行"
      return 0
    fi
    unmanaged=1
    ((quiet)) || info "未找到 PID 文件，按端口找到 Wraith 实例（PID $pid，未托管）..."
  fi

  local mode
  mode="$(pid_arg "$pid" mode)"
  if (( ! unmanaged )); then
    [[ -z "$mode" ]] && mode="$(state_get MODE)"
  fi
  ((quiet)) || info "停止 Wraith（PID $pid${mode:+，$mode 模式}）..."

  if ! kill -TERM "$pid" 2>/dev/null; then
    err "无法向 PID $pid 发送 SIGTERM（权限不足？请用 sudo 运行）"
    return 1
  fi

  local i
  for ((i = 0; i < STOP_TIMEOUT * 4; i++)); do
    is_wraith_pid "$pid" || break
    sleep 0.25
  done

  if is_wraith_pid "$pid"; then
    warn "进程未在 ${STOP_TIMEOUT}s 内退出，发送 SIGKILL"
    kill -KILL "$pid" 2>/dev/null || true
    for ((i = 0; i < 8; i++)); do
      is_wraith_pid "$pid" || break
      sleep 0.25
    done
  fi

  # 保留 state 文件作为「上次运行」信息，便于 stop 后查看日志路径。
  rm -f "$PID_FILE"
  ((quiet)) || ok "Wraith 已停止"
  return 0
}

print_running_status() {
  local pid=$1 managed=${2:-1}
  local mode host port iface started uptime hh state_log
  if ((managed)); then
    state_log="$(state_get LOG)"
    if (( ! LOG_EXPLICIT )) && [[ -n "$state_log" ]]; then
      LOG_FILE="$state_log"
    fi
    mode="$(pid_arg "$pid" mode)"
    [[ -z "$mode" ]] && mode="$(state_get MODE)"
    [[ -z "$mode" ]] && mode="未知"
    host="$(pid_arg "$pid" host)"
    [[ -z "$host" ]] && host="$(state_get HOST)"
    [[ -z "$host" ]] && host="127.0.0.1"
    port="$(pid_arg "$pid" port)"
    [[ -z "$port" ]] && port="$(state_get PORT)"
    [[ -z "$port" ]] && port="8787"
    iface="$(pid_arg "$pid" iface)"
    [[ -z "$iface" ]] && iface="$(state_get IFACE)"
    started="$(state_get STARTED)"
  else
    mode="$(pid_arg "$pid" mode)"
    [[ -z "$mode" ]] && mode="未知"
    host="$(pid_arg "$pid" host)"
    [[ -z "$host" ]] && host="127.0.0.1"
    port="$(pid_arg "$pid" port)"
    [[ -z "$port" ]] && port="8787"
    iface="$(pid_arg "$pid" iface)"
    started=""
  fi
  uptime="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')"
  hh="$(health_host "$host")"

  if ((managed)); then
    printf 'Wraith 服务：%s运行中%s（PID %s）\n' "$C_GREEN" "$C_RESET" "$pid"
  else
    printf 'Wraith 服务：%s运行中%s（PID %s，未由本脚本管理）\n' "$C_GREEN" "$C_RESET" "$pid"
  fi
  printf '  模式：%s\n' "$mode"
  printf '  地址：%s\n' "${C_CYAN}http://${hh}:${port}/${C_RESET}"
  [[ -n "$iface" ]] && printf '  网卡：%s\n' "$iface"
  [[ -n "$uptime" ]] && printf '  运行时长：%s\n' "$uptime"
  [[ -n "$started" ]] && printf '  启动时间：%s\n' "$started"

  if health_ok "$host" "$port"; then
    printf '  健康检查：%s正常%s\n' "$C_GREEN" "$C_RESET"
  else
    printf '  健康检查：%s无响应%s\n' "$C_YELLOW" "$C_RESET"
  fi
  if ((managed)); then
    printf '  日志：%s\n' "$LOG_FILE"
  else
    printf '  日志：未托管（由其他方式启动）\n'
  fi
  return 0
}

status_service() {
  local pid rc
  if pid="$(running_pid)"; then
    print_running_status "$pid" 1
    return 0
  else
    rc=$?
  fi
  if ((rc == 2)); then
    err "PID 文件不可读（可能由其他用户创建）：$PID_FILE"
    err "请尝试：sudo -E $0 status"
    return 1
  fi

  local last_log last_port unmanaged
  last_log="$(state_get LOG)"
  if (( ! LOG_EXPLICIT )) && [[ -n "$last_log" ]]; then
    LOG_FILE="$last_log"
  fi
  last_port="$(state_get PORT)"
  [[ -z "$last_port" ]] && last_port="$PORT"

  unmanaged="$(find_unmanaged_pid "$last_port")"
  if [[ -z "$unmanaged" && "$last_port" != "$PORT" ]]; then
    unmanaged="$(find_unmanaged_pid "$PORT")"
  fi
  if [[ -n "$unmanaged" ]]; then
    print_running_status "$unmanaged" 0
    return 0
  fi

  printf 'Wraith 服务：%s已停止%s\n' "$C_YELLOW" "$C_RESET"
  if port_busy "$last_port"; then
    printf '  %s注意：端口 %s 已有服务监听（可能由其他方式启动）%s\n' "$C_YELLOW" "$last_port" "$C_RESET"
  fi
  [[ -f "$LOG_FILE" ]] && printf '  日志：%s\n' "$LOG_FILE"
  return 3
}

restart_service() {
  local prev_mode prev_host prev_port prev_iface prev_log pid value target_port
  prev_mode="$(state_get MODE)"
  prev_host="$(state_get HOST)"
  prev_port="$(state_get PORT)"
  prev_iface="$(state_get IFACE)"
  prev_log="$(state_get LOG)"

  pid="$(running_pid)" || pid=""
  if [[ -z "$pid" ]]; then
    target_port="${prev_port:-$PORT}"
    pid="$(find_unmanaged_pid "$target_port")"
    if [[ -z "$pid" && "$target_port" != "$PORT" ]]; then
      pid="$(find_unmanaged_pid "$PORT")"
    fi
  fi
  if [[ -n "$pid" ]]; then
    value="$(pid_arg "$pid" mode)";  [[ -n "$value" ]] && prev_mode="$value"
    value="$(pid_arg "$pid" host)";  [[ -n "$value" ]] && prev_host="$value"
    value="$(pid_arg "$pid" port)";  [[ -n "$value" ]] && prev_port="$value"
    value="$(pid_arg "$pid" iface)"; [[ -n "$value" ]] && prev_iface="$value"
  fi

  if ! stop_service 1; then
    err "停止旧服务失败，未启动新服务"
    return 1
  fi

  ((MODE_SET))  || [[ -z "$prev_mode" ]]  || MODE="$prev_mode"
  ((HOST_SET))  || [[ -z "$prev_host" ]]  || HOST="$prev_host"
  ((PORT_SET))  || [[ -z "$prev_port" ]]  || PORT="$prev_port"
  ((IFACE_SET)) || [[ -z "$prev_iface" ]] || IFACE="$prev_iface"
  ((LOG_EXPLICIT)) || [[ -z "$prev_log" ]] || LOG_FILE="$prev_log"

  if [[ "$MODE" != "demo" && "$MODE" != "live" ]]; then
    MODE="demo"
  fi
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
    PORT=8787
  fi

  start_service
}

logs_service() {
  local state_log
  if (( ! LOG_EXPLICIT )); then
    state_log="$(state_get LOG)"
    [[ -n "$state_log" ]] && LOG_FILE="$state_log"
  fi
  if [[ ! -f "$LOG_FILE" ]]; then
    err "日志文件不存在：$LOG_FILE（服务尚未启动？）"
    return 1
  fi
  if [[ ! -r "$LOG_FILE" ]]; then
    err "日志文件不可读：$LOG_FILE（尝试使用 sudo）"
    return 1
  fi
  exec tail -n "$LOG_LINES" -f "$LOG_FILE"
}

case "$COMMAND" in
  start) start_service ;;
  stop) stop_service 0 ;;
  restart) restart_service ;;
  status) status_service ;;
  logs) logs_service ;;
esac
exit $?
