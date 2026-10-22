#!/usr/bin/env bash
# Wraith 工具与依赖检查脚本
#
# 检查 Wraith 运行所需的：
#   - 运行环境：OS、Python 版本、venv、pip、wraith 包
#   - Python 依赖：fastapi / uvicorn / jinja2 / pydantic / httpx
#   - 系统工具：核心注入、抓包破解、WPS、流氓 AP、企业级、洪泛/侦察、辅助命令
#   - 项目目录、磁盘空间、监听端口、默认字典
#   - 实机模式前提（--live）：root、无线网卡、monitor/AP 模式、rfkill
#
# 本脚本只读检查，不会安装或修改任何系统配置。
#
# 退出码：0 就绪（可能有警告）；1 缺少关键依赖；2 参数错误
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "$ROOT" || exit 2

DATA_DIR="${WRAITH_DATA_DIR:-$ROOT/data}"
CONFIG_FILE="$DATA_DIR/config.json"

LIVE=0
JSON=0
QUIET=0
COLOR=auto

usage() {
  cat <<'EOF'
用法：./scripts/check-deps.sh [选项]

检查 Wraith 运行所需的 Python 依赖、系统无线工具、项目目录与端口。
默认只做演示模式检查；--live 追加实机模式前提。

选项：
  --live       追加实机模式检查（root、无线网卡、monitor/AP、rfkill）
  --json       以 JSON 输出，便于 CI / 自动化消费
  --quiet, -q  只显示警告与错误
  --no-color   禁用彩色输出
  --color      强制彩色输出
  -h, --help   显示本帮助

退出码：
  0  环境就绪（可能有警告）
  1  缺少关键依赖
  2  参数错误

示例：
  ./scripts/check-deps.sh
  ./scripts/check-deps.sh --live
  sudo -E ./scripts/check-deps.sh --live --json
EOF
}

while (($#)); do
  case "$1" in
    --live) LIVE=1 ;;
    --json) JSON=1; QUIET=1 ;;
    --quiet|-q) QUIET=1 ;;
    --no-color) COLOR=never ;;
    --color) COLOR=always ;;
    -h|--help) usage; exit 0 ;;
    *)
      printf '未知参数：%s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

# ---------------------------------------------------------------- 颜色
USE_COLOR=0
if [[ "$COLOR" == "always" ]]; then
  USE_COLOR=1
elif [[ "$COLOR" == "auto" && -t 1 && -z "${NO_COLOR:-}" ]]; then
  USE_COLOR=1
fi
if ((USE_COLOR)); then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_CYAN=""
fi

# ---------------------------------------------------------------- 状态
FAILURES=0
WARNINGS=0
PY_DEPS_MISSING=0
CHECKS=()
APT_PKGS=()
MANUAL_TOOLS=()
MISSING_CRITICAL=()
SECTION=""
IS_ROOT=0
[[ "$(id -u)" -eq 0 ]] && IS_ROOT=1
OS_NAME=""
PY=""
PYVER=""

has() { command -v "$1" >/dev/null 2>&1; }

read_config_value() {
  local key=$1
  [[ -r "$CONFIG_FILE" && -n "$PY" && -x "$PY" ]] || return 0
  "$PY" - "$CONFIG_FILE" "$key" <<'PY' 2>/dev/null
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle).get(sys.argv[2], "")
except Exception:
    value = ""

if value is not None:
    print(value)
PY
}

record() {
  local level=$1 section=$2 name=$3 detail=${4:-}
  detail=${detail//$'\t'/ }
  detail=${detail//$'\n'/ }
  name=${name//$'\t'/ }
  CHECKS+=("${level}"$'\t'"${section}"$'\t'"${name}"$'\t'"${detail}")
}

section() {
  SECTION="$1"
  if (( !JSON && !QUIET )); then
    printf '\n%s%s%s\n' "${C_BOLD}${C_CYAN}" "$1" "$C_RESET"
  fi
}

log_ok() {
  local name=$1 detail=${2:-}
  record ok "$SECTION" "$name" "$detail"
  if (( !JSON && !QUIET )); then
    printf '  %s %-18s %s\n' "${C_GREEN}●${C_RESET}" "$name" "$detail"
  fi
}

log_info() {
  local name=$1 detail=${2:-}
  record info "$SECTION" "$name" "$detail"
  if (( !JSON && !QUIET )); then
    printf '  %s %-18s %s\n' "${C_DIM}·${C_RESET}" "$name" "$detail"
  fi
}

log_warn() {
  local name=$1 detail=${2:-}
  WARNINGS=$((WARNINGS + 1))
  record warn "$SECTION" "$name" "$detail"
  if (( !JSON )); then
    printf '  %s %-18s %s\n' "${C_YELLOW}▲${C_RESET}" "$name" "$detail"
  fi
}

log_fail() {
  local name=$1 detail=${2:-}
  FAILURES=$((FAILURES + 1))
  record fail "$SECTION" "$name" "$detail"
  if (( !JSON )); then
    printf '  %s %-18s %s\n' "${C_RED}✖${C_RESET}" "$name" "$detail"
  fi
}

# ---------------------------------------------------------------- 工具检查
check_tool() {
  local name=$1 pkg=$2 purpose=$3 critical=${4:-0}
  if has "$name"; then
    log_ok "$name" "$purpose · $(command -v "$name")"
    return 0
  fi

  if [[ "$pkg" == "hostapd-mana" ]]; then
    MANUAL_TOOLS+=("$name")
    log_warn "$name" "$purpose · 缺失（需源码编译安装）"
    return 0
  fi

  APT_PKGS+=("$pkg")
  if ((critical)); then
    MISSING_CRITICAL+=("$name")
    log_fail "$name" "$purpose · 缺失（$pkg）"
  else
    log_warn "$name" "$purpose · 缺失（$pkg）"
  fi
}

check_group() {
  local title=$1
  shift
  section "$title"
  local spec name pkg purpose crit
  for spec in "$@"; do
    IFS='|' read -r name pkg purpose crit <<< "$spec"
    check_tool "$name" "$pkg" "$purpose" "${crit:-0}"
  done
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

detect_wireless_ifaces() {
  if has iw; then
    iw dev 2>/dev/null | awk '$1 == "Interface" {print $2}'
    return 0
  fi
  local d
  for d in /sys/class/net/*/wireless; do
    [[ -e "$d" ]] && basename "$(dirname "$d")"
  done
}

# ---------------------------------------------------------------- 标题
if (( !JSON && !QUIET )); then
  printf '\n  %s\n' "${C_BOLD}Wraith · 工具与依赖检查${C_RESET}"
  printf '  %s\n' "${C_DIM}仅限获得明确授权的安全测试；本脚本只读检查，不修改系统${C_RESET}"
fi

# ---------------------------------------------------------------- 运行环境
section "运行环境"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_NAME="${PRETTY_NAME:-${NAME:-Linux}}"
else
  OS_NAME="$(uname -s)"
fi
log_ok "操作系统" "$OS_NAME · $(uname -m) · 内核 $(uname -r)"

if ((IS_ROOT)); then
  log_ok "运行用户" "root"
else
  log_info "运行用户" "uid=$(id -u)（实机模式需要 root）"
fi

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
  log_ok "虚拟环境" ".venv/bin/python"
else
  PY="$(command -v python3 || true)"
  log_warn "虚拟环境" "未找到 .venv，回退到 ${PY:-python3}；建议运行 ./install.sh"
fi

if [[ -z "$PY" || ! -x "$PY" ]]; then
  log_fail "Python" "未找到 python3（需要 3.10+）"
else
  PYVER="$("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || true)"
  if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    log_ok "Python 版本" "${PYVER:-未知} · $PY"
  else
    log_fail "Python 版本" "${PYVER:-未知}（需要 3.10+）"
  fi

  if "$PY" -m pip --version >/dev/null 2>&1; then
    log_ok "pip" "$("$PY" -m pip --version 2>/dev/null | head -n 1)"
  else
    log_warn "pip" "不可用；建议安装 python3-venv / python3-pip"
  fi

  if "$PY" -c 'import wraith' >/dev/null 2>&1; then
    WRAITH_VER="$("$PY" -c 'import wraith; print(wraith.__version__)' 2>/dev/null || true)"
    log_ok "wraith 包" "可导入 · v${WRAITH_VER:-?}"
  else
    log_fail "wraith 包" "无法导入；请运行 ./install.sh 或 $PY -m pip install -e ."
  fi
fi

# ---------------------------------------------------------------- Python 依赖
section "Python 依赖"
if [[ -n "$PY" && -x "$PY" ]]; then
  for mod in fastapi uvicorn jinja2 pydantic httpx; do
    if "$PY" -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$mod') else 1)" >/dev/null 2>&1; then
      log_ok "$mod" "已安装"
    else
      PY_DEPS_MISSING=$((PY_DEPS_MISSING + 1))
      log_fail "$mod" "缺失（Web 控制台必需）"
    fi
  done
else
  PY_DEPS_MISSING=5
  log_fail "Python 依赖" "无法检查：Python 不可用"
fi

# ---------------------------------------------------------------- 系统工具
CORE_TOOLS=(
  "iw|iw|无线设备与接口配置|1"
  "ip|iproute2|网络接口与路由状态|1"
  "airmon-ng|aircrack-ng|开启 monitor 模式|1"
  "airodump-ng|aircrack-ng|Beacon/客户端扫描与抓包|1"
  "aireplay-ng|aircrack-ng|Deauth / 注入 / ARP 重放|1"
  "macchanger|macchanger|MAC 地址伪造|0"
)
CAPTURE_CRACK_TOOLS=(
  "hcxdumptool|hcxdumptool|PMKID / 握手捕获|0"
  "hcxpcapngtool|hcxtools|pcapng → hashcat 22000|0"
  "tshark|tshark|EAPOL 握手检测|0"
  "aircrack-ng|aircrack-ng|WEP/WPA 离线破解|1"
  "hashcat|hashcat|GPU 高速破解|0"
  "john|john|John the Ripper（备用）|0"
)
WPS_TOOLS=(
  "reaver|reaver|WPS Pixie Dust / PIN 爆破|0"
  "wash|reaver|WPS 开启状态探测|0"
  "bully|bully|WPS PIN 攻击（备用）|0"
  "pixiewps|pixiewps|Pixie Dust 离线计算|0"
)
ROGUE_TOOLS=(
  "hostapd|hostapd|搭建软 AP（邪恶双胞胎）|0"
  "dnsmasq|dnsmasq|DHCP/DNS 劫持（强制门户）|0"
  "hostapd-mana|hostapd-mana|Karma / MANA 与企业 EAP|0"
  "wifiphisher|wifiphisher|流氓 AP 钓鱼框架|0"
)
ENTERPRISE_TOOLS=(
  "eaphammer|eaphammer|企业级 Evil Twin（凭证收割）|0"
)
FLOOD_RECON_TOOLS=(
  "mdk4|mdk4|Beacon/Auth/Deauth 洪泛|0"
  "bettercap|bettercap|802.11 侦察与 MITM|0"
  "kismet|kismet|被动侦察 / WIDS|0"
)
AUX_TOOLS=(
  "curl|curl|健康检查与下载|0"
  "ss|iproute2|端口与连接状态|0"
  "pgrep|procps|进程检测|0"
  "setsid|util-linux|后台会话管理|0"
  "rfkill|rfkill|无线开关状态|0"
)

check_group "核心与注入" "${CORE_TOOLS[@]}"
check_group "抓包与破解" "${CAPTURE_CRACK_TOOLS[@]}"
check_group "WPS" "${WPS_TOOLS[@]}"
check_group "流氓 AP 与门户" "${ROGUE_TOOLS[@]}"
check_group "企业级" "${ENTERPRISE_TOOLS[@]}"
check_group "洪泛与侦察" "${FLOOD_RECON_TOOLS[@]}"
check_group "辅助命令" "${AUX_TOOLS[@]}"

# ---------------------------------------------------------------- 项目与端口
section "项目目录与端口"
for d in data captures; do
  if [[ -d "$ROOT/$d" ]]; then
    if [[ -w "$ROOT/$d" ]]; then
      log_ok "$d/" "存在且可写"
    else
      log_fail "$d/" "存在但不可写（检查目录权限）"
    fi
  else
    log_warn "$d/" "不存在（首次启动会自动创建）"
  fi
done

if [[ -d "$DATA_DIR/run" && ! -w "$DATA_DIR/run" ]]; then
  log_warn "data/run/" "不可写；后台启动脚本会失败（检查权限）"
fi

AVAIL_KB="$(df -Pk "$ROOT" 2>/dev/null | awk 'NR == 2 {print $4}')"
if [[ "$AVAIL_KB" =~ ^[0-9]+$ ]]; then
  if ((AVAIL_KB < 1048576)); then
    log_warn "磁盘空间" "剩余 $((AVAIL_KB / 1024)) MiB，建议清理"
  else
    log_ok "磁盘空间" "剩余 $((AVAIL_KB / 1024)) MiB"
  fi
fi

PORT="${WRAITH_PORT:-}"
[[ -z "$PORT" ]] && PORT="$(read_config_value port)"
[[ -z "$PORT" ]] && PORT=8787
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  PORT=8787
fi
if port_busy "$PORT"; then
  log_info "端口 $PORT" "已有服务监听（可能 Wraith 正在运行）"
else
  log_ok "端口 $PORT" "空闲"
fi

WORDLIST="${WRAITH_WORDLIST:-}"
[[ -z "$WORDLIST" ]] && WORDLIST="$(read_config_value wordlist)"
if [[ -z "$WORDLIST" ]]; then
  for candidate in /usr/share/wordlists/rockyou.txt "$DATA_DIR/wordlists/demo.txt"; do
    if [[ -r "$candidate" ]]; then
      WORDLIST="$candidate"
      break
    fi
  done
fi
if [[ -n "$WORDLIST" && -r "$WORDLIST" ]]; then
  log_ok "默认字典" "$WORDLIST"
else
  log_warn "默认字典" "未找到 rockyou.txt；破解前需在设置中指定字典"
fi

# ---------------------------------------------------------------- 实机模式
if ((LIVE)); then
  section "实机模式前提"

  if ((IS_ROOT)); then
    log_ok "root 权限" "已具备"
  else
    log_fail "root 权限" "实机模式需要 root：sudo -E ./scripts/check-deps.sh --live"
  fi

  IFACE="${WRAITH_IFACE:-}"
  [[ -z "$IFACE" ]] && IFACE="$(read_config_value iface)"

  mapfile -t WIRELESS < <(detect_wireless_ifaces)
  if ((${#WIRELESS[@]} == 0)); then
    log_fail "无线网卡" "未检测到（需要支持 monitor 模式的无线网卡）"
  else
    log_ok "无线网卡" "${WIRELESS[*]}"
    if [[ -z "$IFACE" ]]; then
      if ((${#WIRELESS[@]} == 1)); then
        IFACE="${WIRELESS[0]}"
        log_info "默认网卡" "$IFACE"
      else
        log_warn "默认网卡" "未指定；请用 --iface 或 WRAITH_IFACE 选择"
      fi
    fi
    if [[ -n "$IFACE" ]]; then
      if [[ -d "/sys/class/net/$IFACE" ]]; then
        ITYPE="$(iw dev "$IFACE" info 2>/dev/null | awk '$1 == "type" {print $2; exit}')"
        log_ok "网卡 $IFACE" "存在 · 当前类型 ${ITYPE:-未知}"
      else
        log_fail "网卡 $IFACE" "不存在（检查 WRAITH_IFACE / 设置中的网卡）"
      fi
    fi
  fi

  if has iw; then
    IW_LIST="$(iw list 2>/dev/null)"
    if grep -qE '^[[:space:]]*\* monitor' <<< "$IW_LIST"; then
      log_ok "monitor 模式" "网卡/驱动支持"
    else
      log_fail "monitor 模式" "未在 iw list 中找到"
    fi
    if grep -qE '^[[:space:]]*\* AP' <<< "$IW_LIST"; then
      log_ok "AP 模式" "网卡/驱动支持"
    else
      log_warn "AP 模式" "未找到 AP 模式（邪恶双胞胎/降级模块不可用）"
    fi
  else
    log_fail "monitor 模式" "缺少 iw，无法检测"
  fi

  if has rfkill; then
    RFKILL_BLOCKED="$(rfkill list wlan 2>/dev/null | grep -E 'Soft blocked: yes|Hard blocked: yes' || true)"
    if [[ -n "$RFKILL_BLOCKED" ]]; then
      log_warn "rfkill" "无线设备被禁用：$RFKILL_BLOCKED"
    else
      log_ok "rfkill" "无线设备未被禁用"
    fi
  else
    log_warn "rfkill" "未安装，无法检查无线开关"
  fi
fi

# ---------------------------------------------------------------- 汇总 / JSON
print_summary() {
  printf '\n%s\n' "${C_BOLD}────────────────────────────────────────${C_RESET}"
  if ((FAILURES)); then
    printf '  %s检查未通过：%d 项错误，%d 项警告%s\n' "$C_RED" "$FAILURES" "$WARNINGS" "$C_RESET"
  else
    printf '  %s检查通过：%d 项警告%s\n' "$C_GREEN" "$WARNINGS" "$C_RESET"
  fi

  if ((${#MISSING_CRITICAL[@]})); then
    printf '  关键缺失：%s\n' "${MISSING_CRITICAL[*]}"
  fi

  if ((${#APT_PKGS[@]})); then
    local -a packages=()
    mapfile -t packages < <(printf '%s\n' "${APT_PKGS[@]}" | sort -u)
    printf '  安装缺失工具：sudo apt install -y %s\n' "${packages[*]}"
    printf '  或运行：./install.sh --tools\n'
  fi

  if ((${#MANUAL_TOOLS[@]})); then
    printf '  需手动安装：%s（hostapd-mana 需源码编译，见 README）\n' "${MANUAL_TOOLS[*]}"
  fi

  if ((PY_DEPS_MISSING)); then
    printf '  安装 Python 依赖：%s -m pip install -e .\n' "${PY:-python3}"
  fi

  if ((FAILURES == 0)); then
    printf '  提示：%s -m wraith doctor 可查看平台内置依赖矩阵\n' "${PY:-python3}"
  fi
  printf '\n'
}

json_output() {
  if [[ -z "$PY" || ! -x "$PY" ]]; then
    printf '{"ok":false,"error":"python3 not found"}\n'
    return 1
  fi

  local tmp ok
  tmp="$(mktemp "${TMPDIR:-/tmp}/wraith-check.XXXXXX")" || {
    printf '{"ok":false,"error":"mktemp failed"}\n'
    return 1
  }
  if ((${#CHECKS[@]})); then
    printf '%s\n' "${CHECKS[@]}" > "$tmp"
  else
    : > "$tmp"
  fi

  ok=1
  ((FAILURES)) && ok=0

  local old_ifs="$IFS"
  IFS=','
  local critical="${MISSING_CRITICAL[*]:-}"
  local apt="${APT_PKGS[*]:-}"
  local manual="${MANUAL_TOOLS[*]:-}"
  IFS="$old_ifs"

  CHECK_FILE="$tmp" \
  CHECK_OK="$ok" \
  CHECK_LIVE="$LIVE" \
  CHECK_ROOT="$IS_ROOT" \
  CHECK_OS="$OS_NAME" \
  CHECK_PY="$PY" \
  CHECK_PYVER="$PYVER" \
  CHECK_FAILURES="$FAILURES" \
  CHECK_WARNINGS="$WARNINGS" \
  CHECK_CRITICAL="$critical" \
  CHECK_APT="$apt" \
  CHECK_MANUAL="$manual" \
  CHECK_PYDEPS="$PY_DEPS_MISSING" \
  "$PY" - <<'PY'
import json
import os


def split_env(key):
    return [item for item in os.environ.get(key, "").split(",") if item]


checks = []
with open(os.environ["CHECK_FILE"], encoding="utf-8") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t", 3)
        parts += [""] * (4 - len(parts))
        checks.append(dict(zip(("level", "section", "name", "detail"), parts)))

payload = {
    "ok": os.environ.get("CHECK_OK") == "1",
    "live": os.environ.get("CHECK_LIVE") == "1",
    "root": os.environ.get("CHECK_ROOT") == "1",
    "os": os.environ.get("CHECK_OS", ""),
    "python": {
        "path": os.environ.get("CHECK_PY", ""),
        "version": os.environ.get("CHECK_PYVER", ""),
    },
    "errors": int(os.environ.get("CHECK_FAILURES", "0")),
    "warnings": int(os.environ.get("CHECK_WARNINGS", "0")),
    "missing_critical": split_env("CHECK_CRITICAL"),
    "missing_apt": split_env("CHECK_APT"),
    "manual_missing": split_env("CHECK_MANUAL"),
    "python_missing_count": int(os.environ.get("CHECK_PYDEPS", "0")),
    "checks": checks,
}
print(json.dumps(payload, ensure_ascii=False, indent=2))
PY
  local rc=$?
  rm -f "$tmp"
  return $rc
}

if ((JSON)); then
  if ! json_output; then
    exit 1
  fi
else
  print_summary
fi

if ((FAILURES)); then
  exit 1
fi
exit 0
