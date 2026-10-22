#!/usr/bin/env bash
# Wraith 安装脚本：创建 venv、安装 Python 依赖、可选安装无线工具
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CYAN='\033[36m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; DIM='\033[2m'; RESET='\033[0m'
info()  { printf "${CYAN}[*]${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}[+]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${RESET} %s\n" "$*"; }
fail()  { printf "${RED}[x]${RESET} %s\n" "$*" >&2; }

printf "\n  Wraith · Wi-Fi 渗透测试平台 安装\n"
printf "  ${DIM}仅限获得明确授权的安全测试${RESET}\n\n"

# ---------------------------------------------------------------- Python
if ! command -v python3 >/dev/null 2>&1; then
  fail "未找到 python3，请先安装 Python 3.10+"
  exit 1
fi
PYVER="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
info "Python $PYVER"

if [[ ! -d .venv ]]; then
  info "创建虚拟环境 .venv"
  if ! python3 -m venv .venv 2>/dev/null; then
    fail "无法创建 venv，请安装 python3-venv：sudo apt install python3-venv"
    exit 1
  fi
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
info "安装 Python 依赖（fastapi/uvicorn/jinja2/pydantic）"
pip install --quiet -e .
ok "Python 依赖安装完成"

# ---------------------------------------------------------------- 系统工具
# 通用 Debian/Ubuntu 仓库即可提供的工具
APT_PACKAGES=(aircrack-ng hcxdumptool hcxtools reaver bully pixiewps hostapd dnsmasq mdk4 macchanger iw hashcat john tshark kismet)
# 主要在 Kali 仓库中提供的工具（普通 Debian/Ubuntu 可能没有，失败可忽略）
APT_EXTRA=(hostapd-mana eaphammer bettercap wifiphisher)
if [[ "${1:-}" == "--tools" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    info "安装系统无线工具（需要 sudo）"
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      "${APT_PACKAGES[@]}" || warn "部分工具安装失败，可稍后重试"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_EXTRA[@]}" \
      || warn "可选工具（${APT_EXTRA[*]}）未安装，相关攻击模块会标记为不可用"
  else
    warn "非 Debian/Ubuntu 系统，请手动安装：${APT_PACKAGES[*]} ${APT_EXTRA[*]}"
  fi
fi

# ---------------------------------------------------------------- 检查
info "依赖检查"
python -m wraith doctor || true

cat <<'EOF'

  启动方式
  ────────────────────────────────────────────────
  演示模式（无需 root）：
    ./scripts/run-demo.sh
    # 或 source .venv/bin/activate && python -m wraith web --demo --open

  实机模式（需要 root + monitor 网卡）：
    sudo -E .venv/bin/python -m wraith web --live --open --iface wlan0
    # 然后在「设置 → 授权门禁」输入 AUTHORIZED

  文档：README.md · docs/ATTACK_TECHNIQUES.md
  ────────────────────────────────────────────────
EOF
