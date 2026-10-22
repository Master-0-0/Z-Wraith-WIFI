#!/usr/bin/env bash
# 以 stdio MCP 服务器启动 Wraith（供 DSH / Claude Desktop / Codex 等客户端拉起）。
# stdout 只输出 MCP JSON-RPC；日志在 stderr。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -x .venv/bin/python ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

# 默认演示模式，避免 AI 代理误触真实无线设备；显式传 --live 才会进入实机路径。
if [[ $# -eq 0 ]]; then
  set -- --demo
fi

exec "$PY" -m wraith mcp "$@"
