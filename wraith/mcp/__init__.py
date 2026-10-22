"""Wraith 的 MCP（Model Context Protocol）接入层.

设计原则
--------
1. **功能对等**：平台 REST API 暴露的每个功能点都有对应的 MCP 工具，
   工具不复制业务逻辑，而是复用同一套 HTTP 处理路径，避免两套行为漂移。
2. **双传输**：``stdio``（供 DSH/Claude Desktop 等本地代理直接拉起）与
   ``streamable-http``（挂载在 ``/mcp``，供远程或常驻 Web 控制台使用）。
3. **授权门禁不绕过**：live 模式的攻击仍由 ``AuthorizationGate`` 强制校验，
   MCP 只是调用入口，不会降低原有安全约束。
4. **可审计**：每次工具调用写入 ``data/mcp-audit.jsonl``，敏感参数自动脱敏。
"""

from __future__ import annotations

from .protocol import MCPServer, MCPError
from .runtime import PlatformRuntime, ToolError
from .specs import TOOL_SPECS, ToolSpec

__all__ = [
    "MCPServer",
    "MCPError",
    "PlatformRuntime",
    "ToolError",
    "TOOL_SPECS",
    "ToolSpec",
]
