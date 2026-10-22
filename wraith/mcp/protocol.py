"""最小但完整的 MCP JSON-RPC 协议层.

支持 stdio 与 Streamable HTTP 共用的方法：

- ``initialize`` / ``notifications/initialized``
- ``ping``
- ``tools/list`` / ``tools/call``

服务器故意只声明 ``tools`` 能力，不实现 resources/prompts，减少攻击面。
``server/discover`` 返回 -32601，让新版客户端回退到 2025 版 ``initialize`` 握手
（与 DSH 内置 MCP SDK 的版本协商兼容）。
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from .specs import tool_definitions

SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
)
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

INSTRUCTIONS = """Wraith 是面向授权测试的 Wi-Fi 安全评估平台。所有功能通过工具暴露。
推荐链路：system_info → scan_start → aps → attack_start → attack_wait → captures → crack_start → crack_wait → report。
demo 模式全部为模拟，不会触碰真实无线设备；live 模式必须先调用 authorize（令牌 AUTHORIZED），
且目标必须落在授权范围内，否则攻击入口返回 403。
攻击会独占无线网卡，同一时间只允许一个攻击任务；启动攻击会自动停止扫描。
抓包与报告保存在平台本地目录（captures/、data/reports/），可通过 captures / report_files 获取路径。
仅限已获得明确书面授权的安全评估。"""


class MCPError(Exception):
    """JSON-RPC 协议错误。"""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class MCPServer:
    """把工具运行时适配为 MCP 协议处理器。"""

    def __init__(
        self,
        call_tool: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
        *,
        name: str = "wraith",
        version: str = "1.0.0",
        instructions: str = INSTRUCTIONS,
    ) -> None:
        self._call_tool = call_tool
        self.name = name
        self.version = version
        self.instructions = instructions

    # ------------------------------------------------------------------ 协议
    async def handle(self, message: Any) -> dict[str, Any] | None:
        """处理一条 JSON-RPC 消息；通知返回 ``None``。"""
        if not isinstance(message, dict):
            return error_response(None, -32600, "Invalid Request: expected a JSON object")
        if message.get("jsonrpc") != "2.0":
            return error_response(message.get("id"), -32600, "Invalid Request: jsonrpc must be 2.0")

        method = message.get("method")
        if not isinstance(method, str):
            return error_response(message.get("id"), -32600, "Invalid Request: missing method")

        is_notification = "id" not in message
        request_id = message.get("id")
        params = message.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return error_response(request_id, -32602, "Invalid params: expected an object")

        try:
            result = await self._dispatch(method, params)
        except MCPError as exc:
            if is_notification:
                return None
            return error_response(request_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # noqa: BLE001
            if is_notification:
                return None
            return error_response(request_id, -32603, f"Internal error: {exc}")

        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    async def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = (
                requested
                if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": self.version},
                "instructions": self.instructions,
            }
        if method == "notifications/initialized":
            return {}
        if method in {"notifications/cancelled", "notifications/progress"}:
            return {}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": tool_definitions()}
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments")
            if not isinstance(name, str) or not name:
                raise MCPError(-32602, "Invalid params: tools/call requires a tool name")
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                raise MCPError(-32602, "Invalid params: arguments must be an object")
            return await self._call_tool(name, arguments)
        if method == "server/discover":
            # 2026 协议探测；返回 Method not found 让客户端回退到 legacy initialize。
            raise MCPError(-32601, "Method not found: server/discover")
        if method in {"resources/list", "resources/templates/list", "prompts/list"}:
            raise MCPError(-32601, f"Method not found: {method}")
        raise MCPError(-32601, f"Method not found: {method}")


def error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def encode(message: dict[str, Any]) -> str:
    """序列化为单行 JSON（stdio 传输要求）。"""
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"))


__all__ = [
    "MCPServer",
    "MCPError",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "DEFAULT_PROTOCOL_VERSION",
    "INSTRUCTIONS",
    "encode",
    "error_response",
]
