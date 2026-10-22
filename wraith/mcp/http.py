"""Streamable HTTP 传输：把 MCP 挂载到 FastAPI 的 ``/mcp``.

协议要点：
- ``POST /mcp``：单条或批量 JSON-RPC；通知返回 202，请求返回 JSON。
- ``GET /mcp``：未提供服务器主动 SSE 流，按规范返回 405（客户端会优雅降级）。
- ``DELETE /mcp``：无状态服务器，直接 204。
- 校验 ``Origin``，避免恶意网页通过 DNS rebinding 调用本地平台。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from .protocol import MCPServer, SUPPORTED_PROTOCOL_VERSIONS, error_response
from .runtime import PlatformRuntime


def build_mcp_router(server: MCPServer, runtime: PlatformRuntime) -> APIRouter:
    router = APIRouter(tags=["mcp"])

    @router.post("/mcp")
    async def mcp_post(request: Request) -> Response:
        if not _origin_allowed(request):
            return JSONResponse(
                status_code=403,
                content={"error": "origin_not_allowed", "detail": "MCP endpoint only accepts local origins"},
            )
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001 - 非法 JSON 交给协议层报 -32700
            return JSONResponse(
                status_code=400,
                content=error_response(None, -32700, "Parse error"),
            )

        headers = {"Cache-Control": "no-store"}

        if isinstance(payload, list):
            responses = []
            for item in payload:
                response = await server.handle(item)
                if response is not None:
                    responses.append(response)
            if not responses:
                return Response(status_code=202, headers=headers)
            return JSONResponse(content=responses, headers=headers)

        response = await server.handle(payload)
        if response is None:
            return Response(status_code=202, headers=headers)
        return JSONResponse(content=response, headers=headers)

    @router.get("/mcp")
    async def mcp_get() -> Response:
        # 本服务器不发送服务端主动通知；405 会让客户端停止尝试 GET SSE。
        return Response(status_code=405, headers={"Allow": "POST, DELETE"})

    @router.delete("/mcp")
    async def mcp_delete() -> Response:
        return Response(status_code=204)

    @router.get("/mcp/info", include_in_schema=False)
    async def mcp_info() -> dict[str, Any]:
        return {
            "server": server.name,
            "version": server.version,
            "transport": "streamable-http",
            "endpoint": "/mcp",
            "tools": len(runtime.tools()),
            "protocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
        }

    return router


def _origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    try:
        host = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1"}


__all__ = ["build_mcp_router"]
