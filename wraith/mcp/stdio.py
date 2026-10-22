"""stdio 传输：供 DSH / Claude Desktop / Codex 等本地 MCP 客户端拉起.

stdout 只允许出现 JSON-RPC 消息；所有日志都写到 stderr。
嵌入式模式会在第一次 ``tools/call`` 时才启动 AppState，避免 MCP 客户端的
版本探测子进程在数据库里留下空会话。
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import wraith

from .protocol import MCPServer, encode, error_response
from .runtime import PlatformRuntime
from .specs import TOOL_SPECS


class EmbeddedRuntime:
    """惰性启动嵌入式 Wraith 应用，并复用其 ``/mcp`` 运行时。"""

    def __init__(self, config: Any, audit_path: str | Path | None = None) -> None:
        self.config = config
        self.audit_path = audit_path
        self.app: Any = None
        self._runtime: PlatformRuntime | None = None
        self._lifespan: Any = None
        self._lock = asyncio.Lock()

    async def ensure(self) -> PlatformRuntime:
        if self._runtime is not None:
            return self._runtime
        async with self._lock:
            if self._runtime is not None:
                return self._runtime
            from ..web.app import create_app

            app = create_app(self.config)
            lifespan = app.router.lifespan_context(app)
            await lifespan.__aenter__()
            self.app = app
            self._lifespan = lifespan
            self._runtime = app.state.wraith_mcp
            if self.audit_path is not None:
                self._runtime.audit_path = Path(self.audit_path)
            return self._runtime

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        runtime = await self.ensure()
        return await runtime.call(name, arguments)

    async def aclose(self) -> None:
        if self._lifespan is not None:
            lifespan, self._lifespan = self._lifespan, None
            await lifespan.__aexit__(None, None, None)
        if self._runtime is not None:
            runtime, self._runtime = self._runtime, None
            await runtime.aclose()


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


async def run_stdio(
    *,
    config: Any | None = None,
    base_url: str | None = None,
    audit_path: str | Path | None = None,
) -> int:
    """运行 stdio MCP 服务器，直到 stdin 关闭。"""
    if base_url:
        runtime: Any = PlatformRuntime(base_url=base_url, audit_path=audit_path)
        mode = f"远程 {base_url}"
    else:
        if config is None:
            raise ValueError("嵌入式 stdio 模式需要 config")
        runtime = EmbeddedRuntime(config, audit_path=audit_path)
        mode = f"嵌入式 {config.mode}"

    server = MCPServer(runtime.call, name="wraith", version=wraith.__version__)
    _log(f"Wraith MCP stdio 已就绪 · {mode} · {len(TOOL_SPECS)} 个工具")
    try:
        while True:
            line = await asyncio.to_thread(sys.stdin.buffer.readline)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except json.JSONDecodeError as exc:
                _write(error_response(None, -32700, f"Parse error: {exc}"))
                continue

            if isinstance(message, list):
                responses = []
                for item in message:
                    response = await server.handle(item)
                    if response is not None:
                        responses.append(response)
                if responses:
                    _write(responses)
                continue

            response = await server.handle(message)
            if response is not None:
                _write(response)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        await runtime.aclose()
    return 0


def _write(payload: Any) -> None:
    if isinstance(payload, list):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(encode(payload) + "\n")
    sys.stdout.flush()


__all__ = ["EmbeddedRuntime", "run_stdio"]
