"""MCP 工具运行时：校验参数、调用平台 REST API、返回 MCP 结果.

工具层刻意不复制平台业务逻辑：所有操作都走 Web API（进程内 ASGI 或远程 HTTP），
因此 demo/live 行为、授权门禁与审计与 Web 控制台完全一致。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from .specs import SPECS_BY_NAME, ToolSpec, tool_definitions

MAX_INLINE_DOWNLOAD = 16 * 1024 * 1024  # 超过 16 MiB 不载入内存，只返回元数据
MAX_RESULT_CHARS = 400_000
AUDIT_REDACT_KEYS = {"token", "password", "pass", "psk", "key", "secret", "authorization"}


class ToolError(Exception):
    """可展示给模型的工具调用错误。"""

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("***" if str(k).lower() in AUDIT_REDACT_KEYS else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…"
    return value


class PlatformRuntime:
    """把 MCP 工具调用转发到 Wraith Web API。"""

    def __init__(
        self,
        *,
        app: Any | None = None,
        base_url: str | None = None,
        audit_path: str | Path | None = None,
        timeout: float = 120.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if client is not None:
            self._client = client
        elif app is not None:
            self._client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://wraith.internal",
                timeout=httpx.Timeout(timeout, connect=10.0),
                headers={"User-Agent": "wraith-mcp"},
            )
        else:
            if not base_url:
                raise ValueError("必须提供 app 或 base_url")
            self._client = httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                timeout=httpx.Timeout(timeout, connect=10.0),
                headers={"User-Agent": "wraith-mcp"},
            )
        self.audit_path = Path(audit_path) if audit_path else None
        self._audit_lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------ 元数据
    @staticmethod
    def tools() -> list[dict[str, Any]]:
        return tool_definitions()

    # ------------------------------------------------------------------ 调用
    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行一次工具调用，始终返回 MCP ``CallToolResult``。"""
        started = time.time()
        args = arguments if isinstance(arguments, dict) else {}
        ok = False
        error = ""
        result: dict[str, Any]
        spec = SPECS_BY_NAME.get(name)
        try:
            if spec is None:
                raise ToolError(
                    f"未知工具 {name}",
                    "请先调用 tools/list 查看可用工具，或从 health/system_info 开始。",
                )
            values = self._prepare(spec, args)
            data = await self._dispatch(spec, values)
            result = self._success(data)
            ok = True
        except ToolError as exc:
            error = exc.message
            result = self._failure(exc.message, exc.hint)
        except Exception as exc:  # noqa: BLE001 - 工具层不应把堆栈抛给协议层
            error = f"{type(exc).__name__}: {exc}"
            result = self._failure(f"工具执行失败：{exc}")
        finally:
            self._audit(name, args, ok, error, time.time() - started)
        return result

    async def _dispatch(self, spec: ToolSpec, values: dict[str, Any]) -> Any:
        if spec.kind == "wait_attack":
            return await self._wait(
                job_id=str(values["job_id"]),
                timeout=float(values.get("timeout_sec") or 60),
                detail_spec=SPECS_BY_NAME["attack_job"],
                terminal={"success", "failed", "stopped"},
                label="攻击",
            )
        if spec.kind == "wait_crack":
            return await self._wait(
                job_id=str(values["job_id"]),
                timeout=float(values.get("timeout_sec") or 60),
                detail_spec=SPECS_BY_NAME["crack_detail"],
                terminal={"found", "exhausted", "failed", "stopped"},
                label="破解",
            )
        if spec.kind == "capture_download":
            return await self._capture_download(int(values["capture_id"]))
        if spec.kind == "report_download":
            return await self._report_download(str(values["name"]))
        return await self._request(spec, values)

    # ------------------------------------------------------------------ 参数
    def _prepare(self, spec: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
        allowed = {a.name for a in spec.args}
        unknown = sorted(set(args) - allowed)
        if unknown:
            raise ToolError(
                f"工具 {spec.name} 不支持参数：{', '.join(unknown)}",
                f"可用参数：{', '.join(sorted(allowed)) or '无'}",
            )

        values: dict[str, Any] = {}
        for arg in spec.args:
            if arg.name in args and args[arg.name] is not None:
                value = self._coerce(arg, args[arg.name])
                self._check(arg, value)
                values[arg.name] = value
            elif arg.default is not None:
                values[arg.name] = arg.default
            elif arg.required:
                raise ToolError(
                    f"工具 {spec.name} 缺少必填参数 {arg.name}",
                    arg.description or "请补充该参数后重试。",
                )

        for arg in spec.path_args:
            if arg.name not in values:
                continue
            value = str(values[arg.name])
            if any(ch in value for ch in ("/", "\\", "\x00")):
                raise ToolError(f"参数 {arg.name} 不能包含路径分隔符")
            if arg.name == "name" and (value in {"", ".", ".."} or Path(value).name != value):
                raise ToolError("报告文件名不合法")
            if arg.name == "module_id" and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                raise ToolError("module_id 只能包含字母、数字、下划线和连字符")
        return values

    def _coerce(self, arg: Any, value: Any) -> Any:
        """对模型常见的字符串化标量做宽松转换。"""
        if arg.type == "integer" and isinstance(value, str):
            text = value.strip()
            if re.fullmatch(r"[+-]?\d+", text):
                return int(text)
        if arg.type == "number" and isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return value
        if arg.type == "boolean" and isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            if lowered in {"false", "0", "no", "off"}:
                return False
        return value

    def _check(self, arg: Any, value: Any) -> None:
        expected = arg.type
        if expected == "string":
            valid = isinstance(value, str)
        elif expected == "integer":
            valid = isinstance(value, int) and not isinstance(value, bool)
        elif expected == "number":
            valid = isinstance(value, (int, float)) and not isinstance(value, bool)
        elif expected == "boolean":
            valid = isinstance(value, bool)
        elif expected == "object":
            valid = isinstance(value, dict)
        elif expected == "array":
            valid = isinstance(value, list) and all(
                isinstance(item, str) for item in value
            )
        else:
            valid = True
        if not valid:
            raise ToolError(f"参数 {arg.name} 类型应为 {expected}，收到 {type(value).__name__}")
        if arg.enum and value not in arg.enum:
            raise ToolError(
                f"参数 {arg.name} 取值必须是 {', '.join(arg.enum)} 之一",
                f"收到：{value}",
            )
        if arg.minimum is not None and isinstance(value, (int, float)) and value < arg.minimum:
            raise ToolError(f"参数 {arg.name} 不能小于 {arg.minimum}")
        if arg.maximum is not None and isinstance(value, (int, float)) and value > arg.maximum:
            raise ToolError(f"参数 {arg.name} 不能大于 {arg.maximum}")

    # ------------------------------------------------------------------ HTTP
    def _build_request(self, spec: ToolSpec, values: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
        path_values = {
            arg.name: quote(str(values[arg.name]), safe="")
            for arg in spec.path_args
            if arg.name in values
        }
        path = spec.path.format(**path_values)
        params = {
            arg.name: _query_value(values[arg.name])
            for arg in spec.query_args
            if arg.name in values
        }
        body = None
        if spec.method != "GET":
            body = {arg.name: values[arg.name] for arg in spec.body_args if arg.name in values}
            if not body:
                body = None
        return path, params, body

    async def _request(self, spec: ToolSpec, values: dict[str, Any]) -> Any:
        path, params, body = self._build_request(spec, values)
        kwargs: dict[str, Any] = {}
        if params:
            kwargs["params"] = params
        if body is not None:
            kwargs["json"] = body
        response = await self._client.request(spec.method, path, **kwargs)
        return self._parse_response(response, spec)

    async def _request_bytes(self, spec: ToolSpec, values: dict[str, Any]) -> tuple[bytes, httpx.Response]:
        path, params, body = self._build_request(spec, values)
        kwargs: dict[str, Any] = {}
        if params:
            kwargs["params"] = params
        if body is not None:
            kwargs["json"] = body
        response = await self._client.request(spec.method, path, **kwargs)
        self._raise_for_status(response)
        return response.content, response

    def _parse_response(self, response: httpx.Response, spec: ToolSpec) -> Any:
        self._raise_for_status(response)
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            return response.json()
        if content_type.startswith("text/") or "json" in content_type:
            return response.text
        return {
            "content_type": content_type or "application/octet-stream",
            "bytes": len(response.content),
        }

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        detail = ""
        try:
            payload = response.json()
            detail = payload.get("detail") if isinstance(payload, dict) else str(payload)
        except (ValueError, AttributeError):
            detail = response.text.strip()
        if isinstance(detail, list):
            detail = "；".join(
                f"{'.'.join(str(part) for part in item.get('loc', []))}: {item.get('msg', '')}"
                for item in detail
                if isinstance(item, dict)
            )
        message = str(detail or response.reason_phrase or "请求失败")
        hint = ""
        if response.status_code == 403:
            hint = 'live 模式请先调用 authorize(token="AUTHORIZED") 完成授权，并确认目标在授权范围内。'
        elif response.status_code == 404:
            hint = "请检查 ID/名称是否存在；可先调用对应的列表工具。"
        elif response.status_code == 409:
            hint = "当前存在冲突任务；可先调用 scan_stop / attack_stop 或查看状态。"
        raise ToolError(f"[HTTP {response.status_code}] {message}", hint)

    # ------------------------------------------------------------------ 组合工具
    async def _wait(
        self,
        *,
        job_id: str,
        timeout: float,
        detail_spec: ToolSpec,
        terminal: set[str],
        label: str,
    ) -> dict[str, Any]:
        timeout = max(1.0, min(float(timeout), 600.0))
        deadline = time.monotonic() + timeout
        while True:
            job = await self._request(detail_spec, {"job_id": job_id})
            status = str(job.get("status") or "")
            if status in terminal:
                return job
            if time.monotonic() >= deadline:
                raise ToolError(
                    f"等待{label}任务 {job_id} 超时（{int(timeout)}s），当前状态：{status or 'unknown'}",
                    "可稍后继续用攻击/破解详情工具查询，或调用 stop 工具终止任务。",
                )
            await asyncio.sleep(1.0)

    async def _capture_download(self, capture_id: int) -> dict[str, Any]:
        listing = await self._request(SPECS_BY_NAME["captures"], {})
        captures = listing.get("captures", []) if isinstance(listing, dict) else []
        meta = next((c for c in captures if c.get("id") == capture_id), None)
        if meta is None:
            raise ToolError(f"抓包 #{capture_id} 不存在", "可先调用 captures 查看可用抓包。")
        result: dict[str, Any] = {
            "capture_id": capture_id,
            "filename": meta.get("filename") or Path(str(meta.get("path") or "")).name,
            "path": meta.get("path"),
            "size": meta.get("size"),
            "exists": meta.get("exists", False),
            "ssid": meta.get("ssid"),
            "bssid": meta.get("bssid"),
        }
        size = int(meta.get("size") or 0)
        if not meta.get("exists", False):
            raise ToolError("抓包文件已丢失", "请重新执行捕获或检查 captures/ 目录。")
        if size > MAX_INLINE_DOWNLOAD:
            result["note"] = "文件较大，未载入内存；请直接从 path 读取。"
            return result
        content, response = await self._request_bytes(
            SPECS_BY_NAME["capture_download"], {"capture_id": capture_id}
        )
        result["sha256"] = hashlib.sha256(content).hexdigest()
        result["content_type"] = response.headers.get("content-type", "application/octet-stream")
        result["note"] = "文件保留在平台本地，可由文件系统读取 path。"
        return result

    async def _report_download(self, name: str) -> Any:
        content, response = await self._request_bytes(
            SPECS_BY_NAME["report_download"], {"name": name}
        )
        content_type = response.headers.get("content-type", "").lower()
        if content_type.startswith("text/") or "json" in content_type:
            text = content.decode("utf-8", errors="replace")
            if "json" in content_type:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return text
            return text
        return {
            "filename": name,
            "content_type": content_type or "application/octet-stream",
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    # ------------------------------------------------------------------ 结果
    def _success(self, data: Any) -> dict[str, Any]:
        if isinstance(data, str):
            text = data
            structured = None
        else:
            text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
            structured = data if isinstance(data, dict) else None
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + "\n…（结果过长，已截断；请改用分页/筛选工具）"
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
        if structured is not None:
            result["structuredContent"] = structured
        return result

    def _failure(self, message: str, hint: str = "") -> dict[str, Any]:
        text = f"❌ {message}"
        if hint:
            text += f"\n提示：{hint}"
        return {"content": [{"type": "text", "text": text}], "isError": True}

    # ------------------------------------------------------------------ 审计
    def _audit(self, tool: str, args: dict[str, Any], ok: bool, error: str, seconds: float) -> None:
        if not self.audit_path:
            return
        record = {
            "ts": time.time(),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "tool": tool,
            "ok": ok,
            "ms": round(seconds * 1000, 1),
            "args": _redact(args),
        }
        if error:
            record["error"] = error[:1000]
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
            with self._audit_lock:
                with self.audit_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError:
            pass

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()


def _query_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def audit_path_for(data_dir: str | Path) -> Path:
    return Path(data_dir) / "mcp-audit.jsonl"


__all__ = [
    "PlatformRuntime",
    "ToolError",
    "audit_path_for",
]
