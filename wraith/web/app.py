"""FastAPI 应用：REST API + WebSocket 实时事件 + 静态控制台。"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import wraith
from ..config import Config
from ..models import AP, vendor_for
from ..report.generator import ReportGenerator
from ..system import deps
from .state import AppState

STATIC_DIR = Path(__file__).resolve().parent / "static"


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    iface: str | None = None
    channel: int | None = None
    duration: float | None = Field(default=None, ge=3, le=86400)


class AttackRequest(BaseModel):
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    security: str = ""
    wps: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


class StopAttackRequest(BaseModel):
    job_id: str | None = None


class CrackRequest(BaseModel):
    method: str = "auto"
    wordlist: str | None = None


class AuthorizeRequest(BaseModel):
    token: str
    operator: str | None = None
    scope: list[str] | None = None


class ModeRequest(BaseModel):
    mode: str


class PortalRequest(BaseModel):
    ssid: str = "Wraith-Guest"
    title: str = "Wi-Fi 网络认证"
    port: int | None = None


class NotesRequest(BaseModel):
    notes: str = ""


class ConfigRequest(BaseModel):
    iface: str | None = None
    wordlist: str | None = None
    operator: str | None = None
    portal_port: int | None = None
    stealth: bool | None = None


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def _vendor_for_row(row: dict[str, Any], key: str) -> str:
    """数据库里的厂商可能来自旧版小表（Unknown），读取时用完整 OUI 库补正。"""
    vendor = (row.get("vendor") or "").strip()
    if not vendor or vendor.upper() == "UNKNOWN":
        vendor = vendor_for(row.get(key) or "")
    return vendor


def _ap_from_row(row: dict[str, Any], client_count: int = 0) -> dict[str, Any]:
    ap = AP(
        bssid=row["bssid"],
        ssid=row.get("ssid") or "",
        channel=row.get("channel") or 0,
        frequency=row.get("frequency"),
        privacy=row.get("privacy") or "",
        cipher=row.get("cipher") or "",
        auth=row.get("auth") or "",
        power=row.get("power"),
        beacons=row.get("beacons") or 0,
        data=row.get("data") or 0,
        wps=bool(row.get("wps")),
        vendor=_vendor_for_row(row, "bssid"),
        first_seen=row.get("first_seen") or time.time(),
        last_seen=row.get("last_seen") or time.time(),
        clients=client_count,
        session_id=row.get("session_id") or 0,
    )
    return ap.to_dict()


def _build_state(config: Config) -> AppState:
    return AppState(config)


# ---------------------------------------------------------------------------
# 应用工厂
# ---------------------------------------------------------------------------


def create_app(config: Config | None = None) -> FastAPI:
    cfg = config or Config.load()
    state = _build_state(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await state.start()
        try:
            yield
        finally:
            await state.shutdown()

    app = FastAPI(
        title="Wraith Wi-Fi 渗透测试平台",
        version=wraith.__version__,
        description="面向授权测试的 802.11 安全评估平台 API",
        lifespan=lifespan,
    )
    app.state.wraith = state
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ------------------------------------------------------------------ 异常
    @app.exception_handler(PermissionError)
    async def _permission_handler(request: Request, exc: PermissionError):
        return JSONResponse(status_code=403, content={"detail": str(exc), "error": "forbidden"})

    @app.exception_handler(ValueError)
    async def _value_handler(request: Request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc), "error": "bad_request"})

    @app.exception_handler(KeyError)
    async def _key_handler(request: Request, exc: KeyError):
        return JSONResponse(status_code=404, content={"detail": str(exc), "error": "not_found"})

    @app.exception_handler(FileNotFoundError)
    async def _file_handler(request: Request, exc: FileNotFoundError):
        return JSONResponse(status_code=404, content={"detail": str(exc), "error": "not_found"})

    @app.exception_handler(RuntimeError)
    async def _runtime_handler(request: Request, exc: RuntimeError):
        return JSONResponse(status_code=409, content={"detail": str(exc), "error": "conflict"})

    # ------------------------------------------------------------------ 页面
    @app.get("/", include_in_schema=False)
    async def index():
        index_path = STATIC_DIR / "index.html"
        if not index_path.exists():
            return HTMLResponse("<h1>Wraith</h1><p>前端资源缺失</p>", status_code=500)
        return FileResponse(index_path)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=204)

    # ------------------------------------------------------------------ 系统
    @app.get("/api/health")
    async def health():
        return {"ok": True, "app": "wraith", "version": wraith.__version__, "ts": time.time()}

    @app.get("/api/system")
    async def system_info():
        return await state.system_info()

    @app.get("/api/overview")
    async def overview():
        return await state.overview()

    @app.get("/api/interfaces")
    async def interfaces():
        items = await state.iface_mgr.list_interfaces()
        return {"interfaces": [i.to_dict() for i in items], "root": state.iface_mgr.is_root()}

    @app.post("/api/system/mode")
    async def set_mode(body: ModeRequest):
        return state.set_mode(body.mode)

    @app.post("/api/system/config")
    async def update_config(body: ConfigRequest):
        changed = {}
        for field in ("iface", "wordlist", "operator", "portal_port", "stealth"):
            value = getattr(body, field)
            if value is not None and getattr(state.config, field) != value:
                setattr(state.config, field, value)
                changed[field] = value
        try:
            state.config.save()
        except OSError as exc:
            raise RuntimeError(f"配置保存失败：{exc}") from exc
        if changed:
            state.bus.emit(
                "info",
                "system",
                "配置已更新：" + "，".join(f"{k}={v}" for k, v in changed.items()),
                changed=changed,
            )
        return {"ok": True, "changed": changed, "config": state.config.public_dict()}

    @app.get("/api/deps")
    async def dependencies():
        return deps.doctor()

    # ------------------------------------------------------------------ 授权
    @app.get("/api/authorization")
    async def authorization_status():
        return state.gate.status()

    @app.post("/api/authorization")
    async def authorize(body: AuthorizeRequest):
        if body.operator:
            state.config.operator = body.operator
        ok, message = state.gate.grant(body.token, body.scope)
        if not ok:
            raise PermissionError(message)
        return {"ok": True, "message": message, "status": state.gate.status()}

    @app.post("/api/authorization/revoke")
    async def revoke():
        state.gate.revoke()
        return {"ok": True, "status": state.gate.status()}

    @app.get("/api/authorization/audit")
    async def audit_log(limit: int = Query(default=100, ge=1, le=1000)):
        return {"records": state.gate.recent_audit(limit)}

    # ------------------------------------------------------------------ 扫描
    @app.get("/api/scanner")
    async def scanner_status():
        return state.scanner.snapshot()

    @app.post("/api/scan/start")
    async def scan_start(body: ScanRequest):
        if not state.scanner:
            raise RuntimeError("扫描器未初始化")
        status = await state.scanner.start(body.iface, duration=body.duration, channel=body.channel)
        return status

    @app.post("/api/scan/stop")
    async def scan_stop():
        if not state.scanner:
            raise RuntimeError("扫描器未初始化")
        return await state.scanner.stop()

    @app.get("/api/aps")
    async def aps():
        snapshot = state.scanner.snapshot() if state.scanner else {"status": {}, "aps": [], "clients": []}
        known = {ap["bssid"]: ap for ap in snapshot["aps"]}
        # 以数据库为准统计每个 AP 的关联客户端：服务重启后扫描器内存为空，
        # 只依赖 snapshot 会让所有 AP 的客户端数变成 0。
        db_clients = state.store.list_clients(state.session_id)
        counts: dict[str, int] = {}
        for client in db_clients:
            if client.get("bssid"):
                counts[client["bssid"]] = counts.get(client["bssid"], 0) + 1
        for row in state.store.list_aps(state.session_id):
            if row["bssid"] not in known:
                known[row["bssid"]] = _ap_from_row(row, counts.get(row["bssid"], 0))
        for ap in known.values():
            ap["clients"] = counts.get(ap["bssid"], 0)
        items = sorted(known.values(), key=lambda a: a.get("power") or -100, reverse=True)
        return {
            "status": snapshot["status"],
            "aps": items,
            "clients": snapshot["clients"] or db_clients,
        }

    @app.get("/api/aps/{bssid}")
    async def ap_detail(bssid: str):
        bssid = bssid.lower()
        row = state.store.get_ap(state.session_id, bssid)
        clients = [c for c in state.store.list_clients(state.session_id, bssid)]
        if not row and not clients:
            raise HTTPException(status_code=404, detail="未找到该 AP")
        detail = _ap_from_row(row, len(clients)) if row else {
            "bssid": bssid,
            "ssid": "",
            "security": "UNKNOWN",
        }
        captures = [c for c in state.store.list_captures(state.session_id) if c.get("bssid") == bssid]
        findings = [f for f in state.store.list_findings(state.session_id) if f.get("bssid") == bssid]
        return {"ap": detail, "clients": clients, "captures": captures, "findings": findings}

    @app.get("/api/clients")
    async def clients():
        return {"clients": state.store.list_clients(state.session_id)}

    # ------------------------------------------------------------------ 攻击
    @app.get("/api/attacks")
    async def attack_modules():
        if not state.attacks:
            raise RuntimeError("攻击管理器未初始化")
        return {
            "modules": state.attacks.modules(),
            "active": state.attacks.active_job.to_dict() if state.attacks.active_job else None,
            "jobs": state.attacks.jobs(20),
        }

    @app.post("/api/attacks/{module_id}/start")
    async def attack_start(module_id: str, body: AttackRequest):
        if not state.attacks:
            raise RuntimeError("攻击管理器未初始化")
        params: dict[str, Any] = {
            "bssid": body.bssid,
            "ssid": body.ssid,
            "channel": body.channel,
            "security": body.security,
            "wps": body.wps,
        }
        params.update(body.options or {})
        job = await state.attacks.start(module_id, params)
        return job.to_dict()

    @app.post("/api/attacks/stop")
    async def attack_stop(body: StopAttackRequest | None = None):
        if not state.attacks:
            raise RuntimeError("攻击管理器未初始化")
        job_id = body.job_id if body else None
        stopped = await state.attacks.stop(job_id)
        active = state.attacks.active_job
        return {"stopped": stopped, "active": active.to_dict() if active else None}

    @app.get("/api/attacks/jobs")
    async def attack_jobs(limit: int = Query(default=20, ge=1, le=200)):
        if not state.attacks:
            return {"jobs": []}
        return {"jobs": state.attacks.jobs(limit)}

    # ------------------------------------------------------------------ 抓包/破解
    @app.get("/api/captures")
    async def captures():
        items = state.store.list_captures(state.session_id)
        for item in items:
            path = Path(item["path"])
            item["filename"] = path.name
            item["exists"] = path.exists()
        return {"captures": items}

    @app.get("/api/captures/{capture_id}/download")
    async def capture_download(capture_id: int):
        capture = state.store.get_capture(capture_id)
        if not capture:
            raise HTTPException(status_code=404, detail="抓包不存在")
        path = Path(capture["path"]).resolve()
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="抓包文件已丢失")
        if not path.is_relative_to(Path(state.config.capture_path).resolve()):
            raise PermissionError("抓包路径不在允许目录内")
        return FileResponse(path, filename=path.name)

    @app.post("/api/captures/{capture_id}/crack")
    async def crack_capture(capture_id: int, body: CrackRequest):
        if not state.cracks:
            raise RuntimeError("破解管理器未初始化")
        config = state.config
        expected = Path(config.capture_path).resolve()
        capture = state.store.get_capture(capture_id)
        if not capture:
            raise HTTPException(status_code=404, detail="抓包不存在")
        if not Path(capture["path"]).resolve().is_relative_to(expected):
            raise PermissionError("抓包路径不在允许目录内")
        job_id = await state.cracks.start(
            capture_id, wordlist=body.wordlist, method=body.method
        )
        return {"job_id": job_id}

    @app.get("/api/cracks")
    async def cracks():
        return {
            "cracks": state.store.list_cracks_for_session(state.session_id, 50),
            "active": state.cracks.active if state.cracks else [],
        }

    @app.post("/api/cracks/{job_id}/stop")
    async def crack_stop(job_id: int):
        if not state.cracks:
            raise RuntimeError("破解管理器未初始化")
        return {"stopped": await state.cracks.stop(job_id)}

    # ------------------------------------------------------------------ 数据
    @app.get("/api/credentials")
    async def credentials():
        return {"credentials": state.store.list_credentials(state.session_id)}

    @app.get("/api/findings")
    async def findings():
        return {"findings": state.store.list_findings(state.session_id)}

    @app.get("/api/events")
    async def events(limit: int = Query(default=200, ge=1, le=1000)):
        return {"events": state.bus.history(limit)}

    @app.get("/api/session")
    async def session_info():
        return {
            "session": state.store.get_session(state.session_id),
            "stats": state.store.stats(state.session_id),
        }

    @app.get("/api/session/export")
    async def session_export():
        return state.store.session_export(state.session_id)

    @app.post("/api/session/notes")
    async def save_notes(body: NotesRequest):
        state.store._execute(
            "UPDATE sessions SET notes=? WHERE id=?", (body.notes, state.session_id)
        )
        return {"ok": True}

    # ------------------------------------------------------------------ 门户
    @app.get("/api/portal")
    async def portal_status():
        return state.portal_info()

    @app.post("/api/portal/open")
    async def portal_open(body: PortalRequest):
        return await state.open_portal(ssid=body.ssid, title=body.title, port=body.port)

    @app.post("/api/portal/stop")
    async def portal_stop():
        return await state.close_portal()

    # ------------------------------------------------------------------ 报告
    def _report() -> ReportGenerator:
        return ReportGenerator(state.store, state.session_id)

    @app.get("/api/report/html", response_class=HTMLResponse)
    async def report_html():
        return HTMLResponse(_report().html())

    @app.get("/api/report/json")
    async def report_json():
        return JSONResponse(_report().json())

    @app.get("/api/report/md", response_class=PlainTextResponse)
    async def report_md():
        return PlainTextResponse(_report().markdown())

    @app.post("/api/report/save")
    async def report_save():
        paths = _report().save(state.config.report_path)
        state.bus.emit("success", "report", "报告已生成", paths=paths)
        return {"paths": paths}

    @app.get("/api/report/files")
    async def report_files():
        directory = Path(state.config.report_path)
        if not directory.exists():
            return {"files": []}
        files = sorted(
            (
                {"name": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime}
                for p in directory.iterdir()
                if p.is_file()
            ),
            key=lambda f: f["mtime"],
            reverse=True,
        )
        return {"files": files[:100]}

    @app.get("/api/report/download/{name}")
    async def report_download(name: str):
        safe = Path(name).name
        path = Path(state.config.report_path) / safe
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="报告不存在")
        return FileResponse(path, filename=safe)

    # ------------------------------------------------------------------ WS
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        queue = state.bus.subscribe()
        sender: asyncio.Task | None = None
        receiver: asyncio.Task | None = None

        async def send_loop() -> None:
            while True:
                event = await queue.get()
                await websocket.send_json({"type": "event", "event": event.to_dict()})

        async def recv_loop() -> None:
            while True:
                message = await websocket.receive_text()
                if message == "ping":
                    await websocket.send_json({"type": "pong", "ts": time.time()})
                elif message == "status":
                    await websocket.send_json(
                        {"type": "status", "ts": time.time(), "mode": state.config.mode}
                    )

        try:
            await websocket.send_json(
                {
                    "type": "hello",
                    "version": wraith.__version__,
                    "mode": state.config.mode,
                    "authorized": state.gate.authorized,
                    "session_id": state.session_id,
                }
            )
            for event in state.bus.history(80):
                await websocket.send_json({"type": "event", "event": event})
            sender = asyncio.create_task(send_loop())
            receiver = asyncio.create_task(recv_loop())
            done, pending = await asyncio.wait(
                {sender, receiver}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, WebSocketDisconnect):
                    pass
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001
            pass
        finally:
            for task in (sender, receiver):
                if task and not task.done():
                    task.cancel()
            state.bus.unsubscribe(queue)

    return app
