"""攻击任务编排：单任务执行、参数清洗、授权校验、事件与日志。"""

from __future__ import annotations

import asyncio
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..authorization import AuthorizationGate
from ..config import Config
from ..events import EventBus
from ..store import Store
from ..system.iface import IfaceManager
from ..system.runner import Runner
from . import get_module, list_modules
from .base import AttackContext, AttackModule, AttackResult


@dataclass
class AttackJob:
    id: str
    module_id: str
    name: str
    target: dict[str, Any]
    params: dict[str, Any]
    status: str = "queued"  # queued | running | success | failed | stopped
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    result: dict[str, Any] | None = None
    error: str = ""
    log: list[str] = field(default_factory=list)

    def to_dict(self, with_log: bool = True) -> dict[str, Any]:
        data = {
            "id": self.id,
            "module_id": self.module_id,
            "name": self.name,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "seconds": round((self.finished_at or time.time()) - self.started_at, 1),
        }
        if with_log:
            data["log"] = self.log[-200:]
        return data


class AttackManager:
    def __init__(
        self,
        config: Config,
        store: Store,
        bus: EventBus,
        runner: Runner,
        iface_mgr: IfaceManager,
        gate: AuthorizationGate,
        session_id: int,
        scanner: Any = None,
    ) -> None:
        self.config = config
        self.store = store
        self.bus = bus
        self.runner = runner
        self.iface_mgr = iface_mgr
        self.gate = gate
        self.session_id = session_id
        self.scanner = scanner
        self._active: str | None = None
        self._tasks: dict[str, asyncio.Task] = {}
        self._jobs: dict[str, AttackJob] = {}
        self._active_portal: Any = None

    # ------------------------------------------------------------------ 状态
    @property
    def active_job(self) -> AttackJob | None:
        if not self._active:
            return None
        job = self._jobs.get(self._active)
        if job and job.status in {"queued", "running"}:
            return job
        return None

    def get(self, job_id: str) -> AttackJob | None:
        return self._jobs.get(job_id)

    @property
    def active_portal(self) -> Any:
        if self._active_portal is not None and getattr(self._active_portal, "running", False):
            return self._active_portal
        return None

    def _register_portal(self, portal: Any) -> None:
        self._active_portal = portal

    def jobs(self, limit: int = 20) -> list[dict[str, Any]]:
        ordered = sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)
        return [job.to_dict(with_log=False) for job in ordered[:limit]]

    # ------------------------------------------------------------------ 启动
    async def start(self, module_id: str, raw_params: dict[str, Any]) -> AttackJob:
        if self.active_job:
            raise RuntimeError(f"已有攻击正在运行：{self.active_job.name}，请先停止")
        module: AttackModule = get_module(module_id)
        params = module.clean(raw_params)

        bssid = (params.get("bssid") or "").lower()
        ap = self.store.get_ap(self.session_id, bssid) if bssid else None
        if ap:
            params.setdefault("ssid", ap.get("ssid") or "")
            if not params.get("channel"):
                params["channel"] = ap.get("channel") or 0
            if not params.get("security"):
                params["security"] = _security_of(ap)
            if "wps" not in params:
                params["wps"] = bool(ap.get("wps"))

        issues = module.validate(params)
        if issues:
            raise ValueError("；".join(issues))

        decision = self.gate.check(module.id, bssid=bssid, ssid=params.get("ssid", ""))
        if not decision.allowed:
            self.gate.audit_target(module.id, bssid, params.get("ssid", ""))
            raise PermissionError(decision.reason)

        preflight = module.preflight(
            AttackContext(
                config=self.config,
                bus=self.bus,
                store=self.store,
                runner=self.runner,
                iface_mgr=self.iface_mgr,
                gate=self.gate,
                session_id=self.session_id,
                scanner=self.scanner,
            )
        )
        if preflight:
            raise RuntimeError("；".join(preflight))

        # 攻击要独占无线网卡：任何攻击都先停扫描。邪恶双胞胎虽然不需要监听模式，
        # 但它要在同一块射频上建 AP，扫描（monitor + 跳信道）会直接让 hostapd
        # 设置 beacon 失败（-16 Device or resource busy）。
        if self.scanner and getattr(self.scanner, "running", False):
            await self.scanner.stop()
            self.bus.emit("info", "attack", "已暂停扫描以释放无线网卡")

        job = AttackJob(
            id=uuid.uuid4().hex[:10],
            module_id=module_id,
            name=module.name,
            target={
                "bssid": bssid,
                "ssid": params.get("ssid", ""),
                "channel": params.get("channel", 0),
            },
            params=params,
        )
        self._jobs[job.id] = job
        self._active = job.id
        job.status = "running"
        self.bus.emit(
            "attack",
            "attack",
            f"▶ 攻击开始：{module.name} → {params.get('ssid') or bssid or '全局'}",
            job_id=job.id,
            module=module_id,
            target=job.target,
        )
        self._tasks[job.id] = asyncio.create_task(self._run(job, module, params))
        return job

    async def _run(self, job: AttackJob, module: AttackModule, params: dict[str, Any]) -> None:
        ctx = AttackContext(
            config=self.config,
            bus=self.bus,
            store=self.store,
            runner=self.runner,
            iface_mgr=self.iface_mgr,
            gate=self.gate,
            session_id=self.session_id,
            scanner=self.scanner,
            log_sink=self._log_sink(job),
            portal_sink=self._register_portal,
        )
        try:
            result: AttackResult = await module.run(ctx, params)
            job.result = result.to_dict()
            job.status = "success" if result.ok else "failed"
            job.finished_at = time.time()
            self.bus.emit(
                "success" if result.ok else "warning",
                "attack",
                f"{'✅' if result.ok else '⚠️'} 攻击结束：{result.summary}",
                job_id=job.id,
                result=result.to_dict(),
            )
        except asyncio.CancelledError:
            job.status = "stopped"
            job.finished_at = time.time()
            job.result = AttackResult(
                ok=False,
                summary=f"任务已手动停止（运行 {int(job.finished_at - job.started_at)}s，未跑完完整流程）",
                detail={"stopped": True},
                duration=job.finished_at - job.started_at,
            ).to_dict()
            self.bus.emit(
                "warning",
                "attack",
                f"攻击已停止：{job.name}",
                job_id=job.id,
                result=job.result,
            )
            raise
        except PermissionError as exc:
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = time.time()
            self.bus.emit("error", "attack", f"授权拒绝：{exc}", job_id=job.id)
        except Exception as exc:  # noqa: BLE001
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = time.time()
            detail = traceback.format_exc()[-1200:]
            job.log.append(detail)
            self.bus.emit("error", "attack", f"攻击失败：{exc}", job_id=job.id, traceback=detail)
        finally:
            if self._active == job.id:
                self._active = None
            self._tasks.pop(job.id, None)
            # 释放监听模式：否则攻击结束后网卡会一直停在 wlan0mon，
            # NetworkManager 再拿不回设备（真实环境实测：握手攻击后 wlan0 直接消失）。
            if not ctx.demo and ctx.monitor_iface:
                try:
                    await self.iface_mgr.disable_monitor(ctx.monitor_iface)
                except Exception:  # noqa: BLE001
                    pass
                ctx.monitor_iface = ""
            try:
                if ctx.portal:
                    await ctx.portal.stop()
            except Exception:  # noqa: BLE001
                pass
            if self._active_portal is ctx.portal:
                self._active_portal = None

    def _log_sink(self, job: AttackJob):
        def sink(message: str) -> None:
            job.log.append(message)
            if len(job.log) > 400:
                del job.log[:100]

        return sink

    # ------------------------------------------------------------------ 停止
    async def stop(self, job_id: str | None = None) -> bool:
        target = job_id or self._active
        if not target:
            return False
        task = self._tasks.get(target)
        job = self._jobs.get(target)
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=6)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        if job and job.status in {"running", "queued"}:
            job.status = "stopped"
            job.finished_at = time.time()
        return True

    async def stop_all(self) -> None:
        for job_id in list(self._tasks):
            await self.stop(job_id)

    # ------------------------------------------------------------------ 列表
    def modules(self) -> list[dict[str, Any]]:
        return list_modules()


def _security_of(ap: dict[str, Any]) -> str:
    from ..models import classify_security

    return classify_security(ap.get("privacy"), ap.get("auth"), ap.get("cipher"))
