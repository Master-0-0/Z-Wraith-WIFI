"""攻击模块基类、上下文与结果模型."""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import Config
from ..events import EventBus
from ..models import (
    ENTERPRISE_SUFFIX,
    TRANSITION,
    Capture,
    Finding,
    is_mac,
    normalize_mac,
)
from ..store import Store
from ..system.deps import is_installed
from ..system.iface import IfaceManager
from ..system.runner import Runner
from ..authorization import AuthorizationGate


# ---------------------------------------------------------------------------
# 选项与参数
# ---------------------------------------------------------------------------


@dataclass
class Option:
    name: str
    label: str
    type: str = "text"  # text | int | bool | select | textarea | password | mac
    default: Any = ""
    help: str = ""
    choices: list[str] = field(default_factory=list)
    required: bool = False
    placeholder: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "type": self.type,
            "default": self.default,
            "help": self.help,
            "choices": self.choices,
            "required": self.required,
            "placeholder": self.placeholder,
        }


class AttackContext:
    """一次攻击运行所需的全部依赖."""

    def __init__(
        self,
        *,
        config: Config,
        bus: EventBus,
        store: Store,
        runner: Runner,
        iface_mgr: IfaceManager,
        gate: AuthorizationGate,
        session_id: int,
        scanner: Any = None,
        log_sink: Callable[[str], None] | None = None,
        portal_sink: Callable[[Any], None] | None = None,
    ) -> None:
        self.config = config
        self.bus = bus
        self.store = store
        self.runner = runner
        self.iface_mgr = iface_mgr
        self.gate = gate
        self.session_id = session_id
        self.scanner = scanner
        self.log_sink = log_sink
        self.portal_sink = portal_sink
        self.monitor_iface = ""
        self.portal: Any = None

    def register_portal(self, portal: Any) -> None:
        """把运行中的门户暴露给上层（控制台/API）。"""
        self.portal = portal
        if self.portal_sink:
            try:
                self.portal_sink(portal)
            except Exception:  # noqa: BLE001
                pass

    @property
    def demo(self) -> bool:
        return not self.config.is_live

    # ------------------------------------------------------------------ 输出
    def emit(self, level: str, message: str, **data: Any) -> None:
        self.bus.emit(level, "attack", message, **data)
        if self.log_sink:
            try:
                self.log_sink(message)
            except Exception:  # noqa: BLE001
                pass

    def log(self, message: str) -> None:
        self.emit("debug", message)
        if self.log_sink:
            try:
                self.log_sink(message)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ 持久化
    def finding(
        self,
        title: str,
        severity: str,
        *,
        bssid: str = "",
        ssid: str = "",
        detail: str = "",
        category: str = "attack",
    ) -> int:
        fid = self.store.add_finding(
            Finding(
                session_id=self.session_id,
                title=title,
                severity=severity,
                bssid=bssid,
                ssid=ssid,
                detail=detail,
                category=category,
            )
        )
        self.emit(
            "success" if severity in {"critical", "high"} else "info",
            f"发现 [{severity.upper()}] {title}",
            finding_id=fid,
            bssid=bssid,
        )
        return fid

    def capture_path(self, kind: str, bssid: str, ext: str) -> Path:
        self.config.ensure_dirs()
        safe_bssid = bssid.replace(":", "") or "unknown"
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return self.config.capture_path / f"{kind}-{safe_bssid}-{stamp}.{ext}"

    def register_capture(
        self,
        kind: str,
        path: str | Path,
        *,
        bssid: str = "",
        ssid: str = "",
        meta: dict[str, Any] | None = None,
    ) -> int:
        p = Path(path)
        size = p.stat().st_size if p.exists() else 0
        hash_lines = 0
        if p.suffix in {".22000", ".hccapx"} and p.exists():
            hash_lines = sum(
                1
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.startswith("WPA*")
            )
        cap = Capture(
            kind=kind,
            path=str(p),
            bssid=normalize_mac(bssid) if bssid else "",
            ssid=ssid,
            size=size,
            hash_lines=hash_lines,
            session_id=self.session_id,
            meta=meta or {},
        )
        capture_id = self.store.add_capture(cap)
        self.emit(
            "success",
            f"已保存抓包 #{capture_id}: {p.name}"
            + (f"（{hash_lines} 条可用哈希）" if hash_lines else ""),
            capture_id=capture_id,
            path=str(p),
        )
        return capture_id

    # ------------------------------------------------------------------ 接口
    async def monitor(self) -> str:
        if self.demo:
            self.monitor_iface = self.monitor_iface or "demo0mon"
            return self.monitor_iface
        iface = await self.iface_mgr.resolve(self.config.iface)
        if not iface:
            raise RuntimeError("未找到可用无线网卡")
        self.monitor_iface = await self.iface_mgr.enable_monitor(iface.name)
        return self.monitor_iface

    async def set_channel(self, channel: int) -> None:
        if self.demo:
            return
        monitor = self.monitor_iface or await self.monitor()
        if channel:
            await self.iface_mgr.set_channel(monitor, channel)

    def authorize(self, action: str, bssid: str = "", ssid: str = "") -> None:
        decision = self.gate.audit_target(action, bssid, ssid)
        if not decision.allowed:
            raise PermissionError(decision.reason)

    async def pause(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


@dataclass
class AttackResult:
    ok: bool
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    capture_id: int | None = None
    findings: list[int] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "summary": self.summary,
            "detail": self.detail,
            "capture_id": self.capture_id,
            "findings": self.findings,
            "duration": round(self.duration, 2),
        }


# ---------------------------------------------------------------------------
# 基类
# ---------------------------------------------------------------------------


class AttackModule:
    id: str = ""
    name: str = ""
    category: str = "attack"
    description: str = ""
    requires: tuple[str, ...] = ()
    risk: str = "medium"
    demo_supported: bool = True
    needs_monitor: bool = True
    options: list[Option] = []

    # ------------------------------------------------------------------ 元数据
    @classmethod
    def to_dict(cls) -> dict[str, Any]:
        return {
            "id": cls.id,
            "name": cls.name,
            "category": cls.category,
            "description": cls.description,
            "requires": list(cls.requires),
            "risk": cls.risk,
            "demo_supported": cls.demo_supported,
            "needs_monitor": cls.needs_monitor,
            "options": [opt.to_dict() for opt in cls.options],
            "available": all(is_installed(dep) for dep in cls.requires) if cls.requires else True,
        }

    # ------------------------------------------------------------------ 校验
    def preflight(self, ctx: AttackContext) -> list[str]:
        issues: list[str] = []
        if ctx.demo:
            return issues
        for dep in self.requires:
            if not is_installed(dep):
                issues.append(f"缺少依赖工具：{dep}")
        if self.needs_monitor and not os.geteuid() == 0:
            issues.append("需要 root 权限来切换监听模式（请用 sudo 启动或使用演示模式）")
        return issues

    def validate(self, params: dict[str, Any]) -> list[str]:
        issues: list[str] = []
        bssid = params.get("bssid") or ""
        if not is_mac(bssid):
            issues.append("目标 BSSID 无效")
        channel = params.get("channel")
        if channel is not None and channel != "":
            try:
                ch = int(channel)
                if not 1 <= ch <= 233:
                    issues.append("信道需在 1-233 之间")
            except (TypeError, ValueError):
                issues.append("信道必须为整数")
        return issues

    def clean(self, params: dict[str, Any]) -> dict[str, Any]:
        cleaned = dict(params or {})
        for opt in self.options:
            if opt.name not in cleaned or cleaned[opt.name] in (None, ""):
                cleaned[opt.name] = opt.default
                continue
            value = cleaned[opt.name]
            if opt.type == "int":
                try:
                    cleaned[opt.name] = int(value)
                except (TypeError, ValueError):
                    cleaned[opt.name] = opt.default
            elif opt.type == "bool":
                if isinstance(value, str):
                    cleaned[opt.name] = value.strip().lower() in {"1", "true", "yes", "on"}
                else:
                    cleaned[opt.name] = bool(value)
        return cleaned

    async def run(self, ctx: AttackContext, params: dict[str, Any]) -> AttackResult:
        raise NotImplementedError

    # ------------------------------------------------------------------ 辅助
    @staticmethod
    def target_of(params: dict[str, Any]) -> dict[str, Any]:
        return {
            "bssid": (params.get("bssid") or "").lower(),
            "ssid": params.get("ssid") or "",
            "channel": int(params.get("channel") or 0),
        }


def security_hint(security: str) -> str:
    if security.endswith(ENTERPRISE_SUFFIX):
        return "enterprise"
    if security == TRANSITION:
        return "transition"
    return security.lower()
