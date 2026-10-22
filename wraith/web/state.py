"""Web 应用运行时状态：装配各子系统，管理生命周期。"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import wraith
from ..attacks import list_modules
from ..attacks.manager import AttackManager
from ..attacks.portal import PortalServer
from ..authorization import AuthorizationGate
from ..config import Config
from ..crack.manager import CrackManager
from ..events import EventBus
from ..mcp.specs import TOOL_SPECS
from ..models import Credential, Session
from ..recon.demo import DEMO_WORDLIST
from ..recon.scanner import Scanner
from ..store import Store
from ..system import deps
from ..system.iface import IfaceManager
from ..system.runner import Runner


class AppState:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.config.ensure_dirs()
        self.started_at = time.time()
        self.bus = EventBus()
        self.store = Store(config.db_path)
        self.gate = AuthorizationGate(config, self.bus)
        self.runner = Runner(dry_run=not config.is_live, audit=self._audit_command)
        self.iface_mgr = IfaceManager(self.runner)
        self.session_id = 0
        self.scanner: Scanner | None = None
        self.attacks: AttackManager | None = None
        self.cracks: CrackManager | None = None
        self.portal: PortalServer | None = None

    # ------------------------------------------------------------------ 生命周期
    async def start(self) -> None:
        self.bus.bind_loop(asyncio.get_running_loop())
        # 旧版本只用一张很小的 OUI 表，历史会话里会残留大量 Unknown；
        # 启动时用随包分发的完整 OUI 库回填一次。
        try:
            self.store.backfill_vendors()
        except Exception:  # noqa: BLE001 - 回填失败不应阻塞启动
            pass
        session = Session(
            name=time.strftime("无线评估 %Y-%m-%d %H:%M"),
            mode=self.config.mode,
            iface=self.config.iface,
            operator=self.config.operator,
        )
        self.session_id = self.store.create_session(session)
        self.scanner = Scanner(
            self.config, self.store, self.bus, self.runner, self.iface_mgr, self.session_id
        )
        self.attacks = AttackManager(
            self.config,
            self.store,
            self.bus,
            self.runner,
            self.iface_mgr,
            self.gate,
            self.session_id,
            scanner=self.scanner,
        )
        self.cracks = CrackManager(
            self.config, self.store, self.bus, self.runner, self.session_id
        )
        self._prepare_demo_wordlist()
        self.bus.emit(
            "info",
            "system",
            f"Wraith v{wraith.__version__} 已启动 · {self.config.mode} 模式 · 会话 #{self.session_id}",
            session_id=self.session_id,
        )
        if not self.config.is_live:
            self.bus.emit(
                "warning",
                "system",
                "当前为演示模式：所有攻击均在模拟环境执行，不会触碰真实无线设备",
            )
        elif not self.config.authorized:
            self.bus.emit(
                "warning",
                "system",
                "live 模式尚未授权：执行攻击前需在「设置」中输入 AUTHORIZED 完成授权确认",
            )

    async def shutdown(self) -> None:
        try:
            if self.attacks:
                await self.attacks.stop_all()
            if self.scanner:
                await self.scanner.stop()
            if self.portal:
                await self.portal.stop()
        finally:
            if self.session_id:
                self.store.end_session(self.session_id)
            self.bus.emit("info", "system", "Wraith 已关闭")
            self.store.close()

    # ------------------------------------------------------------------ 工具
    def _audit_command(self, record: dict[str, Any]) -> None:
        try:
            path = self.config.data_path / "commands.jsonl"
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.time(), **record}, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _prepare_demo_wordlist(self) -> None:
        """演示模式使用内置小字典，保证「捕获 → 破解」闭环可体验。"""
        demo_path = self.config.data_path / "wordlists" / "demo.txt"
        demo_path.parent.mkdir(parents=True, exist_ok=True)
        if not demo_path.exists():
            demo_path.write_text("\n".join(DEMO_WORDLIST) + "\n", encoding="utf-8")
        if not self.config.is_live:
            current = Path(self.config.wordlist)
            if not current.exists() or current.stat().st_size > 2 * 1024 * 1024:
                self.config.wordlist = str(demo_path)

    def set_mode(self, mode: str) -> dict[str, Any]:
        if mode not in {"demo", "live"}:
            raise ValueError("模式只能是 demo 或 live")
        if self.scanner and self.scanner.running:
            raise RuntimeError("请先停止扫描再切换模式")
        self.config.mode = mode
        self.runner.dry_run = mode != "live"
        try:
            self.config.save()
        except OSError:
            pass
        self.bus.emit(
            "warning",
            "system",
            f"已切换到 {mode} 模式"
            + ("（模拟执行）" if mode == "demo" else "（将对真实无线设备发包）"),
            mode=mode,
        )
        return self.config.public_dict()

    # ------------------------------------------------------------------ 端口
    async def open_portal(
        self,
        *,
        ssid: str = "Wraith-Guest",
        title: str = "Wi-Fi 网络认证",
        port: int | None = None,
    ) -> dict[str, Any]:
        if self.portal and self.portal.running:
            return {"running": True, "url": self.portal.url, "port": self.portal.port}
        self.portal = PortalServer(
            host="127.0.0.1" if not self.config.is_live else "0.0.0.0",
            port=port if port is not None else (0 if not self.config.is_live else self.config.portal_port),
            ssid=ssid,
            title=title,
            on_credential=self._credential_handler(ssid),
            template_path=self.config.data_path / "portal" / "index.html",
        )
        bound = await self.portal.start()
        self.bus.emit("success", "portal", f"门户已启动：{self.portal.url}", url=self.portal.url)
        return {"running": True, "url": self.portal.url, "port": bound}

    async def close_portal(self) -> dict[str, Any]:
        if self.portal:
            await self.portal.stop()
            self.portal = None
            self.bus.emit("info", "portal", "门户已关闭")
        return {"running": False}

    def _credential_handler(self, label: str):
        def handler(record: dict[str, Any]) -> None:
            cred = Credential(
                session_id=self.session_id,
                username=record.get("username", ""),
                password=record.get("password", ""),
                portal=label,
                ip=record.get("ip", ""),
                user_agent=record.get("user_agent", ""),
            )
            cred_id = self.store.add_credential(cred)
            self.bus.emit(
                "success",
                "portal",
                f"🎯 门户捕获凭证 #{cred_id}：{record.get('username')} / {record.get('password')}",
                credential_id=cred_id,
            )

        return handler

    # ------------------------------------------------------------------ 快照
    def portal_info(self) -> dict[str, Any]:
        portal = None
        source = ""
        if self.portal and self.portal.running:
            portal, source = self.portal, "standalone"
        elif self.attacks and self.attacks.active_portal:
            portal, source = self.attacks.active_portal, "attack"
        if not portal:
            return {"running": False}
        return {
            "running": True,
            "url": portal.url,
            "port": portal.port,
            "source": source,
            "hits": portal.stats.hits,
            "submissions": portal.stats.submissions,
        }

    def attack_info(self) -> dict[str, Any]:
        active = self.attacks.active_job if self.attacks else None
        return {
            "active": active.to_dict() if active else None,
            "jobs": self.attacks.jobs(15) if self.attacks else [],
        }

    async def system_info(self) -> dict[str, Any]:
        interfaces = await self.iface_mgr.list_interfaces()
        return {
            "app": "Wraith",
            "version": wraith.__version__,
            "mode": self.config.mode,
            "demo": not self.config.is_live,
            "root": self.iface_mgr.is_root(),
            "session": self.store.get_session(self.session_id),
            "stats": self.store.stats(self.session_id),
            "config": self.config.public_dict(),
            "auth": self.gate.status(),
            "scanner": self.scanner.status() if self.scanner else {},
            "interfaces": [i.to_dict() for i in interfaces],
            "portal": self.portal_info(),
            "attack": self.attack_info(),
            "crack_active": self.cracks.active if self.cracks else [],
            "deps": deps.doctor(),
            "mcp": {
                "enabled": True,
                "endpoint": "/mcp",
                "transports": ["stdio", "streamable-http"],
                "stdio_command": "wraith mcp --demo",
                "tool_count": len(TOOL_SPECS),
                "audit_path": str(self.config.data_path / "mcp-audit.jsonl"),
            },
            "uptime": round(time.time() - self.started_at, 1),
        }

    async def overview(self) -> dict[str, Any]:
        snapshot = self.scanner.snapshot() if self.scanner else {"status": {}, "aps": [], "clients": []}
        return {
            "system": await self.system_info(),
            "scanner": snapshot["status"],
            "aps": snapshot["aps"],
            "clients": snapshot["clients"],
            "captures": self.store.list_captures(self.session_id),
            "cracks": self.store.list_cracks(30),
            "findings": self.store.list_findings(self.session_id),
            "credentials": self.store.list_credentials(self.session_id),
            "events": self.bus.history(250),
            "modules": list_modules(),
        }
