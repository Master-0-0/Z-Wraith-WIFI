"""授权门禁与审计日志.

设计目标：让"是否获得授权"成为一条**代码层面的强制路径**，而不是文档里的一句话。

规则
----
1. ``demo`` 模式：永远允许，但所有输出标记为「模拟」，不触碰真实无线设备。
2. ``live`` 模式：必须显式授权（``grant("AUTHORIZED")`` 或 ``WRAITH_AUTHORIZED=1``）。
3. 若配置了 ``scope``，目标 BSSID/SSID 必须命中范围，否则拒绝。
4. 每一次允许/拒绝都会写入 ``data/audit.jsonl``，包含操作者、动作、目标、时间。
"""

from __future__ import annotations

import fnmatch
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .events import EventBus

AUTH_TOKEN = "AUTHORIZED"


@dataclass
class AuthDecision:
    allowed: bool
    reason: str
    demo: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "demo": self.demo}


class AuthorizationGate:
    def __init__(self, config: Config, bus: EventBus | None = None) -> None:
        self.config = config
        self.bus = bus
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 状态
    @property
    def demo(self) -> bool:
        return not self.config.is_live

    @property
    def authorized(self) -> bool:
        return self.demo or bool(self.config.authorized)

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.config.mode,
            "demo": self.demo,
            "authorized": self.authorized,
            "operator": self.config.operator,
            "scope": list(self.config.scope),
            "token_hint": AUTH_TOKEN,
            "audit_path": str(self.config.audit_path),
        }

    # ------------------------------------------------------------------ 授权
    def grant(self, token: str, scope: list[str] | None = None) -> tuple[bool, str]:
        if token.strip().upper() != AUTH_TOKEN:
            return False, f"授权令牌不正确（请输入 {AUTH_TOKEN}）"
        self.config.authorized = True
        if scope is not None:
            self.config.scope = [s.strip() for s in scope if s.strip()]
        try:
            self.config.save()
        except OSError as exc:  # 只读目录下仍允许内存授权
            self._log("grant", allowed=True, reason=f"配置保存失败: {exc}")
        self._log("grant", allowed=True, reason="操作者确认已获得书面授权")
        if self.bus:
            self.bus.emit(
                "warning",
                "authorization",
                f"已启用 live 模式授权（操作者: {self.config.operator}，范围: "
                f"{', '.join(self.config.scope) if self.config.scope else '全部目标'}）",
            )
        return True, "授权已启用"

    def revoke(self) -> None:
        self.config.authorized = False
        try:
            self.config.save()
        except OSError:
            pass
        self._log("revoke", allowed=False, reason="操作者撤销授权")
        if self.bus:
            self.bus.emit("warning", "authorization", "live 模式授权已撤销")

    # ------------------------------------------------------------------ 校验
    def _scope_match(self, bssid: str, ssid: str) -> tuple[bool, str]:
        if not self.config.scope:
            return True, "未限制范围"
        bssid_l = (bssid or "").lower()
        bssid_hex = bssid_l.replace(":", "").replace("-", "")
        for entry in self.config.scope:
            e = entry.strip().lower()
            if not e:
                continue
            if e == "*":
                return True, "范围: *"
            cleaned = e.replace("-", ":").replace(".", ":")
            is_mac = ":" in cleaned and len(cleaned.replace(":", "")) >= 6
            if is_mac:
                prefix = cleaned.replace(":", "")
                if bssid_hex.startswith(prefix):
                    return True, f"BSSID 命中范围 {entry}"
            if ssid and fnmatch.fnmatch(ssid.lower(), e):
                return True, f"SSID 命中范围 {entry}"
        return False, f"目标不在授权范围 {self.config.scope} 内"

    def check(
        self,
        action: str,
        *,
        bssid: str = "",
        ssid: str = "",
        demo_allowed: bool = True,
    ) -> AuthDecision:
        if self.demo:
            if not demo_allowed:
                return AuthDecision(False, "演示模式不支持该操作", demo=True)
            return AuthDecision(True, "演示模式（模拟执行）", demo=True)
        if not self.config.authorized:
            return AuthDecision(
                False,
                f"live 模式需要先完成授权确认（输入 {AUTH_TOKEN}，或设置 WRAITH_AUTHORIZED=1）",
            )
        ok, reason = self._scope_match(bssid, ssid)
        if not ok:
            return AuthDecision(False, reason)
        return AuthDecision(True, reason)

    def require(self, action: str, *, bssid: str = "", ssid: str = "") -> None:
        decision = self.check(action, bssid=bssid, ssid=ssid)
        self._log(action, allowed=decision.allowed, bssid=bssid, ssid=ssid, reason=decision.reason)
        if not decision.allowed:
            raise PermissionError(decision.reason)

    # ------------------------------------------------------------------ 审计
    def _log(
        self,
        action: str,
        *,
        allowed: bool,
        bssid: str = "",
        ssid: str = "",
        reason: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "ts": time.time(),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "operator": self.config.operator,
            "mode": self.config.mode,
            "action": action,
            "bssid": bssid,
            "ssid": ssid,
            "allowed": allowed,
            "reason": reason,
            "detail": detail or {},
        }
        try:
            self.config.ensure_dirs()
            with self._lock:
                with Path(self.config.audit_path).open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass

    def audit_target(self, action: str, bssid: str, ssid: str) -> AuthDecision:
        decision = self.check(action, bssid=bssid, ssid=ssid)
        self._log(action, allowed=decision.allowed, bssid=bssid, ssid=ssid, reason=decision.reason)
        return decision

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        path = Path(self.config.audit_path)
        if not path.exists():
            return []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
