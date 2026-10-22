"""无线网卡管理：枚举、能力、监听模式、信道、AP 模式。"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .runner import Runner

_IFACE_RE = re.compile(r"^\s*Interface\s+(\S+)\s*$")
_PHY_RE = re.compile(r"^phy#(\d+)\s*$")
_TYPE_RE = re.compile(r"^\s*type\s+(\S+)\s*$")
_CHAN_RE = re.compile(r"^\s*channel\s+(\d+)\s*\((\d+)\s*MHz\)")
_ADDR_RE = re.compile(r"^\s*addr\s+([0-9a-fA-F:]{17})")


@dataclass
class IfaceInfo:
    name: str
    phy: str = ""
    mode: str = ""
    channel: int = 0
    frequency: int = 0
    mac: str = ""
    modes: list[str] = field(default_factory=list)

    @property
    def monitor_capable(self) -> bool:
        return "monitor" in self.modes

    @property
    def ap_capable(self) -> bool:
        return "AP" in self.modes

    @property
    def is_monitor(self) -> bool:
        return self.mode == "monitor"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "phy": self.phy,
            "mode": self.mode,
            "channel": self.channel,
            "frequency": self.frequency,
            "mac": self.mac,
            "monitor_capable": self.monitor_capable,
            "ap_capable": self.ap_capable,
            "is_monitor": self.is_monitor,
            "modes": self.modes,
        }


class IfaceManager:
    # 等待 airmon-ng 完成接口创建/销毁的窗口期（秒）；测试可调小
    settle_timeout: float = 5.0

    def __init__(self, runner: Runner) -> None:
        self.runner = runner
        self._monitor_map: dict[str, str] = {}  # monitor -> original
        self._orig_map: dict[str, str] = {}  # original -> monitor

    # ------------------------------------------------------------------ 查询
    @staticmethod
    def is_root() -> bool:
        return os.geteuid() == 0

    async def list_interfaces(self) -> list[IfaceInfo]:
        result = await self.runner.query(["iw", "dev"], timeout=8)
        if not result.ok:
            return []
        interfaces: list[IfaceInfo] = []
        current_phy = ""
        current: IfaceInfo | None = None
        for line in result.stdout.splitlines():
            phy_match = _PHY_RE.match(line)
            if phy_match:
                current_phy = f"phy{phy_match.group(1)}"
                continue
            iface_match = _IFACE_RE.match(line)
            if iface_match:
                current = IfaceInfo(name=iface_match.group(1), phy=current_phy)
                interfaces.append(current)
                continue
            if current is None:
                continue
            type_match = _TYPE_RE.match(line)
            if type_match:
                current.mode = type_match.group(1)
                continue
            chan_match = _CHAN_RE.match(line)
            if chan_match:
                current.channel = int(chan_match.group(1))
                current.frequency = int(chan_match.group(2))
                continue
            addr_match = _ADDR_RE.match(line)
            if addr_match:
                current.mac = addr_match.group(1).lower()
        # 补齐 phy 能力
        for iface in interfaces:
            if iface.phy:
                iface.modes = await self.phy_modes(iface.phy)
        return interfaces

    async def phy_modes(self, phy: str) -> list[str]:
        result = await self.runner.query(["iw", "phy", phy, "info"], timeout=8)
        if not result.ok:
            return []
        modes: list[str] = []
        in_modes = False
        for line in result.stdout.splitlines():
            if "Supported interface modes" in line:
                in_modes = True
                continue
            if in_modes:
                if "Band " in line:
                    break
                match = re.match(r"^\s*\*\s+(.+?)\s*$", line)
                if match:
                    modes.append(match.group(1))
                elif line.strip() and not line.startswith("\t\t"):
                    in_modes = False
        return modes

    async def info(self, name: str) -> IfaceInfo | None:
        for iface in await self.list_interfaces():
            if iface.name == name:
                return iface
        return None

    async def resolve(self, preferred: str = "") -> IfaceInfo | None:
        """选择可用网卡：优先配置网卡，其次第一个支持 monitor 的网卡。"""
        interfaces = await self.list_interfaces()
        if not interfaces:
            return None
        if preferred:
            for iface in interfaces:
                if iface.name == preferred:
                    return iface
        for iface in interfaces:
            if iface.monitor_capable and iface.mode != "monitor":
                return iface
        for iface in interfaces:
            if iface.monitor_capable:
                return iface
        return interfaces[0]

    # ------------------------------------------------------------------ 模式切换
    async def _wait_iface(self, name: str, timeout: float = 5.0) -> IfaceInfo | None:
        """等待接口出现（airmon-ng 的创建/销毁是异步的，两次动作之间常有窗口期）."""
        deadline = time.monotonic() + timeout
        while True:
            info = await self.info(name)
            if info is not None:
                return info
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.25)

    async def enable_monitor(self, name: str, manage_conflicts: bool = False) -> str:
        """开启监听模式，返回监听接口名.

        优先使用 ``airmon-ng``（兼容性好）；失败则回退到 ip/iw 手工流程。
        需要 root；非 root 会抛出 PermissionError。
        """
        if not self.is_root() and not self.runner.dry_run:
            raise PermissionError("开启监听模式需要 root 权限（请使用 sudo 运行，或使用演示模式）")

        if name in self._orig_map:
            return self._orig_map[name]

        current = await self.info(name)
        if current is None:
            # 上一次攻击收尾时 airmon-ng 可能把网卡改名/重建，调用方拿到的名字会短暂失效
            current = await self._wait_iface(name, self.settle_timeout)
        if current is None:
            replacement = None
            for candidate in await self.list_interfaces():
                if candidate.monitor_capable:
                    replacement = candidate
                    break
            if replacement is None:
                raise RuntimeError(f"无线网卡 {name} 已不存在，且没有其他支持 monitor 的网卡")
            name = replacement.name
            current = replacement
        if current.is_monitor:
            self._monitor_map[name] = name
            return name

        if manage_conflicts:
            await self.runner.run(["airmon-ng", "check", "kill"], timeout=20)

        before = {i.name for i in await self.list_interfaces()}
        result = await self.runner.run(["airmon-ng", "start", name], timeout=25)
        after = {i.name for i in await self.list_interfaces()}
        created = sorted(after - before)
        monitor_name = ""
        for candidate in created:
            info = await self.info(candidate)
            if info and info.is_monitor:
                monitor_name = candidate
                break
        if not monitor_name:
            match = re.search(r"monitor mode (?:enabled|vif enabled) on (\S+)", result.text)
            if match:
                monitor_name = match.group(1)
        if not monitor_name and result.ok:
            # airmon-ng 可能重命名原接口
            for candidate in after:
                info = await self.info(candidate)
                if info and info.is_monitor:
                    monitor_name = candidate
                    break

        if not monitor_name:
            # 回退：手工切换
            await self.runner.run(["ip", "link", "set", name, "down"], timeout=8)
            await self.runner.run(["iw", "dev", name, "set", "type", "monitor"], timeout=8)
            up = await self.runner.run(["ip", "link", "set", name, "up"], timeout=8)
            if not up.ok and not self.runner.dry_run:
                raise RuntimeError(f"无法将 {name} 切换为监听模式：{up.text[:300]}")
            monitor_name = name

        self._monitor_map[monitor_name] = name
        self._orig_map[name] = monitor_name
        return monitor_name

    async def disable_monitor(self, monitor_name: str) -> str:
        original = self._monitor_map.get(monitor_name)
        if not original:
            return monitor_name
        if monitor_name != original:
            stop = await self.runner.run(["airmon-ng", "stop", monitor_name], timeout=20)
            # airmon-ng 返回 0 不代表网卡已经回到 managed 状态，必须确认原名真的回来了，
            # 否则下一次攻击会拿到一个已失效的接口名（实测：handshake 紧接 deauth 时必现）。
            restored = await self._wait_iface(original, self.settle_timeout)
            if not stop.ok or restored is None or restored.is_monitor:
                # airmon-ng 失败时手工恢复，并尽量把名字改回去，
                # 否则后续按配置网卡名（wlan0）会解析不到设备。
                if await self.info(monitor_name) is not None:
                    await self.runner.run(["ip", "link", "set", monitor_name, "down"], timeout=8)
                    await self.runner.run(
                        ["iw", "dev", monitor_name, "set", "type", "managed"], timeout=8
                    )
                    if await self.info(original) is None:
                        await self.runner.run(
                            ["iw", "dev", monitor_name, "set", "name", original], timeout=8
                        )
                if await self.info(original) is not None:
                    await self.runner.run(["ip", "link", "set", original, "up"], timeout=8)
            # airmon-ng stop 有时会保留 monitor vif（wlan0 与 wlan0mon 同时存在）
            leftover = await self.info(monitor_name)
            if leftover is not None and leftover.is_monitor and await self.info(original) is not None:
                await self.runner.run(["iw", "dev", monitor_name, "del"], timeout=8)
        else:
            await self.runner.run(["ip", "link", "set", monitor_name, "down"], timeout=8)
            await self.runner.run(
                ["iw", "dev", monitor_name, "set", "type", "managed"], timeout=8
            )
            await self.runner.run(["ip", "link", "set", monitor_name, "up"], timeout=8)
        self._monitor_map.pop(monitor_name, None)
        self._orig_map.pop(original, None)
        return original

    async def set_channel(self, name: str, channel: int) -> bool:
        if not channel:
            return False
        result = await self.runner.run(["iw", "dev", name, "set", "channel", str(channel)], timeout=8)
        return result.ok

    async def set_type(self, name: str, iface_type: str) -> bool:
        await self.runner.run(["ip", "link", "set", name, "down"], timeout=8)
        result = await self.runner.run(["iw", "dev", name, "set", "type", iface_type], timeout=8)
        await self.runner.run(["ip", "link", "set", name, "up"], timeout=8)
        return result.ok

    async def set_mac(self, name: str, mac: str) -> bool:
        result = await self.runner.run(["macchanger", "-m", mac, name], timeout=10)
        return result.ok

    async def up(self, name: str) -> bool:
        result = await self.runner.run(["ip", "link", "set", name, "up"], timeout=8)
        return result.ok
