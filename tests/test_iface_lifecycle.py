"""网卡生命周期回归测试：连续攻击之间 airmon-ng 改名/重建导致的接口名失效."""

from __future__ import annotations

import pytest

from wraith.attacks.pmkid import build_hcxdumptool_cmd
from wraith.system.iface import IfaceManager
from wraith.system.runner import CommandResult


class FakeRunner:
    """用内存里的接口表模拟 iw / airmon-ng / ip 的行为."""

    dry_run = True

    def __init__(self, world: dict[str, str], *, keep_monitor_on_stop: bool = False) -> None:
        self.world = dict(world)
        self.keep_monitor_on_stop = keep_monitor_on_stop
        self.calls: list[list[str]] = []
        self.version = "hcxdumptool 7.1.2 (C) 2026 ZeroBeat"

    async def _exec(self, cmd, timeout: float = 8.0) -> CommandResult:
        self.calls.append(list(cmd))
        op = cmd[0]
        if op == "hcxdumptool" and "--version" in cmd:
            return CommandResult(list(cmd), 0, stdout=self.version)
        if op == "iw" and len(cmd) >= 2 and cmd[1] == "phy":
            return CommandResult(
                list(cmd), 0,
                stdout="\tSupported interface modes:\n\t\t * managed\n\t\t * monitor\n\t\t * AP\nBand 1:",
            )
        if op == "iw" and len(cmd) >= 2 and cmd[1] == "dev":
            if len(cmd) == 2:  # iw dev
                lines: list[str] = []
                for name, kind in self.world.items():
                    lines += [
                        "phy#6",
                        f"\tInterface {name}",
                        f"\t\ttype {kind}",
                        "\t\tchannel 6 (2437 MHz), width: 20 MHz",
                        "\t\taddr aa:bb:cc:dd:ee:ff",
                    ]
                return CommandResult(list(cmd), 0, stdout="\n".join(lines))
            name = cmd[2]
            if "del" in cmd:
                self.world.pop(name, None)
                return CommandResult(list(cmd), 0)
            if "type" in cmd:
                if name not in self.world:
                    return CommandResult(list(cmd), 1, stderr=f'command failed: No such device ({name})')
                self.world[name] = cmd[cmd.index("type") + 1]
            if "name" in cmd:
                new = cmd[cmd.index("name") + 1]
                if name not in self.world:
                    return CommandResult(list(cmd), 1, stderr=f'command failed: No such device ({name})')
                self.world[new] = self.world.pop(name)
            return CommandResult(list(cmd), 0)
        if op == "airmon-ng" and len(cmd) >= 3 and cmd[1] in {"start", "stop"}:
            name = cmd[2]
            if cmd[1] == "start":
                if name not in self.world:
                    return CommandResult(list(cmd), 1, stderr="No such device")
                self.world.pop(name, None)
                self.world[name + "mon"] = "monitor"
            else:
                monitor = name
                base = monitor[:-3] if monitor.endswith("mon") else monitor
                self.world.pop(monitor, None)
                self.world[base] = "managed"
                if self.keep_monitor_on_stop:  # 模拟 airmon-ng 返回 0 但遗留 monitor vif
                    self.world[monitor] = "monitor"
            return CommandResult(list(cmd), 0)
        if op == "ip" and len(cmd) >= 4 and cmd[1:3] == ["link", "set"]:
            if cmd[3] == "up" and cmd[2] not in self.world:
                return CommandResult(list(cmd), 1, stderr=f'Cannot find device "{cmd[2]}"')
            return CommandResult(list(cmd), 0)
        return CommandResult(list(cmd), 0)

    async def query(self, cmd, timeout: float = 8.0) -> CommandResult:
        return await self._exec(cmd, timeout)

    async def run(self, cmd, timeout: float = 8.0) -> CommandResult:
        return await self._exec(cmd, timeout)


@pytest.fixture()
def mgr():
    def build(world, **kw):
        runner = FakeRunner(world, **kw)
        manager = IfaceManager(runner)
        manager.settle_timeout = 0.05
        return manager, runner

    return build


@pytest.mark.asyncio
async def test_enable_monitor_re_resolves_stale_name(mgr):
    """上一次攻击后 wlan0mon 已消失、只剩 wlan0 时，应按新名字重新开监听."""
    manager, runner = mgr({"wlan0": "managed"})

    monitor = await manager.enable_monitor("wlan0mon")

    assert monitor == "wlan0mon"
    assert runner.world == {"wlan0mon": "monitor"}
    assert manager._monitor_map["wlan0mon"] == "wlan0"


@pytest.mark.asyncio
async def test_enable_monitor_raises_clear_error_without_adapter(mgr):
    manager, _ = mgr({})
    with pytest.raises(RuntimeError, match="没有其他支持 monitor 的网卡"):
        await manager.enable_monitor("wlan0")


@pytest.mark.asyncio
async def test_disable_monitor_cleans_leftover_vif(mgr):
    """airmon-ng stop 返回 0 但把 wlan0mon 留着时，必须清掉以免下次解析到失效名字."""
    manager, runner = mgr({"wlan0mon": "monitor"}, keep_monitor_on_stop=True)
    manager._monitor_map["wlan0mon"] = "wlan0"
    manager._orig_map["wlan0"] = "wlan0mon"

    original = await manager.disable_monitor("wlan0mon")

    assert original == "wlan0"
    assert runner.world == {"wlan0": "managed"}
    assert manager._monitor_map == {}


@pytest.mark.asyncio
async def test_enable_monitor_uses_existing_monitor_iface(mgr):
    manager, runner = mgr({"wlan0mon": "monitor"})
    assert await manager.enable_monitor("wlan0mon") == "wlan0mon"
    assert ["airmon-ng", "start", "wlan0mon"] not in runner.calls


@pytest.mark.asyncio
async def test_hcxdumptool_cmd_v7():
    runner = FakeRunner({})
    cmd = await build_hcxdumptool_cmd(runner, "wlan0mon", "/tmp/x.pcapng", 6)
    assert "--rds=3" in cmd
    assert "--enable_status=3" not in cmd
    assert cmd[cmd.index("-c") + 1] == "6a"


@pytest.mark.asyncio
async def test_hcxdumptool_cmd_v7_5ghz():
    runner = FakeRunner({})
    cmd = await build_hcxdumptool_cmd(runner, "wlan0mon", "/tmp/x.pcapng", 36)
    assert cmd[cmd.index("-c") + 1] == "36b"


@pytest.mark.asyncio
async def test_hcxdumptool_cmd_v6_keeps_legacy_flag():
    runner = FakeRunner({})
    runner.version = "hcxdumptool 6.2.0 (C) 2022 ZeroBeat"
    cmd = await build_hcxdumptool_cmd(runner, "wlan0mon", "/tmp/x.pcapng", 6)
    assert "--enable_status=3" in cmd
    assert "--rds=3" not in cmd
