"""扫描引擎：airodump-ng（live）与内置演示环境（demo）.

CSV 解析器与驱动逻辑分离，便于单元测试（不依赖无线硬件）。
"""

from __future__ import annotations

import asyncio
import csv
import io
import random
import re
import time
from pathlib import Path
from typing import Any

from ..config import Config
from ..events import EventBus
from ..models import AP, Client, Finding, band_for_channel, is_mac
from ..store import Store
from ..system.deps import is_installed
from ..system.iface import IfaceManager
from ..system.runner import Runner
from .demo import DEMO_NETWORKS, DemoAP, demo_ap_object, demo_clients_for

HANDSHAKE_LINE_RE = re.compile(r"WPA handshake:\s*([0-9A-Fa-f:]{17})", re.IGNORECASE)


def parse_airodump_csv(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """解析 airodump-ng 的 CSV 输出.

    返回 ``(aps, clients, handshake_bssids)``。容错处理空行、表头与截断行。
    """
    aps: list[dict[str, Any]] = []
    clients: list[dict[str, Any]] = []
    handshakes: list[str] = []
    section: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip("\x00\r\n ")
        if not line:
            continue
        if line.startswith("BSSID,"):
            section = "ap"
            continue
        if line.startswith("Station MAC,"):
            section = "station"
            continue
        handshake = HANDSHAKE_LINE_RE.search(line)
        if handshake:
            handshakes.append(handshake.group(1).lower())
            continue
        try:
            row = next(csv.reader(io.StringIO(line)))
        except (StopIteration, csv.Error):
            continue
        if not row or not is_mac(row[0].strip()):
            continue

        if section == "ap" and len(row) >= 14:
            try:
                channel = int(row[3].strip() or 0)
            except ValueError:
                channel = 0
            power = _to_int(row[8]) if len(row) > 8 else None
            beacons = (_to_int(row[9]) or 0) if len(row) > 9 else 0
            privacy = row[5].strip() if len(row) > 5 else ""
            # airodump 对"只从客户端数据帧推断出的 AP"会写一行空壳：
            # Privacy 为空、Beacon 为 0、功率 -1。这类行没有任何可攻击信息，
            # 若落库会被 classify_security("") 误判成 OPEN（真实环境 114 个 AP
            # 里有 15 行这种空壳，报告会把它们列成开放网络）。
            if not privacy and beacons == 0:
                continue
            aps.append(
                {
                    "bssid": row[0].strip().lower(),
                    "channel": channel,
                    "privacy": privacy,
                    "cipher": row[6].strip() if len(row) > 6 else "",
                    "auth": row[7].strip() if len(row) > 7 else "",
                    "power": power,
                    "beacons": beacons,
                    "data": (_to_int(row[10]) or 0) if len(row) > 10 else 0,
                    "ssid": (row[13] if len(row) > 13 else "").strip(),
                }
            )
        elif section == "station" and len(row) >= 6:
            probes = [p.strip() for p in row[6:] if p.strip()] if len(row) > 6 else []
            # airodump-ng 对未关联（仅在探测）的客户端用 "(not associated)" 填充
            # BSSID 列；这不是 MAC，落库前必须清空，否则 Client 的 MAC 校验会抛异常
            # 并导致整轮扫描中断（真实环境踩到过）。
            bssid = row[5].strip().lower() if len(row) > 5 else ""
            clients.append(
                {
                    "mac": row[0].strip().lower(),
                    "power": _to_int(row[3]) if len(row) > 3 else None,
                    "packets": (_to_int(row[4]) or 0) if len(row) > 4 else 0,
                    "bssid": bssid if is_mac(bssid) else "",
                    "probes": probes,
                }
            )
    return aps, clients, handshakes


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def airodump_args(prefix: str, monitor_iface: str, channel: int | None = None) -> list[str]:
    """构造 airodump-ng 参数.

    必须显式传 ``--band abg``：airodump-ng 的默认跳频只覆盖 2.4GHz，
    真实环境里 5GHz 目标会整轮扫不到（MT7921U 上实测 56 个 AP 全是 2.4GHz，
    加 abg 后同一位置扫到 96 个，含大量 5GHz）。
    """
    args = [
        "airodump-ng",
        "--band", "abg",
        "--write", prefix,
        "--output-format", "csv,pcap",
        "--write-interval", "1",
        "--ignore-negative-one",
        monitor_iface,
    ]
    if channel:
        args[1:1] = ["-c", str(channel)]
    return args


class Scanner:
    def __init__(
        self,
        config: Config,
        store: Store,
        bus: EventBus,
        runner: Runner,
        iface_mgr: IfaceManager,
        session_id: int,
    ) -> None:
        self.config = config
        self.store = store
        self.bus = bus
        self.runner = runner
        self.iface_mgr = iface_mgr
        self.session_id = session_id
        self.state = "idle"
        self.iface = ""
        self.monitor_iface = ""
        self.packets = 0
        self.started_at = 0.0
        self.aps: dict[str, AP] = {}
        self.clients: dict[str, Client] = {}
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._prefix = ""
        self._proc: asyncio.subprocess.Process | None = None
        self._last_csv_size = 0
        self._discovered: set[str] = set()

    @property
    def running(self) -> bool:
        return self.state == "running"

    # ------------------------------------------------------------------ 控制
    async def start(
        self,
        iface: str | None = None,
        *,
        duration: float | None = None,
        channel: int | None = None,
    ) -> dict[str, Any]:
        if self.running:
            raise RuntimeError("扫描已在运行")
        preferred = iface or self.config.iface
        resolved = None
        if not self.config.is_live:
            self.iface = preferred or "demo0"
        else:
            resolved = await self.iface_mgr.resolve(preferred)
            if not resolved:
                raise RuntimeError("未发现可用无线网卡（需要支持 monitor 模式的适配器）")
            self.iface = resolved.name

        self.state = "running"
        self.started_at = time.time()
        self.packets = 0
        self.aps.clear()
        self.clients.clear()
        self._discovered.clear()
        self._stop.clear()
        self._last_csv_size = 0
        self.config.ensure_dirs()
        self.bus.emit(
            "info",
            "scan",
            f"开始{'模拟' if not self.config.is_live else ''}扫描，接口 {self.iface}",
            iface=self.iface,
        )
        self._task = asyncio.create_task(self._run(channel=channel, duration=duration))
        return self.status()

    async def stop(self) -> dict[str, Any]:
        if self.state == "idle":
            return self.status()
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=8)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self._task = None
        # 兜底：任务被取消时 _live_loop 的 finally 可能来不及跑完，
        # 监听接口会留在 wlan0mon，后续建伪 AP 就会解析错网卡。
        if self.monitor_iface:
            name, self.monitor_iface = self.monitor_iface, ""
            restore = asyncio.create_task(self.iface_mgr.disable_monitor(name))
            try:
                await asyncio.shield(restore)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self.state = "idle"
        self.bus.emit("info", "scan", "扫描已停止")
        return self.status()

    async def _run(self, *, channel: int | None, duration: float | None) -> None:
        try:
            if self.config.is_live:
                await self._live_loop(channel=channel, duration=duration)
            else:
                await self._demo_loop(duration=duration)
        except PermissionError as exc:
            self.state = "error"
            self.bus.emit("error", "scan", str(exc))
        except Exception as exc:  # noqa: BLE001
            self.state = "error"
            self.bus.emit("error", "scan", f"扫描失败: {exc}")
        finally:
            self.state = "idle" if self.state != "error" else "error"

    # ------------------------------------------------------------------ live
    async def _live_loop(self, *, channel: int | None, duration: float | None) -> None:
        self.monitor_iface = await self.iface_mgr.enable_monitor(self.iface)
        if channel:
            await self.iface_mgr.set_channel(self.monitor_iface, channel)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self._prefix = str(
            self.config.capture_path / f"scan-{self.session_id}-{stamp}"
        )
        args = airodump_args(self._prefix, self.monitor_iface, channel)
        self.bus.emit("info", "scan", f"airodump-ng 已启动: {self.monitor_iface}")
        self._proc = await self.runner.background(
            args, on_line=self._on_airodump_line, delay=2.0
        )
        csv_path = Path(self._prefix + "-01.csv")
        next_wash = time.time() + 20
        deadline = time.time() + duration if duration else None

        try:
            while not self._stop.is_set():
                if deadline and time.time() >= deadline:
                    break
                await asyncio.sleep(self.config.scan_interval)
                if csv_path.exists():
                    size = csv_path.stat().st_size
                    if size != self._last_csv_size:
                        self._last_csv_size = size
                        self._ingest_csv(csv_path.read_text(encoding="utf-8", errors="replace"))
                if is_installed("wash") and time.time() >= next_wash:
                    next_wash = time.time() + 30
                    await self._wash_mark()
        finally:
            # 任务可能因 stop() 超时被 cancel，清理阶段的 await 也会抛 CancelledError；
            # 必须逐段兜住，否则网卡会永远停在 wlan0mon。
            try:
                await self.runner.terminate(self._proc)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._proc = None
            try:
                await self.iface_mgr.disable_monitor(self.monitor_iface)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    def _on_airodump_line(self, line: str) -> None:
        match = HANDSHAKE_LINE_RE.search(line)
        if match:
            bssid = match.group(1).lower()
            self.bus.emit("success", "scan", f"检测到握手: {bssid}", bssid=bssid)

    async def _wash_mark(self) -> None:
        from ..crack.tools import wash_scan

        try:
            entries = await wash_scan(self.runner, self.monitor_iface, timeout=25)
        except Exception:  # noqa: BLE001
            return
        for entry in entries:
            ap = self.aps.get(entry["bssid"])
            if ap and not ap.wps:
                ap.wps = True
                self.store.upsert_ap(ap, self.session_id)
                self.bus.emit("info", "scan", f"WPS 已启用: {ap.ssid}", bssid=ap.bssid)

    def _ingest_csv(self, text: str) -> None:
        aps, clients, handshakes = parse_airodump_csv(text)
        now = time.time()
        for item in aps:
            bssid = item["bssid"]
            ap = self.aps.get(bssid)
            if ap is None:
                ap = AP(
                    bssid=bssid,
                    ssid=item["ssid"],
                    channel=item["channel"],
                    privacy=item["privacy"],
                    cipher=item["cipher"],
                    auth=item["auth"],
                    power=item["power"],
                    beacons=item["beacons"],
                    data=item["data"],
                )
                self.aps[bssid] = ap
                self.bus.emit(
                    "info",
                    "scan",
                    f"发现 AP: {ap.display_ssid} [{ap.security}] ch{ap.channel} {ap.power}dBm",
                    bssid=bssid,
                    ssid=ap.ssid,
                    security=ap.security,
                )
            else:
                if item["ssid"] and not ap.ssid:
                    ap.ssid = item["ssid"]
                ap.channel = item["channel"] or ap.channel
                ap.privacy = item["privacy"] or ap.privacy
                ap.auth = item["auth"] or ap.auth
                ap.cipher = item["cipher"] or ap.cipher
                ap.power = item["power"]
                ap.beacons = item["beacons"]
                ap.data = item["data"]
            ap.last_seen = now
            self.store.upsert_ap(ap, self.session_id)
            self.packets = max(self.packets, ap.beacons + ap.data)

        for item in clients:
            mac = item["mac"]
            client = self.clients.get(mac)
            if client is None:
                client = Client(
                    mac=mac,
                    bssid=item["bssid"],
                    power=item["power"],
                    packets=item["packets"],
                    probes=item["probes"],
                )
                self.clients[mac] = client
                self.bus.emit(
                    "info",
                    "scan",
                    f"发现客户端: {mac} ({client.vendor}) 关联 {item['bssid'] or '未关联'}",
                    mac=mac,
                    bssid=item["bssid"],
                    probes=item["probes"],
                )
            else:
                client.bssid = item["bssid"] or client.bssid
                client.power = item["power"]
                client.packets = item["packets"]
                if item["probes"]:
                    client.probes = sorted(set(client.probes) | set(item["probes"]))
            client.last_seen = now
            self.store.upsert_client(client, self.session_id)

        # 更新 AP 的客户端计数
        counts: dict[str, int] = {}
        for client in self.clients.values():
            if client.bssid:
                counts[client.bssid] = counts.get(client.bssid, 0) + 1
        for bssid, ap in self.aps.items():
            ap.clients = counts.get(bssid, 0)

        for bssid in handshakes:
            if bssid not in self._discovered:
                self._discovered.add(bssid)
                self.store.add_finding(
                    Finding(
                        session_id=self.session_id,
                        title="捕获到 WPA 四次握手",
                        severity="high",
                        bssid=bssid,
                        ssid=self.aps[bssid].ssid if bssid in self.aps else "",
                        detail="扫描过程中被动捕获到 EAPOL 四次握手，可离线验证口令强度。",
                        category="capture",
                    )
                )
                self.bus.emit("success", "scan", f"握手已保存: {bssid}", bssid=bssid)

    # ------------------------------------------------------------------ demo
    async def _demo_loop(self, *, duration: float | None) -> None:
        rng = random.Random(int(self.started_at) & 0xFFFF)
        queue: list[DemoAP] = list(DEMO_NETWORKS)
        revealed: list[DemoAP] = []
        self.bus.emit("info", "scan", "演示环境已加载：14 个虚拟 AP / 多厂商客户端")
        deadline = time.time() + duration if duration else None

        while not self._stop.is_set():
            if deadline and time.time() >= deadline:
                break
            if queue:
                revealed.append(queue.pop(0))
                net = revealed[-1]
                ap = demo_ap_object(net)
                ap.session_id = self.session_id
                self.aps[ap.bssid] = ap
                self.store.upsert_ap(ap, self.session_id)
                for client in demo_clients_for(net, seed=1):
                    client.session_id = self.session_id
                    self.clients[client.mac] = client
                    self.store.upsert_client(client, self.session_id)
                self.bus.emit(
                    "info",
                    "scan",
                    f"发现 AP: {ap.display_ssid} [{ap.security}] ch{ap.channel} {ap.power}dBm"
                    + (" · WPS" if ap.wps else ""),
                    bssid=ap.bssid,
                    ssid=ap.ssid,
                    security=ap.security,
                    wps=ap.wps,
                )
                await asyncio.sleep(0.8 if duration and duration < 8 else 1.4)
                continue

            # 持续刷新信号与客户端
            for net in revealed:
                ap = self.aps.get(net.bssid)
                if not ap:
                    continue
                ap.power = net.power + rng.randint(-4, 4)
                ap.beacons += rng.randint(1, 12)
                ap.data += rng.randint(0, 6)
                ap.last_seen = time.time()
                self.store.upsert_ap(ap, self.session_id)
                for client in demo_clients_for(net, seed=1):
                    client.power = (client.power or -70) + rng.randint(-3, 3)
                    client.packets += rng.randint(1, 60)
                    client.last_seen = time.time()
                    self.clients[client.mac] = client
                    self.store.upsert_client(client, self.session_id)

            counts: dict[str, int] = {}
            for client in self.clients.values():
                if client.bssid:
                    counts[client.bssid] = counts.get(client.bssid, 0) + 1
            for bssid, ap in self.aps.items():
                ap.clients = counts.get(bssid, 0)

            self.packets += rng.randint(30, 160)
            await asyncio.sleep(max(0.8, self.config.scan_interval))

    # ------------------------------------------------------------------ 查询
    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "state": self.state,
            "iface": self.iface,
            "monitor_iface": self.monitor_iface,
            "seconds": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "aps": len(self.aps),
            "clients": len(self.clients),
            "packets": self.packets,
            "mode": self.config.mode,
        }

    def snapshot(self) -> dict[str, Any]:
        aps = sorted((ap.to_dict() for ap in self.aps.values()), key=lambda a: a["power"] or -100, reverse=True)
        clients = [c.to_dict() for c in self.clients.values()]
        clients.sort(key=lambda c: c["power"] or -100, reverse=True)
        return {"status": self.status(), "aps": aps, "clients": clients}
