"""系统工具依赖探测。"""

from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolSpec:
    name: str
    package: str
    purpose: str
    category: str = "core"
    root: bool = False
    install: str = ""
    fallback: str = ""


TOOLS: dict[str, ToolSpec] = {
    # 基础
    "iw": ToolSpec("iw", "iw", "无线设备与接口配置", "core", True, "apt install iw"),
    "ip": ToolSpec("ip", "iproute2", "接口状态管理", "core", True, "apt install iproute2"),
    "airmon-ng": ToolSpec(
        "airmon-ng", "aircrack-ng", "开启监听模式", "core", True, "apt install aircrack-ng"
    ),
    "airodump-ng": ToolSpec(
        "airodump-ng", "aircrack-ng", "Beacon/客户端扫描与抓包", "core", True, "apt install aircrack-ng"
    ),
    "aireplay-ng": ToolSpec(
        "aireplay-ng", "aircrack-ng", "Deauth / 注入 / ARP 重放", "attack", True, "apt install aircrack-ng"
    ),
    "aircrack-ng": ToolSpec(
        "aircrack-ng", "aircrack-ng", "WEP/WPA 离线破解", "crack", False, "apt install aircrack-ng"
    ),
    "macchanger": ToolSpec("macchanger", "macchanger", "MAC 地址伪造", "core", True, "apt install macchanger"),
    # 抓包/破解
    "hcxdumptool": ToolSpec(
        "hcxdumptool", "hcxdumptool", "PMKID / 握手捕获（现代方案）", "capture", True, "apt install hcxdumptool"
    ),
    "hcxpcapngtool": ToolSpec(
        "hcxpcapngtool", "hcxtools", "pcapng → hashcat 22000 转换", "crack", False, "apt install hcxtools"
    ),
    "hashcat": ToolSpec("hashcat", "hashcat", "GPU 高速破解", "crack", False, "apt install hashcat", "aircrack-ng"),
    "john": ToolSpec("john", "john", "John the Ripper（备用）", "crack", False, "apt install john"),
    "tshark": ToolSpec("tshark", "tshark", "EAPOL 握手检测", "capture", False, "apt install tshark"),
    # WPS
    "reaver": ToolSpec("reaver", "reaver", "WPS Pixie Dust / PIN 爆破", "wps", True, "apt install reaver"),
    "wash": ToolSpec("wash", "reaver", "WPS 开启状态探测", "wps", True, "apt install reaver"),
    "bully": ToolSpec("bully", "bully", "WPS PIN 攻击（备用）", "wps", True, "apt install bully"),
    "pixiewps": ToolSpec("pixiewps", "pixiewps", "Pixie Dust 离线计算", "wps", False, "apt install pixiewps"),
    # 流氓 AP / 企业
    "hostapd": ToolSpec("hostapd", "hostapd", "搭建软 AP（邪恶双胞胎）", "rogue", True, "apt install hostapd"),
    "dnsmasq": ToolSpec("dnsmasq", "dnsmasq", "DHCP/DNS 劫持（强制门户）", "rogue", True, "apt install dnsmasq"),
    "hostapd-mana": ToolSpec(
        "hostapd-mana", "hostapd-mana", "Karma/MANA 与企业 EAP 降级", "rogue", True,
        "git clone https://github.com/sensepost/hostapd-mana && make",
    ),
    "eaphammer": ToolSpec(
        "eaphammer", "eaphammer", "企业级 Evil Twin（凭证收割）", "enterprise", True,
        "apt install eaphammer 或 git clone https://github.com/s0lst1c3/eaphammer",
    ),
    # 洪泛 / 辅助
    "mdk4": ToolSpec("mdk4", "mdk4", "Beacon/Auth/Deauth 洪泛", "flood", True, "apt install mdk4"),
    "bettercap": ToolSpec("bettercap", "bettercap", "802.11 侦察与 MITM", "recon", True, "apt install bettercap"),
    "kismet": ToolSpec("kismet", "kismet", "被动侦察 / WIDS", "recon", True, "apt install kismet"),
    "wifiphisher": ToolSpec("wifiphisher", "wifiphisher", "流氓 AP 钓鱼框架", "rogue", True, "apt install wifiphisher"),
}

PYTHON_DEPS = {
    "fastapi": "Web 框架",
    "uvicorn": "ASGI 服务器",
    "jinja2": "报告模板",
    "pydantic": "请求校验",
}


@dataclass
class DepStatus:
    name: str
    installed: bool
    path: str = ""
    purpose: str = ""
    category: str = "core"
    package: str = ""
    root: bool = False
    install: str = ""
    fallback: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "installed": self.installed,
            "path": self.path,
            "purpose": self.purpose,
            "category": self.category,
            "package": self.package,
            "root": self.root,
            "install": self.install,
            "fallback": self.fallback,
        }


def tool_path(name: str) -> str | None:
    return shutil.which(name)


def is_installed(name: str) -> bool:
    return shutil.which(name) is not None


def status(name: str) -> DepStatus:
    spec = TOOLS.get(name) or ToolSpec(name, name, "未知工具")
    path = shutil.which(name) or ""
    return DepStatus(
        name=name,
        installed=bool(path),
        path=path,
        purpose=spec.purpose,
        category=spec.category,
        package=spec.package,
        root=spec.root,
        install=spec.install,
        fallback=spec.fallback,
    )


def detect_all() -> list[dict]:
    """按真实可执行文件名去重后返回探测结果。

    早前用字典键去重，导致 ``dnsmasq_lease`` 这类别名（二进制实为 dnsmasq）
    被当成独立工具，永远显示「缺失」。这里改为按 ToolSpec.name 去重，
    保证同一可执行文件只出现一次。
    """
    seen: set[str] = set()
    out: list[dict] = []
    for name, spec in TOOLS.items():
        tool_name = spec.name
        if tool_name in seen:
            continue
        seen.add(tool_name)
        out.append(status(name).to_dict())
    return out


def missing(names: list[str]) -> list[str]:
    return [n for n in names if not is_installed(n)]


def python_missing() -> list[str]:
    return [mod for mod in PYTHON_DEPS if importlib.util.find_spec(mod) is None]


def doctor() -> dict:
    tools = detect_all()
    py_missing = python_missing()
    critical = ["iw", "ip", "airodump-ng", "aireplay-ng", "aircrack-ng"]
    critical_missing = [n for n in critical if not is_installed(n)]
    return {
        "tools": tools,
        "python": {
            "missing": py_missing,
            "ok": not py_missing,
            "modules": {mod: importlib.util.find_spec(mod) is not None for mod in PYTHON_DEPS},
        },
        "critical_missing": critical_missing,
        "ready": not critical_missing and not py_missing,
        "installed_count": sum(1 for t in tools if t["installed"]),
        "total_count": len(tools),
    }


def suggest_install(names: list[str]) -> str:
    packages = sorted({TOOLS[n].package for n in names if n in TOOLS})
    if not packages:
        return ""
    return "sudo apt install -y " + " ".join(packages)
