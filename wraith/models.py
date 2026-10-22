"""领域模型：AP、客户端、抓包、破解任务、发现、事件。"""

from __future__ import annotations

import gzip
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 常量与工具
# ---------------------------------------------------------------------------

OPEN, WEP, WPA, WPA2, WPA3 = "OPEN", "WEP", "WPA", "WPA2", "WPA3"
TRANSITION = "WPA2/WPA3"
ENTERPRISE_SUFFIX = "-ENT"
OWE = "OWE"
UNKNOWN = "UNKNOWN"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

# 常见 OUI（人工整理的短名称，优先于完整数据库；用于演示与常见设备）
_OUI: dict[str, str] = {
    "000C29": "VMware",
    "001C42": "Parallels",
    "005056": "VMware",
    "080027": "PCS Systemtechnik",
    "00037F": "Atheros",
    "001374": "Atheros",
    "0018E7": "Cameo",
    "0024B2": "Netgear",
    "204E7F": "Netgear",
    "A00460": "Netgear",
    "C40415": "Netgear",
    "001E2A": "Netgear",
    "0026F2": "Netgear",
    "001D7E": "Cisco-Linksys",
    "0018F8": "Cisco-Linksys",
    "00259C": "Cisco-Linksys",
    "001A70": "Cisco-Linksys",
    "000C41": "Cisco-Linksys",
    "48F8B3": "Cisco-Linksys",
    "68DB96": "Cisco-Linksys",
    "F8D111": "TP-Link",
    "A42BB0": "TP-Link",
    "50C7BF": "TP-Link",
    "C46E1F": "TP-Link",
    "1C61B4": "TP-Link",
    "003A7D": "TP-Link",
    "749781": "TP-Link",
    "9C5322": "Compal",
    "D46E5C": "Huawei",
    "00E0FC": "Huawei",
    "002568": "Huawei",
    "4C1FCC": "Huawei",
    "886639": "Huawei",
    "2C58E8": "Huawei",
    "F4C714": "Huawei",
    "5C7D5E": "Huawei",
    "00E04C": "Realtek",
    "52540A": "QEMU",
    "525400": "QEMU",
    "00155D": "Microsoft",
    "7C1E52": "Microsoft",
    "C83F26": "Microsoft",
    "000D3A": "Microsoft",
    "001B63": "Apple",
    "0025BC": "Apple",
    "3C0754": "Apple",
    "A4C361": "Apple",
    "F0DBF8": "Apple",
    "AC293A": "Apple",
    "D0817A": "Apple",
    "F0766F": "Apple",
    "54E43A": "Apple",
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "2C3AE8": "Espressif",
    "246F28": "Espressif",
    "A020A6": "Espressif",
    "84F3EB": "Espressif",
    "5CCF7F": "Espressif",
    "3C71BF": "Espressif",
    "8CAAB5": "Espressif",
    "24A160": "Espressif",
    "D8A01D": "Espressif",
    "7CDFA1": "Espressif",
    "0017A4": "Hewlett Packard",
    "001B78": "Hewlett Packard",
    "6CC217": "Hewlett Packard",
    "0024E8": "Dell",
    "D067E5": "Dell",
    "F8BC12": "Dell",
    "001C23": "Dell",
    "F0DEF1": "Wistron",
    "001CF0": "D-Link",
    "0022B0": "D-Link",
    "1CBDB9": "D-Link",
    "78321B": "D-Link",
    "340804": "D-Link",
    "F07D68": "D-Link",
    "00248C": "ASUS",
    "1C872C": "ASUS",
    "2C56DC": "ASUS",
    "04D4C4": "ASUS",
    "08606E": "ASUS",
    "AC9E17": "ASUS",
    "F832E4": "ASUS",
    "00156D": "Ubiquiti",
    "0418D6": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "44D9E7": "Ubiquiti",
    "74ACB9": "Ubiquiti",
    "F09FC2": "Ubiquiti",
    "788A20": "Ubiquiti",
    "0016C1": "MikroTik",
    "2CC81B": "MikroTik",
    "48A98A": "MikroTik",
    "6C3B6B": "MikroTik",
    "744D28": "MikroTik",
    "C4AD34": "MikroTik",
    "E48D8C": "MikroTik",
    "0023CD": "Tenda",
    "C83A35": "Tenda",
    "08B2A3": "Tenda",
    "D832E3": "Tenda",
    "000C43": "Ralink",
    "00A0C9": "Intel",
    "001E64": "Intel",
    "001B21": "Intel",
    "3C9509": "Intel",
    "5CE0C5": "Intel",
    "7CB27D": "Intel",
    "A0A8CD": "Intel",
    "F8E43B": "Intel",
    "001E58": "D-Link",
    "D46AA8": "Huawei",
    "5C6B32": "ZTE",
    "B075D5": "ZTE",
    "9C2EA1": "ZTE",
    "0015EB": "ZTE",
    "344B50": "ZTE",
    "000E2E": "H3C",
    "002389": "H3C",
    "3CA9F4": "H3C",
    "70F96D": "H3C",
    "0090E8": "Ruijie",
    "00D0F8": "Ruijie",
    "2C3A28": "Fiberhome",
    "D4B7B0": "Fiberhome",
    "0C8268": "TCL",
    "3C46D8": "TP-Link",
    "A0F3C1": "TP-Link",
    "60A4D0": "TP-Link",
    "F8A45F": "Xiaomi",
    "8CBEBE": "Xiaomi",
    "64CC2E": "Xiaomi",
    "78110F": "Xiaomi",
    "4419B6": "Hikvision",
    "4C3C16": "Hikvision",
    "BCAD28": "Hikvision",
    "F0B4D2": "D-Link",
    "48F8DB": "Huawei",
}


# 完整 OUI 数据库：IEEE MA-L/MA-M/MA-S/IAB + nmap 汇总（24/28/36 位前缀）
_OUI_DB_PATH = Path(__file__).with_name("data") / "oui.tsv.gz"

# 无 OUI 记录时的展示文案：本地管理位为 1 的地址通常是随机化 MAC
LOCAL_MAC_VENDOR = "随机 MAC"
UNREGISTERED_VENDOR = "未注册"

# 把注册局的全称折叠成控制台里更好读的短名称
_VENDOR_ALIASES = {
    "zte": "ZTE",
    "beijing xiaomi mobile software": "Xiaomi",
    "xiaomi communications": "Xiaomi",
    "tp-link technologies": "TP-Link",
    "new h3c technologies": "H3C",
    "hewlett packard enterprise": "HPE",
    "hewlett-packard company": "HP",
    "beijing jingdong century trading": "JD",
    "gd midea air-conditioning equipment": "Midea",
    "beijing zhongyuanyishang technology": "Zhongyuanyishang",
    "hong kong water world technology limited": "Water World",
    "ubiquiti inc": "Ubiquiti",
    "cisco systems, inc": "Cisco",
    "apple, inc.": "Apple",
}


def _pretty_vendor(name: str) -> str:
    cleaned = " ".join((name or "").split())
    key = cleaned.lower()
    alias = _VENDOR_ALIASES.get(key)
    if alias:
        return alias
    # IEEE 注册名会带不同的公司后缀，按品牌前缀折叠
    for prefix, label in (
        ("beijing xiaomi", "Xiaomi"),
        ("xiaomi", "Xiaomi"),
        ("zte", "ZTE"),
        ("ubiquiti", "Ubiquiti"),
        ("tp-link", "TP-Link"),
        ("new h3c", "H3C"),
        ("beijing zhongyuanyishang", "Zhongyuanyishang"),
        ("hong kong water world", "Water World"),
        ("gd midea", "Midea"),
        ("beijing jingdong", "JD"),
        ("n-radio", "N-Radio"),
        ("hewlett packard enterprise", "HPE"),
    ):
        if key.startswith(prefix):
            return label
    return cleaned


@lru_cache(maxsize=1)
def _oui_db() -> dict[str, str]:
    """惰性加载随包分发的 OUI 数据库（约 5.9 万条，首次查询时解压）。"""
    try:
        with gzip.open(_OUI_DB_PATH, "rt", encoding="utf-8", errors="replace") as fh:
            table: dict[str, str] = {}
            for line in fh:
                if not line or line.startswith("#"):
                    continue
                prefix, sep, name = line.rstrip("\n").partition("\t")
                if sep and prefix and name:
                    table[prefix.upper()] = name
            return table
    except (OSError, EOFError):
        return {}


def _oui_lookup(raw: str) -> str:
    table = _oui_db()
    for length in (9, 7, 6):  # MA-S/IAB / MA-M / MA-L，最长前缀优先
        vendor = table.get(raw[:length])
        if vendor:
            return vendor
    return ""


def is_locally_administered(mac: str) -> bool:
    """MAC 的 locally-administered 位是否为 1（随机化/虚拟地址）。"""
    raw = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    return len(raw) >= 2 and bool(int(raw[:2], 16) & 0x02)


@lru_cache(maxsize=8192)
def vendor_for(mac: str) -> str:
    """由 MAC 前缀推断厂商.

    优先命中人工整理的常见厂商表，其次是完整 OUI 数据库（支持 28/36 位前缀）。
    未注册的全局地址返回 ``未注册``；本地管理地址（随机 MAC）返回 ``随机 MAC``。
    """
    raw = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    if len(raw) < 12:
        return "Unknown"
    vendor = _OUI.get(raw[:6]) or _oui_lookup(raw)
    if vendor:
        return _pretty_vendor(vendor)
    if int(raw[:2], 16) & 0x02:
        return LOCAL_MAC_VENDOR
    return UNREGISTERED_VENDOR



def is_mac(value: str) -> bool:
    return bool(_MAC_RE.match(value.strip()))


def normalize_mac(value: str) -> str:
    raw = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(raw) != 12:
        raise ValueError(f"非法 MAC: {value!r}")
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)).lower()


def band_for_channel(channel: int | None, frequency: int | None = None) -> str:
    if frequency:
        if frequency >= 5925:
            return "6GHz"
        if frequency >= 4900:
            return "5GHz"
        if frequency >= 2400:
            return "2.4GHz"
    if not channel:
        return "?"
    if channel <= 14:
        return "2.4GHz"
    if channel <= 196:
        return "5GHz"
    return "6GHz"


def classify_security(
    privacy: str | None,
    auth: str | None = None,
    cipher: str | None = None,
) -> str:
    """把 airodump 风格的 Privacy/Authentication 归一化为安全类型字符串."""
    privacy_u = (privacy or "").upper().strip()
    auth_u = (auth or "").upper().strip()
    cipher_u = (cipher or "").upper().strip()

    if not privacy_u or privacy_u in {"OPN", "OPEN", "NONE"}:
        return OWE if "OWE" in privacy_u else OPEN
    # airodump 对"只从数据帧推断出的 BSSID"（beacons=0）会写出 "WPA WEP"
    # 这种自相矛盾的 Privacy。真实 WEP 的 Privacy 只会是 "WEP"；一旦同时带
    # WPA 标记就按 WPA 系列处理，否则 WPA2/WPA3 过渡 AP 会被误判成 WEP，
    # 让 WEP 模块对着非 WEP 目标空跑数分钟。
    if "WEP" in privacy_u and "WPA" not in privacy_u:
        return WEP
    if "OWE" in privacy_u:
        return OWE

    has_wpa3 = "WPA3" in privacy_u or "SAE" in privacy_u
    has_wpa2 = "WPA2" in privacy_u
    has_wpa1 = "WPA" in privacy_u and not has_wpa2 and not has_wpa3
    is_ent = "MGT" in auth_u or "EAP" in privacy_u or "802.1X" in auth_u

    if has_wpa3 and has_wpa2:
        base = TRANSITION
    elif has_wpa3:
        base = WPA3
    elif has_wpa2:
        base = WPA2
    elif has_wpa1:
        base = WPA
    else:
        base = UNKNOWN

    if is_ent and base in {WPA2, WPA3, WPA, TRANSITION}:
        return base + ENTERPRISE_SUFFIX
    return base


def signal_quality(dbm: int | None) -> int:
    """把 dBm 映射为 0-100 的信号百分比（近似）。"""
    if dbm is None:
        return 0
    if dbm >= -50:
        return 100
    if dbm <= -100:
        return 0
    return int(round((dbm + 100) * 2))


# ---------------------------------------------------------------------------
# 模型
# ---------------------------------------------------------------------------


@dataclass
class AP:
    bssid: str
    ssid: str = ""
    channel: int = 0
    frequency: int | None = None
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: int | None = None
    beacons: int = 0
    data: int = 0
    wps: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    clients: int = 0
    vendor: str = ""
    session_id: int = 0
    # 关联到的客户端 MAC 列表（运行期缓存，不落库）
    client_macs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.bssid = normalize_mac(self.bssid) if self.bssid else ""
        if not self.vendor or self.vendor.strip().upper() == "UNKNOWN":
            self.vendor = vendor_for(self.bssid)
        if self.ssid is None:
            self.ssid = ""

    @property
    def display_ssid(self) -> str:
        return self.ssid if self.ssid else "<隐藏>"

    @property
    def security(self) -> str:
        return classify_security(self.privacy, self.auth, self.cipher)

    @property
    def has_enterprise(self) -> bool:
        return self.security.endswith(ENTERPRISE_SUFFIX)

    @property
    def is_transition(self) -> bool:
        return self.security.replace(ENTERPRISE_SUFFIX, "") == TRANSITION

    @property
    def band(self) -> str:
        return band_for_channel(self.channel, self.frequency)

    @property
    def quality(self) -> int:
        return signal_quality(self.power)

    @property
    def key(self) -> str:
        return f"{self.bssid}|{self.ssid}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "display_ssid": self.display_ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "band": self.band,
            "privacy": self.privacy,
            "cipher": self.cipher,
            "auth": self.auth,
            "security": self.security,
            "power": self.power,
            "quality": self.quality,
            "beacons": self.beacons,
            "data": self.data,
            "wps": self.wps,
            "vendor": self.vendor,
            "clients": self.clients,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "session_id": self.session_id,
        }


@dataclass
class Client:
    mac: str
    bssid: str = ""
    power: int | None = None
    packets: int = 0
    probes: list[str] = field(default_factory=list)
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    session_id: int = 0

    def __post_init__(self) -> None:
        self.mac = normalize_mac(self.mac) if self.mac else ""
        if self.bssid:
            self.bssid = normalize_mac(self.bssid)
        if not self.vendor or self.vendor.strip().upper() == "UNKNOWN":
            self.vendor = vendor_for(self.mac)

    @property
    def quality(self) -> int:
        return signal_quality(self.power)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "bssid": self.bssid,
            "power": self.power,
            "quality": self.quality,
            "packets": self.packets,
            "probes": list(self.probes),
            "vendor": self.vendor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "session_id": self.session_id,
        }


@dataclass
class Capture:
    id: int = 0
    kind: str = "handshake"  # handshake | pmkid | wep | portal | scan
    path: str = ""
    bssid: str = ""
    ssid: str = ""
    size: int = 0
    hash_lines: int = 0
    created_at: float = field(default_factory=time.time)
    session_id: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "size": self.size,
            "hash_lines": self.hash_lines,
            "created_at": self.created_at,
            "session_id": self.session_id,
            "meta": self.meta,
        }


@dataclass
class CrackJob:
    id: int = 0
    capture_id: int = 0
    method: str = "aircrack"  # aircrack | hashcat | reaver | offline
    wordlist: str = ""
    status: str = "pending"  # pending | running | found | exhausted | failed | stopped
    key: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    log: str = ""
    progress: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "capture_id": self.capture_id,
            "method": self.method,
            "wordlist": self.wordlist,
            "status": self.status,
            "key": self.key,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress": self.progress,
            "log": self.log[-8000:],
        }


@dataclass
class Credential:
    id: int = 0
    username: str = ""
    password: str = ""
    portal: str = ""
    ip: str = ""
    user_agent: str = ""
    created_at: float = field(default_factory=time.time)
    session_id: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "password": self.password,
            "portal": self.portal,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "created_at": self.created_at,
            "session_id": self.session_id,
        }


@dataclass
class Finding:
    id: int = 0
    title: str = ""
    severity: str = "info"
    bssid: str = ""
    ssid: str = ""
    detail: str = ""
    category: str = ""
    created_at: float = field(default_factory=time.time)
    session_id: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "detail": self.detail,
            "category": self.category,
            "created_at": self.created_at,
            "session_id": self.session_id,
        }


@dataclass
class Event:
    ts: float
    level: str  # debug | info | success | warning | error | attack
    source: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "data": self.data,
        }


@dataclass
class Session:
    id: int = 0
    name: str = ""
    mode: str = "demo"
    iface: str = ""
    operator: str = ""
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    notes: str = ""
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "mode": self.mode,
            "iface": self.iface,
            "operator": self.operator,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "notes": self.notes,
            "status": self.status,
        }
