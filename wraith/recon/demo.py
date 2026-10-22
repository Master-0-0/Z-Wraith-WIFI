"""演示环境：真实的协议语义 + 虚构的网络数据.

演示模式不接触任何无线硬件，但生成的 PMKID/握手哈希是**真实可校验**的，
因此「捕获 → 破解」链路与 live 模式行为一致，可用于培训与验收。
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ..models import AP, Client, vendor_for


@dataclass(frozen=True)
class DemoAP:
    ssid: str
    bssid: str
    channel: int
    privacy: str
    auth: str
    cipher: str
    power: int
    wps: bool = False
    psk: str = ""  # 仅用于演示破解，不会主动展示给前端
    clients: int = 2

    @property
    def security(self) -> str:
        from ..models import classify_security

        return classify_security(self.privacy, self.auth, self.cipher)


DEMO_NETWORKS: list[DemoAP] = [
    DemoAP("CMCC-5G-8F2A", "f8:d1:11:8f:2a:01", 149, "WPA2", "PSK", "CCMP", -44,
           wps=True, psk="12345678", clients=3),
    DemoAP("ChinaNet-XmKq", "d4:6e:5c:a1:3c:7e", 6, "WPA2", "PSK", "CCMP", -58,
           psk="password", clients=2),
    DemoAP("HUAWEI-9A3C", "88:66:39:9a:3c:10", 11, "WPA2 WPA3", "PSK SAE", "CCMP", -52,
           wps=True, psk="Huawei@123", clients=2),
    DemoAP("Xiaomi_Anytime", "f8:a4:5f:2b:77:0c", 44, "WPA2", "PSK", "CCMP", -63,
           psk="xiaomi123", clients=1),
    DemoAP("TP-LINK_5G_7D2C", "50:c7:bf:7d:2c:aa", 157, "WPA2", "PSK", "CCMP", -69,
           wps=True, psk="admin888", clients=2),
    DemoAP("Starbucks-WiFi", "00:18:f8:12:9e:30", 1, "OPN", "", "", -71, clients=4),
    DemoAP("Redmi_2A4F", "64:cc:2e:2a:4f:19", 3, "WPA2", "PSK", "CCMP", -66,
           psk="1234567890", clients=1),
    DemoAP("H3C_Office", "00:23:89:5c:11:02", 36, "WPA2", "MGT", "CCMP", -55,
           psk="", clients=3),
    DemoAP("TP-LINK_2.4G_9F1A", "f8:d1:11:9f:1a:02", 9, "WPA2", "PSK", "CCMP", -61,
           wps=True, psk="qwerty123", clients=2),
    DemoAP("CCTV-CAM-01", "44:19:b6:c0:01:01", 13, "WEP", "", "WEP", -74,
           psk="12345", clients=1),
    DemoAP("iPhone 热点", "3c:07:54:aa:bb:cc", 6, "WPA3", "SAE", "CCMP", -68, clients=1),
    DemoAP("Guest-WPA3", "04:18:d6:77:88:99", 100, "WPA3", "SAE", "CCMP", -72, clients=2),
    DemoAP("Printer_HP_3F", "00:17:a4:3f:3f:3f", 6, "OPN", "", "", -77, clients=0),
    DemoAP("MiFi-4G-9A2", "34:4b:50:9a:20:01", 8, "WPA2", "PSK", "CCMP", -70,
           psk="88888888", clients=1),
]

DEMO_WORDLIST = [
    "12345678", "password", "Huawei@123", "xiaomi123", "admin888", "1234567890",
    "qwerty123", "12345", "88888888", "123456", "123456789", "11111111", "00000000",
    "password1", "Password123", "admin123", "root1234", "guest1234", "wifi1234",
    "letmein1", "iloveyou", "sunshine", "princess", "football", "baseball",
    "abc12345", "qwertyuiop", "1qaz2wsx", "zaq12wsx", "P@ssw0rd", "Passw0rd!",
    "welcome1", "master123", "shadow123", "superman", "batman123", "starwars",
    "whatever", "trustno1", "hello123", "test1234", "demo1234", "changeme",
    "Summer2024", "Winter2024", "Spring2024", "Autumn2024", "Company@2024",
    "WiFi@2024", "Guest@2024", "Office@2024", "IOT@2024", "Home@2024",
]

DEMO_CLIENT_OUIS = [
    "3c:07:54", "f0:db:f8", "a4:c3:61", "00:1b:63",  # Apple
    "d4:6e:5c", "88:66:39", "48:f8:db",              # Huawei
    "24:6f:28", "a0:20:a6", "5c:cf:7f",              # Espressif / IoT
    "00:0c:29", "00:50:56",                          # VM
    "7c:1e:52", "c8:3f:26",                          # Microsoft
    "3c:95:09", "f8:e4:3b",                          # Intel
    "b8:27:eb", "dc:a6:32",                          # Raspberry Pi
    "2c:56:dc", "1c:87:2c",                          # ASUS
]


def _bssid_from(ssid: str) -> str:
    for net in DEMO_NETWORKS:
        if net.ssid == ssid:
            return net.bssid
    return ""


def demo_psk(ssid: str) -> str:
    for net in DEMO_NETWORKS:
        if net.ssid == ssid:
            return net.psk
    return ""


def demo_network(ssid: str) -> DemoAP | None:
    for net in DEMO_NETWORKS:
        if net.ssid == ssid:
            return net
    return None


def demo_ap_object(net: DemoAP, jitter: int = 0) -> AP:
    return AP(
        bssid=net.bssid,
        ssid=net.ssid,
        channel=net.channel,
        privacy=net.privacy,
        cipher=net.cipher,
        auth=net.auth,
        power=net.power + jitter,
        beacons=random.randint(80, 400),
        data=random.randint(5, 120),
        wps=net.wps,
        clients=net.clients,
        vendor=vendor_for(net.bssid),
    )


def demo_clients_for(net: DemoAP, seed: int = 0) -> list[Client]:
    rng = random.Random(hash((net.bssid, seed)) & 0xFFFFFFFF)
    out: list[Client] = []
    for idx in range(net.clients):
        oui = rng.choice(DEMO_CLIENT_OUIS)
        mac = f"{oui}:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}"
        out.append(
            Client(
                mac=mac,
                bssid=net.bssid,
                power=max(-92, net.power - rng.randint(3, 18)),
                packets=rng.randint(20, 4000),
                probes=[net.ssid] if net.ssid and rng.random() > 0.35 else [],
            )
        )
    return out
