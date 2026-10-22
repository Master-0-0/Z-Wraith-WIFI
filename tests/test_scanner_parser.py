"""airodump-ng CSV 解析测试。"""

from __future__ import annotations

from wraith.recon.scanner import airodump_args, parse_airodump_csv

SAMPLE = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
F8:D1:11:8F:2A:01, 2026-10-20 04:00:00, 2026-10-20 04:01:00, 149, 1300, WPA2, CCMP, PSK, -44, 231, 12, 0.0.0.0, 12, CMCC-5G-8F2A,
88:66:39:9A:3C:10, 2026-10-20 04:00:00, 2026-10-20 04:01:00, 11, 130, WPA2 WPA3, CCMP, PSK SAE, -52, 100, 0, 0.0.0.0, 12, HUAWEI-9A3C,
WPA handshake: F8:D1:11:8F:2A:01

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
3C:07:54:AA:BB:CC, 2026-10-20 04:00:30, 2026-10-20 04:01:00, -50, 120, F8:D1:11:8F:2A:01, CMCC-5G-8F2A
"""


def test_parse_sample():
    aps, clients, handshakes = parse_airodump_csv(SAMPLE)
    assert len(aps) == 2
    assert aps[0]["ssid"] == "CMCC-5G-8F2A"
    assert aps[0]["channel"] == 149
    assert aps[0]["privacy"] == "WPA2"
    assert aps[0]["power"] == -44
    assert aps[1]["auth"] == "PSK SAE"
    assert handshakes == ["f8:d1:11:8f:2a:01"]
    assert len(clients) == 1
    assert clients[0]["mac"] == "3c:07:54:aa:bb:cc"
    assert clients[0]["probes"] == ["CMCC-5G-8F2A"]


def test_parse_truncated_and_garbage():
    text = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
F8:D1:11:8F:2A:01, 2026-10-20 04:00:00, 2026-10-20 04:01:00, 6, 1300, WPA2
not-a-mac, a, b, c
"""
    aps, clients, handshakes = parse_airodump_csv(text)
    assert aps == [] and clients == [] and handshakes == []


def test_parse_unassociated_station():
    """未关联客户端（探测中）的 BSSID 列是 "(not associated)"，不能当成 MAC。"""
    text = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
F8:D1:11:8F:2A:01, 2026-10-20 04:00:00, 2026-10-20 04:01:00, 6, 1300, WPA2, CCMP, PSK, -44, 231, 12, 0.0.0.0, 12, CMCC-5G-8F2A,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
92:CE:B8:02:56:DB, 2026-10-20 11:31:12, 2026-10-20 11:31:12, -55, 1, (not associated) ,511
DE:ED:F4:1D:03:C5, 2026-10-20 11:31:12, 2026-10-20 11:31:12, -56, 1, (not associated) ,Hlxh#13
3C:07:54:AA:BB:CC, 2026-10-20 04:00:30, 2026-10-20 04:01:00, -50, 120, F8:D1:11:8F:2A:01, CMCC-5G-8F2A
"""
    aps, clients, handshakes = parse_airodump_csv(text)
    assert len(aps) == 1
    assert len(clients) == 3
    assert clients[0]["bssid"] == ""
    assert clients[0]["probes"] == ["511"]
    assert clients[1]["bssid"] == ""
    assert clients[2]["bssid"] == "f8:d1:11:8f:2a:01"


def test_parse_empty():
    aps, clients, handshakes = parse_airodump_csv("")
    assert (aps, clients, handshakes) == ([], [], [])


def test_airodump_args_force_abg_band():
    """默认跳频只覆盖 2.4GHz，必须显式 --band abg 才能兼顾 5GHz。"""
    args = airodump_args("/tmp/scan", "wlan0mon")
    assert args[0] == "airodump-ng"
    assert args[args.index("--band") + 1] == "abg"
    assert args[-1] == "wlan0mon"
    assert "-c" not in args


def test_airodump_args_with_channel():
    args = airodump_args("/tmp/scan", "wlan0mon", 40)
    assert args[1:3] == ["-c", "40"]
    assert args[-1] == "wlan0mon"


def test_skip_beaconless_shell_ap():
    """只从客户端数据帧推断出的 AP 空壳行（无 Privacy、0 Beacon）不应落库。

    airodump 会写这种行，若保留会被 classify_security("") 误判成 OPEN。
    """
    text = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
8C:30:66:3C:65:5F, 2026-10-20 11:43:18, 2026-10-20 11:46:02, 36,  -1, , ,   ,  -1,        0,        0,   0.  0.  0.  0,   0, ,
88:5A:04:B4:E9:CB, 2026-10-20 12:28:07, 2026-10-20 12:28:20, 1, 180, WPA2, CCMP, PSK, -32, 92, 5, 0.0.0.0, 8, SZ078837,
AA:BB:CC:DD:EE:FF, 2026-10-20 12:28:07, 2026-10-20 12:28:20, 6, 130, WPA, TKIP, PSK, -1, 0, 4, 0.0.0.0, 0, ,
"""
    aps, _, _ = parse_airodump_csv(text)
    assert [a["bssid"] for a in aps] == ["88:5a:04:b4:e9:cb", "aa:bb:cc:dd:ee:ff"]
