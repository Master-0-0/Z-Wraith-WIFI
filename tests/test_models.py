"""模型与协议字段归一化测试。"""

from __future__ import annotations

import pytest

from wraith.models import (
    AP,
    ENTERPRISE_SUFFIX,
    LOCAL_MAC_VENDOR,
    TRANSITION,
    UNREGISTERED_VENDOR,
    band_for_channel,
    classify_security,
    is_mac,
    normalize_mac,
    signal_quality,
    vendor_for,
)


@pytest.mark.parametrize(
    "privacy,auth,expected",
    [
        ("OPN", "", "OPEN"),
        ("", "", "OPEN"),
        ("WEP", "", "WEP"),
        # airodump 对 data-frame-only BSSID 会输出矛盾的 "WPA WEP"：不能当 WEP
        ("WPA WEP", "WEP", "WPA"),
        ("WPA", "PSK", "WPA"),
        ("WPA2", "PSK", "WPA2"),
        ("WPA3", "SAE", "WPA3"),
        ("WPA2 WPA3", "PSK SAE", TRANSITION),
        ("WPA3 WPA2", "SAE PSK", TRANSITION),
        ("WPA2", "MGT", "WPA2-ENT"),
        ("WPA3", "MGT", "WPA3-ENT"),
        ("WPA2 WPA3", "MGT", TRANSITION + ENTERPRISE_SUFFIX),
        ("OWE", "", "OWE"),
    ],
)
def test_classify_security(privacy, auth, expected):
    assert classify_security(privacy, auth) == expected


def test_band_for_channel():
    assert band_for_channel(6) == "2.4GHz"
    assert band_for_channel(14) == "2.4GHz"
    assert band_for_channel(36) == "5GHz"
    assert band_for_channel(149) == "5GHz"
    assert band_for_channel(32, 5955) == "6GHz"
    assert band_for_channel(None) == "?"


def test_signal_quality():
    assert signal_quality(-40) == 100
    assert signal_quality(-100) == 0
    assert 40 < signal_quality(-70) < 100


def test_mac_helpers():
    assert normalize_mac("F8-D1-11-8F-2A-01") == "f8:d1:11:8f:2a:01"
    assert is_mac("f8:d1:11:8f:2a:01")
    assert not is_mac("nope")
    with pytest.raises(ValueError):
        normalize_mac("11:22:33")


def test_vendor_lookup():
    assert vendor_for("f8:d1:11:8f:2a:01") == "TP-Link"
    assert vendor_for("24:6f:28:00:00:01") == "Espressif"
    # 完整 OUI 库里的新厂商（旧版小表会返回 Unknown）
    assert vendor_for("e4:38:83:59:c4:05") == "Ubiquiti"
    assert vendor_for("50:92:6a:3c:1a:0b") == "Xiaomi"
    assert vendor_for("00:25:00:ff:94:73") == "Apple"
    # 本地管理位为 1：随机化 MAC，没有 OUI 厂商
    assert vendor_for("02:00:00:00:00:01") == LOCAL_MAC_VENDOR
    assert vendor_for("ea:38:83:59:c4:05") == LOCAL_MAC_VENDOR
    # 未注册的全局地址
    assert vendor_for("88:5a:04:b4:e9:cb") == UNREGISTERED_VENDOR


def test_ap_properties():
    ap = AP(
        bssid="F8:D1:11:8F:2A:01",
        ssid="CMCC-5G",
        channel=149,
        privacy="WPA2 WPA3",
        auth="PSK SAE",
        power=-52,
        wps=True,
    )
    assert ap.bssid == "f8:d1:11:8f:2a:01"
    assert ap.security == TRANSITION
    assert ap.is_transition
    assert ap.band == "5GHz"
    assert ap.quality == 96
    assert ap.display_ssid == "CMCC-5G"
    d = ap.to_dict()
    assert d["security"] == TRANSITION and d["wps"] is True


def test_hidden_ssid_display():
    ap = AP(bssid="f8:d1:11:8f:2a:01", ssid="")
    assert ap.display_ssid == "<隐藏>"
    assert ap.security == "OPEN"
