"""攻击模块注册、校验与演示模式执行测试。"""

from __future__ import annotations

import asyncio
from pathlib import Path

from wraith.attacks import get_module, list_modules
from wraith.attacks.base import AttackContext
from wraith.attacks.deauth import DeauthAttack
from wraith.attacks.evil_twin import EvilTwin
from wraith.attacks.handshake import HandshakeCapture
from wraith.attacks.pmkid import PMKIDCapture
from wraith.attacks.wpa3_downgrade import WPA3Downgrade
from wraith.crack import offline

TARGET = {
    "bssid": "f8:d1:11:8f:2a:01",
    "ssid": "CMCC-5G-8F2A",
    "channel": 149,
    "security": "WPA2",
    "wps": True,
}


def make_ctx(parts) -> AttackContext:
    return AttackContext(
        config=parts.config,
        bus=parts.bus,
        store=parts.store,
        runner=parts.runner,
        iface_mgr=parts.iface,
        gate=parts.gate,
        session_id=parts.session_id,
    )


def test_registry_contains_core_modules():
    ids = {m["id"] for m in list_modules()}
    assert {
        "deauth",
        "handshake",
        "pmkid",
        "wps_pixie",
        "wps_pin",
        "wep",
        "evil_twin",
        "wpa3_downgrade",
        "karma",
        "enterprise",
        "beacon_flood",
    } <= ids
    module = get_module("handshake")
    assert module.name == "四次握手捕获"
    assert module.risk == "high"


def test_validation_requires_valid_target():
    module = DeauthAttack()
    assert module.validate({}) == ["目标 BSSID 无效"]
    assert module.validate({"bssid": "f8:d1:11:8f:2a:01", "channel": 6}) == []
    assert any("信道" in issue for issue in module.validate({"bssid": "f8:d1:11:8f:2a:01", "channel": 999}))


def test_wpa3_downgrade_validation():
    module = WPA3Downgrade()
    pure = module.validate({**TARGET, "security": "WPA3"})
    assert any("纯 WPA3" in issue for issue in pure)
    legacy = module.validate({**TARGET, "security": "WPA2"})
    assert any("过渡" in issue for issue in legacy)
    assert module.validate({**TARGET, "security": "WPA2/WPA3"}) == []


def test_option_defaults_are_typed():
    module = HandshakeCapture()
    cleaned = module.clean({"bssid": TARGET["bssid"], "timeout": "30", "deauth": "false"})
    assert cleaned["timeout"] == 30
    assert cleaned["deauth"] is False
    assert cleaned["deauth_interval"] == 15


def test_deauth_demo(parts):
    ctx = make_ctx(parts)

    async def run():
        return await DeauthAttack().run(ctx, {**TARGET, "count": 5, "rounds": 2})

    result = asyncio.run(run())
    assert result.ok
    assert result.detail["frames"] == 10
    findings = parts.store.list_findings(parts.session_id)
    assert findings and findings[0]["category"] == "availability"


def test_handshake_demo_produces_crackable_hash(parts):
    ctx = make_ctx(parts)

    async def run():
        return await HandshakeCapture().run(ctx, {**TARGET, "timeout": 30})

    result = asyncio.run(run())
    assert result.ok and result.capture_id
    captures = parts.store.list_captures(parts.session_id)
    assert captures and captures[0]["kind"] == "handshake"
    assert captures[0]["hash_lines"] == 1

    path = Path(captures[0]["path"])
    assert path.exists()
    entries = offline.parse_22000_file(path)
    key, _ = offline.crack(entries, parts.config.wordlist)
    assert key == "12345678"


def test_pmkid_demo_uses_real_pmkid(parts):
    ctx = make_ctx(parts)

    async def run():
        return await PMKIDCapture().run(ctx, {**TARGET, "timeout": 20})

    result = asyncio.run(run())
    assert result.ok
    capture = parts.store.list_captures(parts.session_id)[0]
    line = Path(capture["path"]).read_text(encoding="utf-8").strip()
    assert line.startswith("WPA*01*")
    entries = offline.parse_22000_file(capture["path"])
    key, _ = offline.crack(entries, parts.config.wordlist)
    assert key == "12345678"


def test_handshake_rejects_open_network(parts):
    module = HandshakeCapture()
    issues = module.validate({**TARGET, "security": "OPEN"})
    assert issues and "没有四次握手" in issues[0]


def test_evil_twin_clones_target_security():
    module = EvilTwin()
    # 扫描结果是大写的 WPA2 / WPA2-WPA3 过渡，必须归一化成 wpa2，否则会退化成开放网络
    assert module._resolve_security("WPA2", "12345678") == "wpa2"
    assert module._resolve_security("WPA2/WPA3", "12345678") == "wpa2"
    assert module._resolve_security("wpa2", "12345678") == "wpa2"
    # 没有口令时只能开放，但 WEP/OWE 无法用 PSK 克隆
    assert module._resolve_security("WPA2", "") == "open"
    assert module._resolve_security("WEP", "12345678") == "open"
    assert module._resolve_security("OPEN", "12345678") == "open"

    conf = module._hostapd_config(
        "wlan0ap", "SZ078837", 1, "wpa2", "12345678", "88:5a:04:b4:e9:cb"
    )
    assert "wpa=2" in conf
    assert "wpa_passphrase=12345678" in conf
    assert "wpa_key_mgmt=WPA-PSK" in conf
    assert "bssid=88:5a:04:b4:e9:cb" in conf

    open_conf = module._hostapd_config("wlan0ap", "SZ078837", 1, "open", "", "")
    assert "wpa=" not in open_conf
    assert "bssid=" not in open_conf


def test_evil_twin_reuses_cracked_psk(parts):
    from wraith.models import Capture, CrackJob

    capture_id = parts.store.add_capture(
        Capture(
            kind="handshake",
            path=str(parts.config.capture_path / "fake.cap"),
            bssid="88:5a:04:b4:e9:cb",
            ssid="SZ078837",
            session_id=parts.session_id,
        )
    )
    parts.store.add_crack(
        CrackJob(capture_id=capture_id, method="offline", status="found", key="12345678")
    )
    ctx = make_ctx(parts)
    assert EvilTwin._cracked_psk(ctx, "88:5a:04:b4:e9:cb") == "12345678"
    assert EvilTwin._cracked_psk(ctx, "f8:d1:11:8f:2a:01") == ""

