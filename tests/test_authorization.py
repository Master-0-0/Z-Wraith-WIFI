"""授权门禁与审计测试。"""

from __future__ import annotations

import json
from pathlib import Path

from wraith.authorization import AUTH_TOKEN, AuthorizationGate


def test_demo_mode_allowed(cfg):
    gate = AuthorizationGate(cfg)
    decision = gate.check("deauth", bssid="f8:d1:11:8f:2a:01")
    assert decision.allowed and decision.demo


def test_live_requires_authorization(cfg):
    cfg.mode = "live"
    gate = AuthorizationGate(cfg)
    decision = gate.check("deauth", bssid="f8:d1:11:8f:2a:01")
    assert not decision.allowed
    assert AUTH_TOKEN in decision.reason


def test_grant_flow_and_scope(cfg):
    cfg.mode = "live"
    gate = AuthorizationGate(cfg)
    ok, _ = gate.grant("wrong-token")
    assert not ok and not cfg.authorized

    ok, _ = gate.grant(AUTH_TOKEN, scope=["f8:d1:11", "Corp-*"])
    assert ok and cfg.authorized
    assert gate.check("deauth", bssid="f8:d1:11:8f:2a:01").allowed
    assert gate.check("deauth", bssid="aa:bb:cc:dd:ee:ff").allowed is False
    assert gate.check("deauth", bssid="aa:bb:cc:dd:ee:ff", ssid="corp-wifi").allowed

    gate.revoke()
    assert not cfg.authorized


def test_audit_file_written(cfg):
    cfg.mode = "live"
    gate = AuthorizationGate(cfg)
    gate.grant(AUTH_TOKEN, scope=["f8:d1:11"])
    gate.audit_target("handshake", "aa:bb:cc:dd:ee:ff", "Other")
    gate.audit_target("handshake", "f8:d1:11:8f:2a:01", "CMCC")

    path = Path(cfg.audit_path)
    assert path.exists()
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert any(r["action"] == "handshake" and r["allowed"] is False for r in records)
    assert any(r["action"] == "handshake" and r["allowed"] is True for r in records)
    assert all("operator" in r for r in records)
    assert gate.recent_audit(10)


def test_require_raises_when_denied(cfg):
    cfg.mode = "live"
    gate = AuthorizationGate(cfg)
    try:
        gate.require("evil_twin", bssid="f8:d1:11:8f:2a:01")
    except PermissionError:
        pass
    else:  # pragma: no cover
        raise AssertionError("未授权时应抛出 PermissionError")
