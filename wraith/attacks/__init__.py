"""攻击模块注册表."""

from __future__ import annotations

from typing import Any

from .base import AttackContext, AttackModule, AttackResult, Option
from .beacon_flood import BeaconFlood
from .deauth import DeauthAttack
from .enterprise import EnterpriseAttack
from .evil_twin import EvilTwin
from .handshake import HandshakeCapture
from .karma import KarmaAttack
from .pmkid import PMKIDCapture
from .wep import WEPAttack
from .wps import WPSPin, WPSPixie
from .wpa3_downgrade import WPA3Downgrade

_MODULE_CLASSES: list[type[AttackModule]] = [
    DeauthAttack,
    HandshakeCapture,
    PMKIDCapture,
    WPSPixie,
    WPSPin,
    WEPAttack,
    EvilTwin,
    WPA3Downgrade,
    KarmaAttack,
    EnterpriseAttack,
    BeaconFlood,
]

MODULES: dict[str, AttackModule] = {cls.id: cls() for cls in _MODULE_CLASSES}


def get_module(module_id: str) -> AttackModule:
    module = MODULES.get(module_id)
    if not module:
        raise KeyError(f"未知攻击模块: {module_id}")
    return module


def list_modules() -> list[dict[str, Any]]:
    order = {
        "credential": 0,
        "wps": 1,
        "downgrade": 2,
        "enterprise": 3,
        "rogue_ap": 4,
        "availability": 5,
    }
    items = [m.to_dict() for m in MODULES.values()]
    items.sort(key=lambda m: (order.get(m["category"], 9), m["name"]))
    return items


def modules_by_id() -> dict[str, AttackModule]:
    return dict(MODULES)


__all__ = [
    "AttackModule",
    "AttackContext",
    "AttackResult",
    "Option",
    "MODULES",
    "get_module",
    "list_modules",
    "modules_by_id",
    "DeauthAttack",
    "HandshakeCapture",
    "PMKIDCapture",
    "WPSPixie",
    "WPSPin",
    "WEPAttack",
    "EvilTwin",
    "WPA3Downgrade",
    "KarmaAttack",
    "EnterpriseAttack",
    "BeaconFlood",
]
