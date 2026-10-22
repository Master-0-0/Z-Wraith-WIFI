"""系统层：依赖探测、命令执行、网卡管理。"""

from .deps import detect_all, doctor, is_installed, missing, status, suggest_install
from .iface import IfaceInfo, IfaceManager
from .runner import CommandResult, Runner

__all__ = [
    "Runner",
    "CommandResult",
    "IfaceManager",
    "IfaceInfo",
    "detect_all",
    "doctor",
    "is_installed",
    "missing",
    "status",
    "suggest_install",
]
