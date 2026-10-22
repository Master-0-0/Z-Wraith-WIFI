"""全局配置：默认值、文件持久化、环境变量覆盖。"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/wordlists/john.lst",
]


def _default_wordlist() -> str:
    for candidate in DEFAULT_WORDLISTS:
        if Path(candidate).exists():
            return candidate
    return "/usr/share/wordlists/rockyou.txt"


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Config:
    """平台运行配置.

    可通过 ``data/config.json`` 持久化，也可由环境变量 ``WRAITH_*`` 覆盖，
    CLI 参数优先级最高。
    """

    mode: str = "demo"  # demo | live
    host: str = "127.0.0.1"
    port: int = 8787
    iface: str = ""
    data_dir: str = str(PROJECT_ROOT / "data")
    capture_dir: str = str(PROJECT_ROOT / "captures")
    wordlist: str = field(default_factory=_default_wordlist)
    # 授权
    authorized: bool = False
    operator: str = "operator"
    scope: list[str] = field(default_factory=list)  # BSSID 前缀 / SSID glob
    # 攻击参数
    deauth_bursts: int = 5
    scan_interval: float = 1.5
    attack_timeout: int = 180
    crack_timeout: int = 3600
    portal_port: int = 80
    # 其它
    stealth: bool = False
    demo_ap_count: int = 12

    # ---------------------------------------------------------------- paths
    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    @property
    def capture_path(self) -> Path:
        return Path(self.capture_dir)

    @property
    def db_path(self) -> Path:
        return self.data_path / "wraith.db"

    @property
    def audit_path(self) -> Path:
        return self.data_path / "audit.jsonl"

    @property
    def report_path(self) -> Path:
        return self.data_path / "reports"

    @property
    def run_path(self) -> Path:
        return self.data_path / "run"

    @property
    def config_path(self) -> Path:
        return self.data_path / "config.json"

    @property
    def is_live(self) -> bool:
        return self.mode == "live"

    def ensure_dirs(self) -> None:
        for p in (
            self.data_path,
            self.capture_path,
            self.report_path,
            self.run_path,
        ):
            p.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- io
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def save(self, path: Path | None = None) -> Path:
        target = Path(path) if path else self.config_path
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        # 授权只对当前进程有效，绝不跨重启持久化
        payload["authorized"] = False
        target.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return target

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        cfg = cls()
        cfg._apply_env()
        target = Path(path) if path else Path(cfg.data_dir) / "config.json"
        if target.exists():
            try:
                raw = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                raw = {}
            cfg._apply_dict(raw)
            cfg._apply_env()  # 环境变量优先于文件
        # 无论配置文件写了什么，授权必须由当前进程显式确认
        if "WRAITH_AUTHORIZED" not in os.environ:
            cfg.authorized = False
        return cfg

    def _apply_dict(self, raw: dict[str, Any]) -> None:
        allowed = set(self.__dataclass_fields__)  # type: ignore[attr-defined]
        for key, value in raw.items():
            if key in allowed and value is not None:
                setattr(self, key, value)

    def _apply_env(self) -> None:
        mapping: dict[str, tuple[str, type]] = {
            "WRAITH_MODE": ("mode", str),
            "WRAITH_HOST": ("host", str),
            "WRAITH_PORT": ("port", int),
            "WRAITH_IFACE": ("iface", str),
            "WRAITH_WORDLIST": ("wordlist", str),
            "WRAITH_OPERATOR": ("operator", str),
            "WRAITH_AUTHORIZED": ("authorized", bool),
            "WRAITH_DATA_DIR": ("data_dir", str),
            "WRAITH_CAPTURE_DIR": ("capture_dir", str),
        }
        for env, (attr, typ) in mapping.items():
            if env not in os.environ:
                continue
            raw = os.environ[env]
            if typ is bool:
                setattr(self, attr, raw.strip().lower() in {"1", "true", "yes", "on"})
            elif typ is int:
                try:
                    setattr(self, attr, int(raw))
                except ValueError:
                    pass
            else:
                setattr(self, attr, raw)

    # ---------------------------------------------------------------- misc
    def public_dict(self) -> dict[str, Any]:
        """暴露给前端的配置（不含敏感信息）。"""
        return {
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "iface": self.iface,
            "wordlist": self.wordlist,
            "wordlist_exists": Path(self.wordlist).exists(),
            "authorized": self.authorized,
            "operator": self.operator,
            "scope": list(self.scope),
            "stealth": self.stealth,
            "portal_port": self.portal_port,
            "data_dir": str(self.data_path),
            "capture_dir": str(self.capture_path),
            "version": __import__("wraith").__version__,
        }
