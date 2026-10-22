"""通用小工具。"""

from __future__ import annotations

import math
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


def now_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time()).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def human_bytes(size: float | int | None) -> str:
    if not size:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    idx = min(int(math.log(value, 1024)) if value >= 1 else 0, len(units) - 1)
    return f"{value / (1024 ** idx):.1f} {units[idx]}"


def human_duration(seconds: float | int | None) -> str:
    if seconds is None or seconds < 0:
        return "-"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def slugify(value: str, fallback: str = "target") -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "").strip("-.")
    return value or fallback


def safe_filename(value: str, fallback: str = "file") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "").strip("._")
    return cleaned[:80] or fallback


def mask_secret(value: str, keep: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def redact_command(cmd: Iterable[str]) -> list[str]:
    """对命令行中的口令类参数做脱敏，避免写进日志。"""
    out: list[str] = []
    sensitive_next = False
    for token in cmd:
        if sensitive_next:
            out.append(mask_secret(token))
            sensitive_next = False
            continue
        low = token.lower()
        if low in {"-w", "-p", "--wpa-passphrase", "-a"}:
            out.append(token)
            sensitive_next = False
            continue
        if low.startswith("wpa_passphrase="):
            out.append("wpa_passphrase=***")
            continue
        out.append(token)
    return out


def parse_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def make_run_dir(base: Path, prefix: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = base / f"{safe_filename(prefix)}-{stamp}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[: limit // 2] + "\n...[截断]...\n" + text[-limit // 2 :]
