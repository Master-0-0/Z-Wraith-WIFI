"""WPA/WPA2 离线校验的纯 Python 实现.

用途：
1. **演示模式**下生成真实的 PMKID 校验值，使破解流程不是"假动画"；
2. 无 aircrack-ng / hashcat 时的兜底破解（小字典）；
3. 单元测试的参考实现。

算法（IEEE 802.11i / RFC 2898）：

- ``PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32)``
- ``PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)``
- ``PTK = PRF-X(PMK, "Pairwise key expansion", min/max(MAC) || min/max(Nonce))``
- ``MIC = HMAC-SHA1(KCK, EAPOL)[:16]``（CCMP / keyver 2）
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

WPA_KEY_INFO_MIC = 0x0100
EAPOL_MIC_OFFSET = 81
EAPOL_MIC_LEN = 16
EAPOL_SNONCE_OFFSET = 17
EAPOL_SNONCE_LEN = 32


# ---------------------------------------------------------------------------
# 基础算法
# ---------------------------------------------------------------------------


def derive_pmk(passphrase: str | bytes, ssid: str | bytes) -> bytes:
    """PBKDF2-HMAC-SHA1，4096 轮，输出 32 字节 PMK。"""
    pw = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    salt = ssid.encode("utf-8") if isinstance(ssid, str) else ssid
    return hashlib.pbkdf2_hmac("sha1", pw, salt, 4096, 32)


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", "").lower())


def compute_pmkid(pmk: bytes, ap_mac: str, sta_mac: str) -> bytes:
    data = b"PMK Name" + _mac_bytes(ap_mac) + _mac_bytes(sta_mac)
    return hmac.new(pmk, data, hashlib.sha1).digest()[:16]


def _prf(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    """IEEE 802.11 PRF（HMAC-SHA1，计数器从 0 开始）。"""
    result = b""
    counter = 0
    while len(result) < length:
        result += hmac.new(key, label + b"\x00" + data + bytes([counter]), hashlib.sha1).digest()
        counter += 1
    return result[:length]


def compute_ptk(
    pmk: bytes,
    ap_mac: str,
    sta_mac: str,
    anonce: bytes,
    snonce: bytes,
) -> bytes:
    bssid = _mac_bytes(ap_mac)
    sta = _mac_bytes(sta_mac)
    mac_min, mac_max = sorted([bssid, sta])
    nonce_min, nonce_max = sorted([anonce, snonce])
    data = mac_min + mac_max + nonce_min + nonce_max
    return _prf(pmk, b"Pairwise key expansion", data, 64)


def compute_mic(kck: bytes, eapol: bytes) -> bytes:
    """计算 EAPOL-Key 帧的 MIC（先清零 MIC 字段）。"""
    frame = bytearray(eapol)
    if len(frame) >= EAPOL_MIC_OFFSET + EAPOL_MIC_LEN:
        frame[EAPOL_MIC_OFFSET : EAPOL_MIC_OFFSET + EAPOL_MIC_LEN] = b"\x00" * EAPOL_MIC_LEN
    return hmac.new(kck, bytes(frame), hashlib.sha1).digest()[:16]


def eapol_snonce(eapol: bytes) -> bytes:
    return eapol[EAPOL_SNONCE_OFFSET : EAPOL_SNONCE_OFFSET + EAPOL_SNONCE_LEN]


# ---------------------------------------------------------------------------
# .22000 解析
# ---------------------------------------------------------------------------


@dataclass
class HashLine:
    raw: str
    kind: str  # pmkid | mic
    pmkid: bytes = b""
    mic: bytes = b""
    ap_mac: str = ""
    sta_mac: str = ""
    ssid: str = ""
    anonce: bytes = b""
    eapol: bytes = b""

    @property
    def label(self) -> str:
        return f"{self.ssid or '<隐藏>'} ({self.ap_mac})"


def parse_22000(line: str) -> HashLine | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split("*")
    if len(parts) < 6 or parts[0] != "WPA":
        return None
    try:
        htype = parts[1]
        ap_mac = parts[3].lower()
        sta_mac = parts[4].lower()
        ssid = bytes.fromhex(parts[5]).decode("utf-8", "replace") if parts[5] else ""
    except (ValueError, IndexError):
        return None

    if htype == "01":
        try:
            pmkid = bytes.fromhex(parts[2])
        except ValueError:
            return None
        return HashLine(line, "pmkid", pmkid=pmkid, ap_mac=ap_mac, sta_mac=sta_mac, ssid=ssid)

    if htype == "02":
        # WPA*02*MIC*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR
        try:
            mic = bytes.fromhex(parts[2])
            anonce = bytes.fromhex(parts[6]) if len(parts) > 6 and parts[6] else b""
            eapol = bytes.fromhex(parts[7]) if len(parts) > 7 and parts[7] else b""
        except ValueError:
            return None
        if len(eapol) < EAPOL_MIC_OFFSET + EAPOL_MIC_LEN:
            return None
        return HashLine(
            line,
            "mic",
            mic=mic,
            ap_mac=ap_mac,
            sta_mac=sta_mac,
            ssid=ssid,
            anonce=anonce,
            eapol=eapol,
        )
    return None


def parse_22000_file(path: str | Path) -> list[HashLine]:
    p = Path(path)
    if not p.exists():
        return []
    out: list[HashLine] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = parse_22000(line)
        if parsed:
            out.append(parsed)
    return out


# ---------------------------------------------------------------------------
# 校验与破解
# ---------------------------------------------------------------------------


def verify(entry: HashLine, passphrase: str) -> bool:
    pmk = derive_pmk(passphrase, entry.ssid)
    if entry.kind == "pmkid":
        return hmac.compare_digest(compute_pmkid(pmk, entry.ap_mac, entry.sta_mac), entry.pmkid)
    snonce = eapol_snonce(entry.eapol)
    if len(entry.anonce) != 32 or len(snonce) != 32:
        return False
    ptk = compute_ptk(pmk, entry.ap_mac, entry.sta_mac, entry.anonce, snonce)
    return hmac.compare_digest(compute_mic(ptk[:16], entry.eapol), entry.mic)


def make_pmkid_line(
    passphrase: str,
    ssid: str,
    ap_mac: str,
    sta_mac: str,
) -> str:
    """生成 hashcat 22000 格式的 PMKID 行（用于演示环境与测试）。"""
    pmk = derive_pmk(passphrase, ssid)
    pmkid = compute_pmkid(pmk, ap_mac, sta_mac).hex()
    ssid_hex = ssid.encode("utf-8").hex()
    ap = ap_mac.replace(":", "").lower()
    sta = sta_mac.replace(":", "").lower()
    return f"WPA*01*{pmkid}*{ap}*{sta}*{ssid_hex}***"


def build_eapol_m2(
    ap_mac: str,
    sta_mac: str,
    snonce: bytes,
) -> bytes:
    """构造一个最小的 EAPOL-Key M2 帧（演示/测试用）.

    字段偏移与真实帧一致，MIC 字段留零，供 :func:`compute_mic` 填充。
    """
    # 802.1X header: version=2, type=3 (Key), length=95
    header = struct.pack("!BBH", 2, 3, 95)
    # descriptor type 2 (RSN), key info 0x010a (Key MIC + pairwise + CCMP), key length 16
    key_info = struct.pack("!H", 0x010A)
    key_len = struct.pack("!H", 16)
    replay = struct.pack("!Q", 2)
    nonce = snonce
    iv = b"\x00" * 16
    rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    mic = b"\x00" * 16
    key_data_len = struct.pack("!H", 0)
    body = (
        b"\x02"
        + key_info
        + key_len
        + replay
        + nonce
        + iv
        + rsc
        + key_id
        + mic
        + key_data_len
    )
    return header + body


def make_handshake_line(
    passphrase: str,
    ssid: str,
    ap_mac: str,
    sta_mac: str,
    anonce: bytes,
    snonce: bytes,
) -> str:
    """构造一个 MIC 可校验的 22000 type-02 行（演示/测试用）。"""
    pmk = derive_pmk(passphrase, ssid)
    ptk = compute_ptk(pmk, ap_mac, sta_mac, anonce, snonce)
    eapol = build_eapol_m2(ap_mac, sta_mac, snonce)
    mic = compute_mic(ptk[:16], eapol)
    eapol_filled = bytearray(eapol)
    eapol_filled[EAPOL_MIC_OFFSET : EAPOL_MIC_OFFSET + EAPOL_MIC_LEN] = mic
    ap = ap_mac.replace(":", "").lower()
    sta = sta_mac.replace(":", "").lower()
    return (
        f"WPA*02*{mic.hex()}*{ap}*{sta}*{ssid.encode('utf-8').hex()}"
        f"*{anonce.hex()}*{bytes(eapol_filled).hex()}*02"
    )


def crack(
    entries: Iterable[HashLine],
    wordlist: str | Path,
    *,
    progress: Callable[[int, int, float], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    max_candidates: int | None = None,
) -> tuple[str | None, int]:
    """纯 Python 字典破解（小字典/演示用）。

    返回 ``(命中口令 或 None, 尝试次数)``。相同 SSID 的 PMK 只计算一次。
    """
    entries = list(entries)
    if not entries:
        return None, 0
    by_ssid: dict[str, list[HashLine]] = {}
    for entry in entries:
        by_ssid.setdefault(entry.ssid, []).append(entry)

    path = Path(wordlist)
    if not path.exists():
        return None, 0

    import gzip

    opener = gzip.open if path.suffix == ".gz" else open
    tried = 0
    start = 0.0
    import time as _time

    start = _time.monotonic()
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:  # type: ignore[operator]
        for raw in fh:
            candidate = raw.rstrip("\r\n")
            if not candidate:
                continue
            tried += 1
            for ssid, group in by_ssid.items():
                pmk = derive_pmk(candidate, ssid)
                for entry in group:
                    if entry.kind == "pmkid":
                        if hmac.compare_digest(
                            compute_pmkid(pmk, entry.ap_mac, entry.sta_mac), entry.pmkid
                        ):
                            return candidate, tried
                    else:
                        snonce = eapol_snonce(entry.eapol)
                        if len(entry.anonce) != 32 or len(snonce) != 32:
                            continue
                        ptk = compute_ptk(pmk, entry.ap_mac, entry.sta_mac, entry.anonce, snonce)
                        if hmac.compare_digest(compute_mic(ptk[:16], entry.eapol), entry.mic):
                            return candidate, tried
            if progress and tried % 200 == 0:
                elapsed = max(0.001, _time.monotonic() - start)
                progress(tried, tried, tried / elapsed)
            if should_stop and should_stop():
                return None, tried
            if max_candidates and tried >= max_candidates:
                break
    return None, tried
