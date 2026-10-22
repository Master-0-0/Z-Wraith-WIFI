"""WPA/WPA2 离线校验算法测试（含 hashcat 已知向量）。"""

from __future__ import annotations

import hashlib

from wraith.crack import offline
from wraith.crack.offline import (
    compute_mic,
    compute_pmkid,
    derive_pmk,
    make_handshake_line,
    make_pmkid_line,
    parse_22000,
    parse_22000_file,
    verify,
)

# hashcat 官方示例哈希：WPA*01*4d4fe7...*fc690c158264*f4747f87f9f4*686173686361742d6573736964***
HASHCAT_AP = "fc:69:0c:15:82:64"
HASHCAT_STA = "f4:74:7f:87:f9:f4"
HASHCAT_SSID = "hashcat-essid"
HASHCAT_PSK = "hashcat!"
HASHCAT_PMKID = "4d4fe7aac3a2cecab195321ceb99a7d0"


def test_derive_pmk_length_and_determinism():
    pmk = derive_pmk("password", "IEEE")
    assert len(pmk) == 32
    assert pmk == hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32)
    assert pmk != derive_pmk("password", "ieee")


def test_pmkid_known_vector():
    pmk = derive_pmk(HASHCAT_PSK, HASHCAT_SSID)
    assert compute_pmkid(pmk, HASHCAT_AP, HASHCAT_STA).hex() == HASHCAT_PMKID


def test_make_pmkid_line_matches_hashcat_vector():
    line = make_pmkid_line(HASHCAT_PSK, HASHCAT_SSID, HASHCAT_AP, HASHCAT_STA)
    assert line.startswith("WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*")
    assert line.endswith("***")
    parsed = parse_22000(line)
    assert parsed is not None
    assert parsed.kind == "pmkid"
    assert parsed.ssid == HASHCAT_SSID
    assert verify(parsed, HASHCAT_PSK)
    assert not verify(parsed, "wrong-password")


def test_handshake_line_roundtrip_and_mic():
    anonce = bytes(range(32))
    snonce = bytes(range(32, 64))
    line = make_handshake_line("Huawei@123", "HUAWEI-9A3C", HASHCAT_AP, HASHCAT_STA, anonce, snonce)
    parsed = parse_22000(line)
    assert parsed is not None and parsed.kind == "mic"
    assert len(parsed.eapol) >= 97
    assert parsed.anonce == anonce
    assert verify(parsed, "Huawei@123")
    assert not verify(parsed, "Huawei@1234")

    # MIC 必须落在 EAPOL 帧的 MIC 字段
    pmk = derive_pmk("Huawei@123", "HUAWEI-9A3C")
    ptk = offline.compute_ptk(pmk, HASHCAT_AP, HASHCAT_STA, anonce, snonce)
    expected = compute_mic(ptk[:16], parsed.eapol)
    assert expected == parsed.mic


def test_parse_rejects_garbage():
    assert parse_22000("") is None
    assert parse_22000("hello world") is None
    assert parse_22000("WPA*01*zzzz*aa*bb*cc***") is None
    assert parse_22000("WPA*02*00*aa*bb*cc*dd*ee*ff") is None


def test_crack_small_wordlist(tmp_path):
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("123456\npassword\nHuawei@123\n", encoding="utf-8")
    line = make_pmkid_line("Huawei@123", "HUAWEI-9A3C", HASHCAT_AP, HASHCAT_STA)
    entries = [parse_22000(line)]
    key, tried = offline.crack(entries, wordlist)
    assert key == "Huawei@123"
    assert tried == 3


def test_crack_gzip_wordlist(tmp_path):
    import gzip

    path = tmp_path / "w.txt.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("aaa\nHuawei@123\n")
    line = make_pmkid_line("Huawei@123", "HUAWEI-9A3C", HASHCAT_AP, HASHCAT_STA)
    key, _ = offline.crack([parse_22000(line)], path)
    assert key == "Huawei@123"


def test_parse_file(tmp_path):
    line = make_pmkid_line("x", "ssid", HASHCAT_AP, HASHCAT_STA)
    path = tmp_path / "h.22000"
    path.write_text(line + "\n" + "# comment\n" + line + "\n", encoding="utf-8")
    assert len(parse_22000_file(path)) == 2


def test_empty_wordlist_returns_none(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    line = make_pmkid_line("x", "ssid", HASHCAT_AP, HASHCAT_STA)
    key, tried = offline.crack([parse_22000(line)], empty)
    assert key is None and tried == 0
