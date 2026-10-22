"""SQLite 存储层测试。"""

from __future__ import annotations

import time

from wraith.models import AP, Capture, Client, CrackJob, Credential, Event, Finding


def test_upsert_ap_updates_and_preserves_first_seen(parts):
    store = parts.store
    sid = parts.session_id
    first = AP(bssid="f8:d1:11:8f:2a:01", ssid="CMCC", channel=6, privacy="WPA2", power=-60)
    store.upsert_ap(first, sid)
    row = store.get_ap(sid, "f8:d1:11:8f:2a:01")
    assert row["ssid"] == "CMCC" and row["power"] == -60

    updated = AP(bssid="f8:d1:11:8f:2a:01", ssid="", channel=11, privacy="WPA2", power=-40, wps=True)
    updated.first_seen = first.first_seen - 100  # 不应覆盖首次时间
    store.upsert_ap(updated, sid)
    row = store.get_ap(sid, "f8:d1:11:8f:2a:01")
    assert row["ssid"] == "CMCC"  # 空 SSID 不覆盖旧值
    assert row["channel"] == 11
    assert row["power"] == -40
    assert row["wps"] == 1
    assert abs(row["first_seen"] - first.first_seen) < 1

    aps = store.list_aps(sid)
    assert len(aps) == 1


def test_clients_probes_roundtrip(parts):
    store, sid = parts.store, parts.session_id
    store.upsert_client(
        Client(mac="3c:07:54:aa:bb:cc", bssid="f8:d1:11:8f:2a:01", power=-50, probes=["CMCC", "Guest"]),
        sid,
    )
    store.upsert_client(
        Client(mac="3c:07:54:aa:bb:cc", bssid="f8:d1:11:8f:2a:01", power=-45, probes=["Office"]),
        sid,
    )
    clients = store.list_clients(sid)
    assert len(clients) == 1
    assert clients[0]["power"] == -45
    assert clients[0]["probes"] == ["Office"]


def test_capture_crack_and_stats(parts, tmp_path):
    store, sid = parts.store, parts.session_id
    cap = tmp_path / "cap.22000"
    cap.write_text("WPA*01*aa*bb*cc*dd***\n", encoding="utf-8")
    capture_id = store.add_capture(
        Capture(kind="pmkid", path=str(cap), bssid="f8:d1:11:8f:2a:01", ssid="CMCC", session_id=sid)
    )
    job_id = store.add_crack(
        CrackJob(capture_id=capture_id, method="offline", status="running", started_at=time.time())
    )
    store.update_crack(job_id, status="found", key="12345678", progress=1.0)
    cracks = store.list_cracks()
    assert cracks[0]["key"] == "12345678"
    assert cracks[0]["status"] == "found"

    stats = store.stats(sid)
    assert stats["captures"] == 1 and stats["cracked"] == 1

    store.add_finding(Finding(session_id=sid, title="t", severity="high", bssid="x"))
    assert len(store.list_findings(sid)) == 1
    store.add_credential(Credential(session_id=sid, username="u", password="p"))
    assert store.stats(sid)["credentials"] == 1


def test_events_exclude_debug(parts):
    store, sid = parts.store, parts.session_id
    store.add_event(sid, Event(ts=time.time(), level="debug", source="x", message="hidden"))
    store.add_event(sid, Event(ts=time.time(), level="info", source="x", message="shown"))
    events = store.list_events(sid)
    assert [e["message"] for e in events] == ["shown"]


def test_backfill_vendors_fixes_legacy_rows(parts):
    store, sid = parts.store, parts.session_id
    store.upsert_ap(AP(bssid="e4:38:83:59:c4:05", vendor="Ubiquiti"), sid)
    store.upsert_client(Client(mac="00:25:00:ff:94:73", vendor="Apple"), sid)
    # 模拟旧版本写入的 Unknown
    store._execute("UPDATE aps SET vendor='Unknown' WHERE bssid='e4:38:83:59:c4:05'")
    store._execute("UPDATE clients SET vendor='' WHERE mac='00:25:00:ff:94:73'")

    assert store.backfill_vendors() == 2
    assert store.get_ap(sid, "e4:38:83:59:c4:05")["vendor"] == "Ubiquiti"
    assert store.list_clients(sid)[0]["vendor"] == "Apple"


def test_session_lifecycle(parts):
    store, sid = parts.store, parts.session_id
    session = store.get_session(sid)
    assert session["status"] == "active"
    store.end_session(sid)
    assert store.get_session(sid)["status"] == "closed"
    export = store.session_export(sid)
    assert export["session"]["id"] == sid
