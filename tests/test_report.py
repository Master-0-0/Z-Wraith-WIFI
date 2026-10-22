"""报告生成测试。"""

from __future__ import annotations

import json
import time
from pathlib import Path

from wraith.models import AP, Capture, Credential, Finding
from wraith.report.generator import ReportGenerator


def _seed(parts, tmp_path: Path) -> int:
    store, sid = parts.store, parts.session_id
    store.upsert_ap(
        AP(bssid="f8:d1:11:8f:2a:01", ssid="CMCC-5G", channel=149, privacy="WPA2", power=-44, wps=True),
        sid,
    )
    store.add_finding(
        Finding(
            session_id=sid,
            title="WPS 已启用",
            severity="high",
            bssid="f8:d1:11:8f:2a:01",
            ssid="CMCC-5G",
            detail="WPS 可被 Pixie Dust 攻击。",
            category="wps",
        )
    )
    capture_path = tmp_path / "cap.22000"
    capture_path.write_text("WPA*01*aa*bb*cc*dd***\n", encoding="utf-8")
    capture_id = store.add_capture(
        Capture(
            kind="pmkid",
            path=str(capture_path),
            bssid="f8:d1:11:8f:2a:01",
            ssid="CMCC-5G",
            size=32,
            hash_lines=1,
            session_id=sid,
        )
    )
    job_id = store.add_crack(
        type(
            "J",
            (),
            {
                "capture_id": capture_id,
                "method": "offline",
                "wordlist": "words.txt",
                "status": "running",
                "key": "",
                "started_at": time.time(),
                "finished_at": 0.0,
                "progress": 0.0,
                "log": "",
            },
        )()
    )
    store.update_crack(job_id, status="found", key="12345678", finished_at=time.time())
    store.add_credential(
        Credential(session_id=sid, username="alice", password="s3cret", portal="evil-twin", ip="10.0.0.5")
    )
    return sid


def test_report_html_contains_assets(parts, tmp_path):
    sid = _seed(parts, tmp_path)
    generator = ReportGenerator(parts.store, sid)
    html = generator.html()
    assert "Wi-Fi 渗透测试报告" in html
    assert "CMCC-5G" in html
    assert "12345678" in html
    assert "alice" in html
    assert "WPS 已启用" in html
    assert "严重" in html or "高危" in html


def test_report_markdown_and_json(parts, tmp_path):
    sid = _seed(parts, tmp_path)
    generator = ReportGenerator(parts.store, sid)
    md = generator.markdown()
    assert "# Wi-Fi 渗透测试报告" in md
    assert "| CMCC-5G |" in md
    data = generator.json()
    assert data["stats"]["aps"] == 1
    assert data["cracked_count"] == 1
    assert data["severity_counts"]["high"] == 1
    json.dumps(data, default=str)


def test_report_save_creates_three_formats(parts, tmp_path):
    sid = _seed(parts, tmp_path)
    out = tmp_path / "reports"
    paths = ReportGenerator(parts.store, sid).save(out)
    assert set(paths) == {"html", "json", "md"}
    for path in paths.values():
        assert Path(path).exists() and Path(path).stat().st_size > 0
