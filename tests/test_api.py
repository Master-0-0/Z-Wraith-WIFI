"""端到端 API 测试（演示模式，不触碰真实硬件）。"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from wraith.web.app import create_app


def _wait(client: TestClient, predicate, timeout: float = 20.0, interval: float = 0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("等待条件超时")


def test_health_and_system(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 404  # 只暴露 /api/health
        health = client.get("/api/health").json()
        assert health["ok"] and health["app"] == "wraith"
        system = client.get("/api/system").json()
        assert system["demo"] is True
        assert system["session"]["id"] > 0
        assert "deps" in system and system["auth"]["demo"] is True
        modules = client.get("/api/attacks").json()["modules"]
        assert len(modules) >= 11
        assert client.get("/").status_code == 200


def test_scan_attack_crack_and_report(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        # 扫描
        response = client.post("/api/scan/start", json={"duration": 10})
        assert response.status_code == 200, response.text

        aps = _wait(
            client,
            lambda: client.get("/api/aps").json().get("aps"),
            timeout=15,
        )
        assert aps
        target = next((a for a in aps if a["ssid"] == "CMCC-5G-8F2A"), aps[0])

        # 握手攻击
        response = client.post(
            "/api/attacks/handshake/start",
            json={
                "bssid": target["bssid"],
                "ssid": target["ssid"],
                "channel": target["channel"],
                "security": target["security"],
                "options": {"deauth": True, "timeout": 30},
            },
        )
        assert response.status_code == 200, response.text
        job = response.json()
        assert job["status"] == "running"

        _wait(
            client,
            lambda: client.get("/api/attacks").json()["active"] is None,
            timeout=25,
        )
        jobs = client.get("/api/attacks/jobs").json()["jobs"]
        assert jobs and jobs[0]["status"] == "success", jobs[0]

        captures = client.get("/api/captures").json()["captures"]
        assert captures, "攻击成功后应产生抓包"
        capture = captures[0]

        # 破解
        response = client.post(
            f"/api/captures/{capture['id']}/crack",
            json={"method": "offline", "wordlist": str(cfg.wordlist)},
        )
        assert response.status_code == 200, response.text
        job_id = response.json()["job_id"]
        _wait(
            client,
            lambda: next(
                (
                    c
                    for c in client.get("/api/cracks").json()["cracks"]
                    if c["id"] == job_id and c["status"] in {"found", "exhausted", "failed"}
                ),
                None,
            ),
            timeout=30,
        )
        crack = next(c for c in client.get("/api/cracks").json()["cracks"] if c["id"] == job_id)
        assert crack["status"] == "found"
        assert crack["key"] == "12345678"

        # 发现与报告
        findings = client.get("/api/findings").json()["findings"]
        assert any(f["category"] == "capture" for f in findings)
        html = client.get("/api/report/html")
        assert html.status_code == 200 and "Wi-Fi 渗透测试报告" in html.text
        assert target["ssid"] in html.text

        saved = client.post("/api/report/save").json()["paths"]
        assert set(saved) == {"html", "json", "md"}
        files = client.get("/api/report/files").json()["files"]
        assert len(files) >= 3
        download = client.get(f"/api/report/download/{files[0]['name']}")
        assert download.status_code == 200

        # 抓包下载
        download = client.get(f"/api/captures/{capture['id']}/download")
        assert download.status_code == 200

        # 停止扫描
        assert client.post("/api/scan/stop").status_code == 200


def test_websocket_hello(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello"
            ws.send_text("ping")
            message = ws.receive_json()
            assert message["type"] in {"pong", "event"}


def test_live_mode_requires_authorization(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        assert client.post("/api/system/mode", json={"mode": "live"}).status_code == 200
        system = client.get("/api/system").json()
        assert system["demo"] is False

        response = client.post(
            "/api/attacks/deauth/start",
            json={"bssid": "f8:d1:11:8f:2a:01", "channel": 6},
        )
        assert response.status_code == 403, response.text
        assert "授权" in response.json()["detail"]

        # 错误令牌同样被拒绝
        response = client.post("/api/authorization", json={"token": "let-me-in"})
        assert response.status_code == 403
        # 正确令牌可授权
        response = client.post("/api/authorization", json={"token": "AUTHORIZED"})
        assert response.status_code == 200
        assert response.json()["status"]["authorized"] is True

        client.post("/api/system/mode", json={"mode": "demo"})


def test_unknown_module_and_capture(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        assert client.post("/api/attacks/nope/start", json={"bssid": "f8:d1:11:8f:2a:01"}).status_code == 404
        assert client.post("/api/captures/999/crack", json={}).status_code == 404
