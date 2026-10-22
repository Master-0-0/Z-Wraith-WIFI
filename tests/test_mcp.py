"""MCP 接入层测试：协议、工具覆盖、完整 demo 链路与 stdio 传输。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from wraith.mcp.specs import TOOL_SPECS
from wraith.web.app import create_app

ROOT = Path(__file__).resolve().parent.parent


def rpc(client: TestClient, method: str, params: dict | None = None, request_id: int = 1) -> dict:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "error" not in payload, payload
    return payload["result"]


def tool(client: TestClient, name: str, arguments: dict | None = None) -> dict:
    return rpc(client, "tools/call", {"name": name, "arguments": arguments or {}})


def tool_text(result: dict) -> str:
    return "\n".join(
        block.get("text", "")
        for block in result.get("content", [])
        if block.get("type") == "text"
    )


def wait_for(predicate, timeout: float = 20.0, interval: float = 0.25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("等待条件超时")


def test_mcp_protocol_and_tools(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        result = rpc(
            client,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        )
        assert result["protocolVersion"] == "2025-06-18"
        assert result["serverInfo"]["name"] == "wraith"
        assert "tools" in result["capabilities"]
        assert "Wraith" in result["instructions"]

        # 2026 协议探测必须回 -32601，客户端才会回退到 legacy initialize。
        discover = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {}},
        ).json()
        assert discover["error"]["code"] == -32601

        # 通知无响应体。
        notification = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert notification.status_code == 202

        assert rpc(client, "ping") == {}
        tools = rpc(client, "tools/list")["tools"]
        assert len(tools) == len(TOOL_SPECS) >= 40
        names = [item["name"] for item in tools]
        assert len(names) == len(set(names))
        for item in tools:
            assert item["description"]
            schema = item["inputSchema"]
            assert schema["type"] == "object"
            assert schema["additionalProperties"] is False
            for required in schema.get("required", []):
                assert required in schema["properties"]

        # 未知方法、坏 JSON、GET SSE、非法 Origin。
        unknown = client.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "resources/list"}
        ).json()
        assert unknown["error"]["code"] == -32601
        bad = client.post("/mcp", content=b"{not json")
        assert bad.status_code == 400 and bad.json()["error"]["code"] == -32700
        assert client.get("/mcp").status_code == 405
        blocked = client.post(
            "/mcp",
            headers={"Origin": "http://evil.example"},
            json={"jsonrpc": "2.0", "id": 4, "method": "ping"},
        )
        assert blocked.status_code == 403


def test_every_api_route_has_mcp_tool(cfg):
    app = create_app(cfg)
    schema = app.openapi()
    tool_routes = {(spec.method, spec.path) for spec in TOOL_SPECS}
    report_routes = {
        ("GET", "/api/report/html"),
        ("GET", "/api/report/json"),
        ("GET", "/api/report/md"),
    }
    missing = []
    for path, operations in schema["paths"].items():
        if not path.startswith("/api/"):
            continue
        for method in operations:
            method = method.upper()
            if (method, path) in tool_routes:
                continue
            if (method, path) in report_routes:
                continue
            missing.append((method, path))
    assert not missing, f"以下 API 还没有 MCP 工具：{missing}"


def test_mcp_tool_errors_and_audit_redaction(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        unknown = tool(client, "nope")
        assert unknown["isError"] is True
        assert "未知工具" in tool_text(unknown)

        extra = tool(client, "system_info", {"unexpected": 1})
        assert extra["isError"] is True
        assert "不支持参数" in tool_text(extra)

        missing = tool(client, "authorize", {})
        assert missing["isError"] is True
        assert "缺少必填参数" in tool_text(missing)

        bad_enum = tool(client, "set_mode", {"mode": "production"})
        assert bad_enum["isError"] is True
        assert "取值必须是" in tool_text(bad_enum)

        traversal = tool(client, "report_download", {"name": "../secret"})
        assert traversal["isError"] is True
        assert "文件名" in tool_text(traversal) or "路径" in tool_text(traversal)

        # 授权令牌绝不能出现在审计日志里。
        granted = tool(client, "authorize", {"token": "AUTHORIZED", "operator": "pytest"})
        assert granted["isError"] is False
        audit = (cfg.data_path / "mcp-audit.jsonl").read_text(encoding="utf-8")
        assert "AUTHORIZED" not in audit
        assert '"***"' in audit
        assert '"tool": "authorize"' in audit


def test_mcp_live_mode_requires_authorization(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        assert tool(client, "set_mode", {"mode": "live"})["isError"] is False
        info = tool(client, "system_info")["structuredContent"]
        assert info["demo"] is False

        denied = tool(
            client,
            "attack_start",
            {"module_id": "deauth", "bssid": "f8:d1:11:8f:2a:01", "channel": 6},
        )
        assert denied["isError"] is True
        assert "授权" in tool_text(denied)

        wrong = tool(client, "authorize", {"token": "let-me-in"})
        assert wrong["isError"] is True
        assert "令牌" in tool_text(wrong)

        granted = tool(client, "authorize", {"token": "AUTHORIZED", "operator": "pytest"})
        assert granted["isError"] is False
        status = tool(client, "authorization_status")["structuredContent"]
        assert status["authorized"] is True

        revoked = tool(client, "authorization_revoke")
        assert revoked["isError"] is False
        assert tool(client, "authorization_status")["structuredContent"]["authorized"] is False
        assert tool(client, "set_mode", {"mode": "demo"})["isError"] is False


def test_mcp_demo_end_to_end(cfg):
    app = create_app(cfg)
    with TestClient(app) as client:
        assert tool(client, "scan_start", {"duration": 8})["isError"] is False
        aps = wait_for(
            lambda: tool(client, "aps")["structuredContent"]["aps"],
            timeout=15,
        )
        target = next((ap for ap in aps if ap["ssid"] == "CMCC-5G-8F2A"), aps[0])

        started = tool(
            client,
            "attack_start",
            {
                "module_id": "handshake",
                "bssid": target["bssid"],
                "ssid": target["ssid"],
                "channel": target["channel"],
                "security": target["security"],
                "options": {"deauth": True, "timeout": 30},
            },
        )
        assert started["isError"] is False, tool_text(started)
        job = started["structuredContent"]
        assert job["status"] == "running"

        finished = tool(client, "attack_wait", {"job_id": job["id"], "timeout_sec": 25})
        assert finished["isError"] is False, tool_text(finished)
        assert finished["structuredContent"]["status"] == "success"

        captures = tool(client, "captures")["structuredContent"]["captures"]
        assert captures
        capture = captures[0]
        assert capture["exists"] is True

        downloaded = tool(client, "capture_download", {"capture_id": capture["id"]})
        assert downloaded["isError"] is False
        assert len(downloaded["structuredContent"]["sha256"]) == 64

        crack = tool(
            client,
            "crack_start",
            {"capture_id": capture["id"], "method": "offline", "wordlist": str(cfg.wordlist)},
        )
        assert crack["isError"] is False
        cracked = tool(client, "crack_wait", {"job_id": crack["structuredContent"]["job_id"], "timeout_sec": 30})
        assert cracked["isError"] is False, tool_text(cracked)
        assert cracked["structuredContent"]["status"] == "found"
        assert cracked["structuredContent"]["key"] == "12345678"

        findings = tool(client, "findings")["structuredContent"]["findings"]
        assert any(item["category"] == "capture" for item in findings)

        report = tool(client, "report", {"format": "json"})["structuredContent"]
        assert report["session"]["id"] == info_session(client)
        assert any(ap["bssid"] == target["bssid"] for ap in report["aps"])

        saved = tool(client, "report_save")["structuredContent"]["paths"]
        assert set(saved) == {"html", "json", "md"}
        assert tool(client, "report_files")["structuredContent"]["files"]
        name = Path(saved["md"]).name
        markdown = tool(client, "report_download", {"name": name})
        assert markdown["isError"] is False
        assert "Wi-Fi 渗透测试报告" in tool_text(markdown)

        assert tool(client, "session_notes", {"notes": "MCP demo"})["isError"] is False

        # 清理扫描，避免 TestClient 退出时仍有后台任务。
        tool(client, "scan_stop")


def info_session(client: TestClient) -> int:
    return tool(client, "session_info")["structuredContent"]["session"]["id"]


def test_stdio_transport_roundtrip(tmp_path):
    env = {
        **os.environ,
        "WRAITH_DATA_DIR": str(tmp_path / "data"),
        "WRAITH_CAPTURE_DIR": str(tmp_path / "captures"),
        "WRAITH_OPERATOR": "pytest-stdio",
    }
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "health", "arguments": {}}},
    ]
    payload = "\n".join(json.dumps(item, ensure_ascii=False) for item in messages) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "wraith", "mcp", "--demo"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=45,
        cwd=str(ROOT),
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "stdio 已就绪" in proc.stderr
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 4  # 通知不产生响应
    assert lines[0]["error"]["code"] == -32601
    assert lines[1]["result"]["protocolVersion"] == "2025-06-18"
    assert len(lines[2]["result"]["tools"]) == len(TOOL_SPECS)
    assert lines[3]["result"]["content"][0]["type"] == "text"
    assert json.loads(lines[3]["result"]["content"][0]["text"])["ok"] is True
    assert (tmp_path / "data" / "mcp-audit.jsonl").exists()
