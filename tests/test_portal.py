"""强制门户服务测试。"""

from __future__ import annotations

import asyncio
import http.client
import urllib.parse

from wraith.attacks.portal import PortalServer


def test_portal_serves_page_and_captures_credentials():
    captured: list[dict] = []
    seen: list[str] = []

    async def run():
        server = PortalServer(
            host="127.0.0.1",
            port=0,
            ssid="Wraith-Guest",
            title="网络认证",
            on_credential=captured.append,
            on_request=seen.append,
        )
        port = await server.start()
        assert port > 0

        def get(path: str):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", path)
            response = conn.getresponse()
            body = response.read().decode("utf-8", "replace")
            status = response.status
            location = response.getheader("Location")
            conn.close()
            return status, body, location

        status, body, _ = await asyncio.to_thread(get, "/")
        assert status == 200
        assert "Wraith-Guest" in body
        assert "网络认证" in body

        # 系统连通性探测直接返回门户页面（200 HTML）：iOS/Android/Windows 发现
        # 内容不是预期的 Success/204 就会弹出强制门户登录页。
        status, body, _ = await asyncio.to_thread(get, "/generate_204")
        assert status == 200 and "Wraith-Guest" in body
        status, body, _ = await asyncio.to_thread(get, "/hotspot-detect.html")
        assert status == 200 and "Wraith-Guest" in body

        # 每次请求都要能被上层记录（用于定位“连上了但不弹门户”）
        assert any("/hotspot-detect.html" in line for line in seen)

        def post():
            payload = urllib.parse.urlencode({"username": "alice", "password": "s3cret!"})
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request(
                "POST",
                "/submit",
                body=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = conn.getresponse()
            result = (response.status, response.getheader("Location"))
            response.read()
            conn.close()
            return result

        status, location = await asyncio.to_thread(post)
        assert status == 303 and location == "/success"
        assert captured and captured[0]["username"] == "alice"
        assert captured[0]["password"] == "s3cret!"

        await server.stop()
        assert not server.running

    asyncio.run(run())


def test_portal_success_page():
    async def run():
        server = PortalServer(host="127.0.0.1", port=0, ssid="X")
        port = await server.start()

        def get():
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/success")
            response = conn.getresponse()
            body = response.read().decode()
            conn.close()
            return response.status, body

        status, body = await asyncio.to_thread(get)
        assert status == 200 and "验证成功" in body
        await server.stop()

    asyncio.run(run())
