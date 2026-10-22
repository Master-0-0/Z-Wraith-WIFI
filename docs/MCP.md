# Wraith MCP 接入指南

Wraith 现在把**每个功能点**都暴露为 MCP（Model Context Protocol）工具，DSH、Claude
Desktop、Codex 等 AI 代理可以直接扫描、选目标、执行授权测试、破解、取证和出报告，
而不需要理解网页控制台或手写 REST 调用。

> **授权边界没有变化。** MCP 只是调用入口：live 模式仍然必须显式授权，目标必须在
> 授权范围内，所有允许/拒绝都会写入 `data/audit.jsonl`。演示模式不会触碰真实无线设备。

---

## 1. 架构

```
┌────────────────────┐        stdio (JSON-RPC)        ┌──────────────────────────┐
│ DSH / Claude / Codex│ ─────────────────────────────▶ │ wraith mcp --demo         │
│  MCP 客户端         │                                │  ├─ embedded AppState     │
└────────────────────┘                                │  └─ PlatformRuntime       │
                                                       └────────────┬─────────────┘
┌────────────────────┐   streamable HTTP  /mcp                     │ ASGI / HTTP
│ 远程 AI 代理        │ ─────────────────────────────▶ ┌───────────▼─────────────┐
└────────────────────┘                                │ FastAPI REST / Web 控制台 │
                                                       └───────────┬─────────────┘
                                                                   │
                              ┌────────────────────────────────────┼────────────────────┐
                              ▼                                    ▼                    ▼
                        SQLite + 抓包 + 报告              授权门禁 + 审计         攻击/扫描/破解
```

MCP 工具层**不复制业务逻辑**：每个工具映射到一条现有 REST 端点，经由进程内
ASGI 或远程 HTTP 调用。因此 demo/live 行为、参数校验、授权门禁、事件流与 Web
控制台完全一致，不会出现“网页能跑、MCP 行为不同”的漂移。

---

## 2. 快速开始（演示模式，无需网卡）

```bash
cd "/home/kali/桌面/ wifi"

# 方式 A：stdio（推荐给 DSH 本地拉起）
./scripts/mcp-stdio.sh --demo

# 方式 B：挂载在 Web 控制台的 HTTP 端点
.venv/bin/python -m wraith web --demo
# → MCP: http://127.0.0.1:8787/mcp

# 方式 C：只启动 MCP HTTP 服务（端口 8790）
.venv/bin/python -m wraith mcp --transport http --demo -p 8790
# → MCP: http://127.0.0.1:8790/mcp
```

stdio 模式下 **stdout 只输出 JSON-RPC**，所有日志在 stderr。默认就是 demo 模式；
要进入实机路径必须显式传 `--live` 并在工具中完成授权。

### 2.1 DSH 配置

在 `~/.dsh/profiles/<profile>/cordis.patch.yml` 增加：

```yaml
- id: mcp-wraith
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: wraith
    transport: stdio
    command: /home/kali/桌面/ wifi/scripts/mcp-stdio.sh
    args: ['--demo']
    cwd: /home/kali/桌面/ wifi
    toolCallTimeoutMs: 120000
    failOnStartupError: false
```

重启/重载 DSH 后，工具会以 `mcp__wraith__<tool>` 出现，例如
`mcp__wraith__scan_start`、`mcp__wraith__attack_start`。

也可以走 HTTP（需要先启动 `wraith web`）：

```yaml
- id: mcp-wraith
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: wraith
    transport: streamable-http
    url: http://127.0.0.1:8787/mcp
    toolCallTimeoutMs: 120000
```

### 2.2 Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "wraith": {
      "command": "/home/kali/桌面/ wifi/scripts/mcp-stdio.sh",
      "args": ["--demo"],
      "cwd": "/home/kali/桌面/ wifi"
    }
  }
}
```

### 2.3 代理到已运行的控制台

如果 Web 控制台已经在跑，stdio 进程可以只做代理，让 AI 与网页共享同一个会话、
扫描器和事件流：

```bash
.venv/bin/python -m wraith mcp --url http://127.0.0.1:8787
```

### 2.4 实机冒烟（需要 root + 无线网卡）

live 模式要开启 monitor/AP，必须由 root 持有网卡。**不要为了 live 直接把 DSH 以 root 运行**；
更稳妥的做法是让 root 启动常驻 Web 平台，DSH 通过 HTTP MCP 连接：

```bash
# 1) 插入支持 monitor + AP 的 USB 网卡（虚拟机需在宿主机直通）
iw dev                                   # 确认出现 wlanX

# 2) root 启动 live Web 平台（含 /mcp）
sudo WRAITH_IFACE=wlan0 ./scripts/restart-live.sh

# 3) DSH 改用 HTTP MCP
#    transport: streamable-http
#    url: http://127.0.0.1:8787/mcp

# 4) 通过 MCP 授权，且把范围限制在自有测试 AP
#    authorize(token="AUTHORIZED", scope=["aa:bb:cc", "Lab-*"])
```

授权后再执行 `scan_start` / `attack_start`。首次实机冒烟建议只做被动扫描与
`pmkid`/`handshake`，不要在企业或邻居网络上操作。

---

## 3. 工具清单（43 个）

`*` 表示必填参数。完整 JSON Schema 通过 MCP `tools/list` 获取，也可查看
`wraith/mcp/specs.py`。

| 工具 | 名称 | 映射端点 | 参数 |
|---|---|---|---|
| `health` | 健康检查 | `GET /api/health` | — |
| `system_info` | 平台状态 | `GET /api/system` | — |
| `overview` | 全局总览 | `GET /api/overview` | — |
| `interfaces` | 无线网卡 | `GET /api/interfaces` | — |
| `set_mode` | 切换模式 | `POST /api/system/mode` | mode* |
| `update_config` | 更新配置 | `POST /api/system/config` | iface, wordlist, operator, portal_port, stealth |
| `doctor` | 依赖体检 | `GET /api/deps` | — |
| `authorization_status` | 授权状态 | `GET /api/authorization` | — |
| `authorize` | live 模式授权 | `POST /api/authorization` | token*, operator, scope |
| `authorization_revoke` | 撤销授权 | `POST /api/authorization/revoke` | — |
| `audit_log` | 审计日志 | `GET /api/authorization/audit` | limit |
| `scan_status` | 扫描状态 | `GET /api/scanner` | — |
| `scan_start` | 开始扫描 | `POST /api/scan/start` | iface, channel, duration |
| `scan_stop` | 停止扫描 | `POST /api/scan/stop` | — |
| `aps` | AP 列表 | `GET /api/aps` | — |
| `ap_detail` | AP 详情 | `GET /api/aps/{bssid}` | bssid* |
| `clients` | 客户端列表 | `GET /api/clients` | — |
| `attack_modules` | 攻击模块 | `GET /api/attacks` | — |
| `attack_start` | 启动攻击 | `POST /api/attacks/{module_id}/start` | module_id*, bssid, ssid, channel, security, wps, options |
| `attack_stop` | 停止攻击 | `POST /api/attacks/stop` | job_id |
| `attack_jobs` | 攻击历史 | `GET /api/attacks/jobs` | limit |
| `attack_job` | 攻击任务详情 | `GET /api/attacks/jobs/{job_id}` | job_id* |
| `attack_wait` | 等待攻击结束 | `GET /api/attacks/jobs/{job_id}` | job_id*, timeout_sec |
| `captures` | 抓包列表 | `GET /api/captures` | — |
| `capture_download` | 校验抓包文件 | `GET /api/captures/{capture_id}/download` | capture_id* |
| `crack_start` | 启动破解 | `POST /api/captures/{capture_id}/crack` | capture_id*, method, wordlist |
| `cracks` | 破解任务 | `GET /api/cracks` | — |
| `crack_detail` | 破解任务详情 | `GET /api/cracks/{job_id}` | job_id* |
| `crack_stop` | 停止破解 | `POST /api/cracks/{job_id}/stop` | job_id* |
| `crack_wait` | 等待破解结束 | `GET /api/cracks/{job_id}` | job_id*, timeout_sec |
| `credentials` | 门户凭证 | `GET /api/credentials` | — |
| `findings` | 风险发现 | `GET /api/findings` | — |
| `events` | 事件流 | `GET /api/events` | limit |
| `session_info` | 当前会话 | `GET /api/session` | — |
| `session_export` | 导出会话 | `GET /api/session/export` | — |
| `session_notes` | 保存备注 | `POST /api/session/notes` | notes* |
| `portal_status` | 门户状态 | `GET /api/portal` | — |
| `portal_open` | 打开测试门户 | `POST /api/portal/open` | ssid, title, port |
| `portal_stop` | 关闭测试门户 | `POST /api/portal/stop` | — |
| `report` | 生成报告 | `GET /api/report/{format}` | format |
| `report_save` | 保存报告 | `POST /api/report/save` | — |
| `report_files` | 报告文件 | `GET /api/report/files` | — |
| `report_download` | 读取报告文件 | `GET /api/report/download/{name}` | name* |

### 推荐调用链

```text
system_info
  → scan_start(duration=30)
  → aps                       # 选择目标
  → attack_modules            # 确认模块与参数
  → attack_start(module_id, bssid, ...)
  → attack_wait(job_id)       # 等待并拿最终结果
  → captures                  # 找到本次抓包
  → crack_start(capture_id, method="auto")
  → crack_wait(job_id)
  → findings / credentials
  → report(format="json") / report_save
```

给 DSH 的提示词可以很简短：

> 用 wraith 的 MCP 工具完成一次演示评估：扫描、选 CMCC-5G-8F2A、跑四次握手捕获、
> 破解、生成报告，并汇报发现。全程使用 demo 模式。

---

## 4. 安全与审计

| 机制 | 说明 |
|---|---|
| 授权门禁 | live 模式攻击前必须 `authorize(token="AUTHORIZED")`；范围外目标返回 403 |
| 范围限制 | `scope` 支持 BSSID 前缀与 SSID glob，例如 `["aa:bb:cc", "Lab-*"]` |
| 操作审计 | 授权决策写 `data/audit.jsonl`；每次 MCP 工具调用写 `data/mcp-audit.jsonl` |
| 参数脱敏 | 审计中的 `token/password/psk/key/secret` 一律写成 `***` |
| 单任务约束 | 攻击独占无线网卡，同一时间只允许一个攻击任务 |
| Origin 校验 | `/mcp` 拒绝非本机 Origin，降低 DNS rebinding 风险 |
| 网络暴露 | `/mcp` 与 REST 同源同权限；默认只绑定 `127.0.0.1`，不要把 `--host 0.0.0.0` 暴露到不可信网络 |
| 工具面 | 只声明 `tools` 能力，不开放 resources/prompts |

MCP 审计示例：

```json
{"ts": 1792651874.5, "tool": "authorize", "ok": true, "ms": 3.1,
 "args": {"token": "***", "operator": "dsh"}}
```

---

## 5. 测试与冒烟

```bash
# 全量测试（含 MCP 协议、43 工具覆盖、demo 全链路、stdio 传输）
.venv/bin/python -m pytest -q

# 只看 MCP
.venv/bin/python -m pytest tests/test_mcp.py -q

# 手工 stdio 握手
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | ./scripts/mcp-stdio.sh --demo
```

已验证与 DSH 内置的 `@modelcontextprotocol/client` 2.2.0 互操作：

- stdio：自动 `server/discover` 探测 → `-32601` 回退 → `initialize` → 43 工具 →
  扫描/握手/破解/报告全链路通过；
- streamable HTTP：`http://127.0.0.1:8787/mcp` 同样完成握手与工具调用。

### 常见问题

| 现象 | 原因/处理 |
|---|---|
| 日志出现 `server/discover ... -32601` | 正常。新版客户端探测 2026 协议，服务器回退到 2025 `initialize` |
| DSH 里看不到工具 | 检查 `cwd`、脚本可执行位、`.venv` 是否存在；`dsh --profile web --dump-config` 校验配置 |
| `live` 攻击返回 403 | 先 `authorize`，并确认 BSSID/SSID 在 `scope` 内 |
| `--url` 连接失败 | 目标 `wraith web` 必须已启动，端口一致 |
| HTTP 模式端口冲突 | `wraith mcp --transport http -p 8790`，或直接使用 `wraith web` 的 `/mcp` |
| 工具返回超时 | 扫描/攻击是异步任务，用 `attack_wait` / `crack_wait`；DSH 的 `toolCallTimeoutMs` 建议 ≥120s |

---

## 6. 实现位置

| 文件 | 职责 |
|---|---|
| `wraith/mcp/specs.py` | 43 个工具声明（名称、描述、JSON Schema、REST 映射） |
| `wraith/mcp/runtime.py` | 参数校验、HTTP/ASGI 调用、等待/下载组合工具、审计 |
| `wraith/mcp/protocol.py` | MCP JSON-RPC：initialize/ping/tools/list/tools/call |
| `wraith/mcp/stdio.py` | stdio 传输与嵌入式惰性启动 |
| `wraith/mcp/http.py` | Streamable HTTP `/mcp` 路由与 Origin 校验 |
| `wraith/cli.py` | `wraith mcp` 子命令 |
| `wraith/web/app.py` | 在 Web 应用内挂载 `/mcp` |
| `tests/test_mcp.py` | 协议、覆盖、授权、全链路、stdio 测试 |
