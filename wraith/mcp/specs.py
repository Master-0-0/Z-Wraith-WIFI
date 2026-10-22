"""MCP 工具清单：把平台功能点声明为可被 AI 代理调用的工具.

每个 :class:`ToolSpec` 映射到一个 REST 端点。工具名保持简短（DSH 会自动加
``mcp__<serverName>__`` 前缀），描述使用中文，便于模型选择。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ArgSpec:
    """一个工具参数的声明（同时用于 JSON Schema 与请求构造）。"""

    name: str
    type: str = "string"
    description: str = ""
    location: str = "body"  # path | query | body
    required: bool = False
    enum: tuple[str, ...] = ()
    default: Any = None
    minimum: float | None = None
    maximum: float | None = None
    items: str | None = None  # 数组元素类型
    additional: bool = False  # object 是否允许额外字段

    def json_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {"type": self.type, "description": self.description}
        if self.enum:
            schema["enum"] = list(self.enum)
        if self.default is not None:
            schema["default"] = self.default
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.maximum is not None:
            schema["maximum"] = self.maximum
        if self.type == "array":
            schema["items"] = {"type": self.items or "string"}
        if self.type == "object":
            schema["additionalProperties"] = True
        return schema


@dataclass(frozen=True)
class ToolSpec:
    """一个 MCP 工具：名称、说明、HTTP 映射与参数。"""

    name: str
    title: str
    description: str
    method: str
    path: str
    args: tuple[ArgSpec, ...] = ()
    kind: str = "http"  # http | wait_attack | wait_crack | capture_download | report_download

    # ---------------------------------------------------------------- 分类
    @property
    def path_args(self) -> tuple[ArgSpec, ...]:
        return tuple(a for a in self.args if a.location == "path")

    @property
    def query_args(self) -> tuple[ArgSpec, ...]:
        return tuple(a for a in self.args if a.location == "query")

    @property
    def body_args(self) -> tuple[ArgSpec, ...]:
        return tuple(a for a in self.args if a.location == "body")

    # ---------------------------------------------------------------- schema
    def input_schema(self) -> dict[str, Any]:
        properties = {a.name: a.json_schema() for a in self.args}
        required = [a.name for a in self.args if a.required]
        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required
        return schema

    def definition(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema(),
        }


# ---------------------------------------------------------------------------
# 参数快捷构造
# ---------------------------------------------------------------------------


def P(
    name: str,
    type: str = "string",
    description: str = "",
    *,
    required: bool = False,
    enum: tuple[str, ...] = (),
    default: Any = None,
    minimum: float | None = None,
    maximum: float | None = None,
    items: str | None = None,
) -> ArgSpec:
    return ArgSpec(
        name=name,
        type=type,
        description=description,
        location="path",
        required=required,
        enum=enum,
        default=default,
        minimum=minimum,
        maximum=maximum,
        items=items,
    )


def Q(
    name: str,
    type: str = "string",
    description: str = "",
    *,
    required: bool = False,
    enum: tuple[str, ...] = (),
    default: Any = None,
    minimum: float | None = None,
    maximum: float | None = None,
    items: str | None = None,
) -> ArgSpec:
    return ArgSpec(
        name=name,
        type=type,
        description=description,
        location="query",
        required=required,
        enum=enum,
        default=default,
        minimum=minimum,
        maximum=maximum,
        items=items,
    )


def B(
    name: str,
    type: str = "string",
    description: str = "",
    *,
    required: bool = False,
    enum: tuple[str, ...] = (),
    default: Any = None,
    minimum: float | None = None,
    maximum: float | None = None,
    items: str | None = None,
) -> ArgSpec:
    return ArgSpec(
        name=name,
        type=type,
        description=description,
        location="body",
        required=required,
        enum=enum,
        default=default,
        minimum=minimum,
        maximum=maximum,
        items=items,
    )


TOOL_SPECS: tuple[ToolSpec, ...] = (
    # ------------------------------------------------------------------ 系统
    ToolSpec(
        "health",
        "健康检查",
        "检查 Wraith 服务是否在线，返回应用名、版本与服务器时间戳。",
        "GET",
        "/api/health",
    ),
    ToolSpec(
        "system_info",
        "平台状态",
        "返回运行模式（demo/live）、当前会话、授权状态、无线网卡、依赖检查以及扫描/攻击/破解的实时状态。AI 代理应先调用本工具了解环境。",
        "GET",
        "/api/system",
    ),
    ToolSpec(
        "overview",
        "全局总览",
        "一次性返回系统状态、扫描快照、AP/客户端、抓包、破解、发现、凭证、事件与攻击模块列表。适合快速建立上下文，数据量较大。",
        "GET",
        "/api/overview",
    ),
    ToolSpec(
        "interfaces",
        "无线网卡",
        "列出无线网卡及其 monitor/AP 能力与当前信道，用于 live 模式选择接口。",
        "GET",
        "/api/interfaces",
    ),
    ToolSpec(
        "set_mode",
        "切换模式",
        "切换 demo/live 模式。demo 模式全部模拟、不触碰真实设备；live 模式会真实发送无线帧，必须先用 authorize 完成授权。",
        "POST",
        "/api/system/mode",
        (B("mode", description="运行模式", required=True, enum=("demo", "live")),),
    ),
    ToolSpec(
        "update_config",
        "更新配置",
        "更新网卡、字典、操作者、门户端口或隐蔽模式等运行配置，并持久化到 data/config.json。",
        "POST",
        "/api/system/config",
        (
            B("iface", description="无线网卡名称，例如 wlan0"),
            B("wordlist", description="离线破解字典路径"),
            B("operator", description="操作者标识，会写入审计日志"),
            B("portal_port", "integer", "强制门户监听端口", minimum=1, maximum=65535),
            B("stealth", "boolean", "隐蔽模式开关"),
        ),
    ),
    ToolSpec(
        "doctor",
        "依赖体检",
        "检查 aircrack-ng、hcxdumptool、hostapd、reaver、hashcat 等系统工具与 Python 依赖是否就绪。",
        "GET",
        "/api/deps",
    ),
    # ------------------------------------------------------------------ 授权
    ToolSpec(
        "authorization_status",
        "授权状态",
        "查看当前模式、是否已授权、操作者与授权范围。",
        "GET",
        "/api/authorization",
    ),
    ToolSpec(
        "authorize",
        "live 模式授权",
        "完成 live 模式授权（令牌固定为 AUTHORIZED），可选限定 BSSID 前缀或 SSID glob 范围。授权决定会写入 data/audit.jsonl。仅限已获得书面授权的测试。",
        "POST",
        "/api/authorization",
        (
            B("token", description="授权令牌，必须为 AUTHORIZED", required=True),
            B("operator", description="操作者标识"),
            B(
                "scope",
                "array",
                "授权范围：BSSID 前缀（如 aa:bb:cc）或 SSID glob（如 Lab-*）；留空表示不限制",
                items="string",
            ),
        ),
    ),
    ToolSpec(
        "authorization_revoke",
        "撤销授权",
        "撤销 live 模式授权。撤销后所有攻击入口立即拒绝并写审计日志。",
        "POST",
        "/api/authorization/revoke",
    ),
    ToolSpec(
        "audit_log",
        "审计日志",
        "读取最近的授权允许/拒绝记录（操作者、动作、目标、原因）。",
        "GET",
        "/api/authorization/audit",
        (Q("limit", "integer", "返回条数", default=100, minimum=1, maximum=1000),),
    ),
    # ------------------------------------------------------------------ 扫描
    ToolSpec(
        "scan_status",
        "扫描状态",
        "返回扫描状态快照：是否运行、接口、已发现 AP/客户端数量、运行秒数、数据包计数，以及当前 AP/客户端列表。",
        "GET",
        "/api/scanner",
    ),
    ToolSpec(
        "scan_start",
        "开始扫描",
        "开始发现 AP 与客户端。demo 模式加载 14 个虚拟 AP；live 模式启动 airodump-ng 并占用无线网卡。扫描会持续到 scan_stop 或 duration 到期。",
        "POST",
        "/api/scan/start",
        (
            B("iface", description="无线网卡名称；live 模式留空则自动选择"),
            B("channel", "integer", "锁定信道", minimum=1, maximum=233),
            B("duration", "number", "扫描时长（秒）；留空表示持续扫描", minimum=3, maximum=86400),
        ),
    ),
    ToolSpec(
        "scan_stop",
        "停止扫描",
        "停止扫描并释放监听网卡。任何攻击启动前平台会自动停止扫描。",
        "POST",
        "/api/scan/stop",
    ),
    ToolSpec(
        "aps",
        "AP 列表",
        "列出当前会话发现的接入点：SSID、BSSID、信道、安全类型、信号、WPS、关联客户端数与厂商。",
        "GET",
        "/api/aps",
    ),
    ToolSpec(
        "ap_detail",
        "AP 详情",
        "查看单个 AP 的完整信息，以及关联客户端、抓包与风险发现。",
        "GET",
        "/api/aps/{bssid}",
        (P("bssid", description="AP 的 BSSID（MAC 地址）", required=True),),
    ),
    ToolSpec(
        "clients",
        "客户端列表",
        "列出扫描发现的无线客户端、关联 BSSID、信号、探针 SSID 与厂商。",
        "GET",
        "/api/clients",
    ),
    # ------------------------------------------------------------------ 攻击
    ToolSpec(
        "attack_modules",
        "攻击模块",
        "列出 11 个攻击模块的 ID、参数、风险等级、依赖工具与可用性。",
        "GET",
        "/api/attacks",
    ),
    ToolSpec(
        "attack_start",
        "启动攻击",
        "启动一个攻击任务。同一时间只允许一个任务；启动前会做授权、参数与依赖 preflight。模块参数可通过 options 传入（如 timeout、deauth、count）。",
        "POST",
        "/api/attacks/{module_id}/start",
        (
            P("module_id", description="模块 ID，例如 handshake / pmkid / deauth / evil_twin", required=True),
            B("bssid", description="目标 BSSID；除 beacon_flood 外必填"),
            B("ssid", description="目标 SSID"),
            B("channel", "integer", "目标信道", minimum=1, maximum=233),
            B("security", description="安全类型：OPEN/WEP/WPA2/WPA3/WPA2-WPA3/ENTERPRISE 等"),
            B("wps", "boolean", "目标是否启用 WPS"),
            B("options", "object", "模块私有参数，例如 {\"timeout\": 60, \"deauth\": true}"),
        ),
    ),
    ToolSpec(
        "attack_stop",
        "停止攻击",
        "停止当前或指定攻击任务，释放监听网卡与门户。",
        "POST",
        "/api/attacks/stop",
        (B("job_id", description="攻击任务 ID；留空表示当前任务"),),
    ),
    ToolSpec(
        "attack_jobs",
        "攻击历史",
        "列出最近的攻击任务及状态、目标、结果摘要。",
        "GET",
        "/api/attacks/jobs",
        (Q("limit", "integer", "返回条数", default=20, minimum=1, maximum=200),),
    ),
    ToolSpec(
        "attack_job",
        "攻击任务详情",
        "查看单个攻击任务的完整状态、结果与执行日志尾部。",
        "GET",
        "/api/attacks/jobs/{job_id}",
        (P("job_id", description="攻击任务 ID", required=True),),
    ),
    ToolSpec(
        "attack_wait",
        "等待攻击结束",
        "轮询指定攻击任务直到结束（success/failed/stopped），返回最终结果与日志尾部。适合 AI 代理在启动攻击后同步等待。",
        "GET",
        "/api/attacks/jobs/{job_id}",
        (
            P("job_id", description="攻击任务 ID", required=True),
            B("timeout_sec", "number", "最长等待秒数", default=60, minimum=1, maximum=600),
        ),
        kind="wait_attack",
    ),
    # ------------------------------------------------------------------ 抓包/破解
    ToolSpec(
        "captures",
        "抓包列表",
        "列出会话中的 .cap/.pcapng/.22000 抓包，包含 SSID、BSSID、大小、哈希行数与本地文件路径。",
        "GET",
        "/api/captures",
    ),
    ToolSpec(
        "capture_download",
        "校验抓包文件",
        "通过下载端点校验抓包文件，返回文件名、大小与 SHA-256（大文件只返回元数据）。文件仍保存在平台 captures/ 目录，可由本地文件系统直接读取。",
        "GET",
        "/api/captures/{capture_id}/download",
        (P("capture_id", "integer", "抓包 ID", required=True, minimum=1),),
        kind="capture_download",
    ),
    ToolSpec(
        "crack_start",
        "启动破解",
        "对抓包启动离线破解。demo 模式统一使用内置 PBKDF2 校验；live 模式可选 aircrack-ng/hashcat/offline。",
        "POST",
        "/api/captures/{capture_id}/crack",
        (
            P("capture_id", "integer", "抓包 ID", required=True, minimum=1),
            B("method", description="破解方法", default="auto", enum=("auto", "aircrack", "hashcat", "offline")),
            B("wordlist", description="字典路径；留空使用平台配置"),
        ),
    ),
    ToolSpec(
        "cracks",
        "破解任务",
        "列出破解任务、状态、命中的口令与尝试进度。",
        "GET",
        "/api/cracks",
    ),
    ToolSpec(
        "crack_detail",
        "破解任务详情",
        "查看单个破解任务的状态、口令、字典与日志。",
        "GET",
        "/api/cracks/{job_id}",
        (P("job_id", "integer", "破解任务 ID", required=True, minimum=1),),
    ),
    ToolSpec(
        "crack_stop",
        "停止破解",
        "停止指定破解任务。",
        "POST",
        "/api/cracks/{job_id}/stop",
        (P("job_id", "integer", "破解任务 ID", required=True, minimum=1),),
    ),
    ToolSpec(
        "crack_wait",
        "等待破解结束",
        "轮询指定破解任务直到结束（found/exhausted/failed/stopped），返回最终结果。",
        "GET",
        "/api/cracks/{job_id}",
        (
            P("job_id", "integer", "破解任务 ID", required=True, minimum=1),
            B("timeout_sec", "number", "最长等待秒数", default=60, minimum=1, maximum=600),
        ),
        kind="wait_crack",
    ),
    # ------------------------------------------------------------------ 数据
    ToolSpec(
        "credentials",
        "门户凭证",
        "列出门户捕获的凭证（用户名/口令、来源门户、客户端 IP 与 User-Agent）。属于敏感数据。",
        "GET",
        "/api/credentials",
    ),
    ToolSpec(
        "findings",
        "风险发现",
        "列出评估过程中记录的风险发现（严重度、标题、目标、详情）。",
        "GET",
        "/api/findings",
    ),
    ToolSpec(
        "events",
        "事件流",
        "读取最近的实时事件（扫描、攻击、破解、门户、系统），用于跟踪任务进展。",
        "GET",
        "/api/events",
        (Q("limit", "integer", "返回条数", default=200, minimum=1, maximum=1000),),
    ),
    ToolSpec(
        "session_info",
        "当前会话",
        "返回当前评估会话的元数据与统计（AP/客户端/抓包/发现/凭证/已破解数量）。",
        "GET",
        "/api/session",
    ),
    ToolSpec(
        "session_export",
        "导出会话",
        "导出当前会话的全部结构化数据（AP、客户端、抓包、发现、凭证、破解、事件），可用于二次分析或交接。",
        "GET",
        "/api/session/export",
    ),
    ToolSpec(
        "session_notes",
        "保存备注",
        "保存当前会话的评估备注，会写入数据库并出现在报告中。",
        "POST",
        "/api/session/notes",
        (B("notes", description="评估备注", required=True),),
    ),
    # ------------------------------------------------------------------ 门户
    ToolSpec(
        "portal_status",
        "门户状态",
        "查看强制门户是否运行、URL、来源（独立/攻击内）、访问量与提交量。",
        "GET",
        "/api/portal",
    ),
    ToolSpec(
        "portal_open",
        "打开测试门户",
        "启动强制门户（demo 绑定 127.0.0.1，live 绑定 0.0.0.0）。门户提交的凭证会实时入库。仅限授权测试。",
        "POST",
        "/api/portal/open",
        (
            B("ssid", description="门户展示的 Wi-Fi 名称", default="Wraith-Guest"),
            B("title", description="门户页面标题", default="Wi-Fi 网络认证"),
            B("port", "integer", "监听端口；留空自动选择（demo）或使用配置（live）", minimum=1, maximum=65535),
        ),
    ),
    ToolSpec(
        "portal_stop",
        "关闭测试门户",
        "关闭强制门户并停止监听。",
        "POST",
        "/api/portal/stop",
    ),
    # ------------------------------------------------------------------ 报告
    ToolSpec(
        "report",
        "生成报告",
        "生成当前会话的评估报告并直接返回内容。format=json 返回结构化数据，md 返回 Markdown，html 返回可打印 HTML。",
        "GET",
        "/api/report/{format}",
        (
            P(
                "format",
                description="报告格式",
                default="json",
                enum=("html", "json", "md"),
            ),
        ),
    ),
    ToolSpec(
        "report_save",
        "保存报告",
        "把 HTML/JSON/Markdown 三种报告保存到 data/reports/，返回三种格式的文件路径。",
        "POST",
        "/api/report/save",
    ),
    ToolSpec(
        "report_files",
        "报告文件",
        "列出已保存的报告文件及大小、修改时间。",
        "GET",
        "/api/report/files",
    ),
    ToolSpec(
        "report_download",
        "读取报告文件",
        "通过下载端点读取已保存的报告；文本格式直接返回内容，二进制返回元数据。",
        "GET",
        "/api/report/download/{name}",
        (P("name", description="报告文件名（不能包含路径）", required=True),),
        kind="report_download",
    ),
)

SPECS_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_SPECS}


def tool_definitions() -> list[dict[str, Any]]:
    """返回 MCP ``tools/list`` 需要的有序定义。"""
    return [spec.definition() for spec in TOOL_SPECS]
