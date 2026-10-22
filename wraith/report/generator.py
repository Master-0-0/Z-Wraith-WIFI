"""渗透测试报告生成：HTML / JSON / Markdown."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from jinja2 import Template

from ..core.utils import human_bytes, human_duration, now_iso
from ..models import SEVERITY_ORDER
from ..store import Store

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

HTML_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wi-Fi 渗透测试报告 · {{ session.name }}</title>
<style>
  :root{
    --bg:#0b1120; --panel:#111c33; --panel2:#0e1729; --line:#1f2f4d;
    --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; --accent2:#8b5cf6;
    --critical:#f43f5e; --high:#fb923c; --medium:#fbbf24; --low:#38bdf8; --info:#94a3b8;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       line-height:1.65}
  .wrap{max-width:1080px;margin:0 auto;padding:48px 28px 80px}
  header{border-bottom:2px solid var(--line);padding-bottom:24px;margin-bottom:36px}
  .eyebrow{color:var(--accent);font-size:12px;letter-spacing:.22em;text-transform:uppercase}
  h1{font-size:30px;margin:8px 0 6px;font-weight:700}
  .meta{color:var(--muted);font-size:13px;display:flex;gap:22px;flex-wrap:wrap;margin-top:12px}
  .disclaimer{margin-top:18px;padding:12px 16px;border-left:3px solid var(--high);
              background:#1a1408;color:#fcd34d;font-size:12.5px;border-radius:0 8px 8px 0}
  h2{font-size:19px;margin:44px 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line)}
  h2 .idx{color:var(--accent2);font-family:ui-monospace,monospace;margin-right:10px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
  .card .v{font-size:26px;font-weight:700;font-family:ui-monospace,monospace}
  .card .k{color:var(--muted);font-size:12px;margin-top:2px}
  table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}
  th{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);
     padding:9px 10px;white-space:nowrap;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}
  td{padding:9px 10px;border-bottom:1px solid #16233c;vertical-align:top;word-break:break-all}
  tr:hover td{background:#13203a}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:10.5px;
         font-weight:700;border:1px solid currentColor;white-space:nowrap}
  .critical{color:var(--critical)} .high{color:var(--high)} .medium{color:var(--medium)}
  .low{color:var(--low)} .info{color:var(--info)}
  .finding{background:var(--panel2);border:1px solid var(--line);border-left-width:4px;
           border-radius:8px;padding:14px 18px;margin-bottom:12px}
  .finding.critical{border-left-color:var(--critical)} .finding.high{border-left-color:var(--high)}
  .finding.medium{border-left-color:var(--medium)} .finding.low{border-left-color:var(--low)}
  .finding.info{border-left-color:var(--info)}
  .finding .t{font-weight:700;font-size:14px;margin-bottom:4px}
  .finding .d{color:var(--muted);font-size:12.5px}
  .kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;font-size:13px}
  .kv span:nth-child(odd){color:var(--muted)}
  .empty{color:var(--muted);font-size:13px;padding:18px;text-align:center;
         border:1px dashed var(--line);border-radius:10px}
  .timeline{font-family:ui-monospace,monospace;font-size:11.5px;max-height:520px;overflow:auto;
            background:#080f1d;border:1px solid var(--line);border-radius:10px;padding:14px}
  .timeline div{padding:3px 0;border-bottom:1px solid #101c30;color:#cbd5e1}
  .timeline .ts{color:#64748b;margin-right:10px}
  .timeline .lv-success{color:#4ade80} .timeline .lv-error{color:#f87171}
  .timeline .lv-warning{color:#fbbf24} .timeline .lv-attack{color:#a78bfa}
  footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);
         color:var(--muted);font-size:12px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
  @media print{body{background:#fff;color:#111}.card,.finding,.timeline{background:#fff}
    .disclaimer{background:#fff8e1}.wrap{max-width:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="eyebrow">WRAITH · WIRELESS SECURITY ASSESSMENT</div>
    <h1>Wi-Fi 渗透测试报告</h1>
    <div class="meta">
      <span>会话：<strong>{{ session.name }}</strong></span>
      <span>操作者：{{ session.operator or '未填写' }}</span>
      <span>开始：{{ started }}</span>
      <span>模式：{{ '实机 (live)' if session.mode == 'live' else '演示 (demo)' }}</span>
      <span>生成：{{ generated }}</span>
    </div>
    <div class="disclaimer">
      本报告仅对已获得书面授权的无线网络进行评估。报告中的口令、凭证与哈希属于敏感信息，
      应按组织的数据分级要求加密存储、限制访问，并在授权范围外立即销毁。
    </div>
  </header>

  <h2><span class="idx">01</span>执行摘要</h2>
  <div class="cards">
    <div class="card"><div class="v">{{ stats.aps }}</div><div class="k">发现 AP</div></div>
    <div class="card"><div class="v">{{ stats.clients }}</div><div class="k">发现客户端</div></div>
    <div class="card"><div class="v">{{ stats.captures }}</div><div class="k">抓包 / 哈希</div></div>
    <div class="card"><div class="v">{{ stats.cracked }}</div><div class="k">已破解</div></div>
    <div class="card"><div class="v">{{ stats.credentials }}</div><div class="k">捕获凭证</div></div>
    <div class="card"><div class="v">{{ stats.findings }}</div><div class="k">风险发现</div></div>
  </div>
  <p style="color:var(--muted);font-size:13px;margin-top:18px">
    评估覆盖 {{ stats.aps }} 个无线接入点，其中
    <strong class="critical">{{ severity_counts.get('critical', 0) }}</strong> 个严重问题、
    <strong class="high">{{ severity_counts.get('high', 0) }}</strong> 个高危问题。
    {% if cracked_count %}已成功恢复 {{ cracked_count }} 组 Wi-Fi 口令，说明口令策略或协议配置存在可被离线爆破的弱点。{% endif %}
  </p>

  <h2><span class="idx">02</span>风险发现</h2>
  {% if findings %}
    {% for f in findings %}
    <div class="finding {{ f.severity }}">
      <div class="t"><span class="badge {{ f.severity }}">{{ severity_label[f.severity] }}</span>
        {{ f.title }}</div>
      <div class="d">{{ f.detail }}</div>
      {% if f.bssid or f.ssid %}
      <div class="d mono" style="margin-top:6px">{{ f.ssid or '<隐藏>' }} · {{ f.bssid or '-' }}</div>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
    <div class="empty">未记录风险发现。</div>
  {% endif %}

  <h2><span class="idx">03</span>无线接入点清单</h2>
  {% if aps %}
  <table>
    <thead><tr><th>SSID</th><th>BSSID</th><th>信道</th><th>安全</th><th>信号</th><th>WPS</th><th>厂商</th></tr></thead>
    <tbody>
    {% for ap in aps %}
      <tr>
        <td>{{ ap.ssid or '<隐藏>' }}</td>
        <td class="mono">{{ ap.bssid }}</td>
        <td class="mono">{{ ap.channel }}</td>
        <td>{{ ap.privacy or 'OPEN' }}{% if ap.auth %} / {{ ap.auth }}{% endif %}</td>
        <td class="mono">{{ ap.power }} dBm</td>
        <td>{{ '是' if ap.wps else '否' }}</td>
        <td>{{ ap.vendor }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<div class="empty">未发现接入点。</div>{% endif %}

  <h2><span class="idx">04</span>口令与凭证</h2>
  {% if cracked %}
  <table>
    <thead><tr><th>SSID</th><th>BSSID</th><th>方法</th><th>口令</th><th>时间</th></tr></thead>
    <tbody>
    {% for c in cracked %}
      <tr><td>{{ c.ssid or '<隐藏>' }}</td><td class="mono">{{ c.bssid }}</td>
          <td>{{ c.method }}</td><td class="mono strong">{{ c.key }}</td>
          <td class="mono">{{ c.finished_at }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<div class="empty">本次评估未恢复任何 Wi-Fi 口令。</div>{% endif %}

  {% if credentials %}
  <table style="margin-top:16px">
    <thead><tr><th>用户名</th><th>口令</th><th>来源门户</th><th>IP</th><th>时间</th></tr></thead>
    <tbody>
    {% for c in credentials %}
      <tr><td class="mono">{{ c.username }}</td><td class="mono">{{ c.password }}</td>
          <td>{{ c.portal }}</td><td class="mono">{{ c.ip }}</td>
          <td class="mono">{{ c.created_at }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2><span class="idx">05</span>抓包与破解任务</h2>
  {% if captures %}
  <table>
    <thead><tr><th>#</th><th>类型</th><th>目标</th><th>文件</th><th>大小</th><th>哈希</th><th>时间</th></tr></thead>
    <tbody>
    {% for c in captures %}
      <tr><td class="mono">{{ c.id }}</td><td>{{ c.kind }}</td>
          <td>{{ c.ssid or '<隐藏>' }}<br><span class="mono" style="color:var(--muted)">{{ c.bssid }}</span></td>
          <td class="mono">{{ c.filename }}</td><td class="mono">{{ c.size }}</td>
          <td class="mono">{{ c.hash_lines }}</td><td class="mono">{{ c.created_at }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}<div class="empty">未生成抓包。</div>{% endif %}

  {% if cracks %}
  <table style="margin-top:16px">
    <thead><tr><th>#</th><th>抓包</th><th>方法</th><th>状态</th><th>结果</th></tr></thead>
    <tbody>
    {% for c in cracks %}
      <tr><td class="mono">{{ c.id }}</td><td class="mono">{{ c.capture_id }}</td><td>{{ c.method }}</td>
          <td>{{ c.status }}</td><td class="mono">{{ c.key or '-' }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2><span class="idx">06</span>事件时间线</h2>
  <div class="timeline">
    {% for e in events %}
      <div><span class="ts">{{ e.time }}</span><span class="lv-{{ e.level }}">[{{ e.level }}]</span>
        {{ e.message }}</div>
    {% else %}
      <div>无事件记录</div>
    {% endfor %}
  </div>

  <h2><span class="idx">07</span>修复建议</h2>
  <div class="kv">
    <span>加密协议</span><span>淘汰 WEP/WPA；优先 WPA3-SAE，暂无法升级时使用 WPA2-CCMP + 强口令（≥12 位随机）。</span>
    <span>WPS</span><span>关闭 WPS；必须使用时升级至 WPS 2.0 并启用锁定策略。</span>
    <span>过渡模式</span><span>禁用 WPA2/WPA3 混合过渡模式，或启用 PMF 强制并要求 <code>pmf=required</code>。</span>
    <span>企业网络</span><span>客户端强制校验 CA 与 CN/SAN；禁用 MSCHAPv2/GTC；优先 EAP-TLS；监控 EAP 中继。</span>
    <span>管理帧</span><span>启用 802.11w（PMF）；部署 WIDS 监控 Deauth 洪泛、Beacon 异常与 BSSID 克隆。</span>
    <span>口令策略</span><span>禁止字典词、手机号、公司名组合；长度 ≥12 且混合字符；定期轮换。</span>
    <span>客户端</span><span>关闭自动连接开放网络、禁用 PNL 广播、及时安装 KRACK/FragAttacks 补丁。</span>
  </div>

  <footer>
    <span>Wraith Wi-Fi 渗透测试平台 · 报告生成于 {{ generated }}</span>
    <span>本报告共 {{ stats.aps }} 个 AP / {{ stats.findings }} 项发现</span>
  </footer>
</div>
</body>
</html>
"""


class ReportGenerator:
    def __init__(self, store: Store, session_id: int) -> None:
        self.store = store
        self.session_id = session_id

    # ------------------------------------------------------------------ 数据
    def collect(self) -> dict[str, Any]:
        session = self.store.get_session(self.session_id) or {}
        aps = self.store.list_aps(self.session_id)
        clients = self.store.list_clients(self.session_id)
        captures = self.store.list_captures(self.session_id)
        findings = self.store.list_findings(self.session_id)
        credentials = self.store.list_credentials(self.session_id)
        cracks = self.store.list_cracks(500)
        capture_ids = {c["id"] for c in captures}
        cracks = [c for c in cracks if c["capture_id"] in capture_ids]
        cracked = [
            {
                **crack,
                "ssid": next((cap["ssid"] for cap in captures if cap["id"] == crack["capture_id"]), ""),
                "bssid": next((cap["bssid"] for cap in captures if cap["id"] == crack["capture_id"]), ""),
                "finished_at": now_iso(crack["finished_at"]) if crack["finished_at"] else "-",
            }
            for crack in cracks
            if crack["status"] == "found" and crack.get("key")
        ]
        events = self.store.list_events(self.session_id, 300)
        for event in events:
            event["time"] = now_iso(event["ts"])
        stats = self.store.stats(self.session_id)
        severity_counts: dict[str, int] = {}
        for finding in findings:
            severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        for cap in captures:
            cap["filename"] = Path(cap["path"]).name
            cap["size"] = human_bytes(cap["size"])
            cap["created_at"] = now_iso(cap["created_at"])
        for cred in credentials:
            cred["created_at"] = now_iso(cred["created_at"])
        return {
            "session": session,
            "aps": aps,
            "clients": clients,
            "captures": captures,
            "findings": findings,
            "credentials": credentials,
            "cracks": cracks,
            "cracked": cracked,
            "cracked_count": len(cracked),
            "events": events,
            "stats": stats,
            "severity_counts": severity_counts,
            "severity_label": SEVERITY_LABEL,
            "started": now_iso(session.get("started_at", time.time())),
            "generated": now_iso(),
            "duration": human_duration(time.time() - session.get("started_at", time.time())),
        }

    # ------------------------------------------------------------------ 输出
    def html(self) -> str:
        return Template(HTML_TEMPLATE).render(**self.collect())

    def markdown(self) -> str:
        data = self.collect()
        session = data["session"]
        lines = [
            f"# Wi-Fi 渗透测试报告 · {session.get('name', '')}",
            "",
            f"- 操作者：{session.get('operator') or '未填写'}",
            f"- 模式：{'实机' if session.get('mode') == 'live' else '演示'}",
            f"- 开始时间：{data['started']}",
            f"- 生成时间：{data['generated']}",
            "",
            "> 本报告仅对已获得书面授权的网络进行评估，口令与凭证属敏感信息。",
            "",
            "## 1. 执行摘要",
            "",
            "| AP | 客户端 | 抓包 | 已破解 | 凭证 | 风险发现 |",
            "|---|---|---|---|---|---|",
            f"| {data['stats']['aps']} | {data['stats']['clients']} | {data['stats']['captures']} "
            f"| {data['stats']['cracked']} | {data['stats']['credentials']} | {data['stats']['findings']} |",
            "",
            "## 2. 风险发现",
            "",
        ]
        if data["findings"]:
            for finding in data["findings"]:
                lines += [
                    f"### [{SEVERITY_LABEL.get(finding['severity'], finding['severity'])}] {finding['title']}",
                    "",
                    f"{finding['detail']}",
                    "",
                    f"`{finding['ssid'] or '<隐藏>'} · {finding['bssid'] or '-'}`",
                    "",
                ]
        else:
            lines.append("未记录风险发现。")
            lines.append("")

        lines += ["## 3. 接入点清单", "", "| SSID | BSSID | 信道 | 加密 | 信号 | WPS | 厂商 |", "|---|---|---|---|---|---|---|"]
        for ap in data["aps"]:
            lines.append(
                f"| {ap['ssid'] or '<隐藏>'} | {ap['bssid']} | {ap['channel']} | "
                f"{ap['privacy'] or 'OPEN'} | {ap['power']} dBm | {'是' if ap['wps'] else '否'} | {ap['vendor']} |"
            )
        lines += ["", "## 4. 已恢复口令", ""]
        if data["cracked"]:
            lines += ["| SSID | BSSID | 方法 | 口令 |", "|---|---|---|---|"]
            for item in data["cracked"]:
                lines.append(f"| {item['ssid'] or '<隐藏>'} | {item['bssid']} | {item['method']} | `{item['key']}` |")
        else:
            lines.append("本次评估未恢复任何 Wi-Fi 口令。")
        lines += ["", "## 5. 修复建议", ""]
        lines += [
            "1. 淘汰 WEP/WPA，优先 WPA3-SAE；WPA2 使用 ≥12 位随机口令。",
            "2. 关闭 WPS；企业网络强制证书校验，禁用 MSCHAPv2/GTC。",
            "3. 启用 802.11w（PMF），禁用或严格监控 WPA2/WPA3 过渡模式。",
            "4. 部署 WIDS，监控 Deauth 洪泛、Beacon 异常与 BSSID 克隆。",
            "5. 关闭客户端自动加入开放网络，及时安装协议补丁。",
            "",
            "---",
            f"Wraith Wi-Fi 渗透测试平台 · {data['generated']}",
        ]
        return "\n".join(lines)

    def json(self) -> dict[str, Any]:
        return self.collect()

    def save(self, directory: str | Path | None = None) -> dict[str, str]:
        data = self.collect()
        base = Path(directory) if directory else Path("reports")
        base.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        name = f"wraith-report-{self.session_id}-{stamp}"
        paths = {
            "html": base / f"{name}.html",
            "json": base / f"{name}.json",
            "md": base / f"{name}.md",
        }
        paths["html"].write_text(Template(HTML_TEMPLATE).render(**data), encoding="utf-8")
        paths["json"].write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        paths["md"].write_text(self.markdown(), encoding="utf-8")
        return {fmt: str(p) for fmt, p in paths.items()}
