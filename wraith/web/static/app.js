/* Wraith — 前端控制台 */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  system: null,
  aps: [],
  clients: [],
  captures: [],
  cracks: [],
  findings: [],
  creds: [],
  modules: [],
  jobs: [],
  activeJob: null,
  events: [],
  scanRunning: false,
  portal: null,
  view: "dashboard",
  ws: null,
  wsRetry: null,
  refreshing: false,
  refreshQueued: false,
};

/* 完整 OUI 库的前端兜底：旧进程或缓存返回 Unknown 时在这里补全厂商。 */
let ouiData = null;
const ouiReady = fetch("/static/oui.json")
  .then((r) => (r.ok ? r.json() : null))
  .then((data) => {
    ouiData = data;
    return data;
  })
  .catch(() => null)
  .finally(() => {
    if (state.aps.some((ap) => String(ap.vendor || "").toUpperCase() === "UNKNOWN")) {
      renderTargets();
    }
  });

function vendorOf(apOrMac, explicitVendor) {
  const isObject = apOrMac && typeof apOrMac === "object";
  const mac = String(isObject ? apOrMac.mac || apOrMac.bssid || "" : apOrMac || "");
  const current = isObject ? apOrMac.vendor : explicitVendor;
  if (current && String(current).toUpperCase() !== "UNKNOWN") return current;
  if (!ouiData) return current || "Unknown";
  const hex = mac.replace(/[^0-9a-f]/gi, "").toUpperCase();
  if (hex.length >= 6) {
    for (const len of [9, 7, 6]) {
      const vendor = ouiData.vendors[hex.slice(0, len)];
      if (vendor) return vendor;
    }
  }
  if (hex.length >= 2 && (parseInt(hex.slice(0, 2), 16) & 0x02)) return ouiData.local;
  return ouiData.unregistered;
}

const CATEGORY_LABEL = {
  credential: "凭据获取",
  wps: "WPS",
  downgrade: "降级",
  enterprise: "企业网络",
  rogue_ap: "流氓 AP",
  availability: "可用性",
};
const RISK_LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
const STATUS_LABEL = {
  queued: "排队中",
  running: "运行中",
  success: "成功",
  failed: "失败",
  stopped: "已停止",
  pending: "等待中",
  found: "已破解",
  exhausted: "字典耗尽",
};
const KIND_LABEL = {
  handshake: "握手",
  pmkid: "PMKID",
  wep: "WEP",
  downgrade: "降级握手",
  portal: "门户",
  scan: "扫描",
};

/* ------------------------------------------------------------------ 工具 */
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const hhmmss = (ts) =>
  new Date((ts || Date.now() / 1000) * 1000).toLocaleTimeString("zh-CN", { hour12: false });
const datetime = (ts) =>
  ts ? new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false }) : "—";
const bytes = (n) => {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
};
const duration = (s) => {
  if (s == null) return "—";
  if (s < 60) return `${Math.round(s)}s`;
  return `${Math.floor(s / 60)}m${String(Math.round(s % 60)).padStart(2, "0")}s`;
};

function securityClass(sec) {
  const s = String(sec || "UNKNOWN").toUpperCase();
  if (s.includes("ENT")) return "ent";
  if (s.includes("WPA2") && s.includes("WPA3")) return "transition";
  if (s.includes("WPA3")) return "wpa3";
  if (s.includes("WPA2")) return "wpa2";
  if (s.includes("WPA")) return "wpa";
  if (s.includes("WEP")) return "wep";
  if (s === "OPEN") return "open";
  return "unknown";
}
const secBadge = (sec) =>
  `<span class="badge ${securityClass(sec)}">${esc(sec || "UNKNOWN")}</span>`;

function signalHtml(power) {
  const dbm = power == null ? -100 : power;
  const q = dbm >= -50 ? 4 : dbm >= -65 ? 3 : dbm >= -78 ? 2 : 1;
  const bars = [1, 2, 3, 4].map((i) => `<i class="${i <= q ? "on" : ""}"></i>`).join("");
  return `<div class="signal sig-${q}"><span class="bars">${bars}</span><span class="dbm">${dbm} dBm</span></div>`;
}

function sevBadge(sev) {
  const label = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" }[sev] || sev;
  return `<span class="sev ${esc(sev)}">${esc(label)}</span>`;
}

function toast(message, type = "info", ms = 3800) {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  $("#toasts").appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transform = "translateY(6px)";
    el.style.transition = ".25s";
    setTimeout(() => el.remove(), 260);
  }, ms);
}

async function api(path, { method = "GET", body } = {}) {
  const options = { method, headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(path, options);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (!res.ok) {
    const detail = data && (data.detail || data.error);
    throw new Error(typeof detail === "string" ? detail : `HTTP ${res.status}`);
  }
  return data;
}

/* ------------------------------------------------------------------ WebSocket */
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${location.host}/ws`;
  try { state.ws = new WebSocket(url); } catch { return; }

  state.ws.onopen = () => {
    $("#ws-status").className = "dot online";
    $("#ws-label").textContent = "实时连接";
    if (state.wsRetry) { clearTimeout(state.wsRetry); state.wsRetry = null; }
    state.ws.send("ping");
  };
  state.ws.onmessage = (evt) => {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }
    if (msg.type === "event") {
      addEvent(msg.event);
    } else if (msg.type === "hello") {
      $("#ws-label").textContent = msg.mode === "live" ? "实机连接" : "演示连接";
    }
  };
  state.ws.onclose = () => {
    $("#ws-status").className = "dot offline";
    $("#ws-label").textContent = "已断开";
    state.wsRetry = setTimeout(connectWS, 2500);
  };
  state.ws.onerror = () => { try { state.ws.close(); } catch { /* ignore */ } };
}

function addEvent(event) {
  state.events.push(event);
  if (state.events.length > 400) state.events.shift();
  appendEventRow(event);
  if (event.level !== "debug" && ["attack", "crack", "system", "portal", "scan"].includes(event.source)) {
    scheduleRefresh(event.source === "scan" ? 1200 : 700);
  }
}

function appendEventRow(event) {
  const feed = $("#feed");
  if (!feed) return;
  const placeholder = feed.querySelector(".empty");
  if (placeholder) placeholder.remove();
  const row = document.createElement("div");
  row.className = `ev ${esc(event.level)}`;
  row.dataset.ts = event.ts;
  row.innerHTML =
    `<span class="t">${hhmmss(event.ts)}</span>` +
    `<span class="src">${esc(event.source)}</span>` +
    `<span class="msg">${esc(event.message)}</span>`;
  const nearBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 70;
  feed.appendChild(row);
  while (feed.children.length > 260) feed.firstElementChild.remove();
  if (nearBottom) feed.scrollTop = feed.scrollHeight;
}

function renderFeed() {
  const feed = $("#feed");
  if (!feed) return;
  if (!state.events.length) {
    feed.innerHTML = `<div class="empty">等待事件… 启动扫描或攻击后这里会显示实时日志</div>`;
    return;
  }
  feed.innerHTML = state.events
    .slice(-200)
    .map(
      (e) =>
        `<div class="ev ${esc(e.level)}"><span class="t">${hhmmss(e.ts)}</span>` +
        `<span class="src">${esc(e.source)}</span><span class="msg">${esc(e.message)}</span></div>`
    )
    .join("");
  feed.scrollTop = feed.scrollHeight;
}

/* ------------------------------------------------------------------ 数据刷新 */
let refreshTimer = null;
function scheduleRefresh(delay = 800) {
  if (refreshTimer) return;
  refreshTimer = setTimeout(async () => {
    refreshTimer = null;
    await refreshAll();
  }, delay);
}

async function refreshSystem() {
  const sys = await api("/api/system");
  state.system = sys;
  state.portal = sys.portal || null;
  state.scanRunning = !!(sys.scanner && sys.scanner.running);
  state.activeJob = sys.attack ? sys.attack.active : null;

  $("#mode-badge").className = `mode-badge ${sys.demo ? "demo" : "live"}`;
  $("#mode-badge").textContent = sys.demo ? "演示模式" : "实机 LIVE";
  $("#settings-mode").className = `mode-badge ${sys.demo ? "demo" : "live"}`;
  $("#settings-mode").textContent = sys.demo ? "演示模式" : "实机 LIVE";
  $("#attack-mode-hint").textContent = sys.demo
    ? "演示模式：模拟执行，不触碰真实设备"
    : `实机模式${sys.root ? "" : "（缺少 root，攻击可能失败）"}`;

  // MCP / AI 代理信息
  const mcp = sys.mcp || {};
  const mcpSet = (id, value) => {
    const el = $(id);
    if (el) el.textContent = value;
  };
  mcpSet("#mcp-endpoint", mcp.endpoint || "/mcp");
  mcpSet("#mcp-command", mcp.stdio_command || "wraith mcp --demo");
  mcpSet("#mcp-transports", (mcp.transports || []).join(" / ") || "stdio / streamable-http");
  mcpSet("#mcp-tools", mcp.tool_count ?? "—");
  mcpSet("#mcp-audit", mcp.audit_path || "data/mcp-audit.jsonl");

  // 网卡下拉
  const select = $("#iface-select");
  const current = select.value || sys.config.iface || "";
  const ifaces = sys.interfaces || [];
  select.innerHTML = ifaces.length
    ? ifaces
        .map(
          (i) =>
            `<option value="${esc(i.name)}" ${i.name === current ? "selected" : ""}>` +
            `${esc(i.name)} · ${esc(i.mode || "?")}${i.monitor_capable ? " · monitor" : ""}</option>`
        )
        .join("")
    : `<option value="">${sys.demo ? "演示环境 (demo0)" : "未检测到无线网卡"}</option>`;

  const cfgIface = $("#cfg-iface");
  if (cfgIface) {
    cfgIface.innerHTML =
      `<option value="">自动选择</option>` +
      ifaces
        .map((i) => `<option value="${esc(i.name)}" ${i.name === (sys.config.iface || "") ? "selected" : ""}>${esc(i.name)} · ${esc(i.mode || "?")}</option>`)
        .join("");
  }

  // 状态徽标
  const scanStatus = sys.scanner || {};
  const pill = $("#scan-status");
  if (scanStatus.running) {
    pill.textContent = `扫描中 · ${scanStatus.aps || 0} AP / ${scanStatus.clients || 0} 客户端`;
    pill.className = "pill on";
  } else {
    pill.textContent = "空闲";
    pill.className = "pill";
  }
  $("#scan-btn").classList.toggle("hidden", state.scanRunning);
  $("#scan-stop").classList.toggle("hidden", !state.scanRunning);

  // 授权
  const auth = sys.auth || {};
  const authDot = $("#auth-dot");
  const authText = $("#auth-text");
  if (authDot) {
    authDot.className = `dot ${auth.authorized ? "online" : "offline"}`;
    authText.textContent = auth.demo
      ? "演示模式（免授权，模拟执行）"
      : auth.authorized
      ? `已授权 · 范围：${(auth.scope || []).join(", ") || "全部"}`
      : "未授权 · live 攻击将被拒绝";
  }
  const scopeList = $("#auth-scope-list");
  if (scopeList) {
    scopeList.innerHTML = (auth.scope || []).map((s) => `<span class="tag">${esc(s)}</span>`).join("");
  }

  // 门户
  renderPortal(sys.portal);

  // 配置字段（只填充一次，避免覆盖用户输入）
  if (sys.config && !$("#cfg-wordlist").dataset.touched) {
    $("#cfg-wordlist").value = sys.config.wordlist || "";
    $("#cfg-operator").value = sys.config.operator || "";
    $("#cfg-wordlist-hint").textContent = sys.config.wordlist_exists
      ? "字典文件存在"
      : "字典文件不存在，破解前请准备可用字典";
  }

  // 依赖摘要
  const deps = sys.deps || {};
  if ($("#deps-summary")) {
    $("#deps-summary").textContent = `${deps.installed_count || 0}/${deps.total_count || 0} 已安装`;
  }
  renderDeps(deps.tools || []);

  // 统计
  applyStats(sys);
  renderAttackBanner();
  renderSettingsMode();
}

function applyStats(sys) {
  const stats = sys.stats || {};
  $("#st-aps").textContent = state.aps.length || stats.aps || 0;
  $("#st-clients").textContent = state.clients.length || stats.clients || 0;
  $("#st-captures").textContent = stats.captures || 0;
  $("#st-cracked").textContent = stats.cracked || 0;
  $("#st-creds").textContent = stats.credentials || 0;
  $("#st-findings").textContent = stats.findings || 0;
  $("#nav-ap-count").textContent = state.aps.length || stats.aps || 0;
  $("#nav-cred-count").textContent = stats.credentials || 0;
}

async function refreshAll() {
  if (state.refreshing) { state.refreshQueued = true; return; }
  state.refreshing = true;
  try {
    const [apsData, captures, cracks, findings, creds, attacks] = await Promise.all([
      api("/api/aps"),
      api("/api/captures"),
      api("/api/cracks"),
      api("/api/findings"),
      api("/api/credentials"),
      api("/api/attacks"),
    ]);
    state.aps = apsData.aps || [];
    state.clients = apsData.clients || [];
    state.captures = captures.captures || [];
    state.cracks = cracks.cracks || [];
    state.findings = findings.findings || [];
    state.creds = creds.credentials || [];
    state.modules = attacks.modules || [];
    state.jobs = attacks.jobs || [];
    state.activeJob = attacks.active || null;

    applyStats(state.system || {});
    renderAPPreview();
    renderTargets();
    renderModules();
    renderJobs();
    renderCaptures();
    renderCracks();
    renderFindings();
    renderCreds();
    renderAttackBanner();
  } catch (err) {
    console.warn("refresh failed", err);
  } finally {
    state.refreshing = false;
    if (state.refreshQueued) {
      state.refreshQueued = false;
      setTimeout(refreshAll, 120);
    }
  }
}

/* ------------------------------------------------------------------ 渲染：总览 */
function renderAPPreview() {
  const body = $("#ap-preview");
  if (!body) return;
  if (!state.aps.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty">尚未扫描</td></tr>`;
    return;
  }
  body.innerHTML = state.aps
    .slice(0, 6)
    .map(
      (ap) => `<tr class="clickable" data-bssid="${esc(ap.bssid)}">
        <td><div class="ssid">${esc(ap.ssid || "<隐藏>")}</div>
            <div class="sub">${esc(ap.bssid)} · ch${esc(ap.channel)}</div></td>
        <td>${secBadge(ap.security)}${ap.wps ? ' <span class="badge wps">WPS</span>' : ""}</td>
        <td>${signalHtml(ap.power)}</td>
        <td><button class="btn sm ghost" data-detail="${esc(ap.bssid)}">详情</button></td>
      </tr>`
    )
    .join("");
}

function renderAttackBanner() {
  const banner = $("#attack-banner");
  const panel = $("#active-attack-panel");
  const job = state.activeJob;
  if (!banner || !panel) return;
  if (!job) {
    banner.classList.add("hidden");
    panel.classList.add("hidden");
    return;
  }
  banner.classList.remove("hidden");
  $("#attack-title").textContent = `${job.name} · ${STATUS_LABEL[job.status] || job.status}`;
  $("#attack-target").textContent = `${job.target.ssid || "<隐藏>"} · ch${job.target.channel || "?"}`;
  const log = (job.log || []).slice(-40);
  $("#attack-log").innerHTML = log.length
    ? log.map((line) => `<div>${esc(line)}</div>`).join("")
    : `<div class="muted">等待模块输出…</div>`;
  $("#attack-log").scrollTop = $("#attack-log").scrollHeight;

  panel.classList.remove("hidden");
  $("#active-attack-name").textContent = `${job.name} · ${STATUS_LABEL[job.status] || job.status}`;
  const logHtml = log.length ? log.map((line) => `<div>${esc(line)}</div>`).join("") : `<span class="muted">等待输出…</span>`;
  $("#active-attack-body").innerHTML = `
    <div class="chip" style="margin-bottom:10px">
      <span>目标：<span class="mono">${esc(job.target.ssid || "<隐藏>")} · ${esc(job.target.bssid || "-")}</span></span>
      <span class="muted">·</span><span>已运行 ${duration(job.seconds)}</span>
    </div>
    <div class="attack-log" style="max-height:220px">${logHtml}</div>`;
}

/* ------------------------------------------------------------------ 渲染：目标 */
function filteredAPs() {
  const term = ($("#ap-search")?.value || "").trim().toLowerCase();
  const filter = $("#ap-filter")?.value || "";
  return state.aps.filter((ap) => {
    if (filter === "ENT" && !String(ap.security).includes("ENT")) return false;
    if (filter === "WPS" && !ap.wps) return false;
    if (filter && filter !== "ENT" && filter !== "WPS" && ap.security !== filter) return false;
    if (!term) return true;
    return [ap.ssid, ap.bssid, vendorOf(ap), ap.channel, ap.security]
      .some((v) => String(v || "").toLowerCase().includes(term));
  });
}

function renderTargets() {
  const body = $("#targets-body");
  if (!body) return;
  const items = filteredAPs();
  $("#target-count").textContent = state.aps.length;
  if (!items.length) {
    body.innerHTML = `<tr><td colspan="9" class="empty"><div class="big">📡</div>${
      state.aps.length ? "没有符合筛选条件的目标" : "还没有发现接入点，先启动扫描"
    }</td></tr>`;
    return;
  }
  body.innerHTML = items
    .map(
      (ap) => `<tr class="clickable" data-bssid="${esc(ap.bssid)}">
        <td><div class="ssid">${esc(ap.ssid || "<隐藏>")}</div>
            <div class="sub">${esc(vendorOf(ap) || "Unknown")}</div></td>
        <td class="mono">${esc(ap.bssid)}</td>
        <td class="mono">${esc(ap.channel)}</td>
        <td>${secBadge(ap.security)}${ap.wps ? ' <span class="badge wps">WPS</span>' : ""}</td>
        <td>${signalHtml(ap.power)}</td>
        <td>${ap.wps ? '<span class="sev high">开</span>' : '<span class="dim">关</span>'}</td>
        <td class="mono">${esc(ap.clients || 0)}</td>
        <td class="muted">${esc(vendorOf(ap) || "—")}</td>
        <td><div class="row-actions">
          <button class="btn sm ghost" data-detail="${esc(ap.bssid)}">详情</button>
          <button class="btn sm primary" data-attack="${esc(ap.bssid)}">攻击</button>
        </div></td>
      </tr>`
    )
    .join("");
}

/* ------------------------------------------------------------------ 渲染：攻击模块 */
function renderModules() {
  const grid = $("#modules-grid");
  if (!grid) return;
  if (!state.modules.length) {
    grid.innerHTML = `<div class="empty">模块加载失败</div>`;
    return;
  }
  grid.innerHTML = state.modules
    .map((m) => {
      const tags = (m.requires || [])
        .map((dep) => `<span class="tag ${m.available ? "ok" : "miss"}">${esc(dep)}</span>`)
        .join("");
      return `<article class="module" data-module="${esc(m.id)}">
        <div class="top">
          <span class="name">${esc(m.name)}</span>
          <span class="risk ${esc(m.risk)}">${esc(RISK_LABEL[m.risk] || m.risk)}</span>
        </div>
        <div class="desc">${esc(m.description)}</div>
        <div class="foot">
          <span class="tag">${esc(CATEGORY_LABEL[m.category] || m.category)}</span>
          ${tags || '<span class="tag ok">内置</span>'}
        </div>
      </article>`;
    })
    .join("");
}

function renderJobs() {
  const body = $("#jobs-body");
  if (!body) return;
  if (!state.jobs.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">暂无任务</td></tr>`;
    return;
  }
  body.innerHTML = state.jobs
    .map(
      (j) => `<tr>
        <td class="mono">${esc(j.id)}</td>
        <td>${esc(j.name)}</td>
        <td class="mono">${esc(j.target.ssid || j.target.bssid || "全局")}</td>
        <td><span class="sev ${j.status === "success" ? "low" : j.status === "failed" ? "critical" : j.status === "stopped" ? "medium" : "info"}">${esc(STATUS_LABEL[j.status] || j.status)}</span></td>
        <td class="mono">${duration(j.seconds)}</td>
        <td class="mono muted">${hhmmss(j.started_at)}</td>
      </tr>`
    )
    .join("");
}

/* ------------------------------------------------------------------ 渲染：抓包/破解 */
function renderCaptures() {
  const body = $("#captures-body");
  if (!body) return;
  $("#captures-count").textContent = `${state.captures.length} 个`;
  if (!state.captures.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty">暂无抓包，先执行握手 / PMKID / WEP 攻击</td></tr>`;
    return;
  }
  body.innerHTML = state.captures
    .map(
      (c) => `<tr>
        <td class="mono">${c.id}</td>
        <td><span class="tag">${esc(KIND_LABEL[c.kind] || c.kind)}</span></td>
        <td>${esc(c.ssid || "<隐藏>")}<div class="sub mono">${esc(c.bssid || "-")}</div></td>
        <td class="mono">${esc(c.filename || c.path.split("/").pop())}</td>
        <td class="mono">${bytes(c.size)}</td>
        <td class="mono">${c.hash_lines || (c.exists === false ? "缺失" : 0)}</td>
        <td class="mono muted">${hhmmss(c.created_at)}</td>
        <td><div class="row-actions">
          <button class="btn sm primary" data-crack="${c.id}" ${c.exists === false ? "disabled" : ""}>破解</button>
        </div></td>
      </tr>`
    )
    .join("");
}

function renderCracks() {
  const body = $("#cracks-body");
  if (!body) return;
  const running = state.cracks.filter((c) => c.status === "running").length;
  $("#cracks-hint").textContent = running ? `${running} 个任务运行中` : "空闲";
  if (!state.cracks.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty">暂无破解任务</td></tr>`;
    return;
  }
  body.innerHTML = state.cracks
    .map((c) => {
      const statusClass = c.status === "found" ? "low" : c.status === "failed" ? "critical" : c.status === "running" ? "info" : "medium";
      const progress = Math.round((c.progress || 0) * 100);
      return `<tr>
        <td class="mono">${c.id}</td>
        <td class="mono">#${c.capture_id}</td>
        <td>${esc(c.method)}</td>
        <td class="mono muted" title="${esc(c.wordlist)}">${esc((c.wordlist || "").split("/").pop())}</td>
        <td><span class="sev ${statusClass}">${esc(STATUS_LABEL[c.status] || c.status)}</span></td>
        <td class="mono">${c.key ? `<strong style="color:var(--green)">${esc(c.key)}</strong>` : '<span class="dim">—</span>'}</td>
        <td style="min-width:90px"><div class="progress"><i style="width:${progress}%"></i></div></td>
        <td>${c.status === "running" ? `<button class="btn sm danger" data-crack-stop="${c.id}">停止</button>` : ""}</td>
      </tr>`;
    })
    .join("");
}

/* ------------------------------------------------------------------ 渲染：发现/凭证 */
function renderFindings() {
  const body = $("#findings-body");
  if (!body) return;
  $("#findings-count").textContent = `${state.findings.length} 项`;
  if (!state.findings.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty">暂无发现</td></tr>`;
    return;
  }
  body.innerHTML = state.findings
    .map(
      (f) => `<tr>
        <td>${sevBadge(f.severity)}</td>
        <td>${esc(f.title)}</td>
        <td>${esc(f.ssid || "<隐藏>")}<div class="sub mono">${esc(f.bssid || "-")}</div></td>
        <td class="muted" style="max-width:420px">${esc(f.detail)}</td>
      </tr>`
    )
    .join("");
}

function renderCreds() {
  const body = $("#creds-body");
  if (!body) return;
  $("#cred-count").textContent = `${state.creds.length} 条`;
  if (!state.creds.length) {
    body.innerHTML = `<tr><td colspan="7" class="empty">暂无凭证</td></tr>`;
    return;
  }
  body.innerHTML = state.creds
    .map(
      (c) => `<tr>
        <td class="mono">${c.id}</td>
        <td class="mono">${esc(c.username || "—")}</td>
        <td class="mono"><strong style="color:var(--green)">${esc(c.password || "—")}</strong></td>
        <td>${esc(c.portal || "—")}</td>
        <td class="mono">${esc(c.ip || "—")}</td>
        <td class="muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.user_agent || "—")}</td>
        <td class="mono muted">${hhmmss(c.created_at)}</td>
      </tr>`
    )
    .join("");
}

function renderPortal(portal) {
  if (!portal) return;
  const running = !!portal.running;
  $("#portal-state").textContent = running ? "运行中" : "未运行";
  $("#portal-state").className = `pill ${running ? "on" : ""}`;
  const link = $("#portal-url");
  if (running) {
    link.textContent = portal.url;
    link.href = portal.url;
  } else {
    link.textContent = "—";
    link.href = "#";
  }
  $("#portal-stats").textContent = running
    ? `· 命中 ${portal.hits || 0} 次 / 提交 ${portal.submissions || 0} 次`
    : "";
}

/* ------------------------------------------------------------------ 渲染：设置 */
function renderSettingsMode() {
  const sys = state.system;
  if (!sys) return;
  const badge = $("#settings-mode");
  badge.className = `mode-badge ${sys.demo ? "demo" : "live"}`;
  badge.textContent = sys.demo ? "演示模式" : "实机 LIVE";
}

function renderDeps(tools) {
  const body = $("#deps-body");
  if (!body) return;
  if (!tools.length) { body.innerHTML = `<span class="muted">未获取到依赖信息</span>`; return; }
  const sorted = [...tools].sort((a, b) => Number(b.installed) - Number(a.installed) || a.name.localeCompare(b.name));
  body.innerHTML = sorted
    .map(
      (t) => `<div class="dep-row">
        <span class="name">${esc(t.name)}</span>
        <span class="purpose">${esc(t.purpose)}</span>
        ${t.installed
          ? `<span class="st ok">● 已安装</span>`
          : `<span class="st no" title="${esc(t.install)}">○ 缺失 · ${esc(t.package)}</span>`}
      </div>`
    )
    .join("");
}

async function refreshAudit() {
  const body = $("#audit-body");
  if (!body) return;
  try {
    const data = await api("/api/authorization/audit?limit=80");
    const records = (data.records || []).slice().reverse();
    if (!records.length) {
      body.innerHTML = `<tr><td colspan="5" class="empty">暂无记录</td></tr>`;
      return;
    }
    body.innerHTML = records
      .map(
        (r) => `<tr>
          <td class="mono muted">${esc((r.time || "").replace("T", " "))}</td>
          <td class="mono">${esc(r.action)}</td>
          <td class="mono">${esc(r.ssid || r.bssid || "—")}</td>
          <td><span class="sev ${r.allowed ? "low" : "critical"}">${r.allowed ? "允许" : "拒绝"}</span></td>
          <td class="muted">${esc(r.reason || "")}</td>
        </tr>`
      )
      .join("");
  } catch { /* ignore */ }
}

/* ------------------------------------------------------------------ 抽屉 */
async function openDrawer(bssid) {
  const drawer = $("#drawer");
  drawer.classList.remove("hidden");
  $("#drawer-title").textContent = "加载中…";
  $("#drawer-sub").textContent = bssid;
  $("#drawer-body").innerHTML = `<div class="empty">读取目标详情…</div>`;
  let detail;
  try {
    detail = await api(`/api/aps/${encodeURIComponent(bssid)}`);
  } catch (err) {
    $("#drawer-body").innerHTML = `<div class="notice danger">${esc(err.message)}</div>`;
    return;
  }
  const ap = detail.ap;
  const security = ap.security || "UNKNOWN";
  $("#drawer-title").textContent = ap.ssid || "<隐藏 SSID>";
  $("#drawer-sub").textContent = `${ap.bssid} · ${vendorOf(ap)}`;

  const clients = detail.clients || [];
  const findings = detail.findings || [];
  const captures = detail.captures || [];
  const quick = quickAttacksFor(ap);

  $("#drawer-body").innerHTML = `
    <div class="chip" style="gap:8px;margin-bottom:14px">
      ${secBadge(security)}
      ${ap.wps ? '<span class="badge wps">WPS</span>' : ""}
      ${ap.band ? `<span class="tag">${esc(ap.band)}</span>` : ""}
    </div>
    <dl class="kv">
      <dt>信道</dt><dd>${esc(ap.channel)} · ${esc(ap.band || "?")}</dd>
      <dt>信号</dt><dd>${esc(ap.power)} dBm（${esc(ap.quality || 0)}%）</dd>
      <dt>加密</dt><dd>${esc(ap.privacy || "OPEN")} / ${esc(ap.auth || "—")} / ${esc(ap.cipher || "—")}</dd>
      <dt>BSSID</dt><dd>${esc(ap.bssid)}</dd>
      <dt>厂商</dt><dd>${esc(vendorOf(ap))}</dd>
      <dt>客户端</dt><dd>${clients.length}</dd>
      <dt>首次发现</dt><dd>${datetime(ap.first_seen)}</dd>
    </dl>
    <div class="section-label">可执行攻击</div>
    <div class="quick-attacks">
      ${quick.map((m) => `<button class="btn sm" data-attack-module="${esc(m.id)}" data-target="${esc(ap.bssid)}">${esc(m.name)}</button>`).join("") || '<span class="muted">无适用模块</span>'}
    </div>
    <div class="section-label">客户端（${clients.length}）</div>
    ${clients.length ? `<table><thead><tr><th>MAC</th><th>厂商</th><th>信号</th><th>探测</th></tr></thead><tbody>
      ${clients.map((c) => `<tr><td class="mono">${esc(c.mac)}</td><td class="muted">${esc(vendorOf(c) || "—")}</td>
        <td class="mono">${esc(c.power)} dBm</td><td class="muted">${esc((c.probes || []).join(", ") || "—")}</td></tr>`).join("")}
    </tbody></table>` : '<div class="empty">未发现关联客户端</div>'}
    <div class="section-label">风险发现（${findings.length}）</div>
    ${findings.length ? findings.map((f) => `<div class="notice ${f.severity === "critical" || f.severity === "high" ? "danger" : "info"}" style="margin-bottom:8px">
      ${sevBadge(f.severity)} <strong>${esc(f.title)}</strong><br><span class="muted">${esc(f.detail)}</span></div>`).join("") : '<div class="empty">暂无</div>'}
    <div class="section-label">相关抓包（${captures.length}）</div>
    ${captures.length ? `<table><tbody>${captures.map((c) => `<tr><td class="mono">#${c.id}</td><td>${esc(KIND_LABEL[c.kind] || c.kind)}</td><td class="mono">${bytes(c.size)}</td><td class="mono">${c.hash_lines || 0} 哈希</td></tr>`).join("")}</tbody></table>` : '<div class="empty">暂无</div>'}
  `;
}

function quickAttacksFor(ap) {
  const security = String(ap.security || "").toUpperCase();
  const ids = [];
  if (security.includes("ENT")) ids.push("enterprise");
  if (security.includes("WPA2") && security.includes("WPA3")) ids.push("wpa3_downgrade");
  if (security === "WEP") ids.push("wep");
  if (ap.wps) ids.push("wps_pixie", "wps_pin");
  ids.push("handshake", "pmkid", "deauth", "evil_twin");
  const result = [];
  ids.forEach((id) => {
    const module = state.modules.find((m) => m.id === id);
    if (module && !result.includes(module)) result.push(module);
  });
  return result;
}

function openAttackChooser(bssid) {
  const ap = state.aps.find((a) => a.bssid === bssid);
  if (!ap) { toast("目标信息已失效，请刷新", "warn"); return; }
  const quick = quickAttacksFor(ap);
  const rest = state.modules.filter((m) => !quick.includes(m));
  const cards = [...quick, ...rest];
  openModal(`
    <div class="modal-head">
      <div><h3>选择攻击模块</h3>
        <p>${esc(ap.ssid || "<隐藏>")} · ${esc(ap.bssid)} · ch${esc(ap.channel)}</p></div>
      <button class="modal-close" data-close>✕</button>
    </div>
    <div class="modal-body">
      <div class="target-preview">${secBadge(ap.security)} ${ap.wps ? '<span class="badge wps">WPS</span>' : ""} · ${esc(vendorOf(ap))}</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:9px">
        ${cards.map((m) => `<button class="module" style="text-align:left;padding:12px" data-pick="${esc(m.id)}">
          <div class="top"><span class="name" style="font-size:12.5px">${esc(m.name)}</span>
            <span class="risk ${esc(m.risk)}" style="font-size:9.5px">${esc(RISK_LABEL[m.risk] || m.risk)}</span></div>
          <div class="desc" style="min-height:0;font-size:11px;margin-top:6px">${esc(m.description.slice(0, 72))}…</div>
        </button>`).join("")}
      </div>
    </div>
    <div class="modal-foot"><button class="btn ghost" data-close>取消</button></div>
  `);
  $$("#modal-root [data-pick]").forEach((btn) =>
    btn.addEventListener("click", () => openAttackModal(btn.dataset.pick, bssid))
  );
}

/* ------------------------------------------------------------------ 弹窗 */
function closeModal() { $("#modal-root").innerHTML = ""; }

function openModal(html) {
  $("#modal-root").innerHTML = `<div class="modal-mask"><div class="modal">${html}</div></div>`;
  $$("#modal-root [data-close]").forEach((btn) => btn.addEventListener("click", closeModal));
  $("#modal-root .modal-mask").addEventListener("click", (e) => {
    if (e.target.id === "modal-root" || e.target.classList.contains("modal-mask")) closeModal();
  });
}

function openAttackModal(moduleId, bssid = "") {
  const module = state.modules.find((m) => m.id === moduleId);
  if (!module) { toast("未知模块", "error"); return; }
  const options = (module.options || []).filter(
    (o) => !["bssid", "ssid", "channel", "security", "wps"].includes(o.name)
  );
  const apOptions = state.aps.length
    ? state.aps
        .map(
          (ap) =>
            `<option value="${esc(ap.bssid)}" ${ap.bssid === bssid ? "selected" : ""}>` +
            `${esc(ap.ssid || "<隐藏>")} · ${esc(ap.bssid)} · ch${esc(ap.channel)}</option>`
        )
        .join("")
    : `<option value="">（无目标，请先扫描）</option>`;

  const fields = options
    .map((o) => {
      const id = `opt-${o.name}`;
      const hint = o.help ? `<span class="hint">${esc(o.help)}</span>` : "";
      if (o.type === "bool") {
        return `<label class="check"><input type="checkbox" id="${id}" ${o.default ? "checked" : ""}> ${esc(o.label)}${hint}</label>`;
      }
      if (o.type === "select") {
        return `<label class="field"><span>${esc(o.label)}</span><select id="${id}">${(o.choices || [])
          .map((c) => `<option value="${esc(c)}" ${String(c) === String(o.default) ? "selected" : ""}>${esc(c)}</option>`)
          .join("")}</select>${hint}</label>`;
      }
      if (o.type === "textarea") {
        return `<label class="field"><span>${esc(o.label)}</span><textarea id="${id}" placeholder="${esc(o.placeholder || "")}">${esc(o.default || "")}</textarea>${hint}</label>`;
      }
      const type = o.type === "int" ? "number" : o.type === "password" ? "password" : "text";
      return `<label class="field"><span>${esc(o.label)}</span><input type="${type}" id="${id}" value="${esc(o.default ?? "")}" placeholder="${esc(o.placeholder || "")}">${hint}</label>`;
    })
    .join("");

  const liveWarning = state.system && !state.system.demo
    ? `<div class="notice danger">实机模式：该操作会向真实无线设备发送帧，请再次确认授权范围。</div>`
    : `<div class="notice info">演示模式：模块将模拟执行，但捕获的哈希可用于真实离线校验。</div>`;

  openModal(`
    <div class="modal-head">
      <div>
        <h3>${esc(module.name)}</h3>
        <p>${esc(CATEGORY_LABEL[module.category] || module.category)} · 风险 ${esc(RISK_LABEL[module.risk] || module.risk)}</p>
      </div>
      <button class="modal-close" data-close>✕</button>
    </div>
    <div class="modal-body">
      ${liveWarning}
      <div class="notice info" style="border-color:var(--line);background:rgba(15,23,42,.6);color:var(--muted)">${esc(module.description)}</div>
      <label class="field"><span>目标 AP</span>
        <select id="target-select">${apOptions}</select>
      </label>
      <div class="target-preview" id="target-preview"></div>
      ${fields}
    </div>
    <div class="modal-foot">
      <button class="btn ghost" data-close>取消</button>
      <button class="btn primary" id="attack-launch">▶ 启动攻击</button>
    </div>
  `);

  const updatePreview = () => {
    const b = $("#target-select")?.value;
    const ap = state.aps.find((a) => a.bssid === b);
    $("#target-preview").innerHTML = ap
      ? `<span class="mono">${esc(ap.ssid || "<隐藏>")}</span> · ${esc(ap.bssid)} · ch${esc(ap.channel)} · ${secBadge(ap.security)}`
      : `<span class="muted">未选择目标</span>`;
  };
  $("#target-select")?.addEventListener("change", updatePreview);
  updatePreview();

  $("#attack-launch").addEventListener("click", async () => {
    const targetBssid = $("#target-select")?.value || "";
    const ap = state.aps.find((a) => a.bssid === targetBssid) || {};
    const payloadOptions = {};
    options.forEach((o) => {
      const el = $(`#opt-${o.name}`);
      if (!el) return;
      if (o.type === "bool") payloadOptions[o.name] = el.checked;
      else if (o.type === "int") payloadOptions[o.name] = Number(el.value || 0);
      else payloadOptions[o.name] = el.value;
    });
    const btn = $("#attack-launch");
    btn.disabled = true;
    btn.textContent = "启动中…";
    try {
      await api(`/api/attacks/${encodeURIComponent(moduleId)}/start`, {
        method: "POST",
        body: {
          bssid: targetBssid,
          ssid: ap.ssid || "",
          channel: Number(ap.channel || 0),
          security: ap.security || "",
          wps: !!ap.wps,
          options: payloadOptions,
        },
      });
      closeModal();
      toast(`已启动：${module.name}`, "success");
      await refreshAll();
    } catch (err) {
      toast(err.message, "error", 6000);
      btn.disabled = false;
      btn.textContent = "▶ 启动攻击";
    }
  });
}

function openCrackModal(captureId) {
  const capture = state.captures.find((c) => c.id === captureId);
  if (!capture) return;
  const wordlist = state.system?.config?.wordlist || "";
  openModal(`
    <div class="modal-head">
      <div><h3>破解 #${capture.id}</h3>
          <p>${esc(capture.ssid || "<隐藏>")} · ${esc(capture.bssid || "-")} · ${esc(capture.filename || "")}</p></div>
      <button class="modal-close" data-close>✕</button>
    </div>
    <div class="modal-body">
      <label class="field"><span>破解方法</span>
        <select id="crack-method">
          <option value="auto">自动选择（推荐）</option>
          <option value="aircrack">aircrack-ng（CPU 字典）</option>
          <option value="hashcat">hashcat（GPU 22000）</option>
          <option value="offline">内置离线校验（小字典）</option>
        </select>
        <span class="hint">演示环境的哈希由真实 PMKID/MIC 生成，内置校验可验证口令</span>
      </label>
      <label class="field"><span>字典路径</span>
        <input type="text" id="crack-wordlist" value="${esc(wordlist)}" placeholder="/usr/share/wordlists/rockyou.txt">
      </label>
      <div class="notice info">仅对已授权获取的哈希执行离线破解；破解结果会写入报告。</div>
    </div>
    <div class="modal-foot">
      <button class="btn ghost" data-close>取消</button>
      <button class="btn primary" id="crack-start">开始破解</button>
    </div>
  `);
  $("#crack-start").addEventListener("click", async () => {
    const btn = $("#crack-start");
    btn.disabled = true;
    btn.textContent = "启动中…";
    try {
      const res = await api(`/api/captures/${capture.id}/crack`, {
        method: "POST",
        body: {
          method: $("#crack-method").value,
          wordlist: $("#crack-wordlist").value || null,
        },
      });
      closeModal();
      toast(`破解任务 #${res.job_id} 已启动`, "success");
      await refreshAll();
    } catch (err) {
      toast(err.message, "error", 6000);
      btn.disabled = false;
      btn.textContent = "开始破解";
    }
  });
}

/* ------------------------------------------------------------------ 动作 */
async function startScan(quick = false) {
  const iface = $("#iface-select").value || null;
  try {
    await api("/api/scan/start", {
      method: "POST",
      body: { iface, duration: quick ? 24 : null },
    });
    state.scanRunning = true;
    $("#scan-btn").classList.add("hidden");
    $("#scan-stop").classList.remove("hidden");
    $("#scan-status").textContent = "启动中…";
    $("#scan-status").className = "pill on";
    toast(quick ? "快速扫描已启动（24 秒）" : "扫描已启动", "success");
    setTimeout(refreshAll, 800);
  } catch (err) {
    toast(err.message, "error", 6000);
  }
}

async function stopScan() {
  try {
    await api("/api/scan/stop", { method: "POST" });
    state.scanRunning = false;
    $("#scan-btn").classList.remove("hidden");
    $("#scan-stop").classList.add("hidden");
    $("#scan-status").textContent = "空闲";
    $("#scan-status").className = "pill";
    toast("扫描已停止", "info");
    await refreshAll();
  } catch (err) {
    toast(err.message, "error", 5000);
  }
}

async function stopAttack() {
  try {
    await api("/api/attacks/stop", { method: "POST", body: {} });
    toast("已请求停止攻击", "info");
    await refreshAll();
  } catch (err) {
    toast(err.message, "error", 5000);
  }
}

async function openPortal() {
  try {
    const res = await api("/api/portal/open", {
      method: "POST",
      body: { ssid: "Wraith-Guest", title: "Wi-Fi 网络认证" },
    });
    toast(`门户已启动：${res.url}`, "success", 6000);
    state.portal = res;
    await refreshSystem();
  } catch (err) {
    toast(err.message, "error", 6000);
  }
}

async function closePortal() {
  try {
    await api("/api/portal/stop", { method: "POST" });
    toast("门户已关闭", "info");
    await refreshSystem();
  } catch (err) {
    toast(err.message, "error", 5000);
  }
}

/* ------------------------------------------------------------------ 视图切换 */
function switchView(name, updateHash = true) {
  if (!document.getElementById(`view-${name}`)) return;
  state.view = name;
  if (updateHash && location.hash !== `#${name}`) {
    history.replaceState(null, "", `#${name}`);
  }
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (name === "report") { refreshReportFiles(); }
  if (name === "settings") { refreshAudit(); }
  if (name === "dashboard") { renderFeed(); }
}

/* ------------------------------------------------------------------ 报告 */
async function refreshReportFiles() {
  const box = $("#report-files");
  if (!box) return;
  try {
    const data = await api("/api/report/files");
    const files = data.files || [];
    if (!files.length) { box.innerHTML = `<span class="muted">尚未生成报告</span>`; return; }
    box.innerHTML = files
      .map(
        (f) => `<div class="dep-row">
          <span class="name">${esc(f.name)}</span>
          <span class="purpose">${bytes(f.size)} · ${new Date(f.mtime * 1000).toLocaleString("zh-CN", { hour12: false })}</span>
          <a class="btn sm ghost" href="/api/report/download/${encodeURIComponent(f.name)}" target="_blank" rel="noopener">下载</a>
        </div>`
      )
      .join("");
  } catch { /* ignore */ }
}

/* ------------------------------------------------------------------ 绑定 */
function bindEvents() {
  $$(".nav-item").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.view)));
  $$("[data-goto]").forEach((btn) => btn.addEventListener("click", () => switchView(btn.dataset.goto)));

  $("#scan-btn").addEventListener("click", () => startScan(false));
  $("#scan-stop").addEventListener("click", stopScan);
  $("#quick-scan").addEventListener("click", () => startScan(true));
  $("#refresh-targets").addEventListener("click", refreshAll);
  $("#refresh-captures").addEventListener("click", refreshAll);
  $("#clear-feed").addEventListener("click", () => { state.events = []; renderFeed(); });
  $("#attack-stop").addEventListener("click", stopAttack);
  $("#active-attack-stop").addEventListener("click", stopAttack);
  $("#open-portal-quick").addEventListener("click", openPortal);
  $("#portal-open").addEventListener("click", openPortal);
  $("#portal-stop").addEventListener("click", closePortal);

  // 表格交互（事件委托）
  document.addEventListener("click", (e) => {
    const detailBtn = e.target.closest("[data-detail]");
    if (detailBtn) { e.stopPropagation(); openDrawer(detailBtn.dataset.detail); return; }
    const attackBtn = e.target.closest("[data-attack]");
    if (attackBtn) { e.stopPropagation(); openAttackChooser(attackBtn.dataset.attack); return; }
    const attackModuleBtn = e.target.closest("[data-attack-module]");
    if (attackModuleBtn) {
      e.stopPropagation();
      openAttackModal(attackModuleBtn.dataset.attackModule, attackModuleBtn.dataset.target);
      return;
    }
    const moduleCard = e.target.closest("[data-module]");
    if (moduleCard) { openAttackModal(moduleCard.dataset.module); return; }
    const crackBtn = e.target.closest("[data-crack]");
    if (crackBtn) { e.stopPropagation(); openCrackModal(Number(crackBtn.dataset.crack)); return; }
    const crackStop = e.target.closest("[data-crack-stop]");
    if (crackStop) {
      e.stopPropagation();
      api(`/api/cracks/${crackStop.dataset.crackStop}/stop`, { method: "POST" })
        .then(() => { toast("已停止破解", "info"); refreshAll(); })
        .catch((err) => toast(err.message, "error"));
      return;
    }
    const row = e.target.closest("tr[data-bssid]");
    if (row && !e.target.closest("button")) { openDrawer(row.dataset.bssid); }
  });

  $("#drawer-close").addEventListener("click", () => $("#drawer").classList.add("hidden"));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeModal(); $("#drawer").classList.add("hidden"); }
  });

  $("#ap-search").addEventListener("input", renderTargets);
  $("#ap-filter").addEventListener("change", renderTargets);

  // 设置
  $("#mode-demo").addEventListener("click", () => switchMode("demo"));
  $("#mode-live").addEventListener("click", () => switchMode("live"));
  $("#cfg-save").addEventListener("click", saveConfig);
  $("#cfg-wordlist").addEventListener("input", (e) => { e.target.dataset.touched = "1"; });
  $("#auth-submit").addEventListener("click", submitAuthorization);
  $("#auth-revoke").addEventListener("click", revokeAuthorization);
  $("#audit-refresh").addEventListener("click", refreshAudit);

  // 报告
  $("#report-preview").addEventListener("click", () => {
    const frame = $("#report-frame");
    frame.src = `/api/report/html?t=${Date.now()}`;
    frame.classList.remove("hidden");
    frame.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("#report-save").addEventListener("click", async () => {
    try {
      const res = await api("/api/report/save", { method: "POST" });
      toast("报告已生成", "success");
      refreshReportFiles();
      if (res.paths && res.paths.html) {
        const frame = $("#report-frame");
        frame.src = `/api/report/download/${encodeURIComponent(res.paths.html.split("/").pop())}`;
        frame.classList.remove("hidden");
      }
    } catch (err) { toast(err.message, "error", 6000); }
  });
  $("#report-refresh").addEventListener("click", refreshReportFiles);
}

async function switchMode(mode) {
  const live = mode === "live";
  if (live && !confirm("切换到实机模式会向真实无线网卡发包，请确认你已获得书面授权。继续？")) return;
  try {
    await api("/api/system/mode", { method: "POST", body: { mode } });
    await refreshSystem();
    toast(live ? "已切换到实机模式，请完成授权确认" : "已切换到演示模式", live ? "warn" : "success");
    if (live && state.system && !state.system.root) {
      toast("当前进程不是 root，live 扫描/攻击需要 sudo 运行", "warn", 7000);
    }
  } catch (err) { toast(err.message, "error", 5000); }
}

async function saveConfig() {
  try {
    await api("/api/system/config", {
      method: "POST",
      body: {
        iface: $("#cfg-iface").value,
        wordlist: $("#cfg-wordlist").value,
        operator: $("#cfg-operator").value,
      },
    });
    toast("配置已保存", "success");
    $("#cfg-wordlist").dataset.touched = "";
    await refreshSystem();
  } catch (err) { toast(err.message, "error", 5000); }
}

async function submitAuthorization() {
  const token = $("#auth-token").value.trim();
  const scope = $("#auth-scope").value.split("\n").map((s) => s.trim()).filter(Boolean);
  try {
    await api("/api/authorization", {
      method: "POST",
      body: { token, operator: $("#cfg-operator").value || null, scope },
    });
    $("#auth-token").value = "";
    toast("授权已启用", "success");
    await refreshSystem();
  } catch (err) { toast(err.message, "error", 6000); }
}

async function revokeAuthorization() {
  try {
    await api("/api/authorization/revoke", { method: "POST" });
    toast("授权已撤销，live 攻击将被拒绝", "warn");
    await refreshSystem();
  } catch (err) { toast(err.message, "error", 5000); }
}

/* ------------------------------------------------------------------ 启动 */
async function init() {
  bindEvents();
  connectWS();
  const initial = location.hash.replace("#", "");
  if (initial && document.getElementById(`view-${initial}`)) switchView(initial, false);
  window.addEventListener("hashchange", () => {
    const view = location.hash.replace("#", "");
    if (view) switchView(view, false);
  });
  try {
    await refreshSystem();
    await refreshAll();
    await refreshAudit();
  } catch (err) {
    toast(`无法连接后端：${err.message}`, "error", 8000);
  }
  renderFeed();
  setInterval(() => {
    if (state.activeJob) { refreshAll(); return; }
    if (state.view === "dashboard" && document.hidden === false) refreshAll();
  }, 4000);
  setInterval(() => {
    if (state.scanRunning && !document.hidden) {
      api("/api/system").then((sys) => {
        state.system = sys;
        const s = sys.scanner || {};
        if (s.running) {
          $("#scan-status").textContent = `扫描中 · ${s.aps || 0} AP / ${s.clients || 0} 客户端`;
          $("#scan-status").className = "pill on";
        }
      }).catch(() => {});
    }
  }, 2200);
  setInterval(refreshAudit, 15000);
}

document.addEventListener("DOMContentLoaded", init);
