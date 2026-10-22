"""SQLite 持久化：会话、AP、客户端、抓包、破解、凭证、发现、事件。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from .models import (
    AP,
    Capture,
    Client,
    CrackJob,
    Credential,
    Event,
    Finding,
    Session,
    vendor_for,
)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'demo',
    iface       TEXT DEFAULT '',
    operator    TEXT DEFAULT '',
    started_at  REAL NOT NULL,
    ended_at    REAL DEFAULT 0,
    notes       TEXT DEFAULT '',
    status      TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS aps (
    bssid       TEXT NOT NULL,
    session_id  INTEGER NOT NULL,
    ssid        TEXT DEFAULT '',
    channel     INTEGER DEFAULT 0,
    frequency   INTEGER,
    privacy     TEXT DEFAULT '',
    cipher      TEXT DEFAULT '',
    auth        TEXT DEFAULT '',
    power       INTEGER,
    beacons     INTEGER DEFAULT 0,
    data        INTEGER DEFAULT 0,
    wps         INTEGER DEFAULT 0,
    vendor      TEXT DEFAULT '',
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    PRIMARY KEY (bssid, session_id)
);

CREATE TABLE IF NOT EXISTS clients (
    mac         TEXT NOT NULL,
    session_id  INTEGER NOT NULL,
    bssid       TEXT DEFAULT '',
    power       INTEGER,
    packets     INTEGER DEFAULT 0,
    probes      TEXT DEFAULT '',
    vendor      TEXT DEFAULT '',
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    PRIMARY KEY (mac, session_id)
);

CREATE TABLE IF NOT EXISTS captures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    path        TEXT NOT NULL,
    bssid       TEXT DEFAULT '',
    ssid        TEXT DEFAULT '',
    size        INTEGER DEFAULT 0,
    hash_lines  INTEGER DEFAULT 0,
    created_at  REAL NOT NULL,
    meta        TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS cracks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id  INTEGER NOT NULL,
    method      TEXT DEFAULT '',
    wordlist    TEXT DEFAULT '',
    status      TEXT DEFAULT 'pending',
    key         TEXT DEFAULT '',
    started_at  REAL DEFAULT 0,
    finished_at REAL DEFAULT 0,
    progress    REAL DEFAULT 0,
    log         TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    username    TEXT DEFAULT '',
    password    TEXT DEFAULT '',
    portal      TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    user_agent  TEXT DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT DEFAULT 'info',
    bssid       TEXT DEFAULT '',
    ssid        TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    category    TEXT DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    ts          REAL NOT NULL,
    level       TEXT DEFAULT 'info',
    source      TEXT DEFAULT '',
    message     TEXT DEFAULT '',
    data        TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_aps_session ON aps(session_id);
CREATE INDEX IF NOT EXISTS idx_clients_session ON clients(session_id);
CREATE INDEX IF NOT EXISTS idx_captures_session ON captures(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""


class Store:
    """线程安全的 SQLite 封装（单连接 + 锁，WAL 模式）。"""

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ 基础
    def _execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def _query_one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self._query(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------------ 会话
    def create_session(self, session: Session) -> int:
        cur = self._execute(
            "INSERT INTO sessions(name, mode, iface, operator, started_at, notes, status)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                session.name,
                session.mode,
                session.iface,
                session.operator,
                session.started_at,
                session.notes,
                session.status,
            ),
        )
        return int(cur.lastrowid)

    def end_session(self, session_id: int) -> None:
        self._execute(
            "UPDATE sessions SET status='closed', ended_at=? WHERE id=?",
            (time.time(), session_id),
        )

    def get_session(self, session_id: int) -> dict[str, Any] | None:
        return self._query_one("SELECT * FROM sessions WHERE id=?", (session_id,))

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------ AP
    def upsert_ap(self, ap: AP, session_id: int) -> None:
        existing = self._query_one(
            "SELECT first_seen FROM aps WHERE bssid=? AND session_id=?",
            (ap.bssid, session_id),
        )
        if existing:
            ssid = ap.ssid
            self._execute(
                "UPDATE aps SET ssid=CASE WHEN ?<>'' THEN ? ELSE ssid END, channel=?,"
                " frequency=?, privacy=?, cipher=?, auth=?, power=?, beacons=?, data=?,"
                " wps=MAX(wps, ?), vendor=?, last_seen=? WHERE bssid=? AND session_id=?",
                (
                    ssid,
                    ssid,
                    ap.channel,
                    ap.frequency,
                    ap.privacy,
                    ap.cipher,
                    ap.auth,
                    ap.power,
                    ap.beacons,
                    ap.data,
                    int(ap.wps),
                    ap.vendor,
                    ap.last_seen,
                    ap.bssid,
                    session_id,
                ),
            )
        else:
            self._execute(
                "INSERT INTO aps(bssid, session_id, ssid, channel, frequency, privacy,"
                " cipher, auth, power, beacons, data, wps, vendor, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ap.bssid,
                    session_id,
                    ap.ssid,
                    ap.channel,
                    ap.frequency,
                    ap.privacy,
                    ap.cipher,
                    ap.auth,
                    ap.power,
                    ap.beacons,
                    ap.data,
                    int(ap.wps),
                    ap.vendor,
                    ap.first_seen,
                    ap.last_seen,
                ),
            )

    def list_aps(self, session_id: int) -> list[dict[str, Any]]:
        return self._query(
            "SELECT * FROM aps WHERE session_id=? ORDER BY power DESC", (session_id,)
        )

    def backfill_vendors(self) -> int:
        """用完整 OUI 数据库回填历史会话中缺失/Unknown 的厂商字段。"""
        updated = 0
        for table, key in (("aps", "bssid"), ("clients", "mac")):
            rows = self._query(
                f"SELECT DISTINCT {key} AS addr FROM {table}"
                " WHERE vendor IS NULL OR vendor='' OR upper(vendor)='UNKNOWN'"
            )
            for row in rows:
                vendor = vendor_for(row["addr"])
                if not vendor or vendor.upper() == "UNKNOWN":
                    continue
                cur = self._execute(
                    f"UPDATE {table} SET vendor=? WHERE {key}=?"
                    " AND (vendor IS NULL OR vendor='' OR upper(vendor)='UNKNOWN')",
                    (vendor, row["addr"]),
                )
                updated += cur.rowcount
        return updated

    def get_ap(self, session_id: int, bssid: str) -> dict[str, Any] | None:
        return self._query_one(
            "SELECT * FROM aps WHERE session_id=? AND bssid=?", (session_id, bssid.lower())
        )

    def delete_ap(self, session_id: int, bssid: str) -> None:
        self._execute("DELETE FROM aps WHERE session_id=? AND bssid=?", (session_id, bssid))

    # ------------------------------------------------------------------ 客户端
    def upsert_client(self, client: Client, session_id: int) -> None:
        probes = json.dumps(client.probes, ensure_ascii=False)
        existing = self._query_one(
            "SELECT mac FROM clients WHERE mac=? AND session_id=?",
            (client.mac, session_id),
        )
        if existing:
            self._execute(
                "UPDATE clients SET bssid=?, power=?, packets=?, probes=?, last_seen=?"
                " WHERE mac=? AND session_id=?",
                (
                    client.bssid,
                    client.power,
                    client.packets,
                    probes,
                    client.last_seen,
                    client.mac,
                    session_id,
                ),
            )
        else:
            self._execute(
                "INSERT INTO clients(mac, session_id, bssid, power, packets, probes,"
                " vendor, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    client.mac,
                    session_id,
                    client.bssid,
                    client.power,
                    client.packets,
                    probes,
                    client.vendor,
                    client.first_seen,
                    client.last_seen,
                ),
            )

    def list_clients(self, session_id: int, bssid: str | None = None) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM clients WHERE session_id=? ORDER BY power DESC", (session_id,)
        )
        for row in rows:
            try:
                row["probes"] = json.loads(row.get("probes") or "[]")
            except json.JSONDecodeError:
                row["probes"] = []
            if not row.get("vendor") or str(row["vendor"]).upper() == "UNKNOWN":
                row["vendor"] = vendor_for(row.get("mac") or "")
        if bssid:
            rows = [r for r in rows if r.get("bssid") == bssid.lower()]
        return rows

    # ------------------------------------------------------------------ 抓包
    def add_capture(self, capture: Capture) -> int:
        cur = self._execute(
            "INSERT INTO captures(session_id, kind, path, bssid, ssid, size, hash_lines,"
            " created_at, meta) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                capture.session_id,
                capture.kind,
                str(capture.path),
                capture.bssid,
                capture.ssid,
                capture.size,
                capture.hash_lines,
                capture.created_at,
                json.dumps(capture.meta, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid)

    def list_captures(self, session_id: int) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM captures WHERE session_id=? ORDER BY id DESC", (session_id,)
        )
        for row in rows:
            try:
                row["meta"] = json.loads(row.get("meta") or "{}")
            except json.JSONDecodeError:
                row["meta"] = {}
        return rows

    def get_capture(self, capture_id: int) -> dict[str, Any] | None:
        row = self._query_one("SELECT * FROM captures WHERE id=?", (capture_id,))
        if row:
            try:
                row["meta"] = json.loads(row.get("meta") or "{}")
            except json.JSONDecodeError:
                row["meta"] = {}
        return row

    def delete_capture(self, capture_id: int) -> None:
        self._execute("DELETE FROM captures WHERE id=?", (capture_id,))

    # ------------------------------------------------------------------ 破解
    def add_crack(self, job: CrackJob) -> int:
        cur = self._execute(
            "INSERT INTO cracks(capture_id, method, wordlist, status, key, started_at,"
            " finished_at, progress, log) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                job.capture_id,
                job.method,
                job.wordlist,
                job.status,
                job.key,
                job.started_at,
                job.finished_at,
                job.progress,
                job.log,
            ),
        )
        return int(cur.lastrowid)

    def update_crack(self, job_id: int, **fields: Any) -> None:
        if not fields:
            return
        allowed = {"method", "wordlist", "status", "key", "started_at", "finished_at", "progress", "log"}
        items = {k: v for k, v in fields.items() if k in allowed}
        if not items:
            return
        assignments = ", ".join(f"{k}=?" for k in items)
        self._execute(
            f"UPDATE cracks SET {assignments} WHERE id=?",
            (*items.values(), job_id),
        )

    def list_cracks(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._query("SELECT * FROM cracks ORDER BY id DESC LIMIT ?", (limit,))

    def get_crack(self, job_id: int) -> dict[str, Any] | None:
        return self._query_one("SELECT * FROM cracks WHERE id=?", (job_id,))

    def list_cracks_for_session(self, session_id: int, limit: int = 100) -> list[dict[str, Any]]:
        return self._query(
            "SELECT c.* FROM cracks c JOIN captures cap ON c.capture_id=cap.id"
            " WHERE cap.session_id=? ORDER BY c.id DESC LIMIT ?",
            (session_id, limit),
        )

    # ------------------------------------------------------------------ 凭证
    def add_credential(self, cred: Credential) -> int:
        cur = self._execute(
            "INSERT INTO credentials(session_id, username, password, portal, ip,"
            " user_agent, created_at) VALUES(?,?,?,?,?,?,?)",
            (
                cred.session_id,
                cred.username,
                cred.password,
                cred.portal,
                cred.ip,
                cred.user_agent,
                cred.created_at,
            ),
        )
        return int(cur.lastrowid)

    def list_credentials(self, session_id: int) -> list[dict[str, Any]]:
        return self._query(
            "SELECT * FROM credentials WHERE session_id=? ORDER BY id DESC", (session_id,)
        )

    # ------------------------------------------------------------------ 发现
    def add_finding(self, finding: Finding) -> int:
        cur = self._execute(
            "INSERT INTO findings(session_id, title, severity, bssid, ssid, detail,"
            " category, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                finding.session_id,
                finding.title,
                finding.severity,
                finding.bssid,
                finding.ssid,
                finding.detail,
                finding.category,
                finding.created_at,
            ),
        )
        return int(cur.lastrowid)

    def list_findings(self, session_id: int) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM findings WHERE session_id=? ORDER BY id DESC", (session_id,)
        )
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda r: order.get(r.get("severity", "info"), 5))
        return rows

    # ------------------------------------------------------------------ 事件
    def add_event(self, session_id: int, event: Event) -> None:
        if event.level == "debug":
            return
        self._execute(
            "INSERT INTO events(session_id, ts, level, source, message, data)"
            " VALUES(?,?,?,?,?,?)",
            (
                session_id,
                event.ts,
                event.level,
                event.source,
                event.message,
                json.dumps(event.data, ensure_ascii=False, default=str),
            ),
        )

    def list_events(self, session_id: int, limit: int = 300) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM events WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        )
        rows.reverse()
        for row in rows:
            try:
                row["data"] = json.loads(row.get("data") or "{}")
            except json.JSONDecodeError:
                row["data"] = {}
        return rows

    def prune_events(self, session_id: int, keep: int = 5000) -> None:
        self._execute(
            "DELETE FROM events WHERE session_id=? AND id NOT IN"
            " (SELECT id FROM events WHERE session_id=? ORDER BY id DESC LIMIT ?)",
            (session_id, session_id, keep),
        )

    # ------------------------------------------------------------------ 统计
    def stats(self, session_id: int) -> dict[str, Any]:
        def count(table: str, extra: str = "") -> int:
            row = self._query_one(
                f"SELECT COUNT(*) AS n FROM {table} WHERE session_id=?{extra}",
                (session_id,),
            )
            return int(row["n"]) if row else 0

        cracked = self._query_one(
            "SELECT COUNT(*) AS n FROM cracks c JOIN captures cap ON c.capture_id=cap.id"
            " WHERE cap.session_id=? AND c.status='found'",
            (session_id,),
        )
        return {
            "aps": count("aps"),
            "clients": count("clients"),
            "captures": count("captures"),
            "findings": count("findings"),
            "credentials": count("credentials"),
            "cracked": int(cracked["n"]) if cracked else 0,
        }

    def session_export(self, session_id: int) -> dict[str, Any]:
        session = self.get_session(session_id) or {}
        return {
            "session": session,
            "aps": self.list_aps(session_id),
            "clients": self.list_clients(session_id),
            "captures": self.list_captures(session_id),
            "findings": self.list_findings(session_id),
            "credentials": self.list_credentials(session_id),
            "cracks": self.list_cracks(1000),
            "events": self.list_events(session_id, 2000),
        }
