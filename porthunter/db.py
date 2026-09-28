"""Almacenamiento persistente en SQLite."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname       TEXT,
    netbios        TEXT,
    mac            TEXT,
    vendor         TEXT,
    alias          TEXT,
    notes          TEXT,
    watched        INTEGER NOT NULL DEFAULT 0,
    current_ip     TEXT,
    status         TEXT NOT NULL DEFAULT 'unknown',
    distance       INTEGER,
    ttl            INTEGER,
    os_guess       TEXT,
    trace_json     TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    last_up        TEXT,
    last_port_scan TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_devices_netbios ON devices(netbios COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(current_ip);

CREATE TABLE IF NOT EXISTS ip_history (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    last_up    TEXT,
    source     TEXT,
    PRIMARY KEY (device_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_ip_history_ip ON ip_history(ip);

CREATE TABLE IF NOT EXISTS ports (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    proto      TEXT NOT NULL,
    port       INTEGER NOT NULL,
    state      TEXT NOT NULL,
    service    TEXT,
    product    TEXT,
    version    TEXT,
    extrainfo  TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (device_id, proto, port)
);

CREATE TABLE IF NOT EXISTS jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    label        TEXT,
    targets      TEXT NOT NULL,
    options_json TEXT NOT NULL DEFAULT '{}',
    commands     TEXT,
    status       TEXT NOT NULL,
    progress     REAL NOT NULL DEFAULT 0,
    phase        TEXT,
    created      TEXT NOT NULL,
    started      TEXT,
    finished     TEXT,
    summary_json TEXT,
    error        TEXT,
    network_id   INTEGER,
    xml_files    TEXT
);

CREATE TABLE IF NOT EXISTS networks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    targets      TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'ping',
    options_json TEXT NOT NULL DEFAULT '{}',
    interval_min INTEGER NOT NULL DEFAULT 0,
    last_run     TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    device_id INTEGER,
    job_id    INTEGER,
    message   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    src          TEXT NOT NULL,
    src_name     TEXT,
    dst          TEXT,
    count        INTEGER NOT NULL DEFAULT 0,
    ports        TEXT,
    hosts        TEXT,
    note         TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    pcap         TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        """Conexión nueva por uso: seguro entre hilos; `with` confirma o deshace."""
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def query(self, sql: str, params=()) -> list[dict]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    def one(self, sql: str, params=()) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def execute(self, sql: str, params=()) -> int:
        with self.connect() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid
