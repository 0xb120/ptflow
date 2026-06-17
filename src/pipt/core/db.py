"""SQLite layer: WAL connection, schema init, idempotent upserts, read API.

The DB is a rebuildable projection of the raw files — it is NEVER written by
fan-out workers, only by the serialized ingest (see ingest.py).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from pipt.core.config import CONFIG

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CORE_SCHEMA = _PROJECT_ROOT / "db" / "schema.sql"


def core_schema() -> str:
    return _CORE_SCHEMA.read_text(encoding="utf-8")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA busy_timeout = {CONFIG.db.busy_timeout_ms}")
    return conn


def init_schema(conn: sqlite3.Connection, *schema_texts: str) -> None:
    for text in schema_texts:
        if text:
            conn.executescript(text)
    conn.commit()


def upsert_target(conn: sqlite3.Connection, *, tid: str, raw: str, kind: str) -> int:
    conn.execute(
        "INSERT INTO target(tid, raw, kind) VALUES(?,?,?) ON CONFLICT(tid) DO NOTHING",
        (tid, raw, kind),
    )
    return conn.execute("SELECT id FROM target WHERE tid=?", (tid,)).fetchone()[0]


def upsert_host(
    conn: sqlite3.Connection,
    *,
    name: str,
    ip: str | None = None,
    source: str | None = None,
) -> int:
    conn.execute(
        "INSERT INTO host(name, ip, source) VALUES(?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET ip=COALESCE(excluded.ip, host.ip), "
        "last_seen=CURRENT_TIMESTAMP",
        (name, ip, source),
    )
    return conn.execute("SELECT id FROM host WHERE name=?", (name,)).fetchone()[0]


def upsert_service(  # noqa: PLR0913
    conn: sqlite3.Connection,
    *,
    ip: str,
    port: int,
    protocol: str | None = None,
    service: str | None = None,
    version: str | None = None,
    source: str | None = None,
) -> int:
    conn.execute(
        "INSERT INTO service(ip, port, protocol, service, version, source) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(ip, port) DO UPDATE SET "
        "protocol=COALESCE(excluded.protocol, service.protocol), "
        "service=COALESCE(excluded.service, service.service), "
        "version=COALESCE(excluded.version, service.version), "
        "source=COALESCE(excluded.source, service.source)",
        (ip, port, protocol, service, version, source),
    )
    return conn.execute("SELECT id FROM service WHERE ip=? AND port=?", (ip, port)).fetchone()[0]


def link_host_target(conn: sqlite3.Connection, host_id: int, target_id: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO host_target(host_id, target_id) VALUES(?,?)",
        (host_id, target_id),
    )


def insert_hypothesis(  # noqa: PLR0913
    conn: sqlite3.Connection,
    *,
    title: str,
    service_id: int | None = None,
    subject: str | None = None,
    rationale: str | None = None,
    technique: str | None = None,
    confidence: str | None = None,
    source: str | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO hypothesis(service_id, subject, title, rationale, technique, confidence, source) "
        "VALUES(?,?,?,?,?,?,?)",
        (service_id, subject, title, rationale, technique, confidence, source),
    )
    return int(cur.lastrowid or 0)


def list_hosts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM host ORDER BY name").fetchall()


def list_services(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM service ORDER BY ip, port").fetchall()


def list_hypotheses(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM hypothesis ORDER BY id").fetchall()
