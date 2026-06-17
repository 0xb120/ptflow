"""Serialized single-writer ingest: raw/manifest artifacts -> SQLite upserts.

Workers never touch the DB. This runs serially at barriers, reads canonical
artifacts by role from a manifest, and upserts. Idempotent — rerunnable from raw.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

from pipt.core import db, workspace

Handler = Callable[[sqlite3.Connection, list[dict]], None]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def ingest_hosts(conn: sqlite3.Connection, records: list[dict]) -> None:
    for r in records:
        hid = db.upsert_host(conn, name=r["name"], ip=r.get("ip"), source=r.get("source"))
        for tid in r.get("targets", []):
            target_pk = db.target_id_by_tid(conn, tid)
            if target_pk is not None:
                db.link_host_target(conn, hid, target_pk)


def ingest_services(conn: sqlite3.Connection, records: list[dict]) -> None:
    for r in records:
        db.upsert_service(
            conn,
            ip=r["ip"],
            port=r["port"],
            protocol=r.get("protocol"),
            service=r.get("service"),
            version=r.get("version"),
            source=r.get("source"),
        )


def ingest_hypotheses(conn: sqlite3.Connection, records: list[dict]) -> None:
    for r in records:
        service_id = None
        key = r.get("service_key")
        if key:
            ip, _, port = key.rpartition(":")
            service_id = db.service_id_by_ip_port(conn, ip, int(port))
        db.insert_hypothesis(
            conn,
            title=r["title"],
            service_id=service_id,
            subject=r.get("subject"),
            rationale=r.get("rationale"),
            technique=r.get("technique"),
            confidence=r.get("confidence"),
            source=r.get("source"),
        )


CORE_HANDLERS: dict[str, Handler] = {
    "hosts": ingest_hosts,
    "services": ingest_services,
    "hypotheses": ingest_hypotheses,
}


def ingest_manifest(
    conn: sqlite3.Connection,
    manifest_path: Path,
    handlers: dict[str, Handler],
) -> None:
    for role, artifact in workspace.roles(manifest_path).items():
        handler = handlers.get(role)
        if handler is None:
            continue
        handler(conn, read_jsonl(artifact))
    conn.commit()
