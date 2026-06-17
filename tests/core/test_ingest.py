import json

from pipt.core import db, ingest, workspace


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def test_ingest_hosts_links_provenance(tmp_path):
    conn = _fresh(tmp_path)
    db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    db.upsert_target(conn, tid="t_bbb222", raw="nmap.org", kind="domain")
    conn.commit()
    ingest.ingest_hosts(
        conn,
        [{"name": "shared.example", "ip": "10.0.0.9", "source": "stub",
          "targets": ["t_aaa111", "t_bbb222"]}],
    )
    assert conn.execute("SELECT COUNT(*) FROM host").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM host_target").fetchone()[0] == 2


def test_ingest_manifest_dispatches_by_role(tmp_path):
    conn = _fresh(tmp_path)
    art = tmp_path / "services.jsonl"
    art.write_text(json.dumps({"ip": "10.0.0.1", "port": 443, "service": "https"}) + "\n")
    m = tmp_path / "manifest.jsonl"
    workspace.record(m, role="services", path=art, tool="enum")
    ingest.ingest_manifest(conn, m, ingest.CORE_HANDLERS)
    rows = db.list_services(conn)
    assert len(rows) == 1
    assert rows[0]["service"] == "https"


def test_ingest_manifest_ignores_unknown_roles(tmp_path):
    conn = _fresh(tmp_path)
    art = tmp_path / "weird.jsonl"
    art.write_text("{}\n")
    m = tmp_path / "manifest.jsonl"
    workspace.record(m, role="not_a_known_role", path=art, tool="x")
    ingest.ingest_manifest(conn, m, ingest.CORE_HANDLERS)  # must not raise
    assert db.list_services(conn) == []
