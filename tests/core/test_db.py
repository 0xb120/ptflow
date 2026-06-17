from pipt.core import db


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def test_pragmas_set(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_upsert_target_is_idempotent(tmp_path):
    conn = _fresh(tmp_path)
    a = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    b = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    assert a == b
    assert conn.execute("SELECT COUNT(*) FROM target").fetchone()[0] == 1


def test_upsert_host_enriches_ip(tmp_path):
    conn = _fresh(tmp_path)
    hid = db.upsert_host(conn, name="a.example.com", source="dns")
    again = db.upsert_host(conn, name="a.example.com", ip="10.0.0.1", source="dns")
    assert hid == again
    row = conn.execute("SELECT ip FROM host WHERE id=?", (hid,)).fetchone()
    assert row["ip"] == "10.0.0.1"


def test_upsert_service_unique_per_ip_port(tmp_path):
    conn = _fresh(tmp_path)
    s1 = db.upsert_service(conn, ip="10.0.0.1", port=443, source="naabu")
    s2 = db.upsert_service(conn, ip="10.0.0.1", port=443, version="1.0", source="fingerprintx")
    assert s1 == s2
    assert conn.execute("SELECT version FROM service WHERE id=?", (s1,)).fetchone()["version"] == "1.0"
    assert conn.execute("SELECT source FROM service WHERE id=?", (s1,)).fetchone()["source"] == "fingerprintx"


def test_link_host_target_and_insert_hypothesis(tmp_path):
    conn = _fresh(tmp_path)
    tid_id = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    hid = db.upsert_host(conn, name="example.com")
    db.link_host_target(conn, hid, tid_id)
    db.link_host_target(conn, hid, tid_id)  # idempotent
    assert conn.execute("SELECT COUNT(*) FROM host_target").fetchone()[0] == 1
    sid = db.upsert_service(conn, ip="10.0.0.1", port=22)
    hyp = db.insert_hypothesis(conn, title="t", service_id=sid, confidence="low", source="stub")
    assert hyp > 0
    assert len(db.list_hypotheses(conn)) == 1
