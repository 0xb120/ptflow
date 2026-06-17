# tests/core/test_orchestrator.py
from pipt.core import db, orchestrator
from pipt.core.stage import Mode, Stage


def test_split_stages():
    s1 = Stage(name="a", mode=Mode.BREADTH, run=lambda *_: None)
    s2 = Stage(name="b", mode=Mode.DEPTH, run=lambda *_: None)
    breadth, depth = orchestrator.split_stages([s1, s2])
    assert breadth == [s1]
    assert depth == [s2]


def _seed_shared_host(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    ta = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    tb = db.upsert_target(conn, tid="t_bbb222", raw="nmap.org", kind="domain")
    h_a = db.upsert_host(conn, name="only.example.com")
    h_b = db.upsert_host(conn, name="only.nmap.org")
    h_s = db.upsert_host(conn, name="shared.host")
    db.link_host_target(conn, h_a, ta)
    db.link_host_target(conn, h_b, tb)
    db.link_host_target(conn, h_s, ta)
    db.link_host_target(conn, h_s, tb)
    conn.commit()
    return conn


def test_assign_aggregate_enumerates_shared_once(tmp_path):
    conn = _seed_shared_host(tmp_path)
    assignment = orchestrator.assign_enum_hosts(conn, aggregate=True)
    all_hosts = [h for hosts in assignment.values() for h in hosts]
    assert all_hosts.count("shared.host") == 1


def test_assign_no_aggregate_enumerates_shared_twice(tmp_path):
    conn = _seed_shared_host(tmp_path)
    assignment = orchestrator.assign_enum_hosts(conn, aggregate=False)
    all_hosts = [h for hosts in assignment.values() for h in hosts]
    assert all_hosts.count("shared.host") == 2
