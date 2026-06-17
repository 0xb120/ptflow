# tests/core/test_agent.py
from pipt.core import agent, db


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def test_stub_proposes_one_per_service(tmp_path):
    conn = _fresh(tmp_path)
    db.upsert_service(conn, ip="10.0.0.1", port=22, service="ssh")
    db.upsert_service(conn, ip="10.0.0.1", port=443, service="https")
    conn.commit()
    n = agent.propose_hypotheses(conn)
    assert n == 2
    rows = db.list_hypotheses(conn)
    assert len(rows) == 2
    assert all(r["source"] == "stub" for r in rows)
    assert rows[0]["service_id"] is not None


def test_custom_provider_used(tmp_path):
    conn = _fresh(tmp_path)
    db.upsert_service(conn, ip="10.0.0.1", port=80)
    conn.commit()

    class P:
        name = "custom"

        def propose(self, hosts, services):  # noqa: ARG002
            return [agent.HypothesisDraft(title="x", confidence="high")]

    assert agent.propose_hypotheses(conn, P()) == 1
    assert db.list_hypotheses(conn)[0]["source"] == "custom"
