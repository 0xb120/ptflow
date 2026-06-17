# tests/core/test_agent.py
from pipt.core import agent, db, ingest
from pipt.core.paths import Engagement


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def _eng(tmp_path):
    return Engagement.for_scan("demo", root=tmp_path).ensure()


def test_stub_proposes_one_per_service(tmp_path):
    conn = _fresh(tmp_path)
    eng = _eng(tmp_path)
    db.upsert_service(conn, ip="10.0.0.1", port=22, service="ssh")
    db.upsert_service(conn, ip="10.0.0.1", port=443, service="https")
    conn.commit()

    n = agent.propose_hypotheses(conn, eng)
    assert n == 2

    # Verify the raw artifact was written with 2 lines
    artifact = eng.surface_canonical("hypotheses.jsonl")
    assert artifact.exists()
    records = ingest.read_jsonl(artifact)
    assert len(records) == 2
    assert all(r["source"] == "stub" for r in records)
    assert all(r.get("service_key") is not None for r in records)

    # Prove projection: ingest the raw artifact into DB and check hypothesis rows
    ingest.ingest_hypotheses(conn, records)
    rows = db.list_hypotheses(conn)
    assert len(rows) == 2
    assert all(r["source"] == "stub" for r in rows)
    assert all(r["service_id"] is not None for r in rows)


def test_custom_provider_used(tmp_path):
    conn = _fresh(tmp_path)
    eng = _eng(tmp_path)
    db.upsert_service(conn, ip="10.0.0.1", port=80)
    conn.commit()

    class P:
        name = "custom"

        def propose(self, hosts, services):  # noqa: ARG002
            return [agent.HypothesisDraft(title="x", confidence="high")]

    n = agent.propose_hypotheses(conn, eng, P())
    assert n == 1

    artifact = eng.surface_canonical("hypotheses.jsonl")
    assert artifact.exists()
    records = ingest.read_jsonl(artifact)
    assert len(records) == 1
    assert records[0]["source"] == "custom"

    # Prove projection propagates source to DB
    ingest.ingest_hypotheses(conn, records)
    rows = db.list_hypotheses(conn)
    assert rows[0]["source"] == "custom"
