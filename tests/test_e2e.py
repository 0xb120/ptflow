# tests/test_e2e.py
from pipt.cli import main
from pipt.core import db
from pipt.core.orchestrator import orchestrate, rebuild_db
from pipt.pipelines import load_pipeline


def _scope(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("example.com\nnmap.org\n")
    return p


def test_orchestrate_end_to_end(tmp_path):
    scope_file = _scope(tmp_path)
    base = orchestrate(
        load_pipeline("example"), "demo", str(scope_file), root=str(tmp_path / "scans"),
    )
    conn = db.connect(base / "db" / "engagement.db")
    assert conn.execute("SELECT COUNT(*) FROM target").fetchone()[0] == 2
    # 2 targets x (apex + www) = 4 hosts
    assert conn.execute("SELECT COUNT(*) FROM host").fetchone()[0] == 4
    assert conn.execute("SELECT COUNT(*) FROM service").fetchone()[0] >= 1
    assert conn.execute("SELECT COUNT(*) FROM hypothesis").fetchone()[0] >= 1
    # extension table exists and is queryable (created by the pipeline's schema.sql)
    assert conn.execute("SELECT COUNT(*) FROM example_note").fetchone()[0] == 0


def test_rebuild_db_matches_run(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "scans")
    base = orchestrate(load_pipeline("example"), "demo", str(scope_file), root=root)
    conn = db.connect(base / "db" / "engagement.db")
    before_service = conn.execute("SELECT COUNT(*) FROM service").fetchone()[0]
    before_hypothesis = conn.execute("SELECT COUNT(*) FROM hypothesis").fetchone()[0]
    conn.close()

    rebuild_db("demo", root=root, pipeline_name="example")
    conn = db.connect(base / "db" / "engagement.db")
    after_service = conn.execute("SELECT COUNT(*) FROM service").fetchone()[0]
    after_hypothesis = conn.execute("SELECT COUNT(*) FROM hypothesis").fetchone()[0]
    assert after_service == before_service
    assert after_hypothesis == before_hypothesis
    assert after_hypothesis >= 1


def test_cli_run_and_ingest(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "scans")
    assert main(["run", "example", "demo", str(scope_file), "--root", root]) == 0
    assert main(["ingest", "demo", "--root", root, "--pipeline", "example"]) == 0
