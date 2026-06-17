# tests/core/test_workspace.py
from pipt.core import workspace


def test_record_and_latest(tmp_path):
    m = tmp_path / "manifest.jsonl"
    art = tmp_path / "hosts.jsonl"
    art.write_text("{}\n")
    workspace.record(m, role="hosts", path=art, tool="discover")
    assert workspace.latest(m, "hosts") == art
    assert workspace.latest(m, "missing") is None


def test_latest_returns_most_recent(tmp_path):
    m = tmp_path / "manifest.jsonl"
    (tmp_path / "a.jsonl").write_text("")
    (tmp_path / "b.jsonl").write_text("")
    workspace.record(m, role="hosts", path=tmp_path / "a.jsonl", tool="t1")
    workspace.record(m, role="hosts", path=tmp_path / "b.jsonl", tool="t2")
    assert workspace.latest(m, "hosts") == tmp_path / "b.jsonl"


def test_roles_maps_each_role(tmp_path):
    m = tmp_path / "manifest.jsonl"
    workspace.record(m, role="hosts", path=tmp_path / "h.jsonl", tool="t")
    workspace.record(m, role="services", path=tmp_path / "s.jsonl", tool="t")
    rmap = workspace.roles(m)
    assert set(rmap) == {"hosts", "services"}
    assert rmap["hosts"] == tmp_path / "h.jsonl"


def test_meta_roundtrip(tmp_path):
    p = tmp_path / "meta.json"
    workspace.write_meta(p, {"tid": "t_abc123", "kind": "domain"})
    assert workspace.read_meta(p)["tid"] == "t_abc123"
