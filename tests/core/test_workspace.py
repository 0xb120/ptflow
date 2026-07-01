from ptflow.core import workspace


def test_meta_roundtrip(tmp_path):
    p = tmp_path / "meta.json"
    workspace.write_meta(p, {"app_id": "abc123", "signature": "app:example.com"})
    data = workspace.read_meta(p)
    assert data["app_id"] == "abc123"
    assert data["signature"] == "app:example.com"


def test_write_meta_creates_parent(tmp_path):
    p = tmp_path / "sub" / "meta.json"
    workspace.write_meta(p, {"x": 1})
    assert workspace.read_meta(p) == {"x": 1}
