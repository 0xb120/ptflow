from pipt.core.paths import Engagement, TargetWorkspace


def test_engagement_layout(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path)
    assert eng.base == tmp_path / "demo"
    assert eng.scope == tmp_path / "demo" / "scope.txt"
    assert eng.db == tmp_path / "demo" / "db" / "engagement.db"
    assert eng.surface_canonical("hosts.jsonl") == tmp_path / "demo" / "surface" / "hosts.jsonl"
    assert eng.surface_raw("discover") == tmp_path / "demo" / "surface" / "raw" / "discover"


def test_target_workspace_paths(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path)
    ws = eng.target("t_abc123")
    assert isinstance(ws, TargetWorkspace)
    assert ws.canonical("services.jsonl") == eng.targets / "t_abc123" / "services.jsonl"
    assert ws.raw("enum") == eng.targets / "t_abc123" / "raw" / "enum"
    assert ws.manifest == eng.targets / "t_abc123" / "manifest.jsonl"


def test_ensure_and_list_targets(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path).ensure()
    assert eng.surface.is_dir()
    assert eng.db.parent.is_dir()
    eng.target("t_aaa111").ensure()
    eng.target("t_bbb222").ensure()
    tids = sorted(ws.root.name for ws in eng.list_targets())
    assert tids == ["t_aaa111", "t_bbb222"]
