from ptflow.core.paths import Activity, AppWorkspace


def test_activity_layout(tmp_path):
    act = Activity.named("acme", root=tmp_path)
    assert act.base == tmp_path / "acme"
    assert act.scope == tmp_path / "acme" / "scope.txt"
    assert act.scope_dns == tmp_path / "acme" / "scope" / "scope_dns.txt"
    assert act.scope_urls == tmp_path / "acme" / "scope" / "scope_urls.txt"
    assert (
        act.asset_discovery_canonical("hosts.jsonl")
        == tmp_path / "acme" / "asset_discovery" / "hosts.jsonl"  # top-level, not under scans/
    )
    assert (
        act.asset_discovery_raw("discover")
        == tmp_path / "acme" / "asset_discovery" / "raw" / "discover"
    )
    assert act.findings == tmp_path / "acme" / "findings"


def test_app_workspace_paths(tmp_path):
    act = Activity.named("acme", root=tmp_path)
    ws = act.app("abc123def456")
    assert isinstance(ws, AppWorkspace)
    assert ws.hosts == act.scans / "abc123def456" / "hosts.txt"
    assert ws.canonical("services.jsonl") == act.scans / "abc123def456" / "services.jsonl"
    assert ws.raw("enum") == act.scans / "abc123def456" / "raw" / "enum"
    assert ws.meta == act.scans / "abc123def456" / "meta.json"


def test_state_paths(tmp_path):
    act = Activity.named("acme", root=tmp_path)
    assert act.state == tmp_path / "acme" / ".state"                 # activity/spanning markers (top-level)
    assert act.app("app1").state == act.scans / "app1" / ".state"    # per-app markers (inside the app dir)


def test_ensure_creates_standard_dirs(tmp_path):
    act = Activity.named("acme", root=tmp_path).ensure()
    for d in (act.scope_dir, act.asset_discovery, act.findings, act.poc, act.tmp, act.wl_global, act.logs):
        assert d.is_dir()


def test_list_apps_returns_only_app_groups(tmp_path):
    act = Activity.named("acme", root=tmp_path).ensure()  # asset_discovery is now top-level, not in scans/
    act.app("app_aaa").ensure()
    act.app("app_bbb").ensure()
    names = sorted(ws.root.name for ws in act.list_apps())
    assert names == ["app_aaa", "app_bbb"]                      # scans/ holds only app groups
    assert act.asset_discovery == act.base / "asset_discovery"  # breadth dir is top-level...
    assert not (act.scans / "asset_discovery").exists()         # ...NOT under scans/
