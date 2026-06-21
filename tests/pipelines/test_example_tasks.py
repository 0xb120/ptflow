from pipt.core import tools, workspace
from pipt.core.paths import Activity
from pipt.pipelines.example import tasks


def _activity_with_scope(tmp_path):
    act = Activity.named("demo", root=tmp_path).ensure()
    act.scope_init.write_text("https://example.com/\nnmap.org\n", encoding="utf-8")
    return act


def test_discover_writes_scope_split_and_hosts(tmp_path):
    act = _activity_with_scope(tmp_path)
    tasks.discover(act)
    assert tools.read_lines(act.scope_urls) == ["https://example.com/"]
    assert tools.read_lines(act.scope_dns) == ["nmap.org"]
    assert tools.read_lines(act.scope_ip) == []
    hosts = tools.read_jsonl(act.asset_discovery_canonical("hosts.jsonl"))
    assert {h["name"] for h in hosts} == {"example.com", "www.example.com", "nmap.org", "www.nmap.org"}
    assert (act.asset_discovery_raw("discover") / "out.jsonl").exists()


def test_cluster_groups_apex_and_www(tmp_path):
    act = _activity_with_scope(tmp_path)
    tasks.discover(act)
    app_ids = tasks.cluster(act)
    assert len(app_ids) == 2
    for app_id in app_ids:
        ws = act.app(app_id)
        meta = workspace.read_meta(ws.meta)
        assert meta["signature"].startswith("app:")
        assert len(tools.read_lines(ws.hosts)) == 2  # apex + www


def test_enum_reads_hosts_writes_services(tmp_path):
    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app_x").ensure()
    tools.write_lines(ws.hosts, ["example.com", "www.example.com"])
    tasks.enum(act, "app_x")
    services = tools.read_jsonl(ws.canonical("services.jsonl"))
    assert len(services) == 2
    assert all(s["port"] == 443 for s in services)
    assert (ws.raw("enum") / "out.jsonl").exists()


def test_pipeline_object_shape():
    from pipt.pipelines.example.pipeline import PIPELINE

    assert PIPELINE.name == "example"
    assert [s.name for s in PIPELINE.stages] == ["discover", "enum"]
