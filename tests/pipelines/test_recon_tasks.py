from pipt.core.scope import Target
from pipt.pipelines.recon import tasks


def test_split_scope_buckets_by_kind():
    targets = [
        Target(raw="https://app.example.com/x", kind="url", normalized="app.example.com", tid="t1"),
        Target(raw="example.com", kind="domain", normalized="example.com", tid="t2"),
        Target(raw="*.corp.example", kind="wildcard", normalized="corp.example", tid="t3"),
        Target(raw="10.0.0.0/24", kind="cidr", normalized="10.0.0.0/24", tid="t4"),
        Target(raw="1.2.3.4", kind="ip", normalized="1.2.3.4", tid="t5"),
    ]
    urls, dns, wildcards, ips_cidr = tasks.split_scope(targets)
    assert urls == ["https://app.example.com/x"]
    assert dns == ["example.com", "app.example.com"]  # domains + url hosts
    assert wildcards == ["corp.example"]
    assert ips_cidr == ["10.0.0.0/24", "1.2.3.4"]


def test_honeypot_split_by_open_port_count():
    lines = [
        "1.1.1.1:80", "1.1.1.1:443",          # 2 open -> valid
        *[f"2.2.2.2:{p}" for p in range(1000, 1020)],  # 20 open -> honeypot
    ]
    valid, honeypots = tasks.honeypot_split(lines, threshold=15)
    assert valid == ["1.1.1.1"]
    assert honeypots == ["2.2.2.2"]


def test_select_unique_webapps_dedups_by_signature():
    records = [
        {"url": "https://a.example", "title": "Home", "content_length": 100, "webserver": "nginx"},
        {"url": "https://b.example", "title": "Home", "content_length": 100, "webserver": "nginx"},  # dup signature
        {"url": "https://c.example", "title": "Login", "content_length": 50, "webserver": "nginx"},
        {"title": "NoUrl", "content_length": 1, "webserver": "x"},  # missing url -> skipped
    ]
    assert tasks.select_unique_webapps(records) == ["https://a.example", "https://c.example"]


def test_pipeline_object_shape():
    from pipt.core.stage import Mode
    from pipt.pipelines.recon.pipeline import PIPELINE

    assert PIPELINE.name == "recon"
    assert [s.name for s in PIPELINE.stages] == [
        "expand", "resolve", "portscan", "fingerprint",  # breadth
        "passive_probe", "crawl", "subenum", "takeover",  # depth (per app)
    ]
    breadth = [s.name for s in PIPELINE.stages if s.mode is Mode.BREADTH]
    depth = [s.name for s in PIPELINE.stages if s.mode is Mode.DEPTH]
    assert breadth == ["expand", "resolve", "portscan", "fingerprint"]
    assert depth == ["passive_probe", "crawl", "subenum", "takeover"]


def test_depth_pure_helpers():
    assert tasks.url_host("https://www.example.com:443/login?x=1") == "www.example.com"
    assert tasks.url_host("http://45.33.32.156:80/") == "45.33.32.156"
    assert tasks.is_ip("45.33.32.156") is True
    assert tasks.is_ip("scanme.nmap.org") is False
    assert tasks.apex("scanme.nmap.org") == "nmap.org"
    assert tasks.apex("example.com") == "example.com"
    assert tasks.denoise(["https://x/app.js", "https://x/logo.png", "https://x/api"]) == [
        "https://x/app.js",
        "https://x/api",
    ]


def test_expand_splits_scope_offline(tmp_path):
    """A domain-only scope invokes no external tools, so expand is testable offline."""
    from pipt.core import tools
    from pipt.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    act.scope_init.write_text("example.com\nnmap.org\n", encoding="utf-8")
    tasks.expand(act)
    assert tools.read_lines(act.scope_urls) == []
    assert tools.read_lines(act.scope_ip) == []
    assert sorted(tools.read_lines(act.scope_dns)) == ["example.com", "nmap.org"]


def test_cluster_groups_by_signature(tmp_path):
    from pipt.core import tools, workspace
    from pipt.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    tools.write_jsonl(
        act.asset_discovery_canonical("httpx_full_metadata.jsonl"),
        [
            {"url": "https://a.example", "title": "Home", "content_length": 100, "webserver": "nginx"},
            {"url": "https://b.example", "title": "Home", "content_length": 100, "webserver": "nginx"},
            {"url": "https://c.example", "title": "Login", "content_length": 50, "webserver": "nginx"},
            {"title": "NoUrl", "content_length": 1, "webserver": "x"},  # no url -> ignored
        ],
    )
    app_ids = tasks.cluster(act)
    assert len(app_ids) == 2  # two distinct signatures

    by_sig = {
        workspace.read_meta(act.app(a).meta)["signature"]: sorted(tools.read_lines(act.app(a).hosts))
        for a in app_ids
    }
    assert by_sig["Home|100|nginx"] == ["https://a.example", "https://b.example"]
    assert by_sig["Login|50|nginx"] == ["https://c.example"]
