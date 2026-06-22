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
    from pipt.pipelines.recon.pipeline import PIPELINE

    assert PIPELINE.name == "recon"
    activity = [s.name for s in PIPELINE.stages if not s.per_app]
    app = [s.name for s in PIPELINE.stages if s.per_app]
    assert activity == ["expand", "resolve", "portscan", "httpx", "nerva"]
    assert app == [
        "passive_probe", "crawl", "subenum", "takeover",
        "wordlist", "fetch_delta", "tech_enum", "content_discovery",
    ]
    by_name = {s.name: s for s in PIPELINE.stages}
    # httpx ∥ nerva (both depend only on portscan, not on each other)
    assert by_name["httpx"].needs == ("portscan",)
    assert by_name["nerva"].needs == ("portscan",)
    # subenum ∥ passive_probe/crawl; takeover waits for both crawl and subenum
    assert by_name["subenum"].needs == ()
    assert set(by_name["takeover"].needs) == {"crawl", "subenum"}
    # loop 1 = enumeration; loop 2 = content discovery (separate per-app loop)
    assert {by_name[n].phase for n in ("passive_probe", "crawl", "subenum", "takeover")} == {1}
    # loop 2 stages cross the loop-1 barrier (no cross-loop `needs`)
    assert {by_name[n].phase for n in ("wordlist", "fetch_delta", "tech_enum", "content_discovery")} == {2}
    assert by_name["wordlist"].needs == ()
    assert by_name["fetch_delta"].needs == ()
    # within loop 2: tech_enum→seed; content_discovery waits for seed + tech_enum surface; fetch_delta ∥
    assert by_name["tech_enum"].needs == ("wordlist",)
    assert set(by_name["content_discovery"].needs) == {"wordlist", "tech_enum"}


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


def test_tokenize_urls_mines_segments_keys_and_basenames():
    corpus = [
        "https://app.example.com/admin/login.php?user=1&redirect=/home",
        "/api/v1/users",                       # bare path (jsluice-style)
        "app.example.com/wp-content/themes",   # scheme-less host/path
        "https://app.example.com/",            # no path → no tokens
        "https://app.example.com/files/12345", # pure-numeric id dropped
        "",                                    # skipped
    ]
    words = tasks.tokenize_urls(corpus)
    assert {"admin", "api", "v1", "users", "wp-content", "themes"} <= set(words)
    assert {"login.php", "login"} <= set(words)   # filename + basename
    assert {"user", "redirect"} <= set(words)     # query-param keys
    assert "12345" not in words                    # numeric id dropped
    assert "home" not in words                     # param value, not a key
    assert words == sorted(set(words))             # sorted + deduped


def test_select_tech_wordlists_matches_existing_files(tmp_path):
    (tmp_path / "cms").mkdir()
    (tmp_path / "cms" / "wordpress.txt").write_text("wp-admin\nwp-login.php\n")
    mapping = {"wordpress": "cms/wordpress.txt", "drupal": "cms/drupal.txt"}
    # case-insensitive substring match on httpx-style tags; mapped-but-missing file skipped
    assert tasks.select_tech_wordlists(["WordPress 6.4", "Nginx"], mapping, tmp_path) == [
        tmp_path / "cms" / "wordpress.txt"
    ]
    # no matching tech, or an absent base dir → no-op (step runs without external data)
    assert tasks.select_tech_wordlists(["Apache"], mapping, tmp_path) == []
    assert tasks.select_tech_wordlists(["WordPress"], mapping, tmp_path / "nope") == []


def test_passive_delta_excludes_crawled_and_static():
    passive = [
        "https://x/api/users",   # keep — not crawled, not static
        "https://x/old/page",    # keep
        "https://x/logo.png",    # drop — static asset
        "https://x/already",     # drop — already fetched by the crawl
        "https://x/api/users",   # dup → collapsed
    ]
    crawled = ["https://x/already", "https://x/home"]
    assert tasks.passive_delta(passive, crawled) == ["https://x/api/users", "https://x/old/page"]


def test_tech_extensions_from_detected_tech():
    mapping = {"php": ["php"], "asp.net": ["asp", "aspx"], "java": ["jsp"]}
    assert tasks.tech_extensions(["PHP", "Nginx"], mapping) == ["php"]   # case-insensitive
    assert tasks.tech_extensions(["ASP.NET 4.8"], mapping) == ["asp", "aspx"]  # substring match
    assert tasks.tech_extensions(["Go"], mapping) == []                  # no match


def test_parse_ferox_keeps_response_records():
    out = (
        '{"type":"response","url":"https://x/admin","status":200,"content_length":12,"word_count":3,"line_count":1}\n'
        '{"type":"response","url":"https://x/old","status":301,"content_length":0,"word_count":0,"line_count":0}\n'
        '{"type":"statistics","total":2}\n'   # dropped — not a response
        "not json\n"                          # dropped — unparseable
        "\n"
    )
    assert tasks.parse_ferox(out) == [
        {"url": "https://x/admin", "status": 200, "length": 12, "words": 3, "lines": 1},
        {"url": "https://x/old", "status": 301, "length": 0, "words": 0, "lines": 0},
    ]


def test_parse_shortscan_harvests_surface_words():
    out = (
        '{"type":"status","url":"https://x/","server":"Microsoft-IIS/10.0","vulnerable":true}\n'
        '{"type":"result","fullmatch":true,"baseurl":"https://x/","shortfile":"ADMINI",'
        '"shortext":".ASP","shorttilde":"~1","partname":"ADMINI?.ASP?","fullname":"administrator.aspx"}\n'
        '{"type":"result","fullmatch":false,"baseurl":"https://x/","shortfile":"BACKUP",'
        '"shortext":".ZIP","shorttilde":"~1","partname":"BACKUP?.ZIP?","fullname":""}\n'
        '{"type":"statistics","requests":100}\n'
        "garbage\n"
    )
    words = tasks.parse_shortscan(out)
    assert {"administrator.aspx", "administrator", "admini", "backup"} <= set(words)  # resolved + 8.3
    assert len(words) == len(set(words))  # deduped, lowercased


def test_build_wordlist_offline(tmp_path):
    """wordlist is pure offline: it tokenizes loop-1's endpoints.txt, never fetches."""
    from pipt.core import tools, workspace
    from pipt.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app1").ensure()
    workspace.write_meta(ws.meta, {"app_id": "app1", "tech": []})
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://app1/admin/index.php?id=2"])

    tasks.build_wordlist(act, "app1")
    words = tools.read_lines(ws.wl / "seed.txt")
    assert {"admin", "index.php", "index", "id"} <= set(words)


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
