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
    activity = [s.name for s in PIPELINE.stages if not s.per_app and not s.spanning]
    spanning = [s.name for s in PIPELINE.stages if s.spanning]
    app = [s.name for s in PIPELINE.stages if s.per_app]
    assert activity == ["provision_wl", "expand", "resolve", "portscan", "httpx", "nerva"]
    assert spanning == ["nuclei_scope"]
    assert app == [
        "screenshot", "passive_probe", "crawl", "crawl_headless", "subenum", "takeover",
        "wordlist", "fetch_delta", "mine_responses", "tech_enum", "content_discovery",
    ]
    by_name = {s.name: s for s in PIPELINE.stages}
    # httpx ∥ nerva (both depend only on portscan, not on each other)
    assert by_name["httpx"].needs == ("portscan",)
    assert by_name["nerva"].needs == ("portscan",)
    # whole-scope nuclei is spanning: starts after httpx, runs ∥ cluster + per-app, joins at fan-in
    assert by_name["nuclei_scope"].spanning is True
    assert by_name["nuclei_scope"].needs == ("httpx",)
    # subenum ∥ passive_probe/crawl; takeover waits for both crawl and subenum
    assert by_name["subenum"].needs == ()
    assert set(by_name["takeover"].needs) == {"crawl", "subenum"}
    # gated headless crawl is a loop-1 step that needs the cheap crawl (for the classification)
    assert by_name["crawl_headless"].needs == ("crawl",)
    # loop 1 = enumeration; loop 2 = content discovery (separate per-app loop)
    assert {by_name[n].phase
            for n in ("screenshot", "passive_probe", "crawl", "crawl_headless", "subenum", "takeover")} == {1}
    assert by_name["screenshot"].needs == ()  # first loop-1 step, runs right after cluster
    # loop 2 stages cross the loop-1 barrier (no cross-loop `needs`)
    loop2 = ("wordlist", "fetch_delta", "mine_responses", "tech_enum", "content_discovery")
    assert {by_name[n].phase for n in loop2} == {2}
    assert by_name["wordlist"].needs == ()
    assert by_name["fetch_delta"].needs == ()
    # within loop 2: tech_enum→seed; mine_responses→osint bodies; content_discovery folds both in
    assert by_name["tech_enum"].needs == ("wordlist",)
    assert by_name["mine_responses"].needs == ("fetch_delta",)
    assert set(by_name["content_discovery"].needs) == {"wordlist", "tech_enum", "mine_responses"}


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


def test_parse_eyewitness_csv_keeps_default_cred_leads():
    csv_text = (
        "Protocol,Port,Domain,URL,Resolved,Request Status,Title,Category,Default Creds,Screenshot Path, Source Path\n"
        'https,443,admin.x.com,https://admin.x.com,1.2.3.4,Successful,"Apache Tomcat",Default Cred,"tomcat/tomcat",screens/a.png,source/a.txt\n'
        'https,443,www.x.com,https://www.x.com,1.2.3.5,Successful,"Home","Web Server","None",screens/b.png,source/b.txt\n'
        'https,443,p.x.com,https://p.x.com,1.2.3.6,Successful,"Printer","Web Server",,screens/c.png,source/c.txt\n'
    )
    # only the row with a real "Default Creds" match survives ("None"/empty dropped)
    assert tasks.parse_eyewitness_csv(csv_text) == [
        {"url": "https://admin.x.com", "title": "Apache Tomcat", "category": "Default Cred", "creds": "tomcat/tomcat"},
    ]


def test_eyewitness_cmd_resolves_env_then_path(monkeypatch, tmp_path):
    # explicit env override wins
    monkeypatch.setenv("PIPT_EYEWITNESS", "python3 /opt/EyeWitness/Python/EyeWitness.py")
    assert tasks._eyewitness_cmd() == ["python3", "/opt/EyeWitness/Python/EyeWitness.py"]
    # nothing resolvable (no env, no PATH eyewitness, no install dir) ⇒ None ⇒ step skips cleanly
    monkeypatch.delenv("PIPT_EYEWITNESS", raising=False)
    monkeypatch.setattr(tasks.shutil, "which", lambda _: None)
    monkeypatch.setattr(tasks, "_EYEWITNESS_DIR", tmp_path / "absent")  # no known-location install
    assert tasks._eyewitness_cmd() is None


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
    words = tools.read_lines(ws.wl_custom / "seed.txt")
    assert {"admin", "index.php", "index", "id"} <= set(words)


def test_parse_katana_extracts_request_endpoints():
    out = (
        '{"timestamp":"t","request":{"method":"GET","endpoint":"https://x/"},"response":{"status_code":200}}\n'
        '{"timestamp":"t","request":{"method":"GET","endpoint":"https://x/app.js","tag":"script"}}\n'
        '{"request":{"method":"POST"}}\n'   # dropped — no endpoint
        "not json\n"                        # dropped — unparseable
        "\n"
    )
    assert tasks.parse_katana(out) == ["https://x/", "https://x/app.js"]


def test_count_hrefs_counts_only_anchors():
    html = '<a href="/a">x</a> <A HREF="/b">y</A> <link href="x.css"> <a class="z" href="/c">'
    assert tasks.count_hrefs(html) == 3   # the three <a href>, not <link href>
    assert tasks.count_hrefs("<html><body>no links</body></html>") == 0


def test_has_thin_shell_marker():
    assert tasks.has_thin_shell_marker('<script id="__NEXT_DATA__" type="application/json">')
    assert tasks.has_thin_shell_marker('<script src="/_nuxt/entry.abc.js"></script>')
    assert tasks.has_thin_shell_marker('<app-root ng-version="17.0.0"></app-root>')
    assert not tasks.has_thin_shell_marker("<html><body><h1>classic site</h1></body></html>")


def test_is_js_rendered_matches_benchmark_cases():
    # JS-rendered (headless wins big): small non-headless link surface, fx dwarfs it
    assert tasks.is_js_rendered(raw_href=8, fx=106, crawley=27, marker=False)   # telepass Next.js SSR
    assert tasks.is_js_rendered(raw_href=5, fx=124, crawley=6, marker=False)    # octofence Nuxt thin-shell
    # traditional / finto-SPA (headless = pure cost): a healthy link surface short-circuits
    assert not tasks.is_js_rendered(raw_href=6, fx=29, crawley=114, marker=False)    # academy (the trap)
    assert not tasks.is_js_rendered(raw_href=50, fx=263, crawley=110, marker=False)  # testfire classic
    # a thin-shell marker forces headless even with tiny counts
    assert tasks.is_js_rendered(raw_href=2, fx=0, crawley=1, marker=True)
    # ...but a healthy link surface wins over the marker (don't pay for a browser)
    assert not tasks.is_js_rendered(raw_href=0, fx=0, crawley=200, marker=True)


def test_is_js_url():
    assert tasks.is_js_url("https://x/a/app.min.js")
    assert tasks.is_js_url("https://x/app.js?v=2")
    assert not tasks.is_js_url("https://x/app.css")
    assert not tasks.is_js_url("https://x/")


def test_http_body_extracts_response_body():
    stored = (
        "https://x/app.js\n\n"
        "GET /app.js HTTP/1.1\nHost: x\n\n\n"
        "HTTP/1.1 200 OK\nContent-Type: application/javascript\n\n\n"
        "var a = 1;\nfetch('/api/v1');\n"
    )
    body = tasks.http_body(stored)
    assert "var a = 1;" in body
    assert "fetch('/api/v1');" in body
    assert "HTTP/1.1 200 OK" not in body  # response headers stripped
    assert "GET /app.js" not in body      # request block stripped
    assert tasks.http_body("no http response here") == ""


def test_best_host_prefers_non_ip_then_https():
    # a non-IP host beats an IP, even when the IP is https
    assert tasks.best_host(["https://1.2.3.4", "http://app.example.com"]) == "http://app.example.com"
    # within non-IP hosts, https beats http
    assert tasks.best_host(["http://app.example.com", "https://app.example.com"]) == "https://app.example.com"
    # all IPs → https preferred, else first
    assert tasks.best_host(["http://1.2.3.4:80", "https://1.2.3.4:443"]) == "https://1.2.3.4:443"
    assert tasks.best_host([]) is None


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
            # same apex + same root fingerprint ⇒ merged (apex-scoped signature edge)
            {"url": "https://a.example.com", "title": "Home", "content_length": 100, "webserver": "nginx"},
            {"url": "https://b.example.com", "title": "Home", "content_length": 100, "webserver": "nginx"},
            {"url": "https://c.example.com", "title": "Login", "content_length": 50, "webserver": "nginx"},
            {"title": "NoUrl", "content_length": 1, "webserver": "x"},  # no url -> ignored
        ],
    )
    app_ids = tasks.cluster(act)
    assert len(app_ids) == 2  # two distinct root fingerprints under the one apex

    by_sig = {
        workspace.read_meta(act.app(a).meta)["signature"]: sorted(tools.read_lines(act.app(a).hosts))
        for a in app_ids
    }
    assert by_sig["Home|100|nginx"] == ["https://a.example.com", "https://b.example.com"]
    assert by_sig["Login|50|nginx"] == ["https://c.example.com"]


def test_dedup_by_body():
    # same backend served as domain + IP (identical body) → one rep (best_host: non-IP wins)
    same = {"http://45.33.32.156": "B1", "http://scanme.nmap.org": "B1"}
    assert tasks.dedup_by_body(["http://45.33.32.156", "http://scanme.nmap.org"], same) \
        == ["http://scanme.nmap.org"]
    # distinct environments (different body) → both kept
    diff = {"https://staging.x.net": "B1", "https://test.x.net": "B2"}
    assert sorted(tasks.dedup_by_body(["https://staging.x.net", "https://test.x.net"], diff)) \
        == ["https://staging.x.net", "https://test.x.net"]
    # unknown body → kept individually (can't prove identity)
    assert tasks.dedup_by_body(["https://a", "https://b"], {}) == ["https://a", "https://b"]


def test_cluster_partition_merges_same_apex_via_favicon():
    # same app on two sibling subdomains, content_length shifted by a token (→ different v1
    # signature) but identical favicon + same apex ⇒ merged (the over-split fix)
    records = [
        {"url": "https://a.x.com", "title": "App", "content_length": 100, "favicon": "999"},
        {"url": "https://b.x.com", "title": "App", "content_length": 137, "favicon": "999"},
    ]
    assert tasks.cluster_partition(records) == [[0, 1]]


def test_cluster_partition_favicon_scoped_to_apex():
    # identical favicon but DIFFERENT apexes ⇒ never merged (no cross-org merge on a fuzzy signal)
    records = [
        {"url": "https://x.com", "title": "App", "content_length": 1, "favicon": "999"},
        {"url": "https://y.org", "title": "App", "content_length": 1, "favicon": "999"},
    ]
    assert tasks.cluster_partition(records) == [[0], [1]]


def test_cluster_partition_ignores_infra_signals():
    # same IP + header-hash + tech (and imagine the same cert) but different apps ⇒ NOT merged:
    # infrastructure is not app identity (precision-first dropped the cert/iht edges)
    infra = {"hash": {"header_sha256": "h1"}, "a": ["1.2.3.4"], "tech": ["nginx"]}
    records = [
        {"url": "https://api.x.com", "title": "Api", "content_length": 1, "favicon": "1", **infra},
        {"url": "https://shop.y.org", "title": "Shop", "content_length": 2, "favicon": "2", **infra},
    ]
    assert tasks.cluster_partition(records) == [[0], [1]]


def test_cluster_partition_merges_via_redirect_final_host():
    # two seeds (e.g. apex + www) that httpx followed (-fr) to the SAME final host ⇒ merged (safe)
    records = [
        {"url": "https://www.x.com/", "title": "A", "content_length": 1},
        {"url": "https://www.x.com/", "title": "B", "content_length": 2},
    ]
    assert tasks.cluster_partition(records) == [[0, 1]]


def test_cluster_partition_demotes_generic_body(monkeypatch):
    # an identical body (e.g. a default error page) across many apexes = generic ⇒ no merge
    monkeypatch.setattr(tasks, "GENERIC_MAX_APEXES", 2)
    body = {"status_code": 200, "hash": {"body_sha256": "same"}}
    records = [
        {"url": "https://x.com", "title": "1", "content_length": 1, **body},
        {"url": "https://y.org", "title": "2", "content_length": 2, **body},
        {"url": "https://z.net", "title": "3", "content_length": 3, **body},
    ]
    assert tasks.cluster_partition(records) == [[0], [1], [2]]
