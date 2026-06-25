from pipt.core.scope import Target
from pipt.pipelines.recon import tasks


def test_preflight_runs_and_logs():
    import logging

    from pipt.core.log import get_logger

    lg = get_logger()
    recs: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = recs.append
    lg.addHandler(handler)
    try:
        tasks.preflight()  # best-effort: must never raise regardless of which tools are installed
    finally:
        lg.removeHandler(handler)
    assert any("preflight" in r.getMessage() for r in recs)  # always logs the tool-inventory summary


def test_web_ports_constant_is_250_distinct_valid():
    ports = [int(p) for p in tasks.WEB_PORTS.split(",")]
    assert len(ports) == 250                       # exactly 250 (the curated web set fed to naabu -p)
    assert len(set(ports)) == 250                  # no duplicates
    assert all(1 <= p <= 65535 for p in ports)     # valid TCP ports
    assert {80, 443, 8080, 8443}.issubset(ports)   # the essentials are present


def test_select_web_ports_keeps_valid_ip_lines():
    naabu = ["1.2.3.4:80", "1.2.3.4:8080", "9.9.9.9:443", "5.5.5.5:22"]
    # only ip:port lines whose IP is in the valid (non-honeypot) set survive → httpx web input
    assert tasks.select_web_ports(naabu, ["1.2.3.4", "5.5.5.5"]) == ["1.2.3.4:80", "1.2.3.4:8080", "5.5.5.5:22"]
    assert tasks.select_web_ports([], ["1.2.3.4"]) == []
    assert tasks.select_web_ports(["bad-line", "1.2.3.4:80"], ["1.2.3.4"]) == ["1.2.3.4:80"]


def test_split_cdn_ip_records_drops_only_bare_ip_cdn():
    records = [
        {"url": "https://ginandjuice.shop", "host": "ginandjuice.shop", "cdn_name": "aws"},  # CDN-fronted hostname → keep
        {"url": "https://34.249.203.140:443", "host": "34.249.203.140", "cdn_name": "aws"},  # bare IP + cdn → drop
        {"url": "http://142.250.154.153", "host": "142.250.154.153", "cdn": True},           # bare IP + cdn(bool) → drop
        {"url": "http://45.33.32.156", "host": "45.33.32.156"},                              # bare IP, not cdn → keep
        {"url": "http://10.0.0.5", "host": "10.0.0.5", "cdn_name": "aws"},                   # bare IP + cdn but in scope → keep
    ]
    kept, dropped = tasks.split_cdn_ip_records(records, {"10.0.0.5"})
    assert {r["host"] for r in dropped} == {"34.249.203.140", "142.250.154.153"}
    assert {r["host"] for r in kept} == {"ginandjuice.shop", "45.33.32.156", "10.0.0.5"}


def test_split_cdn_ip_records_falls_back_to_url_host():
    records = [{"url": "https://8.8.8.8:443", "cdn_name": "google"}]  # no "host" field → derive from url
    kept, dropped = tasks.split_cdn_ip_records(records, set())
    assert kept == []
    assert [r["url"] for r in dropped] == ["https://8.8.8.8:443"]


def test_split_cdn_ip_records_empty():
    assert tasks.split_cdn_ip_records([], set()) == ([], [])


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
    activity = [s.name for s in PIPELINE.stages
                if not s.per_app and not s.spanning and not s.cluster_scope]
    spanning = [s.name for s in PIPELINE.stages if s.spanning]
    cluster_scope = [s.name for s in PIPELINE.stages if s.cluster_scope]
    app = [s.name for s in PIPELINE.stages if s.per_app]
    # full-port scan + nerva are now SPANNING (off the breadth critical path); httpx needs only
    # the fast top-1k web set, so the breadth chain stops at httpx.
    assert activity == ["provision_wl", "expand", "resolve", "portscan", "httpx"]
    assert spanning == ["portscan_full", "nerva", "nuclei_scope"]
    assert cluster_scope == ["screenshot"]  # batched screenshot, post-cluster ∥ the loops
    assert app == [
        "passive_probe", "crawl", "crawl_headless", "subenum", "takeover",
        "wordlist", "fetch_delta", "mine_responses", "tech_enum", "content_discovery",
        "param_fuzz",
    ]
    by_name = {s.name: s for s in PIPELINE.stages}
    # httpx is the breadth tail; the expensive full scan runs ∥ as a spanning chain → nerva
    assert by_name["httpx"].needs == ("portscan",)
    assert by_name["portscan_full"].spanning is True
    assert by_name["portscan_full"].needs == ("portscan",)
    assert by_name["nerva"].spanning is True
    assert by_name["nerva"].needs == ("portscan_full",)
    # whole-scope nuclei is spanning: starts after httpx, runs ∥ cluster + per-app, joins at fan-in
    assert by_name["nuclei_scope"].spanning is True
    assert by_name["nuclei_scope"].needs == ("httpx",)
    # subenum ∥ passive_probe/crawl; takeover waits for both crawl and subenum
    assert by_name["subenum"].needs == ()
    assert set(by_name["takeover"].needs) == {"crawl", "subenum"}
    # gated headless crawl is a loop-1 step that needs the cheap crawl (for the classification)
    assert by_name["crawl_headless"].needs == ("crawl",)
    # screenshot is a post-cluster spanning step (cluster_scope), NOT a per-app loop-1 step
    assert by_name["screenshot"].cluster_scope is True
    assert by_name["screenshot"].per_app is False
    # loop 1 = enumeration; loop 2 = content discovery (separate per-app loop)
    assert {by_name[n].phase
            for n in ("passive_probe", "crawl", "crawl_headless", "subenum", "takeover")} == {1}
    # loop 2 stages cross the loop-1 barrier (no cross-loop `needs`)
    loop2 = ("wordlist", "fetch_delta", "mine_responses", "tech_enum", "content_discovery")
    assert {by_name[n].phase for n in loop2} == {2}
    assert by_name["wordlist"].needs == ()
    assert by_name["fetch_delta"].needs == ()
    # within loop 2: tech_enum→seed; mine_responses→endpoints; content_discovery runs the
    # fuzz→download→mine→fuzz fixpoint then the secret fleet (folds seed + tech + mined endpoints)
    assert by_name["tech_enum"].needs == ("wordlist",)
    assert by_name["mine_responses"].needs == ("fetch_delta",)
    assert set(by_name["content_discovery"].needs) == {"wordlist", "tech_enum", "mine_responses"}
    # loop 3 (phase 3) — param discovery, reads loop-2 artifacts across the barrier (no cross-loop needs)
    assert by_name["param_fuzz"].phase == 3
    assert by_name["param_fuzz"].per_app is True
    assert by_name["param_fuzz"].needs == ()


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


def test_parse_shortscan_findings():
    out = (
        '{"type":"status","url":"https://x/","server":"Microsoft-IIS/10.0","vulnerable":true}\n'
        '{"type":"status","url":"https://y/","server":"Microsoft-IIS/7.5","vulnerable":false}\n'  # not vuln
        '{"type":"result","fullname":"administrator.aspx","shortfile":"ADMINI"}\n'                  # surface
        "garbage\n"
    )
    findings = tasks.parse_shortscan_findings(out)
    assert len(findings) == 1                                   # only the vulnerable host
    assert findings[0]["type"] == "iis-tilde-enumeration"
    assert findings[0]["target"] == "https://x/"
    assert findings[0]["server"] == "Microsoft-IIS/10.0"
    assert findings[0]["source"] == "shortscan"
    assert tasks.parse_shortscan_findings("") == []


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


def test_parse_gitleaks():
    out = '[{"RuleID":"generic-api-key","Secret":"sk_live_X","File":"/b/abc.js","StartLine":2}]'
    assert tasks.parse_gitleaks(out) == [
        {"sources": ["gitleaks"], "type": "generic-api-key", "secret": "sk_live_X",
         "file": "abc.js", "line": 2, "verified": False}]
    assert tasks.parse_gitleaks("") == []
    assert tasks.parse_gitleaks("not json") == []


def test_parse_trufflehog():
    nd = ('{"DetectorName":"AWS","Verified":true,"Raw":"AKIA_X","SourceMetadata":'
          '{"Data":{"Filesystem":{"file":"/b/x.html","line":5}}}}\n')
    assert tasks.parse_trufflehog(nd) == [
        {"sources": ["trufflehog"], "type": "AWS", "secret": "AKIA_X",
         "file": "x.html", "line": 5, "verified": True}]
    assert tasks.parse_trufflehog("") == []


def test_parse_detect_secrets():
    out = ('{"results":{"/b/c.js":[{"type":"AWS Access Key","hashed_secret":"deadbeef",'
           '"line_number":1,"is_verified":false}]}}')
    assert tasks.parse_detect_secrets(out) == [
        {"sources": ["detect-secrets"], "type": "AWS Access Key", "secret": None,
         "hash": "deadbeef", "file": "c.js", "line": 1, "verified": False}]


def test_merge_secrets_dedups_across_tools():
    recs = [
        {"sources": ["gitleaks"], "type": "aws", "secret": "AKIA_X", "file": "a.js", "verified": False},
        {"sources": ["trufflehog"], "type": "AWS", "secret": "AKIA_X", "file": "a.js", "verified": True},
        {"sources": ["detect-secrets"], "type": "Base64", "secret": None, "hash": "h1", "file": "a.js"},
    ]
    merged = tasks.merge_secrets(recs)
    aws = [m for m in merged if m.get("secret") == "AKIA_X"]
    assert len(aws) == 1                                  # same secret+file collapses
    assert aws[0]["sources"] == ["gitleaks", "trufflehog"]  # sources unioned
    assert aws[0]["verified"] is True                      # verified OR-ed
    assert len(merged) == 2                                # + the detect-secrets hash lead


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


def test_header_signals():
    h = {
        "x_cache": "HIT", "server": "nginx/1.25", "x_powered_by": "PHP/8.2",
        "set_cookie": "JSESSIONID=abc; Path=/", "cf_ray": "abc-LHR",
        "strict_transport_security": "max-age=63072000", "date": "irrelevant",
    }
    assert tasks.header_signals(h) == sorted([
        "cache", "backend:nginx", "stack:php", "stack:java", "cdn:cloudflare", "hsts",
    ])
    assert tasks.header_signals({}) == []          # no headers → no signals
    assert tasks.header_signals({"date": "x"}) == []  # only volatile → no signals


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


# --- content-discovery fixpoint (loop 2) ---
def test_select_new_urls_keeps_new_2xx_3xx_then_caps():
    recs = [
        {"url": "https://x/a", "status": 200},
        {"url": "https://x/b", "status": 301},   # 3xx kept
        {"url": "https://x/c", "status": 404},   # dropped — not 2xx/3xx
        {"url": "https://x/a", "status": 200},   # dropped — duplicate
        {"url": "https://x/seen", "status": 200},  # dropped — already in the store
        {"status": 200},                          # dropped — no url
    ]
    assert tasks.select_new_urls(recs, {"https://x/seen"}, cap=10) == ["https://x/a", "https://x/b"]
    # cap bites: order preserved, truncated to the first `cap`
    many = [{"url": f"https://x/{i}", "status": 200} for i in range(5)]
    assert tasks.select_new_urls(many, set(), cap=2) == ["https://x/0", "https://x/1"]


def test_merge_ferox_by_url_accumulates_first_wins():
    acc = [{"url": "https://x/a", "status": 200}]
    new = [
        {"url": "https://x/a", "status": 500},   # dup url ⇒ acc's record kept, not overwritten
        {"url": "https://x/b", "status": 200},   # new ⇒ appended
        {"status": 200},                          # no url ⇒ skipped
    ]
    assert tasks.merge_ferox_by_url(acc, new) == [
        {"url": "https://x/a", "status": 200},
        {"url": "https://x/b", "status": 200},
    ]


def test_dur_seconds_parses_units():
    assert tasks._dur_seconds("20m") == 1200
    assert tasks._dur_seconds("300s") == 300
    assert tasks._dur_seconds("1h") == 3600
    assert tasks._dur_seconds("45") == 45  # bare number ⇒ seconds


def test_ferox_time_limit_round0_full_feedback_capped():
    assert tasks._ferox_time_limit(0, 10) == tasks.FEROX_TIME_LIMIT  # round 0 keeps the full cap
    deep = tasks._dur_seconds(tasks.DEEP_FEROX_TIME_LIMIT)
    assert tasks._ferox_time_limit(1, deep + 999) == f"{deep}s"      # budget ample ⇒ deep cap
    assert tasks._ferox_time_limit(1, 30) == "30s"                   # budget tight ⇒ remaining
    assert tasks._ferox_time_limit(1, 0.4) == "1s"                   # floored at 1s


def test_all_store_indices_globs_every_store(tmp_path):
    from pipt.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app1").ensure()
    for rel in ("index.txt", "headless/index.txt", "osint/response/index.txt",
                "discovered/round0/response/index.txt"):
        p = ws.responses / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("body.html https://x/a (200)\n", encoding="utf-8")
    found = tasks._all_store_indices(ws)
    assert len(found) == 4                              # cheap + headless + osint + discovered round
    assert all(p.name == "index.txt" for p in found)
    assert tasks._all_store_indices(act.app("absent")) == []  # no responses/ dir ⇒ []


# --- param fuzzing (loop 3) ---
def test_path_template_collapses_ids():
    assert tasks.path_template("https://x/user/123/edit?a=1") == "https://x/user/*/edit"
    assert tasks.path_template("https://x/p/deadbeefcafe/view") == "https://x/p/*/view"  # long hex
    assert tasks.path_template("https://x/login") == "https://x/login"
    assert tasks.path_template("https://x/") == "https://x/"
    assert tasks.path_template("https://x/u/1") == tasks.path_template("https://x/u/2")  # same shape


def test_select_param_endpoints_scopes_dedups_caps():
    urls = [
        "https://app.x/user/1", "https://app.x/user/2",   # same template ⇒ one
        "https://app.x/login",
        "https://evil.com/p",                              # out of scope ⇒ dropped
        "https://app.x/search?q=1",                        # query stripped
    ]
    assert tasks.select_param_endpoints(urls, {"app.x"}, cap=10) == [
        "https://app.x/user/1", "https://app.x/login", "https://app.x/search",
    ]
    many = [f"https://app.x/p{i}" for i in range(5)]
    assert tasks.select_param_endpoints(many, {"app.x"}, cap=2) == ["https://app.x/p0", "https://app.x/p1"]


def test_parse_arjun_normalizes():
    # arjun -oJ shape: {<url>: {method, headers, params:[names]}}
    text = ('{"https://x/catalog": {"method": "GET", "headers": {}, '
            '"params": ["searchTerm", "category"]}, "https://x/none": {"method": "GET", "params": []}}')
    assert sorted((r["url"], r["param"], r["sources"][0]) for r in tasks.parse_arjun(text)) == [
        ("https://x/catalog", "category", "arjun"), ("https://x/catalog", "searchTerm", "arjun"),
    ]
    assert tasks.parse_arjun("nope") == []


def test_parse_x8_normalizes():
    # x8 -O json shape: [{url, method, found_params:[{name, reason_kind}]}]
    text = ('[{"method":"GET","url":"https://x/catalog","status":200,'
            '"found_params":[{"name":"searchTerm","reason_kind":"Reflected"},'
            '{"name":"category","reason_kind":"Reflected"}]}]')
    assert sorted((r["param"], r["sources"][0], r["reason"]) for r in tasks.parse_x8(text)) == [
        ("category", "x8", "Reflected"), ("searchTerm", "x8", "Reflected"),
    ]
    assert tasks.parse_x8("not json") == []


def test_merge_params_dedups_across_tools():
    recs = [
        {"url": "https://x/c", "param": "id", "method": "GET", "sources": ["arjun"], "reason": None},
        {"url": "https://x/c", "param": "id", "method": "GET", "sources": ["x8"], "reason": "Reflected"},
        {"url": "https://x/c", "param": "q", "method": "GET", "sources": ["x8"], "reason": "NotReflected"},
    ]
    merged = {m["param"]: m for m in tasks.merge_params(recs)}
    assert len(merged) == 2
    assert merged["id"]["sources"] == ["arjun", "x8"]   # union across tools
    assert merged["id"]["reason"] == "Reflected"         # first non-null wins


# --- wordlist strategy (custom vs traditional) ---
def test_resolve_wl_mode():
    assert tasks.resolve_wl_mode("auto", 5, rich_threshold=200) == "broad"       # thin corpus
    assert tasks.resolve_wl_mode("auto", 500, rich_threshold=200) == "targeted"  # rich corpus
    assert tasks.resolve_wl_mode("targeted", 5, rich_threshold=200) == "targeted"  # explicit wins
    assert tasks.resolve_wl_mode("broad", 999, rich_threshold=200) == "broad"


def test_combine_wordlist_custom_first_and_caps():
    custom = ["app1", "app2"]
    traditional = [["g1", "g2", "g3"], ["t1", "t2"]]   # global content + a tech list
    broad = tasks.combine_wordlist(custom, traditional, mode="broad", cap=1)
    assert broad[:2] == ["app1", "app2"]                                  # custom first
    assert set(broad) == {"app1", "app2", "g1", "g2", "g3", "t1", "t2"}   # traditional in full
    # targeted: each traditional list capped to its top-`cap`
    assert tasks.combine_wordlist(custom, traditional, mode="targeted", cap=1) == [
        "app1", "app2", "g1", "t1",
    ]


def test_build_wordlist_seed_excludes_tech_lists(tmp_path):
    """The layer split: build_wordlist writes ONLY app tokens — tech CMS lists are added later by
    content_discovery's combine, never folded into the custom seed."""
    from pipt.core import tools, workspace
    from pipt.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app1").ensure()
    workspace.write_meta(ws.meta, {"app_id": "app1", "tech": ["WordPress"]})
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://app1/wp-login.php"])
    tools.write_lines(act.wl_global / "wordpress.txt", ["__WP_SENTINEL__"])  # a tech list exists

    tasks.build_wordlist(act, "app1")
    seed = set(tools.read_lines(ws.wl_custom / "seed.txt"))
    assert "wp-login.php" in seed           # app token present
    assert "__WP_SENTINEL__" not in seed    # tech list NOT folded into the custom seed


# --- unified screenshot reconciliation ---
def test_reconcile_by_url():
    index = [                                   # (file, url) from the -srd index
        ("a.com/h1.png", "https://a.com/"),     # index has trailing slash, our map doesn't
        ("b.com/h2.png", "http://b.com"),       # index has none, our map does
        ("c.com/h3.png", "https://c.com/"),     # url not in our candidate map → ignored
    ]
    url_to_app = {"https://a.com": "app_a", "http://b.com/": "app_b"}
    assert tasks.reconcile_by_url(index, url_to_app) == {
        "app_a": "a.com/h1.png", "app_b": "b.com/h2.png",
    }
