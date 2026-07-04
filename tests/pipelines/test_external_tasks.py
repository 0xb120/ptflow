import json

from ptflow.core.scope import Target
from ptflow.pipelines.external import tasks


def test_extract_bodies_skips_missing_indexed_file(tmp_path):
    from ptflow.core.paths import AppWorkspace

    ws = AppWorkspace(tmp_path / "app").ensure()
    store = ws.responses
    store.mkdir(parents=True, exist_ok=True)
    good = store / "good.txt"
    good.write_text("http://x/\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>hi</html>\n")
    # one real stored response + one index entry whose file does NOT exist (must be skipped, not crash)
    (store / "index.txt").write_text(
        f"{good} http://x/a.html (200)\n"
        f"{store / 'missing.txt'} http://x/b.html (200)\n",
    )
    bodies, new_js = tasks._extract_bodies(ws)  # must not raise FileNotFoundError on the missing entry
    assert bodies is not None
    assert new_js == []
    assert any(bodies.iterdir())  # the good body was extracted


def test_screenshot_fingerprint_slims_record():
    rec = {
        "url": "https://ginandjuice.shop", "status_code": 200, "title": "Gin & Juice",
        "webserver": "Apache", "tech": ["PHP", "Apache"], "content_length": 10487,
        "host_ip": "34.249.203.140", "favicon": "1165564288",
        "header": {"server": "nginx", "x_powered_by": "PHP/8.1"},
    }
    fp = tasks._screenshot_fingerprint(rec)
    assert fp["status"] == 200
    assert fp["title"] == "Gin & Juice"
    assert fp["webserver"] == "Apache"
    assert fp["tech"] == ["PHP", "Apache"]
    assert fp["ip"] == "34.249.203.140"
    assert "backend:nginx" in fp["header_signals"]  # curated signals derived from the header dict
    assert "stack:php" in fp["header_signals"]


def test_resolve_profile_from_env(monkeypatch):
    monkeypatch.setenv("PTFLOW_PROFILE", "home")
    assert tasks._resolve_profile().name == "home"
    monkeypatch.setenv("PTFLOW_PROFILE", "WIDE")  # case-insensitive
    assert tasks._resolve_profile().name == "wide"
    monkeypatch.setenv("PTFLOW_PROFILE", "nonsense")  # unknown → default wide
    assert tasks._resolve_profile().name == "wide"
    monkeypatch.delenv("PTFLOW_PROFILE", raising=False)
    assert tasks._resolve_profile().name == "wide"  # default


def test_home_profile_is_gentler_than_wide():
    assert int(tasks.HOME.naabu_rate) < int(tasks.WIDE.naabu_rate)  # the key "clogs router" knob
    assert int(tasks.HOME.nuclei_rl) < int(tasks.WIDE.nuclei_rl)
    assert int(tasks.HOME.ferox_threads) <= int(tasks.WIDE.ferox_threads)
    assert int(tasks.HOME.naabu_conc) < int(tasks.WIDE.naabu_conc)


def test_wide_profile_matches_legacy_rates():
    # `wide` must reproduce today's values so the default run is unchanged
    assert (tasks.WIDE.naabu_rate, tasks.WIDE.nuclei_rl, tasks.WIDE.ferox_threads) == ("1000", "150", "5")


def test_slug_is_filesystem_safe():
    assert tasks._slug("Ginandjuice.Shop") == "ginandjuice.shop"  # lowercased, dots kept
    assert tasks._slug("a b/c:d") == "a-b-c-d"                     # non [a-z0-9.-] → '-'
    assert tasks._slug("") == "app"                               # empty fallback
    s = tasks._slug("x/y:z foo")
    assert "/" not in s
    assert ":" not in s
    assert " " not in s


def test_app_id_is_readable_stable_and_unique():
    a = tasks._app_id("favicon", "1165564288@ginandjuice.shop")
    assert a.startswith("ginandjuice.shop-")                       # apex slug for favicon anchor
    assert a == tasks._app_id("favicon", "1165564288@ginandjuice.shop")  # deterministic/stable
    assert tasks._app_id("host", "scanme.nmap.org").startswith("scanme.nmap.org-")  # host slug
    # same slug (shared hosting), different anchors → distinct ids (hash disambiguates)
    c1 = tasks._app_id("favicon", "111@appspot.com")
    c2 = tasks._app_id("favicon", "222@appspot.com")
    assert c1 != c2
    assert c1.startswith("appspot.com-")
    assert c2.startswith("appspot.com-")


def test_preflight_runs_and_logs():
    import logging

    from ptflow.core.log import get_logger

    lg = get_logger()
    prior_level = lg.level
    lg.setLevel(logging.DEBUG)   # capture the INFO summary regardless of setup_logging / installed tools
    recs: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = recs.append
    lg.addHandler(handler)
    try:
        tasks.preflight()  # best-effort: must never raise regardless of which tools are installed
    finally:
        lg.removeHandler(handler)
        lg.setLevel(prior_level)
    assert any("preflight" in r.getMessage() for r in recs)  # always logs the tool-inventory summary


def test_requirements_manifest_covers_tool_dicts_and_datasets():
    reqs = tasks.requirements()
    by_name = {r.name: r for r in reqs}
    # every tool from the which-based dicts is in the manifest with the matching kind (single source
    # of truth — preflight + doctor both render from this)
    for name in tasks._CORE_TOOLS:
        assert by_name[name].kind == "core"
    for name in tasks._OPTIONAL_TOOLS:
        assert by_name[name].kind == "optional"
    # interactsh-client carries the documented >=1.3 version floor
    assert by_name["interactsh-client"].min_version == "1.3"
    # datasets are represented as category=="dataset" (path-existence checks), e.g. the resolvers file
    datasets = {r.name for r in reqs if r.category == "dataset"}
    assert "resolvers" in datasets


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
    from ptflow.pipelines.external.pipeline import PIPELINE

    assert PIPELINE.name == "external"
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
        "fetch_delta", "api_spec", "mine_responses", "request_catalog",
        "dast", "xss", "sqli", "cve_lookup",
        "wordlist", "tech_enum", "content_discovery", "recrawl", "cloud_assets",
        "request_catalog_full", "param_fuzz", "dast_full", "xss_full", "sqli_full",
        "cve_lookup_full", "tech_vulnscan",
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


def test_pipeline_phase_wiring():
    """The 4-phase surface-first/DAST-first per-app model: phase numbers + intra-phase `needs`
    (cross-phase ordering is the barrier, never `needs`)."""
    from ptflow.pipelines.external.pipeline import PIPELINE

    by_name = {s.name: s for s in PIPELINE.stages}
    # PHASE 1 = explorable surface (OSINT + crawl, NO guessing): crawl/headless + delta fetch + offline
    # mine + the SURFACE request catalog (requests.jsonl). fetch_delta needs the full crawl store; the
    # surface catalog needs the records + extracted corpus.
    phase1 = ("passive_probe", "crawl", "crawl_headless", "subenum", "takeover",
              "fetch_delta", "api_spec", "mine_responses", "request_catalog")
    assert {by_name[n].phase for n in phase1} == {1}
    assert by_name["fetch_delta"].needs == ("crawl_headless",)
    assert by_name["api_spec"].needs == ()            # ∥; reads hosts only
    assert by_name["mine_responses"].needs == ("fetch_delta",)
    assert by_name["request_catalog"].net is False    # offline merge → requests.jsonl (surface only)
    assert set(by_name["request_catalog"].needs) == {"crawl_headless", "mine_responses", "api_spec"}
    # PHASE 2 = DAST the explorable surface (low-hanging fruit): reads requests.jsonl across the barrier.
    # cve_lookup runs ∥ dast (same phase, no needs) — OFFLINE CVE correlation (net=False).
    assert by_name["dast"].phase == 2
    assert by_name["dast"].per_app is True
    assert by_name["dast"].needs == ()
    assert by_name["cve_lookup"].phase == 2
    assert by_name["cve_lookup"].per_app is True
    assert by_name["cve_lookup"].net is False
    assert by_name["cve_lookup"].needs == ()
    # PHASE 3 = guessing / surface expansion: wordlist seed → tech_enum → content_discovery fixpoint →
    # recrawl. wordlist reads the PHASE-1 corpus across the barrier (no needs); content_discovery no
    # longer needs mine_responses (cross-barrier now).
    phase3 = ("wordlist", "tech_enum", "content_discovery", "recrawl")
    assert {by_name[n].phase for n in phase3} == {3}
    assert by_name["wordlist"].needs == ()            # reads PHASE-1 raw/extracted + endpoints across barrier
    assert by_name["wordlist"].net is False
    assert by_name["tech_enum"].needs == ("wordlist",)
    assert set(by_name["content_discovery"].needs) == {"wordlist", "tech_enum"}
    assert by_name["recrawl"].needs == ("content_discovery",)
    # PHASE 4 = DAST the guessed surface (detailed): full catalog (requests_full.jsonl) → param_fuzz →
    # dast_full (delta vs the surface catalog + param-injection requests).
    # cve_lookup_full runs ∥ dast_full (same phase, no needs) over the EXPANDED enumeration, OFFLINE.
    phase4 = ("request_catalog_full", "param_fuzz", "dast_full", "cve_lookup_full")
    assert {by_name[n].phase for n in phase4} == {4}
    assert by_name["request_catalog_full"].net is False
    assert by_name["request_catalog_full"].needs == ()   # reads PHASE-1 + PHASE-3 across barriers
    assert by_name["param_fuzz"].needs == ("request_catalog_full",)
    assert set(by_name["dast_full"].needs) == {"request_catalog_full", "param_fuzz"}
    assert by_name["cve_lookup_full"].net is False
    assert by_name["cve_lookup_full"].needs == ()


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


def test_query_param_names_and_values():
    urls = ["https://x/a?role=admin&page=2&utm_source=mail&token=deadbeefdeadbeef&q=login"]
    assert tasks.query_param_names(urls) == ["page", "q", "role", "token", "utm_source"]
    vals = tasks.query_param_values(urls)
    assert {"admin", "login"} <= set(vals)           # real value words kept
    assert "2" not in vals                           # numeric dropped
    assert "deadbeefdeadbeef" not in vals            # opaque hex token dropped
    # utm_source is a tracking key → its value isn't mined (here 'mail' would be), and stays out
    assert "mail" not in vals


def test_jsluice_param_names_uses_verified_camelcase_fields():
    """Guards the jsluice contract: queryParams/bodyParams are the field names build_wordlist reads."""
    recs = [{"url": "/a", "queryParams": ["page", "sort"], "bodyParams": ["csrf"]},
            {"url": "/a", "queryParams": ["page"]},          # duplicate record per url collapses
            {"url": "/b"}]                                    # no params
    assert tasks.jsluice_param_names(recs) == ["csrf", "page", "sort"]


def test_html_field_names_and_app_name():
    html = ('<title>Acme Shop | Login</title>'
            '<form><input name="user" id="uid"><select name="country"></select></form>')
    assert {"user", "uid", "country"} <= set(tasks.html_field_names(html))
    app = tasks.html_app_name(html)
    assert {"acme", "shop"} <= set(app)
    assert "login" not in app                         # boilerplate dropped


def test_json_keys_depth_bounded():
    obj = {"username": "a", "nested": {"apiKey": "x", "items": [{"deep": 1}]}}
    keys = tasks.json_keys(obj)
    assert {"username", "nested", "apiKey", "items", "deep"} <= set(keys)


def test_stack_terms_strips_signal_prefix():
    assert tasks.stack_terms(["WordPress", "PHP"], ["cdn:cloudflare", "stack:php", "hsts"]) == [
        "cloudflare", "hsts", "php", "wordpress",
    ]


def test_extract_emails_rejects_false_positives():
    text = "reach a@b.example and admin@example.com but not logo@2x.png or x@y.svg"
    emails = tasks.extract_emails(text)
    assert "a@b.example" in emails
    assert "admin@example.com" not in emails         # example.com denied
    assert all("@2x.png" not in e and ".svg" not in e for e in emails)  # asset TLDs denied


def test_extract_identities_collects_emails_and_usernames():
    ids = tasks.extract_identities(
        links=["mailto:owner@acme.example"],
        html_bodies=["contact bob@acme.example"],
        json_objs=[{"username": "alice", "id": 7}])
    assert set(ids["emails"]) == {"owner@acme.example", "bob@acme.example"}
    assert {"alice", "bob", "owner"} <= set(ids["usernames"])   # field value + email local-parts


def test_merge_params_wordlist_custom_first_dedup():
    assert tasks.merge_params_wordlist(["id", "role"], ["role", "page"]) == ["id", "role", "page"]


def test_effective_params_wl_merges_custom_first(tmp_path):
    """param_fuzz uses wl_custom/params.txt custom-first; falls back to the global role when empty."""
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app1").ensure()
    glob = act.wl_global / "params.txt"
    tools.write_lines(glob, ["page", "id"])

    # no custom params → return the global path unchanged (byte-identical to today)
    assert tasks._effective_params_wl(ws, glob) == glob
    assert tasks._effective_params_wl(ws, None) is None

    # custom params present → merged file under raw/, custom-first
    tools.write_lines(ws.wl_custom / "params.txt", ["role", "id"])
    dest = tasks._effective_params_wl(ws, glob)
    assert dest == ws.raw("param_fuzz") / "params.txt"
    assert tools.read_lines(dest) == ["role", "id", "page"]




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
    assert tasks.tech_extensions(["ASP.NET 4.8"], mapping) == ["asp", "aspx"]  # version suffix tolerated
    assert tasks.tech_extensions(["Go"], mapping) == []                  # no match
    # whole-word match: "JavaScript" must NOT trigger the Java ("java") extensions (java ⊂ javascript)
    assert tasks.tech_extensions(["JavaScript"], mapping) == []
    assert tasks.tech_extensions(["Apache Tomcat (Java)"], mapping) == ["jsp"]  # real Java still matches


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


def test_https_to_http_rewrites_scheme_only():
    assert tasks.https_to_http("https://zero.webappsecurity.com") == "http://zero.webappsecurity.com"
    assert tasks.https_to_http("https://x:8443/a?b=1") == "http://x:8443/a?b=1"
    assert tasks.https_to_http("http://x") == "http://x"          # already http — unchanged
    assert tasks.https_to_http("ftp://x") == "ftp://x"            # other scheme — unchanged


def test_ferox_transport_failed_only_on_total_transport_failure():
    # legacy-TLS handshake refused: every request errored, nothing connected → True
    assert tasks.ferox_transport_failed(
        '{"type":"statistics","requests":1,"errors":1,"successes":0,"certificate_errors":1}')
    # connected but found nothing (successes > 0) → False (no fallback)
    assert not tasks.ferox_transport_failed(
        '{"type":"statistics","requests":500,"errors":2,"successes":498}')
    # healthy scan killed by --time-limit emits NO statistics record, only responses → False
    assert not tasks.ferox_transport_failed(
        '{"type":"response","url":"https://x/a","status":200}\n')
    assert not tasks.ferox_transport_failed("")


def test_force_scheme_rewrites_only_mapped_hosts():
    pins = {"zero.webappsecurity.com": "http", "shop.x.com": "https"}
    assert tasks.force_scheme("https://zero.webappsecurity.com/a", pins) == "http://zero.webappsecurity.com/a"
    assert tasks.force_scheme("http://shop.x.com/b?q=1", pins) == "https://shop.x.com/b?q=1"
    assert tasks.force_scheme("https://other.com", pins) == "https://other.com"  # unmapped → unchanged
    assert tasks.force_scheme("https://x", {}) == "https://x"                    # empty map → unchanged


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
    monkeypatch.setenv("PTFLOW_EYEWITNESS", "python3 /opt/EyeWitness/Python/EyeWitness.py")
    assert tasks._eyewitness_cmd() == ["python3", "/opt/EyeWitness/Python/EyeWitness.py"]
    # nothing resolvable (no env, no PATH eyewitness, no install dir) ⇒ None ⇒ step skips cleanly
    monkeypatch.delenv("PTFLOW_EYEWITNESS", raising=False)
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
    from ptflow.core import tools, workspace
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app1").ensure()
    workspace.write_meta(ws.meta, {"app_id": "app1", "tech": []})
    tools.write_lines(ws.canonical("endpoints.txt"), ["https://app1/admin/index.php?id=2"])

    tasks.build_wordlist(act, "app1")
    words = tools.read_lines(ws.wl_custom / "seed.txt")
    assert {"admin", "index.php", "index", "id"} <= set(words)


def test_build_wordlist_mines_links_and_bodies(tmp_path, monkeypatch):
    """The lexicon extractor mines BOTH the link surface AND the extracted bodies into four products:
    seed (endpoints), params (names), values (semantic words), identities (users/emails)."""
    from ptflow.core import tools, workspace
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app1").ensure()
    workspace.write_meta(ws.meta, {"app_id": "app1", "tech": ["WordPress"],
                                   "header_signals": ["cdn:cloudflare"],
                                   "hosts": ["https://app1.example.com"]})
    tools.write_lines(ws.canonical("endpoints.txt"),
                      ["https://app1.example.com/admin/index.php?id=2&role=admin"])
    # bodies mine_responses already extracted to raw/extracted/ (wordlist reads, never re-extracts)
    extracted = ws.raw("extracted")
    extracted.mkdir(parents=True, exist_ok=True)
    (extracted / "app.js").write_text("// js", encoding="utf-8")
    (extracted / "page.html").write_text(
        '<html><head><title>Acme Shop | Login</title></head><body>'
        '<form><input name="username" id="login"><textarea name="comment"></textarea></form>'
        '<a href="mailto:admin@acme.example">mail</a> contact bob@acme.example</body></html>',
        encoding="utf-8")
    (extracted / "data.html").write_text(  # a JSON API response saved as .html by _extract_bodies
        '{"username":"alice","apiKey":"x","items":[{"id":1}]}', encoding="utf-8")
    # hermetic: stand in for the jsluice binary (queryParams/bodyParams are the verified field names)
    monkeypatch.setattr(tasks, "_jsluice_records",
                        lambda _files: [{"url": "/api/v2/users",
                                         "queryParams": ["page", "sort"], "bodyParams": ["csrf"]}])

    tasks.build_wordlist(act, "app1")
    seed = set(tools.read_lines(ws.wl_custom / "seed.txt"))
    params = set(tools.read_lines(ws.wl_custom / "params.txt"))
    values = set(tools.read_lines(ws.wl_custom / "values.txt"))
    identities = set(tools.read_lines(ws.wl_custom / "identities.txt"))

    assert {"admin", "index.php", "index"} <= seed
    # params: query keys + jsluice query/body params + HTML form fields + JSON keys
    assert {"role", "page", "sort", "csrf", "username", "comment", "login", "apiKey"} <= params
    # values: query value + stack/header terms + app-name from <title>
    assert {"admin", "wordpress", "cloudflare", "acme", "shop"} <= values
    assert "login" not in values            # title boilerplate dropped
    # identities: emails + mailto + local-parts + identity-field value
    assert {"admin@acme.example", "bob@acme.example", "bob", "alice"} <= identities


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
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    act.scope_init.write_text("example.com\nnmap.org\n", encoding="utf-8")
    tasks.expand(act)
    assert tools.read_lines(act.scope_urls) == []
    assert tools.read_lines(act.scope_ip) == []
    assert sorted(tools.read_lines(act.scope_dns)) == ["example.com", "nmap.org"]


def test_cluster_groups_by_signature(tmp_path):
    from ptflow.core import tools, workspace
    from ptflow.core.paths import Activity

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


def test_cluster_honors_explicit_scope_scheme(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    act.scope.write_text("http://zero.example.com\nhttps://shop.example.org\n", encoding="utf-8")
    tools.write_jsonl(
        act.asset_discovery_canonical("httpx_full_metadata.jsonl"),
        [
            {"url": "https://zero.example.com", "title": "Z", "content_length": 1, "webserver": "x"},
            {"url": "https://shop.example.org", "title": "S", "content_length": 2, "webserver": "x"},
            {"url": "https://api.example.net", "title": "A", "content_length": 3, "webserver": "x"},
        ],
    )
    tasks.cluster(act)
    hosts = sorted(h for a in act.list_apps() for h in tools.read_lines(a.hosts))
    # explicit http:// honored, explicit https:// kept; a host with NO scope scheme stays httpx's https
    assert hosts == ["http://zero.example.com", "https://api.example.net", "https://shop.example.org"]


def test_working_schemes_prefers_content_discovery_over_hosts(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import AppWorkspace

    ws = AppWorkspace(tmp_path / "app").ensure()
    tools.write_lines(ws.hosts, ["https://a.x.com", "http://b.x.com"])
    tools.write_jsonl(ws.canonical("content_discovery.jsonl"),
                      [{"url": "http://a.x.com/found", "status": 200}])  # feroxbuster reached a over http
    s = tasks._working_schemes(ws)
    assert s["a.x.com"] == "http"   # content_discovery evidence (post http-fallback) overrides hosts.txt
    assert s["b.x.com"] == "http"   # from hosts.txt (no content_discovery hit)


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


# --- content-discovery fixpoint (phase 3) ---
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
    from ptflow.core.paths import Activity

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


# --- param fuzzing (phase 4) ---
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


# --- wordlist strategy (staged combine) ---
def test_roles_for_tech_matches_and_dedupes():
    mapping = {"php": "an_php", "asp.net": "an_aspx", "iis": "an_aspx",
               "java": ("mn_jsp", "mn_do")}
    assert tasks.roles_for_tech(["PHP 8.2", "Nginx"], mapping) == ["an_php"]    # case-insensitive
    assert tasks.roles_for_tech(["ASP.NET", "Microsoft-IIS"], mapping) == ["an_aspx"]  # 2 keys, 1 role, deduped
    assert tasks.roles_for_tech(["Apache Tomcat (Java)"], mapping) == ["mn_jsp", "mn_do"]  # tuple expands
    assert tasks.roles_for_tech(["Go"], mapping) == []                         # no match
    # whole-word match: "java" ⊂ "javascript" must NOT select the Java role (the precision-first bug)
    assert tasks.roles_for_tech(["JavaScript"], mapping) == []


def test_roles_for_tech_word_boundary_no_substring_false_positive():
    # "next" ⊂ "nextcloud" (a PHP app) — must not be mistaken for Next.js → an_apiroutes
    s2 = tasks.STAGE2_TECH_ROLES
    assert tasks.roles_for_tech(["JavaScript"], s2) == []          # not Java (an_jsp)
    assert tasks.roles_for_tech(["Nextcloud"], s2) == []           # not Next.js (an_apiroutes)
    assert tasks.roles_for_tech(["Next.js"], s2) == ["an_apiroutes"]   # the real Next.js still matches
    assert tasks.tech_extensions(["JavaScript"], tasks.TECH_EXTENSIONS) == []  # not .jsp/.do/.action


def test_stage2_and_deepdive_roles_per_stack():
    s2, dd = tasks.STAGE2_TECH_ROLES, tasks.DEEPDIVE_TECH_ROLES
    assert tasks.roles_for_tech(["PHP", "WordPress"], s2) == ["an_php"]
    assert tasks.roles_for_tech(["ASP.NET", "Microsoft-IIS"], s2) == ["an_aspx"]
    assert tasks.roles_for_tech(["Java", "Apache Tomcat"], s2) == ["an_jsp"]
    assert tasks.roles_for_tech(["Express", "Next.js"], s2) == ["an_apiroutes"]      # node/next → apiroutes
    assert tasks.roles_for_tech(["Python", "Django"], s2) == ["an_apiroutes"]        # python → apiroutes
    assert tasks.roles_for_tech(["React"], s2) == []                                 # client-side → no backend list
    # deep-dive: per-stack manual lists, gated
    assert tasks.roles_for_tech(["PHP"], dd) == ["mn_php", "mn_phpmillion"]
    assert tasks.roles_for_tech(["ASP.NET"], dd) == ["mn_aspx", "mn_asp", "mn_cfm"]
    assert tasks.roles_for_tech(["Java"], dd) == ["mn_jsp", "mn_do"]
    assert tasks.roles_for_tech(["Python"], dd) == []                                # no dedicated deep list


def test_assemble_wordlist_custom_first_and_per_layer_caps():
    custom = ["app1", "app2"]
    layers = [(["g1", "g2", "g3"], None), (["d1", "d2", "d3", "d4"], 2)]  # full layer, then capped head
    wl = tasks.assemble_wordlist(custom, layers)
    assert wl[:2] == ["app1", "app2"]                                # custom first
    assert wl == ["app1", "app2", "g1", "g2", "g3", "d1", "d2"]      # full layer whole, capped layer top-2
    assert "d3" not in wl                                            # cap drops the tail
    # dedup keeps first occurrence across layers
    assert tasks.assemble_wordlist(["x"], [(["x", "y"], None)]) == ["x", "y"]


def test_richest_hosts_ranks_by_hit_count_and_caps():
    hits = [{"url": "https://a.test/1"}, {"url": "https://a.test/2"}, {"url": "https://a.test/3"},
            {"url": "https://b.test/1"}, {"url": "https://c.test/1"}, {"url": "https://off.test/x"}]
    hosts = ["https://a.test", "https://b.test", "https://c.test"]  # off.test not scanned → ignored
    assert tasks._richest_hosts(hits, hosts, cap=2) == ["https://a.test", "https://b.test"]


def test_build_wordlist_seed_excludes_tech_lists(tmp_path):
    """The layer split: build_wordlist writes ONLY app tokens — tech CMS lists are added later by
    content_discovery's combine, never folded into the custom seed."""
    from ptflow.core import tools, workspace
    from ptflow.core.paths import Activity

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


# --- request catalog (full-request DAST input — POST/JSON/body, not just GET) ---
def test_build_raw_request_get_has_request_line_host_and_blank_terminator():
    raw = tasks.build_raw_request("get", "https://app.test/search?q=1&p=2")
    assert raw.startswith("GET /search?q=1&p=2 HTTP/1.1\r\n")
    assert "Host: app.test\r\n" in raw
    assert raw.endswith("\r\n\r\n")          # no body → terminated by the blank line


def test_build_raw_request_post_guesses_content_type_and_length():
    form = tasks.build_raw_request("POST", "https://app.test/login", body="u=a&p=b")
    assert "Content-Type: application/x-www-form-urlencoded\r\n" in form
    assert "Content-Length: 7\r\n" in form
    assert form.endswith("\r\n\r\nu=a&p=b")
    js = tasks.build_raw_request("POST", "https://app.test/api", body='{"x":1}')
    assert "Content-Type: application/json\r\n" in js


def test_build_raw_request_does_not_duplicate_caller_host():
    raw = tasks.build_raw_request("GET", "https://app.test/", headers={"Host": "evil", "X-A": "1"})
    assert raw.count("Host:") == 1
    assert "Host: app.test\r\n" in raw
    assert "X-A: 1\r\n" in raw


def test_request_params_by_location():
    assert {("id", "query"), ("q", "query")} == {
        (p["name"], p["loc"]) for p in tasks.request_params("https://a/x?id=1&q=2")}
    assert {("user", "body"), ("pw", "body")} == {
        (p["name"], p["loc"]) for p in tasks.request_params("https://a/x", body="user=a&pw=b")}
    assert {("a", "json"), ("b", "json")} == {
        (p["name"], p["loc"]) for p in
        tasks.request_params("https://a/x", body='{"a":1,"b":2}', content_type="application/json")}


def test_parse_katana_requests_reuses_raw_and_records_method_and_body_params():
    import json
    line = json.dumps({"request": {"endpoint": "https://a/api", "method": "POST",
                                   "body": "x=1", "raw": "POST /api HTTP/1.1\r\nHost: a\r\n\r\nx=1"}})
    [rec] = tasks.parse_katana_requests(line)
    assert rec["method"] == "POST"
    assert rec["url"] == "https://a/api"
    assert rec["raw"].startswith("POST /api HTTP/1.1")    # katana's own raw reused verbatim
    assert {("x", "body")} == {(p["name"], p["loc"]) for p in rec["params"]}


def test_parse_katana_requests_builds_raw_when_absent():
    import json
    [rec] = tasks.parse_katana_requests(json.dumps({"request": {"endpoint": "https://a/p?id=1"}}))
    assert rec["method"] == "GET"
    assert rec["raw"].startswith("GET /p?id=1 HTTP/1.1\r\n")    # synthesized


def test_parse_katana_requests_synthesizes_form_requests():
    import json
    rec = {"request": {"endpoint": "https://a/page"},
           "forms": [{"action": "/login", "method": "post", "parameters": ["username", "password"]},
                     {"action": "search", "method": "get", "fields": [{"name": "q"}]}]}
    out = tasks.parse_katana_requests(json.dumps(rec))
    post = next(r for r in out if r["method"] == "POST")
    assert post["url"] == "https://a/login"
    assert post["body"] == "username=&password="
    assert {("username", "body"), ("password", "body")} == {(p["name"], p["loc"]) for p in post["params"]}
    get = next(r for r in out if r["method"] == "GET" and "search" in r["url"])
    assert get["url"] == "https://a/search?q="    # relative action resolved against the page URL


def test_request_key_collapses_ids_keeps_method():
    a = {"method": "GET", "url": "https://a/user/123"}
    b = {"method": "GET", "url": "https://a/user/456"}
    c = {"method": "POST", "url": "https://a/user/123"}
    assert tasks.request_key(a) == tasks.request_key(b)    # /123 vs /456 collapse to one shape
    assert tasks.request_key(a) != tasks.request_key(c)    # GET vs POST stay distinct


def test_merge_requests_dedups_by_shape_and_unions_sources_and_params():
    a = {"method": "GET", "url": "https://a/user/1", "params": [{"name": "id", "loc": "query"}],
         "sources": ["katana"]}
    b = {"method": "GET", "url": "https://a/user/2", "params": [{"name": "ref", "loc": "query"}],
         "sources": ["katana-headless"]}
    [merged] = tasks.merge_requests([a, b])                # same (GET, /user/*) shape → one record
    assert merged["sources"] == ["katana", "katana-headless"]
    assert {("id", "query"), ("ref", "query")} == {(p["name"], p["loc"]) for p in merged["params"]}


def test_request_params_captures_observed_values():
    q = {(p["name"], p.get("value")) for p in tasks.request_params("https://a/x?id=3&q=")}
    assert q == {("id", "3"), ("q", "")}                    # observed value kept, blank kept as ''
    j = {(p["name"], p.get("value")) for p in
         tasks.request_params("https://a/x", body='{"a":"v","b":2}', content_type="application/json")}
    assert ("a", "v") in j


def test_normalize_request_folds_query_params_into_url_and_raw():
    # the bug: params advertised but absent from raw → a bare GET fed to sqlmap/dalfox has nothing to fuzz
    rec = {"method": "GET", "url": "https://a/catalog", "headers": {}, "body": "",
           "params": [{"name": "category", "loc": "query", "value": ""},      # blank → seeded
                      {"name": "id", "loc": "query", "value": "7"}],          # observed → reused
           "raw": "GET /catalog HTTP/1.1\r\nHost: a\r\n\r\n", "sources": ["x"]}
    out = tasks.normalize_request(rec)
    assert "category=1" in out["url"]        # blank value seeded
    assert "id=7" in out["url"]              # observed value reused
    assert "category=1" in out["raw"]        # raw realigned to the params
    assert "id=7" in out["raw"]
    assert tasks._has_params(out)


def test_normalize_request_folds_body_params_and_sets_content_type():
    rec = {"method": "POST", "url": "https://a/cart", "headers": {}, "body": "",
           "params": [{"name": "productId", "loc": "body", "value": ""}],
           "raw": "POST /cart HTTP/1.1\r\nHost: a\r\n\r\n", "sources": ["x"]}
    out = tasks.normalize_request(rec)
    assert out["body"] == "productId=1"
    assert "Content-Type: application/x-www-form-urlencoded\r\n" in out["raw"]
    assert out["raw"].endswith("\r\n\r\nproductId=1")


def test_normalize_request_leaves_paramless_record_untouched():
    rec = {"method": "GET", "url": "https://a/page", "params": [],
           "raw": "GET /page HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\n\r\n", "sources": ["katana"]}
    assert tasks.normalize_request(rec) is rec              # authoritative raw preserved verbatim


def test_merge_requests_realigns_raw_when_paramless_variant_wins():
    # bare /catalog (no params, first) + a form variant carrying category/searchTerm → merged raw must
    # carry the unioned params (this is the regression: first-wins kept the param-less raw)
    bare = {"method": "GET", "url": "https://a/catalog", "headers": {}, "body": "", "params": [],
            "raw": "GET /catalog HTTP/1.1\r\nHost: a\r\n\r\n", "sources": ["url"]}
    form = {"method": "GET", "url": "https://a/catalog?category=&searchTerm=", "headers": {}, "body": "",
            "params": [{"name": "category", "loc": "query", "value": ""},
                       {"name": "searchTerm", "loc": "query", "value": ""}],
            "raw": "GET /catalog?category=&searchTerm= HTTP/1.1\r\nHost: a\r\n\r\n",
            "sources": ["html-form"]}
    [merged] = tasks.merge_requests([bare, form])
    assert {("category", "query"), ("searchTerm", "query")} == {(p["name"], p["loc"]) for p in merged["params"]}
    assert "category=" in merged["raw"]
    assert "searchTerm=" in merged["raw"]
    assert tasks._has_params(merged)


def test_merge_requests_upgrades_blank_param_value_with_observed():
    a = {"method": "GET", "url": "https://a/p/1", "headers": {}, "body": "",
         "params": [{"name": "productId", "loc": "query", "value": ""}],
         "raw": "GET /p/1 HTTP/1.1\r\nHost: a\r\n\r\n", "sources": ["a"]}
    b = {"method": "GET", "url": "https://a/p/2?productId=3", "headers": {}, "body": "",
         "params": [{"name": "productId", "loc": "query", "value": "3"}],
         "raw": "GET /p/2?productId=3 HTTP/1.1\r\nHost: a\r\n\r\n", "sources": ["b"]}
    [merged] = tasks.merge_requests([a, b])                 # same (GET,/p/*) shape → one record
    assert "productId=3" in merged["raw"]                  # observed value won over the blank


def test_auth_headers_parses_env(monkeypatch):
    monkeypatch.setenv("PTFLOW_HTTP_HEADER", "Cookie: s=1;;Authorization: Bearer x\nBad")
    assert tasks._auth_headers() == ["Cookie: s=1", "Authorization: Bearer x"]    # 'Bad' (no ':') dropped
    assert tasks._header_flags("-H") == ["-H", "Cookie: s=1", "-H", "Authorization: Bearer x"]
    monkeypatch.delenv("PTFLOW_HTTP_HEADER")
    assert tasks._auth_headers() == []
    assert tasks._header_flags() == []


def test_url_to_get_request_shape():
    r = tasks._url_to_get_request("https://a/x?id=1", "passive")
    assert r["method"] == "GET"
    assert r["sources"] == ["passive"]
    assert {("id", "query")} == {(p["name"], p["loc"]) for p in r["params"]}
    assert r["raw"].startswith("GET /x?id=1 HTTP/1.1")


def test_catalog_records_folds_urls_reschemes_and_filters_scope():
    reqs = [{"method": "POST", "url": "https://a/login", "headers": {}, "body": "u=1",
             "params": [{"name": "u", "loc": "body"}],
             "raw": "POST /login HTTP/1.1\r\nHost: a\r\n\r\nu=1", "sources": ["katana"]}]
    get_urls = ["https://a/page?q=1", "https://evil/x"]      # evil host out of scope
    out = tasks.catalog_records(reqs, get_urls, in_scope={"a"}, schemes={"a": "http"})
    urls = {r["url"] for r in out}
    assert "http://a/login" in urls          # full request re-schemed https→http (reachable scheme)
    assert "http://a/page?q=1" in urls       # url-only source folded in as GET, re-schemed
    assert all("evil" not in u for u in urls)  # out-of-scope dropped


def test_url_pathkey_strips_scheme_port_query_fragment():
    assert tasks._url_pathkey("https://a.com:443/x/y?q=1#f") == "a.com/x/y"
    assert tasks._url_pathkey("http://a.com/x/y?q=1") == "a.com/x/y"
    assert tasks._url_pathkey("https://a.com") == "a.com/"            # root → host + '/'
    assert tasks._url_pathkey("https://a.com/about</a>") == "a.com/about</a>"  # garbage path preserved
    # percent-encoding normalized so the encoded catalog form matches the decoded index form
    assert tasks._url_pathkey("https://a.com/about%3C/a%3E") == tasks._url_pathkey("https://a.com/about</a>")


def test_dead_url_keys_only_paths_seen_exclusively_as_404():
    lines = [
        "/store/f1.txt https://a.com/live (200 OK)",
        "/store/f2.txt https://a.com/gone (404 Not Found)",
        "/store/f3.txt https://a.com/gone (410 Gone)",          # still only-dead
        "/store/f4.txt https://a.com/sometimes (404 Not Found)",
        "/store/f5.txt https://a.com/sometimes?x=1 (200 OK)",   # one 200 on the path → alive
        "/store/f6.txt https://a.com/protected (403 Forbidden)",  # exists → alive (not 404/410)
        "malformed line without status",
    ]
    assert tasks.dead_url_keys(lines) == {"a.com/gone"}        # only the exclusively-404/410 path


def test_assemble_catalog_drops_dead_get_keeps_post(tmp_path):
    from ptflow.core.paths import AppWorkspace

    ws = AppWorkspace(tmp_path / "app").ensure()
    ws.responses.mkdir(parents=True, exist_ok=True)
    ws.hosts.write_text("https://a.com\n")
    (ws.responses / "index.txt").write_text(
        "/s/1 https://a.com/dead (404 Not Found)\n"
        "/s/2 https://a.com/login (200 OK)\n")
    # crawl records: a dead GET, an alive GET, and a POST whose path was only seen as 404
    ws.canonical("requests_crawl.jsonl").write_text("\n".join([
        json.dumps({"method": "GET", "url": "https://a.com/dead",
                    "raw": "GET /dead HTTP/1.1\r\nHost: a.com\r\n\r\n", "sources": ["katana"]}),
        json.dumps({"method": "GET", "url": "https://a.com/login",
                    "raw": "GET /login HTTP/1.1\r\nHost: a.com\r\n\r\n", "sources": ["katana"]}),
        json.dumps({"method": "POST", "url": "https://a.com/dead", "body": "u=1",
                    "raw": "POST /dead HTTP/1.1\r\nHost: a.com\r\n\r\nu=1", "sources": ["katana"]}),
    ]) + "\n")
    catalog, _mined, n_dead = tasks._assemble_catalog(ws, include_guessed=False)
    shapes = {(r["method"], tasks._url_pathkey(r["url"])) for r in catalog}
    assert ("GET", "a.com/dead") not in shapes        # dead GET dropped
    assert ("GET", "a.com/login") in shapes           # alive GET kept
    assert ("POST", "a.com/dead") in shapes           # body-bearing POST kept despite dead path
    assert n_dead == 1


def test_select_body_targets_splits_json_and_urlencoded_and_dedups():
    catalog = [
        {"method": "POST", "url": "https://a/login",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "u="},
        {"method": "POST", "url": "https://a/api",
         "headers": {"Content-Type": "application/json"}, "body": '{"q":1}'},
        {"method": "GET", "url": "https://a/page?x=1"},          # no body / GET → excluded
        {"method": "POST", "url": "https://a/login", "body": ""},  # same (POST,/login) shape → deduped
    ]
    body, js = tasks.select_body_targets(catalog, in_scope={"a"}, cap=10)
    assert body == ["https://a/login"]
    assert js == ["https://a/api"]


def test_parse_arjun_and_x8_stamp_location():
    import json
    [p] = tasks.parse_arjun(json.dumps({"https://a/x": {"method": "POST", "params": ["user"]}}), loc="body")
    assert p["loc"] == "body"
    x = json.dumps([{"url": "https://a/x", "method": "GET", "found_params": [{"name": "q"}]}])
    [p2] = tasks.parse_x8(x, loc="header")
    assert p2["loc"] == "header"


def test_merge_params_keeps_locations_distinct():
    recs = [
        {"url": "https://a/x", "param": "id", "loc": "query", "method": "GET", "sources": ["arjun"], "reason": None},
        {"url": "https://a/x", "param": "id", "loc": "query", "method": "GET", "sources": ["x8"], "reason": "refl"},
        {"url": "https://a/x", "param": "id", "loc": "body", "method": "POST", "sources": ["x8"], "reason": None},
    ]
    merged = tasks.merge_params(recs)
    assert len(merged) == 2                  # (id,query) merged across arjun+x8; (id,body) stays distinct
    q = next(m for m in merged if m["loc"] == "query")
    assert q["sources"] == ["arjun", "x8"]
    assert q["reason"] == "refl"


def test_collapse_global_params_collapses_site_wide_reflection():
    # 'category' found on 8/8 query endpoints (≥75%, ≥5 hits) → site-wide reflection, collapse to 1
    recs = [{"url": f"https://a/p{i}", "param": "category", "loc": "query",
             "method": "GET", "sources": ["x8"], "reason": "Reflected"} for i in range(8)]
    # 'productId' on 2 endpoints (endpoint-specific) → untouched
    recs += [{"url": f"https://a/item{i}", "param": "productId", "loc": "query",
              "method": "GET", "sources": ["x8"], "reason": "Text"} for i in range(2)]
    out = tasks.collapse_global_params(recs, {"query": 8})
    cats = [r for r in out if r["param"] == "category"]
    pids = [r for r in out if r["param"] == "productId"]
    assert len(cats) == 1                            # 8 → 1 site-wide record
    assert cats[0]["scope"] == "site-wide"
    assert cats[0]["endpoints"] == 8
    assert len(pids) == 2                            # endpoint-specific kept…
    assert all("scope" not in r for r in pids)       # …and not marked site-wide


def test_collapse_global_params_min_hits_guards_tiny_tested_set():
    # 3/3 = 100% ratio but below min_hits → NOT collapsed (a tiny tested set must not trip it)
    recs = [{"url": f"https://a/p{i}", "param": "q", "loc": "query",
             "method": "GET", "sources": ["x8"], "reason": "Reflected"} for i in range(3)]
    out = tasks.collapse_global_params(recs, {"query": 3})
    assert len(out) == 3
    assert all("scope" not in r for r in out)


# --- DAST (nuclei -dast over the request catalog) ---
def test_build_fuzz_requests_injects_params_per_location():
    params = [
        {"url": "https://a/x", "param": "id", "loc": "query"},
        {"url": "https://a/x", "param": "q", "loc": "query"},
        {"url": "https://a/login", "param": "user", "loc": "body"},
        {"url": "https://a/api", "param": "token", "loc": "json"},
        {"url": "https://a/p", "param": "X-Debug", "loc": "header"},
    ]
    out = {(r["method"], r["url"].split("?")[0]): r for r in tasks.build_fuzz_requests(params)}
    q = out[("GET", "https://a/x")]
    assert "id=" in q["url"]
    assert "q=" in q["url"]
    assert q["raw"].startswith("GET /x?")
    body = out[("POST", "https://a/login")]
    assert body["body"] == "user="
    assert "application/x-www-form-urlencoded" in body["raw"]
    js = out[("POST", "https://a/api")]
    assert '"token"' in js["body"]
    assert "application/json" in js["raw"]
    assert "X-Debug: x\r\n" in out[("GET", "https://a/p")]["raw"]   # header param present in the raw


def test_dast_requests_merges_catalog_and_synth_then_caps():
    catalog = [{"method": "GET", "url": "https://a/known?p=1", "headers": {}, "body": "",
                "params": [{"name": "p", "loc": "query"}],
                "raw": "GET /known?p=1 HTTP/1.1\r\nHost: a\r\n\r\n", "sources": ["katana"]}]
    params = [{"url": "https://a/hidden", "param": "secret", "loc": "query"}]
    urls = {r["url"] for r in tasks.dast_requests(catalog, params, cap=10)}
    assert any("known" in u for u in urls)
    assert any("hidden" in u and "secret=" in u for u in urls)   # discovered hidden param injected
    many = [{"url": f"https://a/p{i}", "param": "x", "loc": "query"} for i in range(20)]
    assert len(tasks.dast_requests([], many, cap=5)) == 5         # cap bites


def test_dedup_dast_findings_collapses_same_injection_point():
    def fz(tid, at, pos="query"):
        return {"template-id": tid, "matched-at": at, "is_fuzzing_result": True,
                "fuzzing_position": pos, "fuzzing_method": "GET"}
    recs = [
        fz("cookie-injection", "https://a/x?category=cookie_injection"),
        fz("cookie-injection", "https://a/x?category=&err=cookie_injection"),  # same path+pos → dup
        fz("cookie-injection", "https://a/y?category=cookie_injection"),       # diff path → kept
        fz("sqli", "https://a/x?id=1'", pos="query"),                          # diff template → kept
        fz("cookie-injection", "https://a/x?h=1", pos="header"),               # diff position → kept
        {"template-id": "tech-detect", "matched-at": "https://a/", "is_fuzzing_result": False},
        {"template-id": "tech-detect", "matched-at": "https://a/", "is_fuzzing_result": False},  # dup
    ]
    out = tasks.dedup_dast_findings(recs)
    keys = [(r["template-id"], r["matched-at"]) for r in out]
    assert len(out) == 5                                          # 7 → 5 (two collapsed)
    assert keys[0] == ("cookie-injection", "https://a/x?category=cookie_injection")  # first wins
    assert ("cookie-injection", "https://a/y?category=cookie_injection") in keys     # distinct path
    assert sum(1 for r in out if r["template-id"] == "tech-detect") == 1             # non-fuzz deduped


# --- dedicated vuln scanners (dalfox / sqlmap) ---
def test_has_params_detects_fuzzable_input():
    assert tasks._has_params({"params": [{"name": "x", "loc": "query"}]})  # enumerated param
    assert tasks._has_params({"url": "http://a/?x=1"})                     # query string
    assert tasks._has_params({"body": "a=1"})                              # body
    assert not tasks._has_params({"url": "http://a/static", "params": []})  # nothing to fuzz


def test_parse_dalfox_normalizes_poc_and_skips_noise():
    out = ('hello banner line (not json)\n'
           '{"type":"R","inject_type":"inHTML-URL","poc_type":"plain","method":"GET",'
           '"data":"http://a/?q=PAYLOAD","param":"q","payload":"\'><svg>","evidence":"line 1",'
           '"cwe":"CWE-79","severity":"Medium","message_str":"Reflected"}\n')
    recs = tasks.parse_dalfox(out)
    assert len(recs) == 1                       # banner line skipped, one PoC parsed
    r = recs[0]
    assert r["type"] == "xss"
    assert r["param"] == "q"
    assert r["severity"] == "medium"            # lowercased
    assert r["matched-at"] == "http://a/?q=PAYLOAD"
    assert r["sources"] == ["dalfox"]


def test_parse_sqlmap_extracts_injection_points():
    out = (
        "sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:\n"
        "---\n"
        "Parameter: productId (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: productId=3 AND 1234=1234\n"
        "\n"
        "    Type: time-based blind\n"
        "    Title: MySQL >= 5.0.12 AND time-based blind\n"
        "    Payload: productId=3 AND SLEEP(5)\n"
        "---\n"
        "[INFO] the back-end DBMS is MySQL\n"
    )
    recs = tasks.parse_sqlmap(out, url="http://a/p?productId=3")
    assert len(recs) == 2                                    # one per technique
    assert {r["technique"] for r in recs} == {"boolean-based blind", "time-based blind"}
    assert all(r["type"] == "sqli" for r in recs)
    assert all(r["param"] == "productId" for r in recs)
    assert all(r["location"] == "GET" for r in recs)
    assert all(r["dbms"] == "MySQL" for r in recs)
    assert recs[0]["matched-at"] == "http://a/p?productId=3"


def test_parse_sqlmap_empty_when_not_injectable():
    assert tasks.parse_sqlmap("all tested parameters do not appear to be injectable") == []


def test_correlate_oast_matches_marker_dedups_and_ignores_noise():
    uid = "d91abc44a9sslssmf88gnx5ua1t34kri8"
    marker_map = {
        "b3": {"url": "https://a/x?q=1", "method": "GET", "params": [{"name": "q", "loc": "query"}]},
        "b7": {"url": "https://a/y", "method": "POST", "params": []},
    }
    interactions = [
        {"full-id": f"b3.{uid}", "protocol": "dns", "remote-address": "1.2.3.4", "timestamp": "t1"},
        {"full-id": f"b3.{uid}", "protocol": "dns", "remote-address": "1.2.3.4", "timestamp": "t2"},
        {"full-id": f"b3.{uid}", "protocol": "http", "remote-address": "1.2.3.4", "timestamp": "t3"},
        {"full-id": uid, "protocol": "dns"},            # bare domain → interactsh noise, ignored
        {"full-id": f"bX.{uid}", "protocol": "dns"},    # unknown marker → ignored
    ]
    out = tasks.correlate_oast(interactions, marker_map, unique_id=uid)
    assert len(out) == 2                                # b3/dns + b3/http; dup dns dropped; noise ignored
    assert {r["oast_protocol"] for r in out} == {"dns", "http"}
    assert out[0]["type"] == "xss"
    assert out[0]["poc_kind"] == "blind"
    assert out[0]["matched-at"] == "https://a/x?q=1"
    assert out[0]["sources"] == ["dalfox", "interactsh"]


# --- API spec discovery (OpenAPI/Swagger expansion) ---
def test_is_openapi_detects_spec():
    assert tasks.is_openapi({"openapi": "3.0.0", "paths": {}})
    assert tasks.is_openapi({"swagger": "2.0", "paths": {}})
    assert not tasks.is_openapi({"paths": {}})            # no version marker
    assert not tasks.is_openapi({"openapi": "3.0.0"})     # no paths
    assert not tasks.is_openapi("nope")


def test_expand_openapi_v3_operations_to_full_requests():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v1"}],                  # relative → origin(spec_url) + this
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path"}],   # shared path-item param
                "get": {"parameters": [{"name": "verbose", "in": "query"},
                                       {"name": "X-Tenant", "in": "header"}]},
                "post": {"requestBody": {"content": {"application/json": {
                    "schema": {"properties": {"name": {}, "email": {}}}}}}},
            },
        },
    }
    by_method = {r["method"]: r for r in tasks.expand_openapi(spec, "https://api.example.com/openapi.json", cap=10)}
    get = by_method["GET"]
    assert get["url"] == "https://api.example.com/api/v1/users/1?verbose="   # base+path('1')+query
    assert "X-Tenant: x\r\n" in get["raw"]
    post = by_method["POST"]
    assert post["url"] == "https://api.example.com/api/v1/users/1"
    assert "application/json" in post["raw"]
    assert '"name"' in post["body"]
    assert '"email"' in post["body"]


def test_expand_openapi_swagger_v2_body_and_basepath():
    import json
    spec = {"swagger": "2.0", "basePath": "/v2",
            "paths": {"/login": {"post": {"parameters": [
                {"name": "creds", "in": "body", "schema": {"properties": {"user": {}, "pass": {}}}}]}}}}
    [req] = tasks.expand_openapi(spec, "https://h/swagger.json", cap=10)
    assert req["method"] == "POST"
    assert req["url"] == "https://h/v2/login"             # origin + basePath
    assert "application/json" in req["raw"]
    assert {"user", "pass"} <= set(json.loads(req["body"]).keys())


def test_expand_openapi_caps_operations():
    spec = {"openapi": "3.0.0", "paths": {f"/p{i}": {"get": {}} for i in range(20)}}
    assert len(tasks.expand_openapi(spec, "https://h/openapi.json", cap=5)) == 5


# --- shape mining from the downloaded corpus (jsluice records + HTML forms → catalog requests) ---
def test_jsluice_requests_recovers_method_body_and_resolves_relative():
    records = [
        {"url": "/api/v2/users", "method": "POST", "contentType": "application/json",
         "headers": {"Content-Type": "application/json"}, "bodyParams": ["name", "email"],
         "filename": "/x/raw/extracted/abc.js"},
        {"url": "/api/search?q=1", "method": "GET", "queryParams": ["q"], "filename": "/x/raw/extracted/abc.js"},
        {"url": "/relative/no-source", "method": "GET", "filename": "/x/raw/extracted/zzz.js"},  # no src → skip
    ]
    out = {(r["method"], r["url"].split("?")[0]): r
           for r in tasks.jsluice_requests(records, {"abc": "https://app.test/static/app.js"})}
    post = out[("POST", "https://app.test/api/v2/users")]      # relative resolved against the JS source
    assert "application/json" in post["raw"]
    assert '"name"' in post["body"]
    assert '"email"' in post["body"]
    assert ("GET", "https://app.test/api/search") in out
    assert all("no-source" not in u for (_, u) in out)         # unresolved relative dropped (no host)


def test_parse_forms_extracts_method_action_fields():
    html = ('<form method="post" action="/login"><input name="user"><input name="pw" type="password">'
            '</form><form action="/search"><input name="q"></form>')
    forms = tasks.parse_forms(html)
    assert {"user", "pw"} == set(forms[0]["fields"])
    assert forms[0]["method"] == "post"
    assert forms[0]["action"] == "/login"
    assert forms[1]["method"] == "GET"                          # default when omitted


def test_html_form_requests_resolves_action_and_builds_requests(tmp_path):
    bodies = tmp_path / "extracted"
    bodies.mkdir()
    (bodies / "page.html").write_text(
        '<form method="post" action="/login"><input name="user"><input name="pw"></form>'
        '<form action="search"><input name="q"></form>')
    out = {(r["method"], r["url"].split("?")[0]): r
           for r in tasks.html_form_requests(bodies, {"page": "https://app.test/account/"})}
    assert out[("POST", "https://app.test/login")]["body"] == "user=&pw="    # absolute action
    assert "q=" in out[("GET", "https://app.test/account/search")]["url"]    # relative action vs page dir


# --- re-seed crawl: seed selection (the bit reviewed before launching a live crawl) ---
def test_first_segment():
    assert tasks._first_segment("/a/b/c") == "a"
    assert tasks._first_segment("/x") == "x"
    assert tasks._first_segment("/") == ""
    assert tasks._first_segment("") == ""


def test_select_recrawl_seeds_picks_uncrawled_territory_only():
    crawled = ["https://app.test/shop/item", "https://app.test/blog/"]
    discovered = [
        "https://app.test/debugging/console",    # /debugging/ never crawled → SEED
        "https://app.test/debugging/logs",        # same new dir → deduped out
        "https://app.test/shop/item?x=1",          # /shop/ crawled → NOT a seed
        "https://app.test/debugging/app.js",       # JS file → dropped (not a page)
        "https://app.test/assets/logo.png",        # static asset → dropped
        "https://evil.test/admin/",                # out of scope → dropped
    ]
    assert tasks.select_recrawl_seeds(discovered, crawled, {"app.test"}, cap=10) == \
        ["https://app.test/debugging/console"]     # one seed per new dir; static/js/scope filtered


def test_select_recrawl_seeds_first_segment_is_conservative_for_subdirs():
    crawled = ["https://app.test/app/page"]        # top-level segment 'app' already crawled
    discovered = ["https://app.test/app/admin/panel"]
    # first-segment selection is conservative: a new sub-dir UNDER an already-crawled top-level → NO seed
    assert tasks.select_recrawl_seeds(discovered, crawled, {"app.test"}, cap=10) == []


def test_select_recrawl_seeds_caps():
    discovered = [f"https://app.test/new{i}/x" for i in range(20)]
    assert len(tasks.select_recrawl_seeds(discovered, [], {"app.test"}, cap=5)) == 5


# --- CVE lookup (phase 2 surface + phase 4 deep) — pure helpers ---
def test_norm_version_strips_patch_and_requires_minor():
    assert tasks._norm_version("6.6.1p1") == "6.6.1"            # SSH patch suffix dropped
    assert tasks._norm_version("Apache/2.4.7 (Ubuntu)") == "2.4.7"
    assert tasks._norm_version("v1.11.0") == "1.11.0"
    assert tasks._norm_version("9") is None                     # bare major is too vague → version-pinned
    assert tasks._norm_version("") is None


def test_tech_software_keeps_only_versioned():
    out = tasks._tech_software(["Apache HTTP Server:2.4.7", "WordPress", "jQuery:1.11.0"])
    assert ("Apache HTTP Server", "2.4.7") in out
    assert ("jQuery", "1.11.0") in out
    assert all(name != "WordPress" for name, _ in out)          # version-less dropped


def test_header_software_parses_server_header():
    assert tasks._header_software("Apache/2.4.7 (Ubuntu)") == ("Apache", "2.4.7")
    assert tasks._header_software("nginx/1.18.0") == ("nginx", "1.18.0")
    assert tasks._header_software("nginx") is None              # no version → skip
    assert tasks._header_software("") is None


def test_banner_software_known_services():
    assert tasks._banner_software("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13") == ("OpenSSH", "6.6.1")
    assert tasks._banner_software("220 (vsFTPd 3.0.2)") == ("vsftpd", "3.0.2")
    assert tasks._banner_software("something unrecognized") is None


def test_corpus_software_mines_lib_and_generator():
    texts = ["/*! jQuery v1.11.0 | (c) jQuery Foundation */",
             '<meta name="generator" content="WordPress 5.2">',
             '<script src="/static/jquery-ui-1.13.2.min.js"></script>']  # versioned asset ref in body
    out = dict(tasks._corpus_software(texts))
    assert out.get("jQuery") == "1.11.0"
    assert out.get("WordPress") == "5.2"
    assert out.get("jQuery UI") == "1.13.2"   # mined from the <script src> filename


def test_mine_asset_versions_from_filenames_and_cdn_paths():
    assert tasks.mine_asset_versions("/static/js/jquery-3.6.0.min.js") == [("jQuery", "3.6.0")]
    assert tasks.mine_asset_versions("//cdn/npm/vue@2.6.14/dist/vue.min.js") == [("Vue.js", "2.6.14")]
    assert tasks.mine_asset_versions("ajax/libs/angularjs/1.8.2/angular.min.js") == [("AngularJS", "1.8.2")]
    # version-adjacency guard: 'jquery' must NOT mis-claim jquery-ui-1.13.2
    assert tasks.mine_asset_versions("/js/jquery-ui-1.13.2.min.js") == [("jQuery UI", "1.13.2")]
    # precision-first: unknown product, unversioned ref, and major-only version → nothing
    assert tasks.mine_asset_versions("/js/superwidget-1.2.3.js") == []
    assert tasks.mine_asset_versions("/js/jquery.min.js") == []
    assert tasks.mine_asset_versions("/js/d3.v7.min.js") == []


def test_collect_software_mines_versioned_asset_urls():
    sw = tasks.collect_software(
        tech=[], server="", services=[], corpus_texts=[],
        corpus_urls=["https://x/assets/bootstrap-5.1.3.min.css",
                     "https://x/assets/app.js"],   # no version → ignored
        app_hosts=["app.test"])
    by_prod = {r["product"]: r for r in sw}
    assert by_prod["Bootstrap"]["version"] == "5.1.3"
    assert by_prod["Bootstrap"]["sources"] == ["corpus"]
    assert by_prod["Bootstrap"]["where"] == ["app.test"]
    assert "app" not in by_prod


def test_collect_software_dedups_and_attributes_sources():
    sw = tasks.collect_software(
        tech=["jQuery:1.11.0"], server="Apache/2.4.7",
        services=[("scanme.test:22", "SSH-2.0-OpenSSH_6.6.1p1")],
        corpus_texts=["Bootstrap v3.3.7"], app_hosts=["app.test"])
    by_prod = {r["product"]: r for r in sw}
    assert by_prod["Apache"]["version"] == "2.4.7"
    assert by_prod["Apache"]["sources"] == ["server"]
    assert by_prod["OpenSSH"]["where"] == ["scanme.test:22"]   # service attributed to its host:port
    assert by_prod["jQuery"]["where"] == ["app.test"]          # app-level sources → the group's hosts
    assert by_prod["Bootstrap"]["sources"] == ["corpus"]


def test_map_hosts_to_ips_parses_dnsx_resp_format():
    # dnsx -a -resp writes '<host> [A] [<ip>]' — the record type and IP are separate bracketed tokens,
    # so the '[A]' column must never be mistaken for an IP (the _app_service_banners bug).
    lines = [
        "app.test [A] [10.0.0.1]",
        "api.test [A] [10.0.0.2] [10.0.0.3]",   # multiple A records
        "other.test [A] [10.0.0.9]",            # not in scope → ignored
        "bare.test 10.0.0.4",                   # no brackets/type → still parsed
    ]
    hosts = {"app.test", "api.test", "bare.test"}
    assert tasks.map_hosts_to_ips(lines, hosts) == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
    assert tasks.map_hosts_to_ips(["app.test [A] [10.0.0.1]"], {"app.test"}) == {"10.0.0.1"}


def test_app_service_banners_attributes_ip_only_record(tmp_path):
    # regression: an IP-only nerva record must attach to the app via domain_ip_map.txt — the old
    # parser took the '[A]' record-type column instead of the bracketed IP, so it never matched.
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    canon = act.asset_discovery_canonical
    tools.write_jsonl(canon("nerva_full_metadata.jsonl"),
                      [{"host": "", "ip": "45.33.32.156", "port": 22,
                        "metadata": {"banner": "SSH-2.0-OpenSSH_6.6.1p1"}}])
    canon("domain_ip_map.txt").write_text("scanme.test [A] [45.33.32.156]\n", encoding="utf-8")
    meta = {"hosts": ["http://scanme.test"]}
    assert tasks._app_service_banners(act, meta) == [("45.33.32.156:22", "SSH-2.0-OpenSSH_6.6.1p1")]


def test_parse_search_vulns_no_match_returns_none():
    out = '{"OpenSSH 6.6.1": "Warning: Could not find matching software for query"}'
    assert tasks.parse_search_vulns(out, "OpenSSH", "6.6.1") is None
    assert tasks.parse_search_vulns("not json", "x", "1.0") is None


def test_parse_search_vulns_extracts_finding_fields():
    out = json.dumps({"vsftpd 3.0.2": {"product_ids": {"cpe": ["cpe:2.3:a:vsftpd_project:vsftpd:3.0.2"]},
        "vulns": {"CVE-2021-3618": {"id": "CVE-2021-3618", "match_reason": "version_in_range",
            "description": "ALPACA", "published": "2022-03-23", "cisa_kev": False, "exploits": [],
            "cwe_ids": ["CWE-295"],
            "severity": {"CVSS": {"score": "7.4", "version": "3.1"}, "EPSS": {"score": "0.00615"}}}}}})
    recs = tasks.parse_search_vulns(out, "vsftpd", "3.0.2")
    assert len(recs) == 1
    r = recs[0]
    assert r["cve"] == "CVE-2021-3618"
    assert r["cvss"] == "7.4"
    assert r["epss"] == "0.00615"
    assert r["kev"] is False
    assert r["exploited"] is False
    assert r["product"] == "vsftpd"
    assert r["cpe"].startswith("cpe:2.3:a:vsftpd")


def test_parse_search_vulns_exploited_when_kev_or_exploits():
    out = json.dumps({"q": {"product_ids": {"cpe": []}, "vulns": {"CVE-2000-0001": {
        "id": "CVE-2000-0001", "cisa_kev": True, "exploits": [], "severity": {}}}}})
    assert tasks.parse_search_vulns(out, "p", "1.0")[0]["exploited"] is True   # KEV ⇒ exploited


def test_cve_sort_key_prioritizes_exploited_then_cvss():
    rows = [
        {"cve": "CVE-A", "exploited": False, "kev": False, "cvss": "9.8"},
        {"cve": "CVE-B", "exploited": True, "kev": False, "cvss": "5.0"},
        {"cve": "CVE-C", "exploited": False, "kev": False, "cvss": None},
    ]
    assert [r["cve"] for r in sorted(rows, key=tasks._cve_sort_key)] == ["CVE-B", "CVE-A", "CVE-C"]


# --- consolidate (terminal fan-in) ---
def test_consolidate_lifts_per_app_findings_by_type(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    a1, a2 = act.app("app-1").ensure(), act.app("app-2").ensure()
    # surface (phase 2) + deep (phase 4) of one scanner fold into ONE type file
    tools.write_jsonl(a1.findings / "cve.jsonl", [{"cve": "CVE-1", "product": "Apache"}])
    tools.write_jsonl(a1.findings / "cve_full.jsonl", [{"cve": "CVE-2", "product": "jQuery"}])
    tools.write_jsonl(a2.findings / "dast.jsonl", [{"template": "xss", "url": "http://b/x"}])
    tools.write_jsonl(a1.findings / "wpprobe.jsonl", [{"component": "give", "cve": "CVE-3"}])
    tools.write_jsonl(a1.canonical("secrets.jsonl"), [{"type": "aws", "secret": "AKIA…"}])
    a2.canonical("takeover.txt").write_text("github.io b.example.com\n", encoding="utf-8")

    counts = tasks.consolidate(act)

    assert counts == {"cve": 2, "dast": 1, "wpprobe": 1, "secrets": 1, "takeover": 1}
    cve = tools.read_jsonl(act.findings / "cve.jsonl")
    assert {(r["app_id"], r["cve"]) for r in cve} == {("app-1", "CVE-1"), ("app-1", "CVE-2")}
    assert tools.read_jsonl(act.findings / "wpprobe.jsonl")[0] == {
        "app_id": "app-1", "component": "give", "cve": "CVE-3"}
    assert tools.read_jsonl(act.findings / "dast.jsonl")[0]["app_id"] == "app-2"  # stamped with app_id
    assert tools.read_jsonl(act.findings / "takeover.jsonl")[0] == {
        "app_id": "app-2", "type": "subdomain-takeover",
        "evidence": "github.io b.example.com", "source": "subjack"}
    # an empty category writes no file (no clutter)
    assert not (act.findings / "tilde_enum.jsonl").exists()
    assert not (act.findings / "default_creds.jsonl").exists()


def test_consolidate_no_findings_returns_empty(tmp_path):
    from ptflow.core.paths import Activity

    act = Activity.named("empty", root=tmp_path).ensure()
    act.app("app-1").ensure()
    assert tasks.consolidate(act) == {}


def test_external_pipeline_exposes_consolidate(tmp_path):
    from ptflow.core.paths import Activity
    from ptflow.pipelines.external.pipeline import PIPELINE

    act = Activity.named("demo", root=tmp_path).ensure()
    act.app("app-1").ensure()
    assert PIPELINE.consolidate(act) == {}   # the pipeline hook delegates to tasks.consolidate


# --- tech_vulnscan / wpprobe ---
def test_parse_wpprobe_extracts_vulns_and_skips_version_only():
    data = {"url": "http://wp.test", "plugins": {
        "give": [{"version": "2.20.1", "severities": [{"critical": [{"auth_type": "Unauth",
            "vulnerabilities": [{"cve": "CVE-2025-22777", "title": "GiveWP PHP Object Injection",
            "cvss_score": 9.8, "cve_link": "https://x"}]}]}]}],
        "wordpress-seo": [{"version": "27.1.1"}]}}        # detected, no known vuln → no finding
    out = tasks.parse_wpprobe(json.dumps(data))
    assert len(out) == 1
    f = out[0]
    assert (f["type"], f["kind"], f["component"], f["version"], f["severity"], f["auth"],
            f["cve"], f["cvss"], f["target"], f["source"]) == (
        "wordpress-plugin-vuln", "plugin", "give", "2.20.1", "critical", "Unauth",
        "CVE-2025-22777", 9.8, "http://wp.test", "wpprobe")


def test_parse_wpprobe_themes_sorting_and_tolerance():
    data = {"url": "http://wp.test",
            "plugins": {"p": [{"version": "1.0", "severities": [{"medium": [{"auth_type": "Auth",
                "vulnerabilities": [{"cve": "CVE-M", "cvss_score": 5.0}]}]}]}]},
            "themes": {"t": [{"version": "2.0", "severities": [{"critical": [{"auth_type": "Unauth",
                "vulnerabilities": [{"cve": "CVE-C", "cvss_score": 9.0}]}]}]}]}}
    out = tasks.parse_wpprobe(json.dumps(data))
    assert [f["cve"] for f in out] == ["CVE-C", "CVE-M"]   # critical (theme) sorts before medium (plugin)
    assert out[0]["type"] == "wordpress-theme-vuln"
    assert tasks.parse_wpprobe("") == []
    assert tasks.parse_wpprobe("not json") == []
    assert tasks.parse_wpprobe('{"url":"x","plugins":{}}') == []


def test_tech_vulnscan_gates_on_wordpress(tmp_path, monkeypatch):
    from ptflow.core import tools, workspace
    from ptflow.core.paths import Activity

    act = Activity.named("demo", root=tmp_path).ensure()
    ws = act.app("app-1").ensure()
    calls: list = []
    monkeypatch.setattr(tasks, "_wpprobe", lambda *a: calls.append(a) or [])

    workspace.write_meta(ws.meta, {"app_id": "app-1", "tech": ["nginx", "PHP"]})  # not WordPress
    tasks.tech_vulnscan(act, "app-1")
    assert calls == []                                    # gate: wpprobe never runs
    assert not (ws.findings / "wpprobe.jsonl").exists()

    fake = [{"type": "wordpress-plugin-vuln", "component": "give", "cve": "CVE-1",
             "severity": "critical", "source": "wpprobe"}]
    monkeypatch.setattr(tasks, "_wpprobe", lambda *_: fake)
    workspace.write_meta(ws.meta, {"app_id": "app-1", "tech": ["WordPress", "PHP"]})
    tasks.tech_vulnscan(act, "app-1")
    assert tools.read_jsonl(ws.findings / "wpprobe.jsonl") == fake


# --- point 5b: JS sourcemap extraction (pure parsers) ------------------------------------------
def test_sourcemap_ref_extracts_last():
    assert tasks.sourcemap_ref("var x=1;\n//# sourceMappingURL=app.js.map\n") == "app.js.map"
    assert tasks.sourcemap_ref("//@ sourceMappingURL=/static/b.map") == "/static/b.map"
    assert tasks.sourcemap_ref("no map here") is None


def test_decode_inline_sourcemap():
    import base64

    payload = base64.b64encode(b'{"version":3}').decode()
    assert tasks.decode_inline_sourcemap(f"data:application/json;base64,{payload}") == '{"version":3}'
    assert tasks.decode_inline_sourcemap("app.js.map") is None       # not a data: URI


def test_parse_sourcemap_reconstructs_sources():
    mt = '{"version":3,"sources":["src/a.js","src/b.js"],"sourcesContent":["export const a=1","//c"]}'
    out = tasks.parse_sourcemap(mt)
    assert ("src/a.js", "export const a=1") in out
    assert len(out) == 2
    assert tasks.parse_sourcemap("not json") == []
    assert tasks.parse_sourcemap('{"sources":["a"],"mappings":";;"}') == []   # no sourcesContent


# --- point 5a: cloud bucket enumeration (pure parsers) -----------------------------------------
def test_parse_cloud_refs_all_providers():
    text = (
        "https://assets-acme.s3.amazonaws.com/logo.png "
        "https://s3.eu-west-1.amazonaws.com/acme-backups/db.sql "
        "https://storage.googleapis.com/acme-static/app.js "
        "https://acmeblob.blob.core.windows.net/uploads/x"
    )
    got = {(r["provider"], r["bucket"]) for r in tasks.parse_cloud_refs(text)}
    assert ("s3", "assets-acme") in got
    assert ("s3", "acme-backups") in got
    assert ("gcs", "acme-static") in got
    assert ("azure", "acmeblob/uploads") in got


def test_bucket_candidates_from_apex():
    cands = tasks.bucket_candidates("ginandjuice.shop")
    assert "ginandjuice" in cands
    assert "ginandjuice-backups" in cands
    assert "assets-ginandjuice" in cands
    assert tasks.bucket_candidates("") == []


def test_cloud_findings_public_beats_exists():
    meta = {"https://a.s3.amazonaws.com": {"provider": "s3", "bucket": "a", "source": "candidate"},
            "https://b.s3.amazonaws.com": {"provider": "s3", "bucket": "b", "source": "passive"}}
    findings = tasks.cloud_findings(
        {"https://a.s3.amazonaws.com"},
        {"https://a.s3.amazonaws.com", "https://b.s3.amazonaws.com"}, meta)
    by = {f["url"]: f for f in findings}
    assert by["https://a.s3.amazonaws.com"]["type"] == "cloud-bucket-public"
    assert by["https://a.s3.amazonaws.com"]["severity"] == "high"
    assert by["https://b.s3.amazonaws.com"]["type"] == "cloud-bucket-exists"   # 403 only


def test_cross_group_surface_routes_by_owning_host(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("xref1", root=tmp_path).ensure()
    a = act.app("attack.com-aaaa").ensure()
    b = act.app("api.company.com-bbbb").ensure()
    tools.write_lines(a.hosts, ["https://attack.com"])
    tools.write_lines(b.hosts, ["https://api.company.com"])
    # discovered under A: one endpoint on B's host, one on a host owned by no group
    tools.write_lines(a.canonical("endpoints_js.txt"),
                      ["https://api.company.com/v1/users", "https://third.example/x"])
    tools.write_jsonl(a.canonical("requests_crawl.jsonl"),
                      [{"method": "POST", "url": "https://api.company.com/v1/login",
                        "headers": {}, "body": "u=1", "params": [], "raw": "r", "sources": ["katana"]}])
    routed = tasks._cross_group_surface(act, b)
    urls = {r["url"] for r in routed}
    assert "https://api.company.com/v1/users" in urls   # endpoint routed into B
    assert "https://api.company.com/v1/login" in urls    # request routed into B
    assert "https://third.example/x" not in urls         # no group owns it → dropped (RoE)
    login = next(r for r in routed if r["url"].endswith("/login"))
    assert login["method"] == "POST"                     # request shape preserved
    assert any(s.startswith("xref:attack.com") for s in login["sources"])  # provenance tag


def test_cross_group_surface_excludes_own_group(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("xref2", root=tmp_path).ensure()
    b = act.app("b").ensure()
    tools.write_lines(b.hosts, ["https://api.company.com"])
    tools.write_lines(b.canonical("endpoints_js.txt"), ["https://api.company.com/self"])
    # only B exists; its own artifacts must not be harvested
    assert tasks._cross_group_surface(act, b) == []
