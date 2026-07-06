# tests/core/test_scope.py
from ptflow.core import scope


def test_classify():
    assert scope.classify("example.com") == "domain"
    assert scope.classify("https://a.example.com/x") == "url"
    assert scope.classify("*.example.com") == "wildcard"
    assert scope.classify("10.0.0.1") == "ip"
    assert scope.classify("10.0.0.0/24") == "cidr"


def test_normalize_url_and_wildcard():
    assert scope.normalize("https://A.Example.com/login", "url") == "a.example.com"
    assert scope.normalize("*.Example.com", "wildcard") == "example.com"
    assert scope.normalize("Example.COM", "domain") == "example.com"


def test_normalize_url_drops_explicit_port():
    # a host:port is not a resolvable DNS name — the port must not leak into scope_dns
    assert scope.normalize("https://example.com:8443/admin", "url") == "example.com"
    assert scope.normalize("http://10.0.0.1:8080", "url") == "10.0.0.1"
    # two ports on one host collapse to one resolution target (one Target after dedup)
    text = "https://example.com:8443/\nhttps://example.com:9000/x\n"
    assert sorted(t.normalized for t in scope.parse_scope(text)) == ["example.com"]


def test_target_id_stable_and_prefixed():
    tid = scope.target_id("example.com")
    assert tid.startswith("t_")
    assert len(tid) == 8
    assert tid == scope.target_id("example.com")


def test_parse_scope_dedups_and_skips_comments():
    text = "example.com\n# comment\n\nhttps://example.com/path\nnmap.org\n"
    targets = scope.parse_scope(text)
    # example.com and https://example.com/path normalize to the same host -> one target
    norms = sorted(t.normalized for t in targets)
    assert norms == ["example.com", "nmap.org"]


def test_target_from_meta_roundtrip():
    t = scope.Target(raw="example.com", kind="domain", normalized="example.com", tid="t_abc123")
    assert scope.target_from_meta(t.__dict__) == t


def test_classify_recognizes_ipv6_and_rejects_bad_octets():
    from ptflow.core import scope
    assert scope.classify("2001:db8::1") == "ip"
    assert scope.classify("2001:db8::/32") == "cidr"
    assert scope.classify("192.0.2.5") == "ip"
    assert scope.classify("192.0.2.0/24") == "cidr"
    assert scope.classify("999.0.0.1") == "domain"   # invalid octets → not an IP
    assert scope.classify("acme.com") == "domain"
    assert scope.classify("*.acme.com") == "wildcard"


def test_build_allowlist_buckets_by_kind():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope(
        "acme.com\nhttps://app.acme.com:8443/x\n*.evil.test\n192.0.2.0/24\n2001:db8::1\n"))
    assert "acme.com" in allow.exact_hosts
    assert "app.acme.com" in allow.exact_hosts        # url → bare host
    assert "evil.test" in allow.wildcard_apexes        # *.x → apex
    assert any(str(n) == "192.0.2.0/24" for n in allow.nets)
    assert any(n.version == 6 for n in allow.nets)     # ipv6 net present


def test_host_in_scope_exact_is_not_its_subdomains():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("acme.com\n"))
    assert scope.host_in_scope("acme.com", allow) is True
    assert scope.host_in_scope("ACME.com.", allow) is True     # case + trailing dot normalized
    assert scope.host_in_scope("app.acme.com", allow) is False  # bare domain ≠ its subdomains


def test_host_in_scope_wildcard_matches_apex_and_every_depth():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("*.acme.com\n"))
    assert scope.host_in_scope("acme.com", allow) is True        # apex included
    assert scope.host_in_scope("a.acme.com", allow) is True
    assert scope.host_in_scope("a.b.c.acme.com", allow) is True  # any depth
    assert scope.host_in_scope("acme.com.evil.test", allow) is False  # suffix-trick rejected


def test_ip_in_scope_v4_and_v6():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("192.0.2.0/24\n2001:db8::/32\n"))
    assert scope.ip_in_scope("192.0.2.5", allow) is True
    assert scope.ip_in_scope("192.0.3.5", allow) is False
    assert scope.ip_in_scope("2001:db8::dead", allow) is True
    assert scope.ip_in_scope("not-an-ip", allow) is False


def test_filter_assets_domain_scope_drops_thirdparty_name_and_ip():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("acme.com\n"))
    name_ips = {"acme.com": ["192.0.2.9"], "cdn.other.test": ["203.0.113.5"]}
    v = scope.filter_assets(["acme.com", "cdn.other.test"], name_ips,
                            ["192.0.2.9", "203.0.113.5"], allow)
    assert "acme.com" in v.kept_names
    assert "cdn.other.test" not in v.kept_names        # third-party apex dropped
    assert "192.0.2.9" in v.kept_ips                    # domain→IP kept
    assert "203.0.113.5" not in v.kept_ips              # third-party IP dropped


def test_filter_assets_ip_only_scope_recovers_vhost_by_rule4():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("192.0.2.0/24\n"))   # IP-only scope
    name_ips = {"mail.acme.com": ["192.0.2.5"],      # SAN on an in-scope IP
                "www.acme.com": ["203.0.113.7"]}     # public DNS points off-scope
    v = scope.filter_assets(["mail.acme.com", "www.acme.com"], name_ips,
                            ["192.0.2.5", "203.0.113.7"], allow)
    assert "mail.acme.com" in v.kept_names            # rule 4: resolves to an in-scope IP
    assert "www.acme.com" not in v.kept_names          # decision (a): resolves off-scope → dropped
    assert "192.0.2.5" in v.kept_ips
    assert "203.0.113.7" not in v.kept_ips


def test_filter_assets_anti_transitivity():
    from ptflow.core import scope
    allow = scope.build_allowlist(scope.parse_scope("acme.com\n"))  # a DOMAIN, no IP net
    # acme.com → 192.0.2.9 (domain-derived, scanned) — but that IP must NOT authorize other names
    name_ips = {"acme.com": ["192.0.2.9"], "hitchhiker.other.test": ["192.0.2.9"]}
    v = scope.filter_assets(["acme.com", "hitchhiker.other.test"], name_ips,
                            ["192.0.2.9"], allow)
    assert "acme.com" in v.kept_names
    assert "hitchhiker.other.test" not in v.kept_names   # rule 4 uses EXPLICIT nets only


def test_filter_assets_empty_allowlist_drops_all():
    from ptflow.core import scope
    allow = scope.build_allowlist([])
    v = scope.filter_assets(["a.test"], {"a.test": ["192.0.2.1"]}, ["192.0.2.1"], allow)
    assert not v.kept_names
    assert not v.kept_ips
    assert len(v.dropped) == 2
