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
