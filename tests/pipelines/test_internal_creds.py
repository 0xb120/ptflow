from ptflow.pipelines.internal import creds


def test_service_sockets_extracts_product_from_field_or_banner():
    services = [
        {"ip": "10.0.0.5", "port": 22, "service": "ssh",
         "metadata": {"banner": "SSH-2.0-OpenSSH_8.9p1"}},
        {"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"},
        {"host": "10.0.0.6", "port": None},
    ]
    socks = creds.service_sockets(services)
    assert len(socks) == 2
    assert next(s for s in socks if s.port == 22).product == "OpenSSH"
    assert next(s for s in socks if s.port == 8443).product == "Acme Router"


def test_product_match_is_bidirectional_and_casefold():
    assert creds._product_matches("Acme Router", "acme router firmware")
    assert creds._product_matches("OpenSSH 8.9", "openssh")
    assert not creds._product_matches("Acme", "")


def test_socket_proto_prefers_service_then_port():
    assert creds.socket_proto(creds.ServiceSocket("h", 3389, "", "ms-wbt-server", "")) == "rdp"
    assert creds.socket_proto(creds.ServiceSocket("h", 5432, "", "", "")) == "postgres"
    assert creds.socket_proto(creds.ServiceSocket("h", 12345, "", "weird", "")) is None


def test_web_urls_uses_web_targets_rule():
    services = [{"ip": "10.0.0.5", "port": 8443, "service": "https"},
                {"ip": "10.0.0.5", "port": 22, "service": "ssh"}]
    urls = creds.web_urls(services)
    assert urls[("10.0.0.5", 8443)] == "https://10.0.0.5:8443"
    assert ("10.0.0.5", 22) not in urls


def test_mode_flags_bundle(monkeypatch):
    monkeypatch.delenv("PTFLOW_CREDS_MODE", raising=False)
    assert creds.resolve_mode() == "cautious"
    assert creds.mode_flags()[:2] == ["-t", "5"]
    assert "--rate-limit" in creds.mode_flags()
    monkeypatch.setenv("PTFLOW_CREDS_MODE", "aggressive")
    assert creds.mode_flags()[:2] == ["-t", "20"]
    monkeypatch.setenv("PTFLOW_CREDS_MODE", "bogus")
    assert creds.resolve_mode() == "cautious"


def test_parse_lockout_threshold_reads_ad_password_policy():
    assert creds.parse_lockout_threshold([{"type": "ad-password-policy", "lockout_threshold": "5"}]) == 5
    assert creds.parse_lockout_threshold([{"type": "ad-password-policy", "lockout_threshold": "None"}]) == 0
    assert creds.parse_lockout_threshold([{"type": "ad-users-enumerated"}]) is None
    assert creds.parse_lockout_threshold([]) is None


def test_account_budget_semantics():
    assert creds.account_budget(None, 3) == 2
    assert creds.account_budget(0, 3) is None
    assert creds.account_budget(1, 3) == 0
    assert creds.account_budget(5, 3) == 4


def test_apply_lockout_caps_per_account_and_skips():
    attempts = [
        {"product": "DC", "protocol": "smb", "host": "10.0.0.1", "port": 445,
         "username": "admin", "password": p, "confidence": c}
        for p, c in (("p1", 0.9), ("p2", 0.5), ("p3", 0.1))
    ] + [{"product": "SW", "protocol": "ssh", "host": "10.0.0.2", "port": 22,
          "username": "root", "password": "x", "confidence": 0.9}]
    kept, skips = creds._apply_lockout(attempts, threshold=2, default=3)
    assert [a["password"] for a in kept if a["protocol"] == "smb"] == ["p1"]
    assert {a["password"] for a in kept if a["protocol"] == "ssh"} == {"x"}
    assert any(s["reason"] == "lockout_budget" for s in skips)
    kept2, skips2 = creds._apply_lockout(attempts, threshold=1, default=3)
    assert not [a for a in kept2 if a["protocol"] == "smb"]
    assert all(s["reason"] == "lockout_policy" for s in skips2 if s["protocol"] == "smb")


def test_parse_brutus_jsonl_keeps_hits_skips_noise():
    text = ('[*] scanning...\n'
            '{"protocol":"ssh","target":"10.0.0.5:22","username":"root","password":"toor"}\n'
            '{"not":"a hit"}\n\n')
    hits = creds.parse_brutus_jsonl(text)
    assert len(hits) == 1
    assert hits[0]["username"] == "root"


def test_redact_masks_password():
    assert creds.redact({"username": "a", "password": "s3cr3t"})["password"] == "****"  # noqa: S105
    assert creds.redact({"username": "a", "password": ""})["password"] == ""


def test_split_target():
    assert creds._split_target("10.0.0.5:22") == ("10.0.0.5", 22)
    assert creds._split_target("https://10.0.0.5:8443") == ("10.0.0.5", 8443)
    assert creds._split_target("10.0.0.5") == ("10.0.0.5", 0)


def _cand(product, user, pw, conf=0.9):
    return {"product": product, "username": user, "password": pw, "confidence": conf,
            "source_urls": ["https://vendor/manual"], "rationale": "manual"}


def test_plan_routes_web_to_both_and_net_to_brutus():
    services = [{"ip": "10.0.0.5", "port": 8443, "product": "Acme Router", "service": "https"},
                {"ip": "10.0.0.5", "port": 22, "product": "Acme Router", "service": "ssh"}]
    candidates = [_cand("Acme Router", "admin", "acme"), _cand("Ghost", "root", "x")]
    brutus, forms, skips = creds.plan_attempts(
        candidates, services, lockout_threshold=None, lockout_default=3)
    assert {(a["protocol"], a["port"]) for a in brutus} == {("https", 8443), ("ssh", 22)}
    assert {a["url"] for a in forms} == {"https://10.0.0.5:8443"}
    assert any(s["reason"] == "no_match" and s["product"] == "Ghost" for s in skips)


def test_group_forms_shape():
    forms = [{"product": "P", "url": "https://10.0.0.5:8443", "host": "10.0.0.5", "port": 8443,
              "username": "admin", "password": "a", "confidence": 0.9,
              "source_urls": ["u"], "rationale": "r"}]
    (job,) = creds.group_forms(forms)
    assert job["url"] == "https://10.0.0.5:8443"
    assert job["pairs"] == [("admin", "a")]
    assert job["by_pair"][("admin", "a")]["product"] == "P"
