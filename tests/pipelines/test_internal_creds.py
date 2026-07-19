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
