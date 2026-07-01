from ptflow.core import tools, workspace
from ptflow.core.paths import Activity
from ptflow.pipelines.internal import tasks


# --- pure transforms ---------------------------------------------------------------------------
def test_scope_entries_keeps_only_ip_and_cidr():
    text = "10.0.0.0/24\n192.168.1.5\nexample.com\nhttps://x.test/\n# comment\n"
    assert tasks.scope_entries(text) == ["10.0.0.0/24", "192.168.1.5"]


def test_subnet_slug_is_filesystem_safe_and_readable():
    assert tasks.subnet_slug("10.0.1.0/24") == "10.0.1.0-24"
    assert tasks.subnet_slug("192.168.5.10") == "192.168.5.10-32"
    assert tasks.subnet_slug("10.0.1.5/24") == "10.0.1.0-24"  # host bits normalised away
    assert tasks.subnet_slug("not-an-ip") == ""


def test_assign_hosts_longest_prefix_wins_on_overlap():
    entries = ["10.0.0.0/16", "10.0.1.0/24"]
    hosts = ["10.0.1.5", "10.0.2.9"]
    groups = tasks.assign_hosts(entries, hosts)
    # 10.0.1.5 belongs to the more-specific /24; 10.0.2.9 only to the /16
    assert groups == {"10.0.1.0-24": ["10.0.1.5"], "10.0.0.0-16": ["10.0.2.9"]}


def test_assign_hosts_bare_ip_and_out_of_scope():
    entries = ["10.0.0.0/24", "192.168.5.10"]
    hosts = ["10.0.0.7", "192.168.5.10", "8.8.8.8"]  # 8.8.8.8 is in no entry → dropped
    groups = tasks.assign_hosts(entries, hosts)
    assert groups == {"10.0.0.0-24": ["10.0.0.7"], "192.168.5.10-32": ["192.168.5.10"]}


def test_assign_hosts_no_empty_groups():
    groups = tasks.assign_hosts(["10.0.0.0/24", "172.16.0.0/24"], ["10.0.0.1"])
    assert list(groups) == ["10.0.0.0-24"]  # the dead 172.16 range produces no group


def test_parse_nmap_up():
    grep = (
        "# Nmap 7.94\n"
        "Host: 10.0.0.1 (gw)\tStatus: Up\n"
        "Host: 10.0.0.2 ()\tStatus: Down\n"
        "Host: 10.0.0.3 (srv)\tStatus: Up\n"
    )
    assert tasks.parse_nmap_up(grep) == ["10.0.0.1", "10.0.0.3"]


def test_parse_naabu():
    assert tasks.parse_naabu(["10.0.0.1:445", "10.0.0.1:139", "garbage", "10.0.0.2:22"]) == [
        {"ip": "10.0.0.1", "port": 445},
        {"ip": "10.0.0.1", "port": 139},
        {"ip": "10.0.0.2", "port": 22},
    ]


def test_software_from_services_explicit_and_banner():
    records = [
        {"host": "10.0.0.1", "port": 22, "product": "OpenSSH", "version": "8.9"},
        {"host": "10.0.0.2", "port": 80, "metadata": {"banner": "Apache/2.4.49 (Unix)"}},
        {"host": "10.0.0.3", "port": 3306, "metadata": {"banner": "no version here"}},
    ]
    sw = tasks.software_from_services(records)
    assert {"product": "openssh", "version": "8.9", "hosts": ["10.0.0.1:22"]} in sw
    assert {"product": "apache", "version": "2.4.49", "hosts": ["10.0.0.2:80"]} in sw
    assert all(s["product"] != "no" for s in sw)  # the version-less banner yields nothing


def test_parse_nxc_smb_banner_and_auth():
    out = (
        "SMB  10.0.0.1  445  DC01     [*] Windows Server 2019 x64 (name:DC01) (domain:corp.local) "
        "(signing:True) (SMBv1:False)\n"
        "SMB  10.0.0.2  445  WS01     [*] Windows 10 x64 (name:WS01) (domain:corp.local) "
        "(signing:False) (SMBv1:True)\n"
        "SMB  10.0.0.2  445  WS01     [+] corp.local\\guest: (Guest)\n"
        "SMB  10.0.0.3  445  FILESRV  [+] corp.local\\admin:Passw0rd (Pwn3d!)\n"
        "SMB  10.0.0.4  445  WS02     [-] corp.local\\user:bad STATUS_LOGON_FAILURE\n"
    )
    findings = tasks.parse_nxc_smb(out)
    by = {(f["host"], f["type"]) for f in findings}
    # 10.0.0.1 has signing:True / SMBv1:False → no finding; 10.0.0.4 is a [-] failure → ignored
    assert ("10.0.0.2", "smb-signing-not-required") in by
    assert ("10.0.0.2", "smbv1-enabled") in by
    assert ("10.0.0.2", "smb-valid-auth") in by       # [+] guest session, not admin
    assert ("10.0.0.3", "smb-admin-access") in by     # Pwn3d! ⇒ high
    assert len(findings) == 4
    assert next(f for f in findings if f["type"] == "smb-admin-access")["severity"] == "high"


def test_parse_onesixtyone_requires_community_bracket():
    out = (
        "Scanning 1 hosts, 5 communities\n"
        "192.168.1.10 [public] Linux router 5.10\n"
        "Error opening community file cisco\n"
    )
    findings = tasks.parse_onesixtyone(out)
    assert len(findings) == 1
    assert findings[0]["host"] == "192.168.1.10"
    assert findings[0]["community"] == "public"


def test_parse_search_vulns():
    out = """{"OpenSSH 8.9": {"vulns": {"CVE-2024-1234": {
        "severity": {"CVSS": {"score": 7.5}}, "cisa_kev": true, "exploits": [], "cwe_ids": ["CWE-79"],
        "description": "example"}}}}"""
    recs = tasks.parse_search_vulns(out, "OpenSSH", "8.9")
    assert len(recs) == 1
    assert recs[0]["cve"] == "CVE-2024-1234"
    assert recs[0]["kev"] is True
    assert recs[0]["exploited"] is True  # KEV ⇒ exploited even with no exploits listed
    assert tasks.parse_search_vulns("not json", "x", "1") == []
    assert tasks.parse_search_vulns('{"x": "no match warning"}', "x", "1") == []


# --- cluster() end-to-end (no external tools) --------------------------------------------------
def test_cluster_partitions_by_scope_cidr(tmp_path):
    act = Activity.named("intdemo", root=tmp_path).ensure()
    act.scope_init.write_text("10.0.1.0/24\n10.0.2.0/24\n", encoding="utf-8")
    canon = act.asset_discovery_canonical
    tools.write_lines(canon("live_hosts.txt"), ["10.0.1.5", "10.0.1.9", "10.0.2.3"])
    tools.write_jsonl(canon("ports.jsonl"), [
        {"ip": "10.0.1.5", "port": 445}, {"ip": "10.0.2.3", "port": 22},
    ])
    app_ids = tasks.cluster(act)
    assert app_ids == ["10.0.1.0-24", "10.0.2.0-24"]

    ws1 = act.app("10.0.1.0-24")
    assert tools.read_lines(ws1.hosts) == ["10.0.1.5", "10.0.1.9"]
    meta = workspace.read_meta(ws1.meta)
    assert meta["cidr"] == "10.0.1.0/24"
    # each group carries only its own slice of the open-port records
    assert tools.read_jsonl(ws1.canonical("ports.jsonl")) == [{"ip": "10.0.1.5", "port": 445}]


def test_consolidate_lifts_per_subnet_findings(tmp_path):
    act = Activity.named("intdemo", root=tmp_path).ensure()
    ws = act.app("10.0.1.0-24").ensure()
    tools.write_jsonl(ws.findings / "smb.jsonl", [{"type": "smb-signing-disabled", "evidence": "x"}])
    counts = tasks.consolidate(act)
    assert counts == {"smb": 1}
    lifted = tools.read_jsonl(act.findings / "smb.jsonl")
    assert lifted == [{"app_id": "10.0.1.0-24", "type": "smb-signing-disabled", "evidence": "x"}]


# --- web-service aggregation + external hand-off (pipeline composition) ---------------------------
def test_web_targets_from_scheme_and_filter():
    ports = [
        {"ip": "10.0.0.1", "port": 80},
        {"ip": "10.0.0.1", "port": 443},
        {"ip": "10.0.0.2", "port": 22},      # not a web port, no http banner → dropped
        {"ip": "10.0.0.3", "port": 7777},    # odd port, but the banner says http → kept as http
    ]
    services = [
        {"ip": "10.0.0.3", "port": 7777, "metadata": {"banner": "HTTP/1.1 200 OK"}},
        {"ip": "10.0.0.1", "port": 443, "service": "https"},
    ]
    assert tasks.web_targets_from(ports, services) == [
        "http://10.0.0.1:80", "http://10.0.0.3:7777", "https://10.0.0.1:443",
    ]


def test_consolidate_writes_web_targets(tmp_path):
    act = Activity.named("intdemo", root=tmp_path).ensure()
    ws = act.app("10.0.1.0-24").ensure()
    tools.write_jsonl(ws.canonical("ports.jsonl"),
                      [{"ip": "10.0.1.5", "port": 8080}, {"ip": "10.0.1.6", "port": 22}])
    tools.write_jsonl(ws.canonical("services.jsonl"), [])
    tasks.consolidate(act)
    assert tools.read_lines(act.base / "web_targets.txt") == ["http://10.0.1.5:8080"]


def test_followups_opt_in(tmp_path, monkeypatch):
    act = Activity.named("intdemo", root=tmp_path).ensure()
    tools.write_lines(act.base / "web_targets.txt", ["http://10.0.1.5:8080"])
    monkeypatch.delenv("PTFLOW_INTERNAL_WEB_HANDOFF", raising=False)
    assert tasks.followups(act) == []                       # off by default (external-call RoE gate)
    monkeypatch.setenv("PTFLOW_INTERNAL_WEB_HANDOFF", "on")
    fus = tasks.followups(act)
    assert len(fus) == 1
    assert fus[0].pipeline == "webscan"
    assert fus[0].activity == "web_recon"
    assert fus[0].scope.endswith("web_targets.txt")


def test_followups_no_web_service_is_noop(tmp_path, monkeypatch):
    act = Activity.named("intdemo", root=tmp_path).ensure()
    monkeypatch.setenv("PTFLOW_INTERNAL_WEB_HANDOFF", "on")
    assert tasks.followups(act) == []                       # no web_targets.txt → nothing to hand off


# --- pipeline object shape ---------------------------------------------------------------------
def test_pipeline_object_shape():
    from ptflow.pipelines.internal.pipeline import PIPELINE

    assert PIPELINE.name == "internal"
    names = [s.name for s in PIPELINE.stages]
    assert names == ["expand", "discover", "portscan", "fingerprint", "cve_lookup",
                     "smb_checks", "snmp_checks", "ldap_checks", "nuclei_net"]
    by_name = {s.name: s for s in PIPELINE.stages}
    assert by_name["fingerprint"].per_app is True
    assert by_name["fingerprint"].phase == 1
    assert all(by_name[n].phase == 2 for n in ("cve_lookup", "smb_checks", "nuclei_net"))
    assert by_name["cve_lookup"].net is False  # offline CVE correlation
    assert by_name["expand"].net is False


def test_load_pipeline_resolves_internal():
    from ptflow.pipelines import load_pipeline

    assert load_pipeline("internal").name == "internal"


def test_requirements_manifest_covers_internal_tool_dicts():
    reqs = tasks.requirements()
    by_name = {r.name: r for r in reqs}
    for name in tasks._CORE_TOOLS:
        assert by_name[name].kind == "core"
    for name in tasks._OPTIONAL_TOOLS:
        assert by_name[name].kind == "optional"
    # internal's OWN toolset (nmap/netexec/…), not external's web toolchain
    assert by_name["nmap"].kind == "core"
    assert "netexec" in by_name
