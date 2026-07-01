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


# --- loop-2 low-hanging-fruit parsers (anon services + RDP/VNC screenshots) --------------------
def test_parse_nxc_ftp_anonymous_success():
    out = (
        "FTP  10.0.0.1  21  10.0.0.1  [*] Banner: 220 (vsFTPd 3.0.3)\n"
        "FTP  10.0.0.1  21  10.0.0.1  [+] anonymous: \n"
        "FTP  10.0.0.2  21  10.0.0.2  [-] anonymous: (530 Login incorrect)\n"
    )
    findings = tasks.parse_nxc_ftp(out)
    assert len(findings) == 1                      # only the [+] anon success, not the [-] failure
    assert findings[0]["host"] == "10.0.0.1"
    assert findings[0]["type"] == "ftp-anonymous"


def test_parse_showmount_exports_severity():
    out = "Export list for 10.0.0.1:\n/srv/share *\n/home 10.0.0.0/24\nclnt_create: RPC: error\n"
    findings = tasks.parse_showmount(out, "10.0.0.1")
    exports = {f["export"]: f for f in findings}
    assert set(exports) == {"/srv/share", "/home"}     # the RPC error line is not an export
    assert exports["/srv/share"]["severity"] == "high"  # world-readable (*)
    assert exports["/home"]["severity"] == "medium"
    assert all(f["type"] == "nfs-export" and f["host"] == "10.0.0.1" for f in findings)
    assert tasks.parse_showmount("clnt_create: RPC: Timed out\n", "10.0.0.1") == []


def test_parse_rsync_modules():
    out = "data           \tBackup area\nwww            \tWeb root\n"
    findings = tasks.parse_rsync_modules(out, "10.0.0.1")
    assert {f["module"] for f in findings} == {"data", "www"}
    assert findings[0]["type"] == "rsync-module"
    assert findings[0]["host"] == "10.0.0.1"
    assert tasks.parse_rsync_modules("@ERROR: access denied\n", "10.0.0.1") == []   # error, no modules


def test_parse_telnet_exposed_from_grepable():
    out = (
        "Host: 10.0.0.1 (gw)\tPorts: 23/open/tcp//telnet//BusyBox telnetd/\n"
        "Host: 10.0.0.2 ()\tPorts: 23/closed/tcp//telnet///\n"
    )
    findings = tasks.parse_telnet(out)
    assert len(findings) == 1                       # only the open telnet port
    assert findings[0]["host"] == "10.0.0.1"
    assert findings[0]["type"] == "telnet-exposed"
    assert "BusyBox" in findings[0]["evidence"]


def test_parse_scrying_maps_pngs_to_findings():
    from pathlib import Path

    pngs = [
        Path("/act/scans/10.0.0.0-24/raw/scrying/rdp/10.0.0.5-3389.png"),
        Path("/act/scans/10.0.0.0-24/raw/scrying/vnc/10.0.0.9-5900.png"),
        Path("/act/scans/10.0.0.0-24/raw/scrying/web/10.0.0.1-80.png"),   # web is ignored
    ]
    findings = tasks.parse_scrying(pngs)
    by = {(f["protocol"], f["host"], f["port"]): f for f in findings}
    assert ("web", "10.0.0.1", 80) not in by                 # only rdp/vnc kept
    assert by[("rdp", "10.0.0.5", 3389)]["type"] == "rdp-screenshot"
    assert by[("vnc", "10.0.0.9", 5900)]["type"] == "vnc-screenshot"
    assert by[("vnc", "10.0.0.9", 5900)]["severity"] == "high"   # a captured VNC framebuffer ⇒ accessible


# --- loot parsers: SMB shares/spider · LDAP dump · SNMP walk (point 4 — from hit to loot) --------
def test_parse_nxc_shares_read_write():
    out = (
        "SMB  10.0.0.1  445  DC01  [*] Enumerated shares\n"
        "SMB  10.0.0.1  445  DC01  Share           Permissions     Remark\n"
        "SMB  10.0.0.1  445  DC01  IPC$            READ            Remote IPC\n"
        "SMB  10.0.0.1  445  DC01  data            READ,WRITE      \n"
        "SMB  10.0.0.1  445  DC01  backups         READ\n"
        "SMB  10.0.0.1  445  DC01  C$                              Default share\n"
    )
    findings = tasks.parse_nxc_shares(out)
    by = {f["share"]: f for f in findings}
    assert set(by) == {"data", "backups"}          # IPC$ noise excluded, C$ (no access) + headers skipped
    assert by["data"]["type"] == "smb-share-writable"
    assert by["data"]["severity"] == "high"
    assert by["backups"]["type"] == "smb-share-readable"
    assert all(f["host"] == "10.0.0.1" for f in findings)


def test_spider_interesting_filters_by_name():
    data = {"data": {"creds/passwords.xlsx": {"size": 12}, "readme.txt": {"size": 5},
                     "db/backup.bak": {"size": 99}, "id_rsa": {"size": 3}}}
    findings = tasks.spider_interesting(data, "10.0.0.1")
    paths = {f["path"] for f in findings}
    assert paths == {"creds/passwords.xlsx", "db/backup.bak", "id_rsa"}   # readme.txt not interesting
    assert all(f["type"] == "smb-interesting-file" and f["share"] == "data" for f in findings)


def test_parse_naming_contexts():
    out = "dn:\nnamingContexts: DC=corp,DC=local\nnamingContexts: CN=Configuration,DC=corp,DC=local\n"
    assert tasks.parse_naming_contexts(out) == ["DC=corp,DC=local", "CN=Configuration,DC=corp,DC=local"]


def test_parse_ldap_accounts():
    out = (
        "dn: CN=Alice,DC=corp,DC=local\nsAMAccountName: alice\ncn: Alice A\n\n"
        "dn: CN=Bob,DC=corp,DC=local\nsAMAccountName: bob\n\n"
        "dn: uid=carol,ou=People\nuid: carol\n"
    )
    accts = tasks.parse_ldap_accounts(out)
    assert accts == ["alice", "bob", "carol"]        # sAMAccountName + uid, sorted-unique


def test_parse_snmpwalk_summary():
    out = (
        "SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.10\n"
        "IP-MIB::ipNetToMediaPhysAddress.2.1.10.0.0.5 = STRING: 0:11:22:33:44:55\n"
        "\n"
    )
    summary = tasks.parse_snmpwalk(out)
    assert "Linux router" in summary["sysdescr"]
    assert summary["entries"] == 2                   # blank line not counted


# --- Tier-1 enumeration parsers: AD null-session · NetBIOS · DNS AXFR --------------------------
def test_parse_nxc_rid_brute():
    out = (
        "SMB  10.0.0.1  445  DC01  [*] Enumerating\n"
        "SMB  10.0.0.1  445  DC01  500: CORP\\Administrator (SidTypeUser)\n"
        "SMB  10.0.0.1  445  DC01  512: CORP\\Domain Admins (SidTypeGroup)\n"
        "SMB  10.0.0.1  445  DC01  1104: CORP\\alice (SidTypeUser)\n"
    )
    res = tasks.parse_nxc_rid_brute(out)
    assert res["users"] == ["Administrator", "alice"]
    assert res["groups"] == ["Domain Admins"]


def test_parse_nxc_pass_pol():
    out = ("SMB  x  445  DC01  Minimum password length: 7\n"
           "SMB  x  445  DC01  Account Lockout Threshold: None\n")
    pol = tasks.parse_nxc_pass_pol(out)
    assert pol["min_length"] == "7"
    assert pol["lockout_threshold"] == "None"


def test_parse_nxc_ldap_signing():
    out = (
        "LDAP  10.0.0.1  389  DC01  Windows Server 2019 (name:DC01) (domain:corp.local) "
        "(signing:None) (channel binding:Never)\n"
        "LDAP  10.0.0.2  389  DC02  Windows Server 2022 (name:DC02) (domain:corp.local) "
        "(signing:Enforced) (channel binding:Always)\n"
        "LDAP  10.0.0.3  389  SRV  Windows (signing:None) (channel binding:When Supported)\n"
    )
    by = {(f["host"], f["type"]) for f in tasks.parse_nxc_ldap_signing(out)}
    assert ("10.0.0.1", "ldap-signing-not-required") in by
    assert ("10.0.0.1", "ldaps-no-channel-binding") in by      # Never ≠ Always
    assert ("10.0.0.2", "ldap-signing-not-required") not in by  # Enforced
    assert ("10.0.0.2", "ldaps-no-channel-binding") not in by   # Always
    assert ("10.0.0.3", "ldaps-no-channel-binding") in by       # When Supported ≠ Always


def test_parse_ldap_descriptions_pairs_account_and_desc():
    out = ("dn: CN=Bob,DC=corp\nsAMAccountName: bob\ndescription: temp pw Summer2024\n\n"
           "dn: CN=Al,DC=corp\nsAMAccountName: al\n\n")
    assert tasks.parse_ldap_descriptions(out) == [{"account": "bob", "description": "temp pw Summer2024"}]


def test_parse_nbstat():
    out = (
        "Nmap scan report for 10.0.0.1\n"
        "Host script results:\n"
        "| nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:11:22:33:44:55 (VMware)\n"
    )
    findings = tasks.parse_nbstat(out)
    assert len(findings) == 1
    assert findings[0]["host"] == "10.0.0.1"
    assert findings[0]["name"] == "DC01"
    assert findings[0]["mac"].startswith("00:11:22:33:44:55")


def test_reverse_zones_from_cidr():
    assert tasks.reverse_zones("10.0.1.0/24") == ["1.0.10.in-addr.arpa"]
    assert tasks.reverse_zones("10.0.0.0/16") == ["0.10.in-addr.arpa"]
    assert tasks.reverse_zones("192.168.5.10/32") == ["5.168.192.in-addr.arpa"]
    assert tasks.reverse_zones("not-a-cidr") == []


def test_parse_dig_axfr():
    out = (
        "; <<>> DiG 9.18 <<>> axfr\n"
        "corp.local.\t86400\tIN\tSOA\tdc01. admin. 1 900\n"
        "dc01.corp.local.\t3600\tIN\tA\t10.0.0.1\n"
        "ws01.corp.local.\t3600\tIN\tA\t10.0.0.5\n"
    )
    recs = tasks.parse_dig_axfr(out)
    types = {r["rtype"] for r in recs}
    assert "A" in types
    assert "SOA" in types
    assert {r["name"] for r in recs if r["rtype"] == "A"} == {"dc01.corp.local.", "ws01.corp.local."}
    assert tasks.parse_dig_axfr("; Transfer failed.") == []


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
    assert names == ["expand", "discover", "portscan", "portscan_full", "nuclei_scope", "fingerprint",
                     "cve_lookup", "smb_checks", "ad_enum", "snmp_checks", "ldap_checks", "ftp_checks",
                     "telnet_checks", "nfs_checks", "rsync_checks", "netbios_checks", "dns_checks",
                     "remote_desktop"]
    by_name = {s.name: s for s in PIPELINE.stages}
    assert by_name["fingerprint"].per_app is True
    assert by_name["fingerprint"].phase == 1
    assert all(by_name[n].phase == 2 for n in
               ("cve_lookup", "smb_checks", "ad_enum", "ftp_checks", "netbios_checks", "dns_checks",
                "remote_desktop"))
    # full-port scan + whole-scope nuclei run ∥ the loops as SPANNING stages (off the critical path)
    assert by_name["portscan_full"].spanning is True
    assert by_name["nuclei_scope"].spanning is True
    assert by_name["nuclei_scope"].needs == ("portscan_full",)  # nuclei scans the COMPLETE surface
    assert "nuclei_net" not in by_name
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
