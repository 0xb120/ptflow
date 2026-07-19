"""Internal pipeline flow-map metadata (the per-step prose the generic renderer can't derive).

`FLOWMETA` is the per-step description (summary/commands/outputs/notes); `SPEC` bundles it with the
title, phase labels and the two non-Stage structural nodes (the per-subnet cluster pivot and the
terminal fan-in). The pipeline exposes `SPEC` via its `flowmap_spec()` hook, and the shared generator
`ptflow.core.flowdocs` renders the three `docs/internal-pipeline-*` views from it.

When you add or change a step in `pipeline.py`/`tasks.py`, add/adjust its `StepMeta` here — the dev
gate (`tests/pipelines/test_flowmap.py`) fails if any Stage is missing one.

Regenerate manually:  uv run python -m ptflow.core.flowdocs
"""

from __future__ import annotations

from ptflow.core.flowmap import MapSpec, StepMeta

FLOWMETA: dict[str, StepMeta] = {
    # --- breadth (activity scope · UNA passata rate-controlled sull'intero scope) ---
    "expand": StepMeta(
        summary="BREADTH — espande lo scope IP/CIDR in una lista di host candidati (mapcidr). "
                "Trasformazione OFFLINE (net=False): nessun pacchetto, solo enumerazione degli indirizzi.",
        commands=("mapcidr -silent   # ogni CIDR → IP · scope IP passthrough se mapcidr assente",),
        outputs=("scope/scope_ip.txt",),
        notes=("solo IP/CIDR: scope_entries tiene i token kind ip|cidr, deduplicati",),
    ),
    "discover": StepMeta(
        summary="BREADTH — ping sweep nmap -sn per trovare gli host LIVE. Se nmap manca o l'ICMP è "
                "filtrato (0 host), fallback su TUTTI i candidati così il portscan gira lo stesso.",
        commands=("nmap -sn -n -oG - -iL -   # parse_nmap_up: le righe 'Status: Up'",),
        outputs=("asset_discovery/live_hosts.txt",),
        notes=("fallback ICMP-filtrato: nessun segnale live → usa tutti i candidati (non salta la scansione)",),
    ),
    "portscan": StepMeta(
        summary="BREADTH — naabu sul set curato di porte di servizio interne (INTERNAL_PORTS, ~100 TCP: "
                "SMB/LDAP/RDP/DB/UI di mgmt) sugli host live → ports.jsonl. Whole-scope + rate-controlled: "
                "UNA passata gentile invece di N flood per-subnet (gear legacy/OT è fragile).",
        commands=("naabu -silent -p <INTERNAL_PORTS> -c <conc> -rate <rate>   # rate/conc = profilo",
                  "# parse_naabu: righe ip:port → [{ip, port}]"),
        outputs=("asset_discovery/ports.jsonl",),
        notes=("rate=profilo (wide 1000/50 · home 300/20) · SNMP è UDP/161 → lo sonda snmp_checks, non qui",
               "carico aggregato ≈ concorrenza x rate: il rate è la leva reale su una linea vincolata",
               "cluster() affetta ports.jsonl per subnet dopo — scan whole-scope, output per-subnet"),
    ),
    # --- spanning (whole-scope) — full-port scan → full-template nuclei, ∥ i loop ---
    "portscan_full": StepMeta(
        summary="SPANNING — scan naabu full 65535 porte sugli host live → ports_full.jsonl. Fuori dal "
                "percorso critico (∥ cluster + loop): i check per-subnet girano sul set curato veloce, "
                "il full-port alimenta nuclei_scope così vede servizi su porte non standard.",
        commands=("naabu -silent -p - -c <conc> -rate <rate>   # rate/conc = profilo, come il portscan veloce",),
        outputs=("asset_discovery/ports_full.jsonl",),
        notes=("stessa profilazione rate del portscan · best-effort: salta se naabu assente",),
    ),
    "nuclei_scope": StepMeta(
        summary="SPANNING — nuclei full-template su OGNI socket scoperta (set FULL-port di portscan_full, "
                "fallback al set veloce), UN solo processo con rate-limit globale (-rl). Più gentile del "
                "per-subnet su gear legacy/OT (una sweep globale invece di N flood). ∥ cluster + loop.",
        commands=("nuclei -ut                                    # update template (best-effort, air-gap ok)",
                  "nuclei -silent -duc -j -stats -rl <profilo>   # stdin = ip:port dai full-port"),
        outputs=("findings/nuclei_scope.jsonl",),
        notes=("-rl = profilo (wide 150 · home 50) · finding a livello activity (come external), non per-subnet",
               "legge ports_full.jsonl (portscan_full) → superficie completa · best-effort: salta se nuclei assente"),
    ),
    "fingerprint_full": StepMeta(
        summary="SPANNING — fingerprint del DELTA full-port (le socket che portscan_full trova OLTRE il set "
                "veloce) whole-scope con nerva → services_full.jsonl. ∥ cluster + loop (join al fan-in): un "
                "servizio su porta non standard ottiene un banner senza serializzare un fingerprint full-scan "
                "davanti al lavoro per-subnet. I banner alimentano cve_lookup_full E il rilevamento web dell'hand-off.",
        commands=("nerva --json   # stdin = delta_sockets(ports_full meno il set veloce), whole-scope",),
        outputs=("asset_discovery/services_full.jsonl",),
        notes=("delta puro/unit-tested: le porte veloci sono già fingerprinted nel loop 1 (niente doppioni)",
               "un web server su porta non standard è riconosciuto SOLO via banner → serve questo stage per l'hand-off",
               "best-effort: salta se nerva assente o delta vuoto"),
    ),
    "cve_lookup_full": StepMeta(
        summary="SPANNING (OFFLINE, net=False) — CVE NOTE sul software del DELTA full-port (services_full.jsonl) "
                "contro il DB locale di search_vulns → findings/cve_full.jsonl a LIVELLO ACTIVITY (come "
                "nuclei_scope; NON sollevato da consolidate). Il gemello whole-scope del cve_lookup per-subnet: "
                "copre le porte non standard che quello non vede.",
        commands=("# software_from_services sul delta → search_vulns -q '<Prodotto Versione>' -f json",
                  "#   --ignore-general-product-vulns --use-created-product-ids · cache memo process-wide"),
        outputs=("findings/cve_full.jsonl",),
        notes=("net=False: gira ∥ tutto, l'overlap col pass per-subnet è gratis via la memo condivisa",
               "delta naturale (solo socket oltre il set veloce) → nessun doppione con findings/cve.jsonl",
               "best-effort: salta se search_vulns/DB assenti"),
    ),
    # --- loop 1: inventario servizi (per-subnet) ---
    "fingerprint": StepMeta(
        summary="LOOP 1 — fingerprint dei servizi sulle socket aperte del gruppo (nerva --json; nmap -sV "
                "è l'alternativa drop-in) → services.jsonl. Base per i check gated del loop 2.",
        commands=("nerva --json   # stdin = le socket ip:port del gruppo (dalla fetta di ports.jsonl)",),
        outputs=("services.jsonl",),
        notes=("best-effort: salta se nerva assente · i banner alimentano cve_lookup + il rilevamento web",),
    ),
    # --- loop 2: frutti bassi (per-subnet · gated sui servizi del loop 1 · tutti ∥, nessun cross-need) ---
    "cve_lookup": StepMeta(
        summary="LOOP 2 — CVE NOTE sui servizi fingerprinted: correlazione OFFLINE (net=False, zero "
                "traffico) contro il DB locale di search_vulns. Gira ∥ agli altri check del loop 2.",
        commands=("# software_from_services: (prodotto, versione) dai record nerva — solo version-pinned",
                  "search_vulns -q '<Prodotto Versione>' -f json --ignore-general-product-vulns",
                  "                                              --use-created-product-ids",
                  "# cache memo process-wide → il fan-out per-subnet non ri-interroga lo stesso prodotto"),
        outputs=("findings/cve.jsonl",),
        notes=("DB costruito FUORI dal run (search_vulns -u) · best-effort: salta se binario/DB assenti",
               "ordinati per triage: known-exploited/KEV first, poi CVSS desc",
               "stessa correlazione offline della pipeline external (search_vulns fa lui il check dei range)"),
    ),
    "smb_checks": StepMeta(
        summary="LOOP 2 — postura SMB + LOOT via netexec sugli host con 445 aperta: signing non richiesto "
                "(NTLM-relay), SMBv1 (EternalBlue), null/guest, admin (Pwn3d!); poi — dalla STESSA sessione "
                "anonima — enum delle share (READ/WRITE) e spider SOLO-METADATI delle share non-default.",
        commands=("nxc smb <host…> -u '' -p ''            # postura → parse_nxc_smb",
                  "nxc smb <host…> -u '' -p '' --shares   # → parse_nxc_shares (WRITE=high · READ=medium)",
                  "nxc smb <host…> -u '' -p '' -M spider_plus -o OUTPUT_FOLDER=<dir>   # metadati, no download",
                  "# spider_interesting: file con nome sospetto (pass/secret/backup/.kdbx/…) → smb-interesting-file"),
        outputs=("findings/smb.jsonl",),
        notes=("read-only: lo spider è SOLO metadati (nessun download di contenuti — follow-up manuale)",
               "spider solo sugli host con una share READABLE non-default (IPC$/PRINT$/ADMIN$/C$ esclusi)",
               "best-effort: salta se nessuna 445 o netexec assente · brute-force/relay/coercion non wired"),
    ),
    "ad_enum": StepMeta(
        summary="LOOP 2 — enumerazione Active Directory SENZA credenziali via netexec sugli host con 445 "
                "aperta: RID cycling (utenti/gruppi di dominio via null session, funziona anche con "
                "RestrictAnonymous) + password policy (la soglia di lockout è il gate per lo spraying sicuro).",
        commands=("nxc smb <host…> -u '' -p '' --rid-brute   # → parse_nxc_rid_brute (utenti/gruppi)",
                  "nxc smb <host…> -u '' -p '' --pass-pol     # → parse_nxc_pass_pol (min length, lockout)",
                  "# → ad-users-enumerated (high) + ad-password-policy (info) · loot: domain_users/groups.txt"),
        outputs=("findings/ad_enum.jsonl",),
        notes=("no-cred: RID cycling via SAMR lookupsids · complementare al dump LDAP (funziona anche se LDAP anon è chiuso)",
               "la password policy prepara il futuro spraying (spray sotto-soglia = niente lockout)",
               "best-effort: salta se nessuna 445 o netexec assente"),
    ),
    "adcs_checks": StepMeta(
        summary="LOOP 2 — enumerazione ADCS SENZA credenziali via netexec `-M enum_ca` sugli host con 445 "
                "aperta: scoperta CA anonima (RPC epmapper su 135) + rilevamento ESC8 (il modulo stesso "
                "sonda /certsrv per il web enrollment HTTP → superficie di NTLM relay verso la CA).",
        commands=("nxc smb <host…> -u '' -p '' -M enum_ca   # CA discovery anonima + probe ESC8",
                  "# parse_enum_ca: 'Certificate Services Found' → adcs-ca-found · 'ESC8' → adcs-esc8-web-enrollment"),
        outputs=("findings/adcs.jsonl",),
        notes=("ESC8 (relay-based) è l'ESC no-cred — si accoppia con le liste smb/ldap-signing",
               "gli ESC su template (ESC1-7) richiedono un bind autenticato → fase con credenziali (certipy find)",
               "best-effort: salta se nessuna 445 o netexec assente"),
    ),
    "kerberoast_asrep": StepMeta(
        summary="LOOP 2 — AS-REP roasting SENZA credenziali via netexec sui KDC del gruppo (host con 88 "
                "aperta). Passa a `nxc ldap --asreproast` la userlist che ad_enum ha già prodotto "
                "(needs=ad_enum, dip. INTRA-loop) e chiede l'AS-REP per gli account DONT_REQ_PREAUTH: nessuna "
                "password inviata, nessun login tentato. Gli hash '$krb5asrep$…' sono loot crackabile offline.",
        commands=("nxc ldap <kdc…> -u domain_users.txt -p '' --asreproast asrep_hashes.txt   # gated su 88",
                  "# parse_asrep_roast: token $krb5asrep$<etype>$<user>@<REALM>:<hash> → asrep-roastable (high)"),
        outputs=("findings/asrep.jsonl",),
        notes=("no-cred: sfrutta il flag DONT_REQ_PREAUTH · userlist da ad_enum (RID cycling) via needs intra-loop",
               "best-effort: salta senza KDC (88) / userlist vuota / netexec assente"),
    ),
    "datastore_checks": StepMeta(
        summary="LOOP 2 — datastore esposti SENZA autenticazione sulle socket datastore del gruppo (Redis "
                "6379 / MongoDB 27017-8 / Memcached 11211 / MSSQL 1433, tutte nel set veloce). UNA run nmap "
                "NSE i cui script rispondono con dati solo se lo store risponde SENZA auth. Elasticsearch (9200) "
                "è HTTP → lasciato all'hand-off web + nuclei_scope. Non-distruttivo (nessun login).",
        commands=("nmap -Pn -n -sV -p <porte> --script redis-info,mongodb-info,mongodb-databases,memcached-info,"
                  "ms-sql-info -oN - <host…>",
                  "# parse_datastore_nse: '| <script>:' → *-unauth-access · mongodb-databases (high) > mongodb-info"),
        outputs=("findings/datastore.jsonl",),
        notes=("tiene il segnale più forte per (host, famiglia) · ms-sql-info = sola esposizione (info)",
               "best-effort: salta senza porta datastore aperta / nmap assente"),
    ),
    "snmp_checks": StepMeta(
        summary="LOOP 2 — community di default SNMP (UDP/161) via onesixtyone su TUTTI gli host + LOOT. Una "
                "community che risponde è un finding; da quella community poi snmpwalk di OID ad alto valore "
                "(system · processi · tabella ARP) → mappa di rete come loot.",
        commands=("onesixtyone -c <communities.txt> -i <hosts.txt>   # public/private/community/manager/cisco",
                  "# parse_onesixtyone: 'ip [community] sysDescr' → snmp-default-community",
                  "snmpwalk -v2c -c <community> <host> <OID>   # 1.3.6.1.2.1.1 / .25.4.2.1.2 / .4.22.1.2",
                  "# parse_snmpwalk: sysDescr + conteggio entry → snmp-info"),
        outputs=("findings/snmp.jsonl",),
        notes=("su TUTTI gli host del gruppo (161 UDP non è nel portscan) · walk read-only, bounded per OID",
               "best-effort: salta se onesixtyone/snmpwalk assenti"),
    ),
    "ldap_checks": StepMeta(
        summary="LOOP 2 — postura + LOOT LDAP sugli host con 389/636 aperta, SENZA credenziali. Due passate "
                "indipendenti: (1) signing/channel-binding dal banner core di netexec (superficie NTLM-relay "
                "→ LDAP); (2) bind anonimo via ldapsearch → naming context + dump account/description.",
        commands=("nxc ldap <host…> -u '' -p ''   # banner: (signing:None|Enforced) (channel binding:…)",
                  "#   parse_nxc_ldap_signing → ldap-signing-not-required · ldaps-no-channel-binding",
                  "ldapsearch -x -H ldap://<host> -s base -b '' namingContexts",
                  "ldapsearch -x -b <baseDN> -z 500 '(|(objectClass=user)…)' sAMAccountName uid description",
                  "#   → ldap-anonymous-bind · ldap-anon-users · ldap-user-description (password in desc)"),
        outputs=("findings/ldap.jsonl",),
        notes=("signing via il PROTOCOLLO core di nxc (il modulo ldap-checker è stato assorbito lì) — no-cred",
               "signing:None + smb-signing-not-required = catena NTLM-relay → LDAP (RBCD/DCSync)",
               "dump bounded (-z) · le description spesso contengono password temporanee · read-only",
               "best-effort: ogni passata salta se il suo tool (netexec/ldapsearch) è assente"),
    ),
    "ftp_checks": StepMeta(
        summary="LOOP 2 — login FTP ANONIMO via netexec sugli host con 21 aperta (`-u anonymous -p ''`). "
                "Una riga '[+]' = login anonimo riuscito → finding. Best-effort.",
        commands=("nxc ftp <host…> -u anonymous -p ''   # gated su 21 aperta",
                  "# parse_nxc_ftp: riga FTP con [+] → ftp-anonymous"),
        outputs=("findings/ftp.jsonl",),
        notes=("best-effort: salta se nessuna 21 o netexec assente · cap wall-clock CHECK_TIMEOUT (300s)",),
    ),
    "telnet_checks": StepMeta(
        summary="LOOP 2 — telnet CLEARTEXT esposto sugli host con 23 aperta (nmap -sV per il banner). "
                "Una porta telnet aperta è già un finding (credenziali in chiaro). Best-effort.",
        commands=("nmap -Pn -n -sV -p23 -oG - <host…>   # gated su 23 aperta",
                  "# parse_telnet: campo grepable 23/open/tcp//telnet//<banner>/ → telnet-exposed"),
        outputs=("findings/telnet.jsonl",),
        notes=("best-effort: salta se nessuna 23 o nmap assente",
               "rilevare no-auth affidabilmente richiede un login attempt (opt-in/futuro): v1 riporta l'esposizione + banner"),
    ),
    "nfs_checks": StepMeta(
        summary="LOOP 2 — export NFS leggibili anonimamente via showmount -e sugli host con 2049 aperta. "
                "Un export world-readable è LHF di alto valore (backup/home dir). Best-effort.",
        commands=("showmount -e <host>   # gated su 2049 aperta, per host",
                  "# parse_showmount: '<path> <clients>' → nfs-export (world '*'/'0.0.0.0' ⇒ high)"),
        outputs=("findings/nfs.jsonl",),
        notes=("best-effort: salta se nessuna 2049 o showmount (nfs-utils) assente",),
    ),
    "rsync_checks": StepMeta(
        summary="LOOP 2 — moduli rsync ANONIMI via `rsync rsync://host/` sugli host con 873 aperta. "
                "Moduli elencabili anonimamente espongono spesso un albero di filesystem. Best-effort.",
        commands=("rsync --contimeout=10 rsync://<host>/   # gated su 873 aperta, per host",
                  "# parse_rsync_modules: righe '<modulo> <commento>' (skip @ERROR/rsync:) → rsync-module"),
        outputs=("findings/rsync.jsonl",),
        notes=("best-effort: salta se nessuna 873 o rsync assente",),
    ),
    "netbios_checks": StepMeta(
        summary="LOOP 2 — identità NetBIOS (137/UDP, quindi su TUTTI gli host del gruppo come SNMP, fuori "
                "dal portscan TCP). nmap nbstat → hostname, utente loggato, MAC/vendor per host. Dati "
                "d'identità cheap e no-cred.",
        commands=("nmap -sU -Pn -n -p137 --script nbstat -oN - <host…>",
                  "# parse_nbstat: 'NetBIOS name/user/MAC' → netbios-info"),
        outputs=("findings/netbios.jsonl",),
        notes=("su TUTTI gli host (137 UDP non è nel portscan) · best-effort: salta se nmap assente",),
    ),
    "dns_checks": StepMeta(
        summary="LOOP 2 — zone transfer DNS (AXFR) sugli host con 53 aperta. Tenta le REVERSE zone del "
                "subnet (derivate deterministicamente dal CIDR del gruppo): un server permissivo "
                "restituisce la PTR map dell'intera subnet (inventario host). Finding high.",
        commands=("dig +time=5 +tries=1 axfr <N.N.N.in-addr.arpa> @<host>   # reverse_zones(cidr)",
                  "# parse_dig_axfr: record BIND → dns-zone-transfer (+ dump record in raw/dig/)"),
        outputs=("findings/dns.jsonl",),
        notes=("gated su 53 · reverse-zone dal CIDR (deterministico) · forward-zone via dominio = futuro",
               "best-effort: salta se nessuna 53 o dig assente"),
    ),
    "remote_desktop": StepMeta(
        summary="LOOP 2 — screenshot di RDP/VNC esposti con scrying (SENZA credenziali). Una sola run su "
                "tutte le socket RDP (3389) + VNC (5900-5906) del gruppo cattura login screen / desktop; "
                "un framebuffer VNC catturato = desktop raggiungibile senza auth (finding high).",
        commands=("scrying -f <targets rdp://·vnc://> -o raw/scrying/ --silent --disable-report",
                  "# parse_scrying: <proto>/<host>-<port>.png → rdp-screenshot (info) / vnc-screenshot (high)"),
        outputs=("findings/remote_desktop.jsonl", "screenshots/<proto>-<host>-<port>.png"),
        notes=("best-effort: salta se nessuna socket RDP/VNC o scrying assente · cap wall-clock (600s)",
               "gli screenshot sono ri-homati in scans/<subnet>/screenshots/ e referenziati dai finding",
               "no password spraying: solo cattura di ciò che è esposto (i check con credenziali sono futuri)"),
    ),
    "ai_credential_research": StepMeta(
        summary="[--ai] LOOP 2 — research agent sulle identità prodotto/versione di services.jsonl: "
                "cerca fonti pubbliche, naviga risultati e link scoperti e propone credenziali "
                "factory/default source-grounded. Nessun tentativo di login.",
        commands=("DuckDuckGo direct / Google Playwright search → HTTP(S) o headless",
                  "# agent loop engine/query/browser + multi-hop → credential_candidates.jsonl"),
        outputs=("credential_research_observations.jsonl", "credential_candidates.jsonl",
                 "raw/research/search_results.jsonl", "raw/research/sources.jsonl",
                 "raw/research/trace.jsonl"),
        notes=("agent:research · net=True · opt-in --ai · non invia IP/hostname nelle query",
               "solo proposte documentate; password file mode 0600; nessun password spraying"),
    ),
    "creds_test_brutus": StepMeta(
        summary="[opt-in PTFLOW_CREDS_TEST] LOOP 3 — prova le credenziali default source-grounded "
                "dell'agente sui servizi non-HTTP e sui pannelli HTTP Basic-auth via Brutus. Solo il set "
                "curato (mai wordlist / mai --experimental-ai), una invocazione per coppia x socket, lockout-aware.",
        commands=("brutus --target <ip:port> --protocol <p> -u <u> -p <p> --json <mode-flags>",
                  "# match prodotto→socket · budget lockout (threshold-1/account su smb/ldap/rdp/winrm)"),
        outputs=("findings/creds_brutus.jsonl", "raw/brutus/*.jsonl"),
        notes=("net=True · best-effort (salta se brutus/candidati/servizi assenti) · findings 0600",
               "PTFLOW_CREDS_MODE→flag reali (cautious=-t 5 --rate-limit 2 …); TLS skip di default"),
    ),
    "creds_test_forms": StepMeta(
        summary="[opt-in PTFLOW_CREDS_TEST] LOOP 3 — prova le credenziali default sui pannelli HTTP "
                "FORM-based via un FormLoginProbe Playwright NOSTRO (deterministico, niente chiave "
                "Anthropic): naviga, compila, invia e giudica il successo per euristica (lead/probable).",
        commands=("FormLoginProbe.attempt(url, user, pass) → judge_login(before, after)",
                  "# routing socket→web via web_targets_from · allow_private (target interni)"),
        outputs=("findings/creds_forms.jsonl",),
        notes=("net=True · best-effort (salta se playwright/chromium assente o nessun form) · findings 0600",
               "consolidate folda creds_brutus + creds_forms → findings/creds.jsonl (0600)"),
    ),
}

_PIVOT = StepMeta(
    summary="Partiziona gli host LIVE per la ENTRY DI SCOPE che li contiene (longest-prefix wins; un IP "
            "nudo è /32). Un gruppo scans/<subnet>/ per ogni entry con ≥1 host live: la compartimentazione "
            "per-subnet dell'operatore, non una /24 arbitraria. app_id = slug del CIDR, stabile.",
    outputs=("meta.json", "hosts.txt", "ports.jsonl"),
    notes=("assign_hosts è puro/unit-tested · scrive la fetta di ports.jsonl del gruppo (no re-scan)",
           "app_id = subnet_slug: '10.0.1.0/24' → '10.0.1.0-24' · '192.168.5.10' → '192.168.5.10-32'"),
)
_FANIN = StepMeta(
    summary="Fan-in terminale DETERMINISTICO (consolidate): solleva i findings per-subnet in "
            "<activity>/findings/<tipo>.jsonl (un file per categoria, ogni record con app_id = slug). "
            "Aggrega inoltre i servizi web in web_targets.txt e (opt-in) fa l'hand-off alla pipeline webscan.",
    outputs=("findings/cve.jsonl", "findings/smb.jsonl", "findings/ad_enum.jsonl", "findings/adcs.jsonl",
             "findings/asrep.jsonl", "findings/datastore.jsonl", "findings/snmp.jsonl", "findings/ldap.jsonl",
             "findings/ftp.jsonl", "findings/telnet.jsonl", "findings/nfs.jsonl", "findings/rsync.jsonl",
             "findings/netbios.jsonl", "findings/dns.jsonl", "findings/remote_desktop.jsonl", "web_targets.txt"),
    notes=("nuclei_scope E cve_full (delta full-port) sono già finding a livello activity — non sollevati qui",
           "web_targets: socket web per-subnet (set veloce) UNIONE full-port (ports_full + services_full) → "
           "un web server su porta NON standard, riconosciuto via banner, raggiunge l'hand-off",
           "hand-off webscan OPT-IN (PTFLOW_INTERNAL_WEB_HANDOFF): crawl/catalog/DAST/fuzz per servizio web",
           "web_targets.txt sempre scritto; solo l'auto-run è gated · seam agente (StubProvider) dormiente accanto"),
)

SPEC = MapSpec(
    title="ptflow · pipeline internal",
    thesis="Pentest interno IP/CIDR: la breadth mappa l'INTERO scope in UNA passata rate-controlled (più "
           "gentile del per-subnet su gear legacy/OT), il cluster fa da pivot fan-out partizionando gli "
           "host live per SUBNET DI SCOPE, poi i loop per-subnet vanno in profondità — inventario servizi, "
           "poi frutti bassi (CVE note offline + check SMB/SNMP/LDAP/nuclei ∥) — con una barriera globale "
           "tra loro. Ogni stage comunica solo via file su disco.",
    steps=FLOWMETA,
    phase_labels={1: "inventario servizi", 2: "frutti bassi", 3: "test credenziali default"},
    pivot=("scans/<subnet>/", _PIVOT),
    fanin=("consolidate", _FANIN),
)
