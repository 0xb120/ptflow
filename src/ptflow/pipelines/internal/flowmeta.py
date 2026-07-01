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
        summary="LOOP 2 — first-check SMB via netexec sugli host con 445 aperta: signing non richiesto "
                "(superficie NTLM-relay), SMBv1 (EternalBlue), sessione null/guest, accesso admin (Pwn3d!).",
        commands=("nxc smb <host…> -u '' -p ''   # gated su 445 aperta (dai ports.jsonl del gruppo)",
                  "# parse_nxc_smb: [*] signing:False/SMBv1:True (medium) · [+] Pwn3d! (high)/valid (medium)"),
        outputs=("findings/smb.jsonl",),
        notes=("best-effort: salta se nessuna 445 o netexec assente · cap wall-clock CHECK_TIMEOUT (300s)",
               "solo check non-distruttivi (null/guest) · brute-force/relay/coercion deliberatamente non wired"),
    ),
    "snmp_checks": StepMeta(
        summary="LOOP 2 — sweep community di default SNMP (UDP/161) via onesixtyone su TUTTI gli host del "
                "gruppo (161 è UDP, fuori dal portscan TCP). Una community che risponde è un finding.",
        commands=("onesixtyone -c <communities.txt> -i <hosts.txt>   # public/private/community/manager/cisco",
                  "# parse_onesixtyone: 'ip [community] sysDescr' → snmp-default-community"),
        outputs=("findings/snmp.jsonl",),
        notes=("su TUTTI gli host del gruppo (161 UDP non è nel portscan) · best-effort: salta se onesixtyone assente",),
    ),
    "ldap_checks": StepMeta(
        summary="LOOP 2 — bind anonimo LDAP via ldapsearch sugli host con 389/636 aperta: un rootDSE che "
                "restituisce i naming context senza credenziali è un finding.",
        commands=("ldapsearch -x -H ldap://<host> -s base -b '' namingContexts   # gated su 389/636 aperta",),
        outputs=("findings/ldap.jsonl",),
        notes=("best-effort: salta se nessuna 389/636 o ldapsearch assente",
               "parsing minimale (namingContexts:) — da rifinire dal vivo su un dominio reale"),
    ),
    "nuclei_net": StepMeta(
        summary="LOOP 2 — template nuclei network + default-login sulle socket aperte del gruppo → "
                "findings/nuclei_net.jsonl.",
        commands=("nuclei -silent -duc -j -tags network,default-login   # stdin = le socket ip:port",),
        outputs=("findings/nuclei_net.jsonl",),
        notes=("best-effort: salta se nuclei assente · -duc = disable update-check (offline-friendly)",),
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
    outputs=("findings/cve.jsonl", "findings/smb.jsonl", "findings/snmp.jsonl",
             "findings/ldap.jsonl", "findings/nuclei_net.jsonl", "web_targets.txt"),
    notes=("web_targets_from: socket con porta HTTP(S) o banner http → scheme://ip:port (https per TLS)",
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
    phase_labels={1: "inventario servizi", 2: "frutti bassi"},
    pivot=("scans/<subnet>/", _PIVOT),
    fanin=("consolidate", _FANIN),
)
