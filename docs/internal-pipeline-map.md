# ptflow · pipeline internal — mappa concettuale (flowchart)

> **Auto-generata** da `ptflow.core.flowdocs` — **non modificare a mano**: un hook la
> rigenera a ogni modifica sotto `src/ptflow/pipelines/`, quindi i comandi e l'ordine qui sotto
> seguono il codice. Versione interattiva pan/zoom: [`internal-pipeline-map.html`](internal-pipeline-map.html).
> Spec dettagliata per-step (summary/output/note): [`internal-pipeline-flow.html`](internal-pipeline-flow.html).

```mermaid
flowchart TD
scope(["scope.txt"])
subgraph BREADTH["① BREADTH · activity scope — una volta su tutto lo scope"]
direction TB
expand["expand  ·  net=False<br>mapcidr -silent   # ogni CIDR → IP · scope IP passthrough se mapcidr assente"]
discover["discover<br>nmap -sn -n -oG - -iL -   # parse_nmap_up: le righe 'Status: Up'"]
portscan["portscan<br>naabu -silent -p &lt;INTERNAL_PORTS&gt; -c &lt;conc&gt; -rate &lt;rate&gt;   # rate/conc = profilo<br># parse_naabu: righe ip:port → [{ip, port}]"]
end
scope -.->|∥ offline| expand
expand --> discover
discover --> portscan
CLUSTER{{"② CLUSTER · pivot fan-out<br>→ scans/&lt;subnet&gt;/"}}
BREADTH ==> CLUSTER
subgraph P1["③ PER-APP · FASE 1 · inventario servizi"]
direction TB
fingerprint["fingerprint<br>nerva --json   # stdin = le socket ip:port del gruppo (dalla fetta di ports.jsonl)"]
end
CLUSTER ==> P1
BAR2[["━━ BARRIERA: FASE 1 → FASE 2 ━━"]]
P1 ==> BAR2
subgraph P2["FASE 2 · frutti bassi"]
direction TB
cve_lookup["cve_lookup  ·  net=False<br># software_from_services: (prodotto, versione) dai record nerva — solo version-pinned<br>search_vulns -q '&lt;Prodotto Versione&gt;' -f json --ignore-general-product-vulns<br>                                              --use-created-product-ids<br># cache memo process-wide → il fan-out per-subnet non ri-interroga lo stesso prodotto"]
smb_checks["smb_checks<br>nxc smb &lt;host…&gt; -u '' -p ''   # gated su 445 aperta (dai ports.jsonl del gruppo)<br># parse_nxc_smb: [*] signing:False/SMBv1:True (medium) · [+] Pwn3d! (high)/valid (medium)"]
snmp_checks["snmp_checks<br>onesixtyone -c &lt;communities.txt&gt; -i &lt;hosts.txt&gt;   # public/private/community/manager/cisco<br># parse_onesixtyone: 'ip [community] sysDescr' → snmp-default-community"]
ldap_checks["ldap_checks<br>ldapsearch -x -H ldap://&lt;host&gt; -s base -b '' namingContexts   # gated su 389/636 aperta"]
nuclei_net["nuclei_net<br>nuclei -silent -duc -j -tags network,default-login   # stdin = le socket ip:port"]
end
BAR2 ==> P2
FANIN[["④ FAN-IN · consolidate<br>findings/&lt;tipo&gt;.jsonl"]]
P2 ==> FANIN
classDef breadth fill:#0d2f54,stroke:#4f9be6,color:#dbe9fb;
classDef span fill:#2e2147,stroke:#a98ee0,color:#ece4fb;
classDef pivot fill:#073b42,stroke:#34d3e6,color:#d6fbff;
classDef bar fill:#3a424c,stroke:#8a96a3,color:#eef2f6,font-weight:bold;
classDef fanin fill:#10331c,stroke:#54d07a,color:#dcf6e3,font-weight:bold;
classDef phase1 fill:#10331c,stroke:#4cc46b,color:#dcf6e3;
classDef phase2 fill:#3a2f06,stroke:#e6c247,color:#f8edc2;
class expand,discover,portscan breadth
class fingerprint phase1
class cve_lookup,smb_checks,snmp_checks,ldap_checks,nuclei_net phase2
class CLUSTER pivot
class BAR2 bar
class FANIN fanin
```
