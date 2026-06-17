# PIPT — Framework pipeline pentest automatizzate (scaffolding)

- **Data:** 2026-06-17
- **Stato:** design approvato in brainstorming, da rivedere prima del piano d'implementazione
- **Working dir:** `/opt/pipt`
- **Riferimenti:** `/opt/custom-tools/CONVENTIONS.md`, `/opt/custom-tools/pipeline/` (recon-pipeline Prefect esistente), `/opt/custom-tools/utils/` (recon pipeline bash documentata — fonte del modello dati)

---

## 1. Obiettivo

Costruire uno **scaffolding riusabile** per ospitare *diverse* pipeline di penetration testing automatizzate, basate su **Prefect** (≥3), con una **struttura fissa e documentata** in linea con `CONVENTIONS.md` e simile alla `pipeline/` esistente.

Questo giro costruisce il **framework (core) + una pipeline d'esempio minima** con tool *stub* (gira senza scanner reali). Il dominio specifico (web / network / ibrido) viene calato dentro lo scaffolding in un secondo momento.

### Requisiti chiave (dall'utente)

1. **DB locale SQLite light** per tracciare assets/ports/ecc., **e** salvataggio dei **file raw su disco**.
2. La pipeline funziona sia su scope **single-target** sia **multi-target**.
3. In multi-target: possibilità di scegliere se eseguire con lo **step di aggregazione** o senza.
4. Ogni target enumerato **in parallelo**.
5. Alla fine dell'enumerazione, uno **stage agent/modello** che fa ipotesi di vulnerabilità/exploitation (da automatizzare in seguito).

---

## 2. Decisioni prese (con motivazione)

| # | Decisione | Motivazione |
|---|-----------|-------------|
| D1 | **Framework (core) + pipeline pluggabili**, non estensione della `pipeline/` esistente | Quella è *una* pipeline (recon web); qui serve un core condiviso che ospiti *diverse* pipeline. |
| D2 | **Raw su disco = source of truth; SQLite = proiezione** popolata da **ingest serializzato** (single writer, WAL, idempotente) | Disaccoppiamento (schema in un posto solo), DB **ricostruibile** dai raw, retry idempotenti, snapshot consistenti, testabilità. *Non* è una scelta dettata dai lock (vedi §6). |
| D3 | **Breadth/depth dichiarativo per-pipeline**; default **phased-hybrid** (breadth-front single-invocation, depth-tail per-target) | È il punto d'incontro di reconFTW / Osmedeus / `pipeline/` esistente. Confine = una riga di config, non un refactor. |
| D4 | **Aggregazione = dedup di scope pre-enum** (toggle `--aggregate/--no-aggregate`) | ON: ogni asset unico enumerato/colpito una sola volta (risparmio lavoro/traffico). OFF: ogni target enumera il suo set anche se sovrapposto. Lo storage è deduplicato comunque dai vincoli `UNIQUE`. |
| D5 | **Stage agent/vuln-hypothesis = seam di prima classe + stub** | Contratto dati fissato ora (input: query inventario da SQLite → output: righe `hypothesis`); il provider Claude reale è un drop-in successivo. |
| D6 | **Tooling identico alla `pipeline/` esistente**: uv, ruff (`ALL`), ty, pytest, Prefect ≥3 | Coerenza col toolkit esistente. |
| D7 | **DB light: core generico + estensione per-pipeline.** NON si usa lo schema engagement di `org/templates/db/` (pesante, interno, popolato da un modello). Il modello dati è ispirato ai dati **reali** di `utils/`. | Core agnostico e leggero; ogni pipeline porta le sue tabelle di dominio. Vedi §5. |

### Contesto di ricerca (D3)

A livello di tool, **breadth è lo standard di fatto**: la toolchain classica (subfinder → httpx → naabu → katana → nuclei) ingerisce l'intera lista in *una* invocazione e si auto-parallelizza/rate-limita. A livello di framework: reconFTW è phase-major (breadth) con checkpoint/resume; **BBOT** è event-driven puro (senza fasi, ricorsivo); **Osmedeus** è un DAG dichiarativo (fasi sequenziali + analisi parallela); **Nextflow** (citato in `CONVENTIONS.md`) è dataflow con `collect()` come barrier. Il phased-hybrid scelto è il fit migliore per una pipeline documentata, a contratto e rieseguibile.

**Euristica per il default del confine:** uno stage è candidato *breadth* quando il suo tool mangia l'intera lista da solo; *depth* quando il lavoro si ramifica realmente per target (config per-app, download, logica custom, isolamento).

---

## 3. Struttura del progetto

```
/opt/pipt/
  README.md
  CONVENTIONS.md              # contratto: eredita quello di custom-tools, esteso col layer DB
  pyproject.toml  uv.lock     # mirror della pipeline/ esistente (uv build, ruff ALL, ty, pytest)
  db/
    schema.sql                # CORE light: target/host/service/host_target/hypothesis (vedi §5)
    queries/                  # query di reporting canoniche (core)
  src/pipt/
    core/
      config.py               # tunable centrali (rate, fanout, retries, net limit) — dataclass frozen
      paths.py                # Engagement / TargetWorkspace, id stabili, tutti i path del contratto
      workspace.py            # manifest.jsonl + meta.json helpers
      tools.py                # subprocess plumbing: run/pipe/dedupe/require
      db.py                   # SQLite: connect WAL, init_schema(core + estensione pipeline), upsert, query API
      ingest.py               # SINGLE-writer: raw/manifest -> upsert DB (idempotente, rieseguibile)
      stage.py                # astrazione Stage: dichiara mode = BREADTH | DEPTH
      orchestrator.py         # runner phased-hybrid generico (vedi §7)
      agent.py                # seam stage vuln-hypothesis + stub (vedi §8)
    pipelines/
      example/
        __init__.py
        pipeline.py           # dichiara la lista ordinata di Stage (breadth/depth)
        tasks.py              # task atomici d'esempio con tool STUB (gira senza scanner reali)
        schema.sql            # estensione DB d'esempio (1 tabella demo, per esercitare il meccanismo)
        ingest.py             # handler di ingest specifici della pipeline (role -> tabella di dominio)
    cli.py                    # pipt run <pipeline> <scan_id> <scope> [--no-aggregate] ...
  tests/
```

**Alternativa scartata:** estendere `pipeline/` direttamente (è una singola pipeline recon → non riusabile per pipeline diverse).

---

## 4. Contratto di workspace (estende `CONVENTIONS.md`)

Due livelli, perché il phased-hybrid ha stage scope-wide (breadth) e per-target (depth):

```
scans/<scan_id>/                      # = una Engagement
  scope.txt
  db/engagement.db                    # proiezione SQLite (WAL) — ricostruibile: pipt ingest <scan_id>
  surface/                            # output stage BREADTH (single-invocation su tutto lo scope)
    raw/<tool>/<run>/ ...             #   raw append-only, mai letto a valle
    <canonical>.{txt,jsonl}           #   artefatti canonici scope-wide
    manifest.jsonl                    #   role -> path + provenance
  targets/<target_id>/                # un workspace per target (id STABILE), output stage DEPTH
    meta.json                         #   identità: raw token, kind, normalized
    raw/<tool>/<run>/ ...
    <canonical>.{txt,jsonl}
    findings/  manifest.jsonl
```

Regole invariate dal contratto: **nessuno step legge da `raw/`**; ogni tool ha un **adapter sottile** che normalizza al nome canonico e appende una riga di manifest; **path solo via helper** (`Engagement`/`TargetWorkspace`), zero letterali; **`target_id` stabile** (hash del token normalizzato).

---

## 5. Layer SQLite — DB light (core + estensione per-pipeline)

**NON** si usa lo schema engagement di `org/templates/db/schema.sql` (pesante: credentials, segments, ledger IP DHCP, findings-markdown, trigger, pensato per popolamento via modello in un pentest interno). Il modello dati è invece ispirato ai **dati reali** prodotti dalla pipeline documentata in `utils/`:

| Entità | Da dove (`utils/`) | Campi reali |
|---|---|---|
| scope token | `scope_init.txt` | IP / domain / cidr / wildcard / url |
| host/dns | `subdomains.txt`, `tlsx_raw.txt`, `domain_ip_map.txt` | name (FQDN/IP) → IP, sorgente (dns/tls/ptr/subfinder) |
| service (porta) | `naabu_*_results.txt`, `fingerprintx`/`nerva` jsonl | ip, port, protocol, service, version |
| web asset (httpx) | `httpx_full_metadata.jsonl` | url, scheme, host, port, host_ip, status_code, content_length, content_type, webserver, title, tech[], body sha256, location |
| app cluster | `surfagr.sh` | identità = (title, content_length, webserver); rep_host, vhosts, screenshot |
| endpoint | `all_endpoints_clean.txt` | url, sorgente (gau/urlfinder/katana) |
| takeover | `run-takeover-*` | host, dettaglio/cname, tool (nuclei/subjack) |

### Core (`db/schema.sql`) — generico, valido per qualunque pipeline

```sql
PRAGMA foreign_keys = ON;  PRAGMA journal_mode = WAL;

CREATE TABLE target  ( id INTEGER PRIMARY KEY, tid TEXT UNIQUE, raw TEXT NOT NULL,
                       kind TEXT CHECK(kind IN('domain','ip','cidr','url','wildcard')),
                       first_seen DATETIME DEFAULT CURRENT_TIMESTAMP );

CREATE TABLE host    ( id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,   -- FQDN o IP
                       ip TEXT, source TEXT,                                -- dns|tls|ptr|subfinder|scope
                       first_seen DATETIME DEFAULT CURRENT_TIMESTAMP, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP );

CREATE TABLE service ( id INTEGER PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL,
                       protocol TEXT, service TEXT, version TEXT, source TEXT,  -- naabu|fingerprintx|nerva
                       first_seen DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(ip,port) );

CREATE TABLE host_target ( host_id INTEGER REFERENCES host(id) ON DELETE CASCADE,   -- provenienza target->host
                           target_id INTEGER REFERENCES target(id) ON DELETE CASCADE,
                           PRIMARY KEY(host_id,target_id) );

CREATE TABLE hypothesis ( id INTEGER PRIMARY KEY,
                          service_id INTEGER REFERENCES service(id) ON DELETE CASCADE,  -- FK core opzionale
                          subject TEXT,                                                 -- pointer libero a entità di pipeline (es. "webasset:<url>")
                          title TEXT NOT NULL, rationale TEXT, technique TEXT,
                          confidence TEXT CHECK(confidence IN('low','medium','high')),
                          source TEXT,                                                  -- 'stub' | nome modello
                          status TEXT DEFAULT 'proposed' CHECK(status IN('proposed','confirmed','dismissed')),
                          created_at DATETIME DEFAULT CURRENT_TIMESTAMP );
```

`hypothesis` resta core-pulita: FK forte solo a `service` (core); per entità di dominio (es. `webasset`) usa il pointer libero `subject` → nessuna dipendenza del core dalle tabelle di pipeline.

### Estensione per-pipeline (`pipelines/<nome>/schema.sql`)

Ogni pipeline aggiunge le sue tabelle di dominio. La futura **recon-web** porterà:

```sql
-- pipelines/recon/schema.sql  (esempio del meccanismo; costruito col dominio reale)
CREATE TABLE webasset ( id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, scheme TEXT, host TEXT, port INTEGER,
                        host_ip TEXT, status_code INTEGER, content_length INTEGER, content_type TEXT,
                        webserver TEXT, title TEXT, tech TEXT, body_hash TEXT, location TEXT, app_id INTEGER );
CREATE TABLE app      ( id INTEGER PRIMARY KEY, aid TEXT UNIQUE, title TEXT, content_length INTEGER,
                        webserver TEXT, rep_host TEXT, screenshot TEXT );   -- aid = hash(title|content_length|webserver)
CREATE TABLE endpoint ( id INTEGER PRIMARY KEY, app_id INTEGER, url TEXT, source TEXT, UNIQUE(app_id,url) );
CREATE TABLE takeover ( id INTEGER PRIMARY KEY, host TEXT NOT NULL, detail TEXT, tool TEXT );
```

`db.py::init_schema(pipeline)` carica **core + estensione attiva**. La pipeline d'esempio ship-a una `schema.sql` con **una sola tabella demo** per esercitare (e testare) il meccanismo di estensione senza dipendere da scanner reali.

`db.py` espone: `connect()` (WAL + `busy_timeout`), `init_schema(pipeline)`, upsert idempotenti per entità core (host/service/...), e una **query API** read-only per lo stage agent.

---

## 6. Ingest serializzato (flusso dati)

- I worker depth scrivono **solo** raw + manifest. **Mai** sul DB → zero contesa.
- `ingest.py` è l'**unico writer**: gira serializzato nel thread del flow (fuori dal fan-out), legge gli artefatti **per ruolo** dal manifest, fa **upsert idempotenti** (i `UNIQUE` deduplicano da soli). Eseguito ai barrier (dopo le fasi breadth, dopo le fasi depth).
- Gli handler di ingest sono **core** (role → tabella core) **+ contributi della pipeline** (`pipelines/<nome>/ingest.py`: role → tabella di dominio). Lo schema vive in `schema.sql`, la mappatura role→tabella in `ingest.py` — entrambi in un posto solo.
- `pipt ingest <scan_id>` **ricostruisce l'intero DB dai raw**.

**Perché serializzato e non direct-write** (deciso esplicitamente, vedi D2):
- Con WAL + `busy_timeout` + fan-out piccolo (~3 worker, governor `net` ~10) + scritture brevi, i lock *non* sarebbero un vero problema — il direct-write funzionerebbe.
- La scelta è per **disaccoppiamento** (schema in `ingest.py`/`schema.sql`, non in N adapter), **rebuildability** (DB ricostruibile, mai source of truth), **idempotenza** dei retry Prefect, **snapshot consistenti** ai barrier, **testabilità** (ingest = funzione pura `raw → righe`).
- Casi in cui il direct-write morderebbe davvero: stesso entity scritto da due worker (es. host condiviso in `--no-aggregate`), transazioni lunghe, scaling a multiprocessing/distribuito o DB su NFS (dove WAL non funziona).

---

## 7. Astrazione Stage + orchestrazione phased-hybrid

`stage.py` espone uno `Stage` che dichiara almeno:
- `name`
- `mode`: `BREADTH` (1 invocazione su tutto lo scope, barrier) | `DEPTH` (catena per-target, fan-out)
- `run`: il task/adapter Prefect
- `inputs`/`outputs`: ruoli letti/prodotti (risolti via manifest)

`ingest.py` (core + pipeline) mantiene gli handler **per ruolo → tabella** (la conoscenza dello schema sta qui, non negli Stage).

L'orchestratore generico, data la lista ordinata di Stage di una pipeline:

```
1. parse scope -> N target  (N=1 => single-target; aggregazione no-op)
2. STAGE BREADTH (discovery): ogni stage = 1 invocazione del tool su tutto lo scope
      -> raw in surface/ ;  INGEST serializzato
3. [--aggregate] BARRIER dedup pre-enum: union + dedupe host/asset cross-target
      -> set di asset unici (ogni asset enumerato/colpito 1 volta)
   [--no-aggregate] ogni target enumera il proprio set (overlap ri-enumerato)
4. STAGE DEPTH (enum): fan-out per target via Prefect .submit()/futures
      ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers) + governor globale tag `net`
      i worker scrivono SOLO raw + manifest
5. BARRIER INGEST serializzato: upsert di tutti i raw depth -> DB
6. STAGE agent (terminale): query inventario da DB -> hypotheses -> DB   (stub)
7. report finale
```

Il confine breadth/depth è **dichiarato nella pipeline**; l'orchestratore mette i barrier dove finiscono gli stage breadth e dove serve l'ingest. Single-target = N=1.

---

## 8. Stage agent/vuln-hypothesis (seam + stub)

`core/agent.py`: `propose_hypotheses(engagement)` interroga l'inventario dal DB (host/service + eventuali entità di pipeline come `webasset`) e delega a un `HypothesisProvider` (interfaccia). Granularità: **passata finale sull'inventario** (barrier terminale), con possibilità futura di farla anche per-target.

- **Stub** (questo giro): ritorna ipotesi d'esempio derivate dall'inventario, scritte come righe `hypothesis` (`source='stub'`, FK `service_id` o pointer `subject`).
- **Provider reale** (dopo): chiamata Claude (default: ultimo modello), drop-in dietro la stessa interfaccia. L'output resta `hypothesis` → da lì in futuro si automatizza la verifica/exploitation.

---

## 9. Config & CLI

- `config.py` (dataclass frozen, `CONFIG` singleton): rate limits per-tool, `fanout.max_workers`, retries (`tool_retries`, delay), `net` concurrency limit, default breadth/depth.
- CLI:
  - `pipt run <pipeline> <scan_id> <scope> [--root DIR] [--aggregate/--no-aggregate]`
  - `pipt ingest <scan_id>` (rebuild DB dai raw)
  - `pipt db query ...` (reporting)

---

## 10. Pipeline d'esempio (gira senza scanner reali)

`pipelines/example/` dichiara ~4 stage con **tool stub**:
- `discover` (BREADTH): genera host/asset finti deterministici dallo scope → `surface/assets.jsonl`
- `[dedup]` (BARRIER opzionale): union + dedupe cross-target
- `enum` (DEPTH, per-target): "fingerprint" stub → `targets/<id>/services.jsonl`
- `hypothesize` (agent stub): inventario → righe `hypothesis`

Usa le tabelle **core** (`target`/`host`/`service`/`hypothesis`) + **una tabella demo** dalla sua `schema.sql` per esercitare il meccanismo di estensione. Scopo: dimostrare **end-to-end** breadth + dedup + depth + ingest + agent, e far girare i **test in CI** senza dipendenze esterne. Gli adapter ai tool reali (e le tabelle web) arrivano con la pipeline recon quando si sceglie il dominio.

---

## 11. Esempio end-to-end — scope `example.com`, `nmap.org`

Con un host condiviso ipotizzato (`status.example.com` e `status.nmap.org` → stesso host `52.215.192.133`, porta 443):

1. **Parse** → 2 target (`t_4f9a1c` example.com, `t_8b2e07` nmap.org).
2. **BREADTH `discover`** (1 invocazione su entrambi) → `surface/assets.jsonl` + raw + manifest → **ingest**: popola `target`, `host`, `service`, `host_target`. Lo shared host = **1 riga `host`** (+ `service` 443), **2 righe `host_target`**.
3. **Aggregazione**:
   - `--aggregate` → host/service unici, `52.215.192.133:443` enumerato **1 volta**.
   - `--no-aggregate` → enumerato **2 volte** (una per workspace target).
4. **DEPTH `enum`** in parallelo (futures + governor `net`) → `targets/<id>/services.jsonl` (solo raw+manifest).
5. **BARRIER ingest** (unico writer) → upsert su `service` (versione/protocollo/sorgente) e, per la recon-web, `webasset`.
6. **Agent `hypothesize`** → query inventario → righe `hypothesis` (es. "OpenSSH datato su `52.215.192.133:22`", "host Statuspage → possibile subdomain takeover").

---

## 12. Out of scope (YAGNI, per ora)

- Adapter ai tool reali (httpx/naabu/nuclei/...) e tabelle web (`webasset`/`app`/`endpoint`/`takeover`) — arrivano come **estensione della pipeline recon** col dominio scelto.
- Provider Claude reale per le ipotesi (solo seam + stub ora).
- Automazione della verifica/exploitation delle ipotesi.
- Schema engagement di `org/templates/db/` (scartato, vedi D7).
- Direct-write / ibrido sul DB (scartati, vedi D2).
- Discovery ricorsiva event-driven stile BBOT (eventuale futuro sotto-loop).
- Worker distribuiti / multiprocessing (il fan-out resta a thread).

---

## 13. Domande aperte

Nessuna bloccante. Da confermare in fase di piano: nomi esatti dei ruoli canonici, la singola tabella demo dell'estensione d'esempio, e il set iniziale di query di reporting in `db/queries/`.
