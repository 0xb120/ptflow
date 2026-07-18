# ptflow — Detection roadmap

## Visione

`ptflow` deve essere uno strumento da eseguire una volta per target o engagement, capace di
automatizzare la maggior parte delle attività ripetitive di un penetration test e di consegnare
all'operatore:

- la superficie più completa possibile entro un budget controllato;
- richieste HTTP complete e realmente eseguibili, non semplici liste di URL;
- finding verificati e corredati da evidenze riproducibili;
- lead ad alto valore già approfonditi automaticamente;
- una base da cui il pentester possa concentrarsi su business logic e catene di attacco, invece che
  ripetere enumerazione e controlli standard.

La priorità di questa roadmap è **qualità e profondità della detection nel singolo run**. Resume,
rerun, lifecycle degli artefatti e CI restano attività utili, ma sono deliberatamente rinviate.

## Principi di progetto

1. **Detection prima del numero di tool.** Un nuovo scanner entra nella pipeline solo se copre una
   classe o una superficie non già coperta meglio dagli strumenti presenti.
2. **Il request catalog è il centro del workflow web.** Browser, crawler, specifiche, traffico
   importato e artifact mining devono convergere nello stesso modello di richiesta completa.
3. **Stateful e identity-aware.** Le vulnerabilità di autorizzazione richiedono sessioni, ruoli,
   oggetti e sequenze; non possono essere ridotte a fuzzing stateless.
4. **Candidate generation separata dalla verifica.** Un detector può produrre lead, ma il report deve
   distinguere chiaramente `verified`, `probable` e `lead`.
5. **Feedback loop.** Ogni nuovo artifact o endpoint deve poter generare ulteriore superficie da
   reimmettere nel catalogo prima del DAST finale.
6. **Budget guidato dal rischio.** I cap restano necessari, ma selezionano richieste rappresentative e
   ad alto valore invece dei primi N elementi.
7. **Sicurezza esplicita.** Test state-changing, credential reuse e tecniche intrusive sono opt-in e
   configurabili prima del run.
8. **Implementazione modulare.** Le nuove feature non devono continuare ad ampliare
   `pipelines/external/tasks.py`: ogni dominio rilevante avrà un modulo dedicato e task sottili di
   integrazione.

## Copertura attuale

| Area | Copertura attuale | Valutazione |
| --- | --- | --- |
| Asset discovery external | DNS, TLS/PTR, wildcard enumeration, porte web, top-1000/full, HTTP fingerprint | Forte |
| Surface web | Katana, Crawley, headless condizionale, passive URL, forced browsing a feedback loop | Forte ma poco interattiva |
| Request catalog | Crawl, form, XHR, JS, OpenAPI parziale, cross-group routing | Buona base |
| Hidden parameter | Query, body, JSON e header con Arjun/x8 | Buona, limitata dai cap e dalla selezione |
| Injection | Nuclei DAST, Dalfox, SQLmap, pack PTFlow | Forte sulle classi classiche |
| API | OpenAPI basilare e probe GraphQL `{__typename}` | Parziale |
| Authorization | Nessun replay sistematico multi-ruolo, IDOR/BOLA o BFLA | Gap critico |
| Stateful/business workflow | Nessun motore di sequenze o browser interaction | Gap critico |
| OAST | Nuclei/Interactsh e Dalfox per-pass, callback brevi | Parziale |
| Verification | Dipende soprattutto dalla qualità nativa del singolo scanner | Parziale |
| Artifact pivot | Source map, secret scanning, cloud bucket, WordPress | Buona base, pochi pivot automatici |
| Internal no-credential | SMB, LDAP, ADCS, AS-REP, datastore, SNMP, NFS, DNS, RDP/VNC | Buona |
| Internal credentialed | Non presente | Gap critico |
| Internal protocol depth | Molta detection delegata a Nuclei e banner/CVE | Parziale |

## Metriche comuni

Prima e dopo ogni milestone devono essere raccolte almeno queste metriche su un corpus di target di
laboratorio versionato:

- request shape uniche scoperte, per sorgente e metodo;
- richieste con baseline valida, per metodo e content type;
- endpoint autenticati raggiunti;
- operazioni OpenAPI/GraphQL generate e realmente accettate;
- percentuale di catalogo coperta da DAST e scanner specializzati;
- finding per classe e livello di confidenza;
- veri positivi, falsi positivi e vulnerabilità note non rilevate;
- callback OAST inviati, ricevuti e correlati;
- candidati esclusi dai cap e motivazione della selezione;
- numero di pivot automatici completati;
- durata e numero di richieste per applicazione.

Il benchmark deve includere applicazioni vulnerabili web, REST, GraphQL, autenticazione multi-ruolo,
upload, SSRF/OAST e un laboratorio Active Directory. Ogni regressione di recall o precisione deve
essere visibile prima del merge.

---

## Milestone 0 — Detection benchmark e modello delle evidenze

### Stato al 18 luglio 2026

La foundation è implementata:

- report schema v2 con il modello comune delle evidenze;
- manifest benchmark v1 con finding positivi/negativi, request shape, callback OAST e azioni vietate;
- comando offline `ptflow evaluate` con TP/FP/FN, precisione/recall per classe, copertura e costo;
- corpus versionato `benchmarks/m0-smoke` e quality gate automatico.

Resta da completare il corpus eseguibile con almeno un caso positivo e negativo per ogni classe
supportata e con target web, REST, GraphQL, multi-ruolo, upload, OAST e Active Directory. Questa
espansione può avanzare insieme alle relative milestone, ma ogni nuova classe dovrà entrare nel golden
set prima di essere considerata stabile.

### Obiettivo

Rendere misurabile ogni miglioramento successivo. Senza un golden set, aggiungere tool o payload non
permette di sapere se la detection è realmente migliorata.

### Implementazione

- Creare un corpus locale/versionato con vulnerabilità e superfici attese.
- Definire un manifest per target con:
  - request shape attese;
  - vulnerabilità attese;
  - ruoli/sessioni disponibili;
  - callback OAST attesi;
  - azioni distruttive vietate.
- Introdurre un modello comune per i risultati di detection:

```text
finding_id
class
target
request_ref
confidence = verified | probable | lead
detector
verification_method
evidence_refs[]
control_evidence_refs[]
```

- Aggiungere un comando di sviluppo `ptflow evaluate` che confronti un report con il golden set.
- Salvare precisione, recall per classe, copertura e costo in un report macchina.

### Definition of done

- Il benchmark gira senza dipendere da servizi esterni non controllati.
- Almeno un caso positivo e uno negativo per ogni classe già supportata.
- Il risultato segnala separatamente detection mancate e falsi positivi.
- Le milestone successive possono dichiarare un delta misurabile rispetto alla baseline.

---

## Milestone 1 — Risk ranking e budget allocator

### Stato al 18 luglio 2026

L'implementazione di M1 è completa:

- scoring deterministico centralizzato in `pipelines/external/ranking.py`;
- quote di copertura per authority, GET/non-GET, location, content type e sorgente, con bonus di novità;
- selezione risk-ranked applicata a `param_fuzz`, Nuclei DAST, Dalfox, SQLmap, recrawl e download degli
  artifact del feedback loop;
- budget totale dell'engagement invariato e capacità inutilizzata riallocata dalle app piccole a quelle
  con più request shape;
- barriere dopo catalogo full e param discovery per rendere deterministica e race-free la domanda
  effettiva di ogni scanner deep;
- audit per-request redatti in `raw/ranking/` e distribuzioni/cap aggregati in `coverage.json`;
- test di determinismo, quote, redazione dei secret, riallocazione e confronto a budget uguale contro la
  precedente strategia first-N.

La validazione su target reali crescerà insieme al golden corpus di M0; ogni nuova classe aggiunta alle
milestone successive dovrà continuare a dimostrare recall non regressiva a parità di budget.

### Obiettivo

Aumentare la probabilità di finding senza aumentare indiscriminatamente il traffico. I cap attuali
devono scegliere le richieste migliori, non semplicemente le prime.

### Implementazione

- Creare un modulo `pipelines/external/ranking.py` con scoring deterministico delle richieste.
- Assegnare peso a:
  - sessione autenticata;
  - metodi state-changing;
  - body JSON, form e multipart;
  - sorgenti browser, XHR, OpenAPI e form reali;
  - percorsi admin/account/import/export/upload/webhook/callback;
  - parametri ID, ruolo, URL, path, file, template, redirect e query;
  - risposte vive e non statiche;
  - novità di host, metodo, content type, sorgente e posizione del parametro.
- Applicare quote minime per:
  - ogni hostname/authority;
  - GET e non-GET;
  - query, body, JSON, header e cookie;
  - crawl, browser, API, JS e guessed surface.
- Riallocare il budget inutilizzato dalle applicazioni piccole a quelle con superficie più ricca.
- Usare ranking e quote per:
  - `param_fuzz`;
  - Nuclei DAST;
  - Dalfox;
  - SQLmap;
  - recrawl e artifact download.
- Registrare score, motivo della selezione e motivo dell'esclusione.

### Definition of done

- La selezione è deterministica e unit-tested.
- Nessun host o tipo di request ad alto valore viene escluso solo perché appare tardi nel catalogo.
- Il benchmark mostra recall uguale o superiore con un budget di richieste uguale.
- `coverage.json` espone distribuzione e cap per sorgente, metodo e parameter location.

---

## Milestone 2 — Catalog import e browser exploration

### Obiettivo

Raggiungere la superficie che crawler link-based e headless non interattivi non vedono.

### Stage proposti

```text
traffic_import      phase 1, offline
browser_explore     phase 1, network
browser_catalog     phase 1, offline
```

### Implementazione

- Supportare input opzionali:
  - HAR;
  - export Burp/ZAP;
  - OpenAPI fornito dall'operatore;
  - browser storage state;
  - liste di richieste raw.
- Normalizzare tutti gli input nel modello corrente:
  `{method,url,headers,body,params,raw,sources}`.
- Implementare `browser_explore` con Playwright:
  - intercettazione fetch/XHR;
  - cattura GraphQL e WebSocket handshake;
  - osservazione di service worker e chiamate generate dal DOM;
  - click su elementi classificati come non distruttivi;
  - compilazione di search/filter/form con valori sintetici;
  - gestione SPA route e lazy-loaded content;
  - export HAR e screenshot delle transizioni principali.
- Introdurre una policy delle azioni:
  - allowlist di azioni sicure;
  - denylist per delete, logout, pagamento, invio messaggi e modifica profilo;
  - limite di transizioni e profondità;
  - classificazione dei form prima dell'invio.
- Non deduplicare gli origin basandosi soltanto sul body della root: eseguire almeno un passaggio cheap
  per ogni authority e applicare dedup solo ai test pesanti dopo aver confrontato le superfici.

### Definition of done

- Il browser scopre e cataloga richieste non presenti nei crawler su almeno tre casi del benchmark.
- Ogni richiesta catturata conserva metodo, header, body e sorgente.
- Nessuna azione nella denylist viene eseguita nei test.
- HAR/import e browser traffic confluiscono nel normale `request_catalog` e nei DAST pass.

---

## Milestone 3 — API engine: OpenAPI, GraphQL e protocolli moderni

### Obiettivo

Produrre richieste API valide e testabili, invece di sole forme sintetiche che possono fallire la
validazione prima di raggiungere la logica vulnerabile.

### OpenAPI

- Spostare parsing e generazione in `pipelines/external/api.py`.
- Risolvere `$ref` locali e gestire:
  - schemi annidati;
  - array;
  - enum;
  - `allOf`, `oneOf`, `anyOf`;
  - `nullable`, `required`, `format`, `minimum`, `maximum`;
  - `example` e `default`;
  - multipart e file upload;
  - JSON, form, XML e altri content type dichiarati.
- Generare valori validi per UUID, email, date, URI, hostname, numeri e identificatori.
- Interpretare security scheme e applicare il profilo auth corretto.
- Eseguire una baseline per ogni operazione e classificare:
  `accepted`, `auth-required`, `validation-failed`, `unreachable`.
- Inviare al DAST prima le operazioni `accepted` e `auth-required` con sessione disponibile.

### GraphQL

- Eseguire introspection solo quando autorizzata.
- Generare query e mutation valide a profondità limitata.
- Estrarre ID, enum, input object e relazioni fra tipi.
- Verificare:
  - introspection exposure;
  - batching;
  - alias amplification;
  - depth/cost limit;
  - field suggestion leakage;
  - accesso a field sensibili;
  - object-level authorization;
  - mutation authorization;
  - persisted query.

### Estensioni successive della milestone

- WebSocket: catalogo handshake e messaggi osservati dal browser.
- SSE: endpoint e token di sottoscrizione.
- SOAP/XML: WSDL discovery e request generation.
- gRPC: reflection e schema import quando disponibili.

### Definition of done

- Le specifiche con `$ref`, oggetti nested e array generano request complete.
- Il benchmark misura un aumento delle operazioni che superano la validazione applicativa.
- GraphQL produce query reali oltre a `{__typename}`.
- Le richieste API entrano nello stesso ranking, DAST e verification layer del traffico web.

---

## Milestone 4 — OAST activity-wide e verification layer

### Obiettivo

Aumentare precisione e copertura blind mantenendo una sessione di callback per l'intero run e
verificando i lead prima del report finale.

### OAST activity-wide

- Aggiungere un lifecycle di servizi run-scoped all'orchestratore.
- Avviare una sola sessione OAST prima dei test di profondità e terminarla al fan-in.
- Correlare ogni payload con un marker:

```text
<pipeline>.<stage>.<app_id>.<request_id>.<parameter>.<nonce>
```

- Supportare callback DNS, HTTP e SMTP quando il backend lo permette.
- Conservare richieste, callback e timestamp come evidenza.
- Aggiungere una finestra di drain finale configurabile.

### Verification layer

Introdurre `verify_surface` dopo la fase 2 e `verify_full` dopo la fase 4. I verifier devono essere
specifici per classe:

- SQLi: true/false pair, controllo negativo e ripetizione;
- XSS: esecuzione browser o callback blind, non sola reflection;
- SSRF/XXE/command injection/SSTI: callback correlato o prova deterministica;
- open redirect e CRLF: verifica strutturale degli header;
- LFI/path traversal: marker/file atteso;
- CORS: origin controllato e comportamento con credenziali;
- CVE: distinzione fra versione correlata e PoC attivamente verificato;
- default credential: distinzione fra pagina riconosciuta e login riuscito.

### Output

Ogni finding viene classificato:

- `verified`: controllo specifico conclusivo;
- `probable`: evidenze forti ma non conclusive;
- `lead`: richiede verifica manuale.

Il report ordina prima `verified`, poi `probable`, poi `lead`, senza perdere le evidenze originali.

### Definition of done

- Un callback ritardato ricevuto in una fase successiva viene ancora correlato correttamente.
- Ogni finding verificato include evidenza positiva e controllo negativo quando applicabile.
- Il benchmark espone precisione e recall separati per detector e verifier.
- Un verifier fallito non trasforma automaticamente il finding in falso positivo: lo degrada a lead.

---

## Milestone 5 — Profili di autenticazione e session management

### Obiettivo

Fornire identità stabili e isolate al browser, agli scanner e ai futuri test di authorization.

### Configurazione proposta

```toml
[auth.anonymous]

[auth.user]
authorities = ["app.example.com", "api.example.com"]
headers = ["Cookie: session=..."]
browser_state = "./user-storage-state.json"
canary_url = "https://app.example.com/profile"

[auth.admin]
authorities = ["app.example.com", "api.example.com"]
headers = ["Authorization: Bearer ..."]
refresh_command = "..."
canary_url = "https://app.example.com/admin"
```

### Implementazione

- Routing delle credenziali per authority e profilo, mai un header globale su target differenti.
- Header, cookie, localStorage e browser state per ruolo.
- Canary di sessione prima delle fasi principali.
- Refresh hook esplicito e limitato, senza registrare i secret nei log.
- Snapshot redatto della configurazione auth.
- Label `auth_context` su ogni request del catalogo.
- Supporto a sessione anonima, utente e amministratore; numero arbitrario di ruoli come estensione.
- Parse locale di JWT e cookie per estrarre scadenza, issuer, audience, claim e attributi di sicurezza.

### Definition of done

- Due authority differenti ricevono soltanto le proprie credenziali.
- Browser e scanner riproducono la stessa sessione.
- La pipeline riconosce una sessione scaduta e tenta il refresh configurato.
- Ogni finding e request reference indica il contesto auth usato, senza esporre il secret.

---

## Milestone 6 — Authorization, IDOR/BOLA e mass assignment

### Obiettivo

Automatizzare le vulnerabilità ad alto valore che richiedono confronto fra identità, oggetti e ruoli.

### Stage proposti

```text
object_inventory       phase 7, offline
authz_replay           phase 7, network
idor                    phase 7, network
mass_assignment         phase 7, network
session_security        phase 7, network/offline
```

La fase 7 usa il catalogo completo dopo la deep detection risk-budgeted di fase 6.

### Object inventory

- Estrarre identificatori da:
  - path;
  - query;
  - body JSON/form;
  - risposte JSON;
  - GraphQL node;
  - link e attributi DOM.
- Classificare ID numerici, UUID, slug, username, email e composite key.
- Associare gli oggetti al ruolo/sessione che li ha osservati.

### Authorization replay

- Ripetere request privilegiate con:
  - sessione anonima;
  - ruolo inferiore;
  - sessione di un altro utente allo stesso livello.
- Confrontare status, struttura JSON, similarità del body e dati sensibili.
- Dare priorità a operazioni admin e state-changing.

### IDOR/BOLA

- Sostituire un identificatore alla volta usando ID osservati da altre sessioni.
- Usare controlli validi, invalidi e cross-owner.
- Distinguere lettura, modifica e cancellazione; queste ultime restano opt-in.
- Verificare l'ownership nel contenuto della risposta quando possibile.

### Mass assignment

- Derivare campi candidati da schema, JS, response object e wordlist contestuale.
- Provare proprietà sensibili come ruolo, owner, stato, prezzo e privilegi.
- Verificare la modifica tramite una successiva richiesta read-only.

### Session security

- Cookie flag, fixation e rotazione dopo login.
- Logout invalidation.
- JWT `alg`, `kid`, JWKS, issuer/audience e claim trust.
- CSRF su operazioni state-changing.
- CORS credentialed differenziale.

### Definition of done

- Il benchmark rileva casi controllati di BOLA, BFLA e mass assignment.
- Ogni finding indica coppia di ruoli, oggetto e confronto usato.
- Le azioni state-changing sono disabilitate salvo opt-in esplicito.
- Il motore separa differenze di contenuto dinamico da reali bypass di autorizzazione.

---

## Milestone 7 — Artifact pivot e automatic deepening

### Obiettivo

Trasformare automaticamente un lead di esposizione in nuova superficie, evidenze e finding più
profondi prima di costruire `requests_full.jsonl`.

### Stage proposto

```text
artifact_expand        phase 3, dopo content_discovery e prima di request_catalog_full
```

### Dispatcher di artifact

| Trigger | Azione bounded |
| --- | --- |
| `.git/HEAD` o `.git/config` | dump repository, history scan, dependency e secret scan |
| `.svn`, `.hg`, `.DS_Store` | ricostruzione/listing e selezione file |
| backup/archivio | download limitato, listing, estrazione sicura e secret scan |
| directory listing | crawl e download selettivo |
| source map | ricostruzione source, endpoint, dependency e secret mining |
| config/env file | parser per framework, endpoint, credenziali e connection string |
| package manifest/lock | inventario versioni e CVE lookup preciso |
| OpenAPI/WSDL trovato dal fuzzing | invio all'API engine |
| JavaScript trovato dal deep dive | download, jsluice, catalog e secret scan |
| upload form/endpoint | invio al modulo upload |
| webhook/import URL | invio al modulo SSRF/OAST |

### Vincoli

- Limiti per file, totale download e profondità archivio.
- Nessuna esecuzione dei file scaricati.
- Protezione da path traversal e archive bomb.
- Provenienza completa dal trigger fino al finding derivato.
- I nuovi endpoint e request shape rientrano nel catalogo full e nel ranking.

### Definition of done

- Almeno `.git`, source map, backup e directory listing hanno un pivot completo nel benchmark.
- Un JavaScript trovato dal deep dive viene scaricato e alimenta il request catalog.
- Secret e dependency trovati negli artifact diventano evidenze correlate, non file isolati.
- Tutti i limiti sono registrati nella coverage.

---

## Milestone 8 — DAST pack e moduli specializzati

### Obiettivo

Ampliare le classi di vulnerabilità solo dopo aver migliorato catalogo, selezione, OAST e verifica.

### Estensione del pack PTFlow

- command injection time-based e OAST;
- XXE per XML, SVG e SOAP;
- NoSQL injection su JSON;
- traversal Windows, encoding multiplo e wrapper;
- host-header injection e password-reset poisoning;
- cache poisoning;
- header e cookie injection;
- JSON type confusion;
- unsafe deserialization con marker non distruttivo;
- SSTI specifica per engine;
- file upload validation;
- GraphQL misconfiguration e injection.

Ogni nuovo template deve includere, quando possibile:

- precondizione;
- controllo negativo;
- matcher ad alto segnale;
- test unitario/parser fixture;
- target vulnerabile e target negativo nel benchmark;
- strategia di verifica.

### Registry di scanner specializzati

Generalizzare `tech_vulnscan` in un registry basato su tecnologia e trigger. Candidati iniziali:

- WordPress, Drupal e Joomla;
- Jenkins, Tomcat, JBoss e WebLogic;
- GitLab, Jira, Confluence ed Exchange;
- Grafana, Kibana, Prometheus e pannelli amministrativi noti.

Gli scanner specializzati devono produrre inventario versionato e finding verificabili, non duplicare
il full-template Nuclei scan.

### Definition of done

- Ogni nuova classe aumenta recall sul benchmark senza peggiorare sensibilmente la precisione.
- I template generici puramente error-based non entrano nel pack stable.
- Il registry evita di eseguire scanner non pertinenti alla tecnologia rilevata.
- Duplicati fra scanner sono correlati in un unico finding con più evidenze.

---

## Milestone 9 — Internal credentialed phase e attack paths

### Obiettivo

Estendere la pipeline internal oltre i controlli anonimi usando esclusivamente credenziali fornite e
autorizzate dall'operatore.

### Configurazione

- Profili distinti per dominio, local account, SSH key e database.
- Scope degli host/protocolli su cui ogni credenziale può essere usata.
- Nessun uso automatico dei secret scoperti durante il run, salvo opt-in separato.
- Politica esplicita per login attempt e lockout.

### Stage proposti

```text
credential_validate
ad_collect
adcs_authenticated
kerberoast
share_collect
remote_access_map
database_collect
attack_paths
```

### Copertura

- BloodHound/LDAP domain collection.
- Certipy e controlli ESC autenticati.
- Kerberoasting autenticato.
- Delegazioni unconstrained, constrained e RBCD.
- ACL pericolose, ownership, DCSync e privilege path.
- LAPS e gMSA leggibili.
- SMB share spider con download selettivo e secret scan.
- Validazione controllata su SMB, WinRM, SSH e database.
- MSSQL, PostgreSQL, MySQL e Oracle inventory.
- Sessioni e privilegi amministrativi rilevati.

### Attack-path correlation

Produrre un grafo deterministico che colleghi almeno:

- SMB signing;
- LDAP signing/channel binding;
- ESC8;
- host relayable;
- account roastable;
- credenziali e privilegi validati;
- delegazioni e ACL;
- accesso remoto e amministrativo.

### Definition of done

- Il laboratorio AD produce inventario e almeno una catena di attacco nota.
- Ogni uso di credenziali è attribuito a profilo, host e protocollo.
- Lockout e spraying restano disabilitati per default.
- Il report distingue esposizioni isolate da catene sfruttabili.

---

## Milestone 10 — Internal protocol depth, UDP e passive discovery

### Obiettivo

Ridurre la dipendenza da banner e template generici per i servizi interni più comuni.

### Moduli protocol-specific

- Docker API, Kubernetes, etcd, Consul e Vault.
- Elasticsearch, Redis, MongoDB, RabbitMQ e MQTT.
- Jenkins, Tomcat/JBoss/WebLogic e management interface.
- SMTP open relay, user enumeration e STARTTLS posture.
- DNS recursion, forward/reverse AXFR e record inventory.
- RPC/NFS e share permission più approfonditi.
- TLS protocol/cipher/certificate posture.
- SSH algorithms, authentication methods e banner verification.
- Database handshake, encryption e accesso con credenziali autorizzate.

### UDP

- Passaggio UDP curated e rate-limited.
- DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IPsec, mDNS, SSDP e servizi OT selezionati.
- Esecuzione degli approfondimenti solo sui protocolli confermati.

### Passive discovery opzionale

- Finestra temporale per LLMNR, NBNS, mDNS, SSDP, DHCPv6 e WPAD.
- Modalità default esclusivamente passiva.
- Poisoning e coercion fuori scope salvo profilo intrusive esplicito.

### Definition of done

- Ogni protocollo supportato ha parser, fixture positiva e negativa.
- I finding distinguono esposizione, misconfigurazione e accesso verificato.
- Il passaggio UDP resta bounded e configurabile per reti legacy/OT.
- Le osservazioni passive alimentano inventory e attack-path graph.

---

## Profili operativi

Le nuove capacità devono essere organizzate in profili selezionabili prima del singolo run:

| Profilo | Comportamento |
| --- | --- |
| `safe` | Read-only, nessuna azione state-changing, nessun credential reuse scoperto |
| `active` | Fuzzing, upload controllati, session replay e verifiche non distruttive |
| `intrusive` | Race, request smuggling, azioni state-changing e tecniche interne invasive esplicitamente abilitate |

Il profilo non sostituisce i gate specifici: credenziali, OAST esterno, upload, spraying, coercion e
azioni state-changing richiedono comunque configurazione esplicita.

## Backlog successivo, non prioritario

Queste attività restano fuori dal percorso detection-first e vanno affrontate dopo le milestone sopra:

- generazioni immutabili degli artefatti;
- pulizia e isolamento dei full rerun;
- resume content-addressed;
- DAG artifact contract e invalidazione selettiva;
- CI/CD e distribuzione;
- ottimizzazione delle barriere globali;
- reporting portfolio multi-run.

## Ordine di implementazione raccomandato

```text
M0  benchmark ed evidenze
 ↓
M1  ranking e budget
 ↓
M2  traffic import + browser
 ↓
M3  OpenAPI/GraphQL
 ↓
M4  OAST + verification
 ↓
M5  auth profiles
 ↓
M6  authorization/IDOR
 ↓
M7  artifact pivots
 ↓
M8  DAST e scanner specializzati
 ↓
M9  internal credentialed
 ↓
M10 internal protocol depth
```

M0–M4 aumentano la qualità di ogni classe di detection esistente. M5–M6 aggiungono il salto più
importante verso le vulnerabilità oggi prevalentemente manuali. M7–M8 trasformano la pipeline in un
motore di approfondimento automatico. M9–M10 portano lo stesso modello nella parte internal.
