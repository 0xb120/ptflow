# Next steps

## AI v2 — da generazione best-effort a supporto operativo verificabile

La prima integrazione multi-provider ha rimosso il vincolo da Claude Code e consente di usare
Ollama, OpenRouter, Hugging Face e endpoint OpenAI-compatible. Il passo successivo non è aggiungere
altro testo generato, ma rendere l'AI misurabile, vincolata alle evidenze e sicura sui dati di un
assessment.

### Principi

- `reports/report.md` e `reports/report.json` deterministici restano la fonte di verità; l'AI produce solo artefatti
  additivi.
- I risultati del modello devono citare gli ID stabili dei finding e vengono scartati quando citano
  evidenze inesistenti.
- I dati degli scanner sono input non fidato, quindi i prompt impongono di ignorare istruzioni e
  prompt injection contenuti nelle evidenze.
- I secret non vengono inviati in chiaro a provider remoti per default.
- Ogni chiamata deve essere osservabile e sottoposta a budget; stesso input e stessa configurazione
  devono poter riusare una cache locale.
- Provider e modello possono essere scelti per singolo stage, mantenendo un fallback globale.

### Milestone 1–5

**Stato: completata il 2026-07-15.**

1. **Triage e report evidence-grounded** — usare i finding normalizzati e i relativi ID stabili;
   produrre output strutturato; validare ogni riferimento prima di scrivere ipotesi e priorità;
   selezionare input ampi in modo bilanciato tra categorie.
2. **Secret triage privacy-safe** — policy `off | redacted | full` per i provider remoti, default
   `redacted`; inviare forma, lunghezza e fingerprint al posto del valore; conservare l'originale
   solo nel workspace locale; usare verdict non ambigui (`likely_credential`, `example`, `noise`,
   `unknown`).
3. **Telemetria AI** — introdurre un `LLMResult` comune con provider, modello, token, costo quando
   esposto dal provider, latenza, finish reason, fallback strutturato, cache hit ed errore; registrare
   gli eventi in `<activity>/ai/usage.jsonl` senza prompt o output sensibili.
4. **Controlli operativi** — timeout e retry espliciti, concorrenza limitata, cache content-addressed
   in `<activity>/ai/cache/`, budget per chiamate, token di input/output e costo massimo. Il
   superamento di un limite degrada lo stage a no-op e non interrompe la scansione.
5. **Routing per stage** — configurare `wordlist`, `secret_triage`, `triage` e `report` separatamente
   per abilitazione, provider, modello, endpoint e limite di output, ereditando le impostazioni
   globali quando non specificate.

### Successivi

6. **Evaluation harness** — corpus versionato di finding sintetici/redatti, golden set per
   riferimenti e classificazioni, metriche per grounding, precisione e stabilità tra modelli.
7. **Map/reduce per assessment molto grandi** — sintesi per app/categoria, correlazione globale solo
   sui candidati ad alto segnale, con tracciamento completo degli ID di origine.
8. **Azioni assistite ma approvate** — generazione di piani di validazione e comandi in sandbox,
   sempre dietro conferma dell'operatore; nessuna esecuzione autonoma suggerita dal modello.

### Criteri di completamento della milestone

- Nessuna ipotesi o priorità AI priva di un finding ID valido.
- Nessun secret in chiaro nei prompt remoti con la configurazione predefinita.
- Ogni chiamata non in cache produce una riga di usage; una cache hit è distinguibile.
- I budget bloccano ulteriori chiamate senza far fallire il run.
- Un preset può usare un provider globale oppure routing misto per stage.
- Test unitari, lint, type check e suite completa verdi.
