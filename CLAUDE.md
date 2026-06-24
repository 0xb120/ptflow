# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Single source of truth.** Architecture, commands, conventions, the workspace
> contract, and ongoing project notes all live in this file. Keep it aligned with
> the code, and put new documentation notes here rather than creating new doc files.
> Inherits the toolkit-wide contract at `/opt/custom-tools/CONVENTIONS.md`.

## What this is

**pipt** is a reusable **Prefect ≥3** scaffolding (`core/`) hosting pluggable pentest
`pipelines/<name>/`. **Files on disk are the only state — there is no database.** A
pipeline runs an asset-discovery (breadth) phase over the whole scope, clusters the
results into "application groups", then runs one or more per-app **loops** (depth)
that fan out under Prefect.

> **Agent seam is suspended.** A terminal agent stage (`core/agent.py`,
> `HypothesisProvider`) still runs as a dormant `StubProvider` fan-in, but its real
> (Claude-backed) implementation is parked. Don't build toward it; the terminal step
> will eventually become a deterministic `consolidate`. Leave the seam in place.

## Commands

```bash
uv sync --all-groups                                   # install (incl. dev/lint/test groups)
uv run pipt run <pipeline> <activity> <scope.txt> [--root DIR] [-v]
                                                       # output → <root>/<activity>/ (root defaults to cwd)
uv run ruff check . && uv run ty check src/ && uv run pytest   # the full dev gate
uv run pytest tests/core/test_orchestrator.py          # one file
uv run pytest tests/core/test_scope.py::test_classify  # one test
```

- `<pipeline>` is `example` or `recon` (see below). Every external command (routed through
  `tools.run`/`tools.pipe`) is logged, and the full run log — every command + output — is persisted
  to `<activity>/logs/run.log` regardless of console verbosity. `-v`/`--verbose` additionally surfaces
  commands and live tool stdout/stderr on the console.
  - The "pipt" logger level is always DEBUG; the *console* handler is raised to INFO without `-v`,
    so the file (DEBUG) captures the full record while the console stays quiet. `is_verbose()` (not
    the logger level) gates console-only behaviour like streaming a tool's stderr.
  - `tools.run` logs a WARNING on any non-zero exit, so a broken tool (bad flag, crash) can't
    masquerade as a clean empty result — the failure shows on the console even without `-v`.
- Ruff runs with `select = ["ALL"]`; respect the `ignore`/`per-file-ignores` in `pyproject.toml`
  rather than adding blanket `# noqa`. `ty` is the type checker (not mypy).

## Architecture

**Orchestration is a dependency DAG** (`core/orchestrator.py`). The flow is:
1. **activity stages** (`per_app=False`) run once over the whole scope as a DAG;
2. **`pipeline.cluster(activity)`** is the fan-out pivot — it groups discovery output into
   `scans/<app_id>/` dirs and returns the list of `app_id`s;
3. **per-app loops** run in order (see below);
4. the **agent** stage runs once as a fan-in (currently the dormant stub).

**Spanning stages** (`spanning=True`, activity-scope) don't block the breadth→cluster barrier:
they're launched once their breadth `needs` are done and awaited only at the fan-in, so they run
**∥ clustering + all the per-app loops** — for a long whole-scope scan (`nuclei_scope`) that hides
its cost behind the per-app work instead of serializing in front of it.

**Only strings cross the Prefect task boundary** (`_run_stage` reconstructs the
`Activity`/`Pipeline` from names + `app_id`); never pass objects through `.submit()`.
**Stages communicate only through on-disk artifacts** — never return values or shared
memory. Each stage's `run(activity)` (or `run(activity, app_id)` when `per_app`) reads
canonical files written by its dependencies and writes its own.

### Per-app loops (the `phase` model)

Per-app stages are grouped into successive **loops** by `Stage.phase` (an int). The
orchestrator (`per_app_loops()` in `core/orchestrator.py`):
- runs all stages sharing a phase as **one per-app DAG**, fanned out across every app group;
- runs loops in **ascending phase order with a global barrier between them** — every app
  finishes loop N before any app starts loop N+1.

**The rule that keeps loops independent:** within a loop, ordering comes from `needs`;
*across* loops, ordering comes from the **barrier, never `needs`**. A later loop reads an
earlier loop's on-disk artifacts directly (they're guaranteed present by the barrier), so a
new loop is added without touching any earlier loop's DAG. The global barrier is also where a
future activity-scope aggregation (e.g. a cross-app wordlist corpus) would slot in.

Concurrency: `ThreadPoolTaskRunner(max_workers=N)` caps total in-flight stages **across all
apps**. Intra-app parallelism therefore competes with fan-out width — only parallelize slow,
network-bound steps. Every network stage is tagged `net` (cap with a Prefect concurrency limit:
`uv run prefect concurrency-limit create net 10`).

**A `Pipeline` (`core/stage.py`)** satisfies a Protocol: `name`, `stages` (a sequence of
`Stage`), `cluster(activity) -> list[str]`, and `provider() -> HypothesisProvider`. Register
new pipelines in `pipelines/__init__.py::load_pipeline`.

### Workspace layout — paths are a contract (`core/paths.py`)

Never write path literals in tasks/flows. All paths come from `Activity` (activity scope) and
`AppWorkspace` (`scans/<app_id>/`, per-app scope).

```
<activity>/
  scope.txt                              # raw input
  scope/  scope_init|urls|dns|ip.txt     # parsed/expanded scope
  scans/
    asset_discovery/  raw/<tool>/  <canonical files>      # BREADTH (httpx_full_metadata.jsonl,
                                                           #   takeovers_scope.jsonl, …)
    <app_id>/                            # one clustered app group (per-app loops)
      meta.json  hosts.txt  endpoints.txt  subs.txt  takeover.txt  …
      endpoints_passive.txt  endpoints_crawley.txt   #   discovery sources fetch_delta downloads
      crawl_class.json                   #   JS-render verdict + signals (gates crawl_headless)
      endpoints_headless.txt             #   gated headless crawl (JS-rendered apps only)
      screenshot.png                     #   root-page screenshot (or screenshot.failed)
      default_creds.jsonl                #   EyeWitness signature-based default-cred leads (optional)
      endpoints_js.txt  secrets.jsonl    #   mine_responses (jsluice over the stored JS)
      content_discovery.jsonl            #   feroxbuster forced-browse results
      wl_custom/seed.txt                 #   per-app GENERATED wordlist (loop 2, offline)
      responses/  responses/headless/    #   downloaded HTML/JS corpus (katana/httpx -srd) — mined offline
      raw/<tool>/  (incl. raw/js/ extracted JS bodies)
  findings/hypotheses.jsonl              # dormant agent fan-in output
  poc/  tmp/  logs/
  wl_global/                             # shared/global INPUT wordlists (SecLists & co.)
```

Two wordlist scopes (deliberately distinct names): `<activity>/wl_global/` is the
shared/global INPUT lists; `scans/<app_id>/wl_custom/` is the wordlists GENERATED for
that app from its own corpus (`Activity.wl_global` / `AppWorkspace.wl_custom`).

**Global wordlists are resolved by ROLE, not hardcoded** (`pipelines/recon/wordlists.py`). The
`provision_wl` breadth stage resolves each role (`content`, `wordpress`, `drupal`, `joomla`) to a
concrete file and symlinks it into `wl_global/<role>.txt`; steps then read by role
(`wordlists.role_path(activity, "content")`). Resolution order: BYO (`wl_global/<role>.txt` already
present) › explicit env `PIPT_WL_<ROLE>` › discovery (first candidate filename under a search dir;
search dirs = env `PIPT_WORDLISTS` ++ common locations like `/usr/share/seclists`) › unresolved →
the step degrades to the generated `wl_custom` (the pipeline never fails for missing wordlists).
This keeps it independent of WHICH collection, WHERE it's installed, and whether it's installed.

### Write each tool output exactly once

This is the load-bearing convention; a verbatim raw↔canonical copy is the bug it forbids.
- **Intermediate** step (output only feeds later steps) → `raw/<tool>/<label>.txt` (provenance).
- **Terminal artifact** step (output *is* a downstream-read file, e.g. `httpx_full_metadata.jsonl`,
  `subdomains.txt`) → write **straight to its canonical name**, no raw copy.
- **Derived artifact** (in-memory merge/dedup/filter, e.g. `unique_ips.txt`, the wordlist) → canonical only.
- **Nothing downstream ever reads `raw/`** — consumers read fixed canonical names.

In recon, `_run(tool, cmd, *, stdin, dest, label)` enforces this: it writes a tool's stdout to
the single caller-chosen `dest`. Keep pure transforms (e.g. `honeypot_split`, `tokenize_urls`,
`denoise`) module-level so they're unit-testable apart from subprocess plumbing.

### Clustering — union-find over app-identity signals (precision-first)

`scans/<app_id>/` groups httpx vhosts into "application-groups". The purpose is **dedup** — scan one
real app once, not once per hostname. **Over-merge (fusing logically-different apps) is a correctness
bug**, not a cosmetic one: a group shares ONE `endpoints.txt`/`hosts.txt`, `content_discovery` fuzzes
the combined wordlist across all its hosts, and `screenshot`/`best_host` represent the group with one
host — so a different app hidden in a group gets under-scanned and mis-attributed. **Over-split (a
duplicate scanned twice) is only wasted work.** Clustering is therefore tuned **precision-first: when
in doubt, do NOT merge.**

It's a **connected-components partition** (`cluster_partition`, pure/unit-tested) over **app-identity**
signals only — deliberately **not** infrastructure (cert / IP routinely front distinct apps under one
company → over-merge):
- **GLOBAL, safe edges**: **redirect-final host** (`-fr`; the #1 true-duplicate — apex/www/http↔https
  converging) and **exact body** sha256 (2xx/3xx). A global value spanning more than
  `GENERIC_MAX_APEXES` apexes is demoted (default/error page, parking) — apex-based, so one app under
  one apex is never demoted.
- **APEX-SCOPED, fuzzy edges**: **favicon** mmh3 (`httpx -favicon`) and the **root fingerprint**
  `Title|CL|Webserver` (non-blank) — keyed by `(value, apex)`, so they merge only sibling subdomains
  of one apex and **never across organizations**. They're the over-split fix (favicon survives a
  `content_length` token-drift) at minimal over-merge risk.

Dropped on purpose (were in an earlier draft): **leaf cert** and **ip+header+tech** — infra, over-merge.

**Stable id:** `app_id` is anchored on the group's plurality `(favicon, apex)` → else plurality host
(`_cluster_anchor`) — collision-free (two groups can't share an apex-scoped favicon, nor a host) and
stable under minority membership changes. `meta.json` records `id_anchor` + `signature` for
debuggability; oversized groups log a WARNING (`CLUSTER_MAX_HOSTS`). The residual (same-apex hosts
with a coincidentally-identical favicon/fingerprint, e.g. a corporate template) is what a future
`recluster` deep-path confirmation pass would resolve. The example stub still hashes a fabricated sig.

## The two pipelines

- **`example`** — stub tasks (deterministic fake IPs/services, no external binaries). Dependency-free;
  this is what the test suite and CI exercise.
- **`recon`** — the REAL ProjectDiscovery toolchain (`pipelines/recon/tasks.py`), a faithful port of
  bash recon scripts (`scope2surface.sh` breadth, `surfagr.sh` clustering). Stages:
  - **Breadth** (activity scope): `provision_wl` (resolve global wordlist roles → `wl_global/`) ∥
    `expand` → `resolve` → `portscan` → `httpx` ∥ `nerva` → `cluster`
    fan-out. Plus `nuclei_scope` — a **spanning** whole-scope full-template nuclei scan (one process,
    one global `-rl` over deduped subdomains + webapps) launched after `httpx`, running ∥ everything,
    joined at the fan-in (`findings/nuclei_scope.jsonl`). It runs `nuclei -ut` (update templates)
    first, then scans with `-duc`. Per-app would multiply traffic on shared backends, so it's
    whole-scope, not per-app.
  - **Loop 1 — enumeration** (`phase=1`): `screenshot` (best-host root shot via httpx -screenshot, +
    OPTIONAL EyeWitness on the SAME single best host for default-credential leads → `default_creds.jsonl`, ∥) ;
    `passive_probe` → `crawl` (katana ∥ crawley + JS-render classification, see below) →
    `crawl_headless` (gated TIER-1 headless, ∥ takeover) ; `subenum` ; `takeover` (← crawl + subenum).
  - **Loop 2 — content discovery** (`phase=2`): `wordlist` (offline) → `tech_enum` (surface-generating
    per-stack scanners) ; `fetch_delta` (OSINT delta) → `mine_responses` (offline JS/secret mining) ;
    both feed `content_discovery` (feroxbuster forced browsing). See below.
  - **Loop 3 — vuln scan** (gated, planned): `tech_vulnscan` — finding-only per-stack scanners
    (`wpprobe`, nuclei tech-tags, `nikto`, …). Specialized scanners are split between loops by output
    role: **surface → `tech_enum`** (loop 2, feeds enum); **findings → `tech_vulnscan`** (loop 3).

### Fetch once, mine offline

Loop 1 `crawl` runs **two crawlers in parallel** (`ThreadPoolExecutor`) for maximum coverage:
- **katana** is the **downloader** — `katana -j -jc -jsl -kf all -fx -pc -fs fqdn -srd <responses/>`
  (depth ≥3 for `-kf`): it parses JS endpoints, known files and forms inline (so `endpoints.txt` is
  JS-/form-enriched) **and** stores every response body under `scans/<app_id>/responses/` (`-omit-body`
  only trims stdout; `-srd` still writes full bodies to disk). It's the downloader for the linked
  surface — don't fetch the same bytes twice.
- **crawley** is a second **discovery** engine — `crawley -headless -all -js -robots crawl` per host
  (one positional URL each). It only finds URLs (no body store), so its discoveries
  (`endpoints_crawley.txt`) join the passive sources as `fetch_delta` candidates. (`-headless` here =
  skip the HEAD pre-flight, **not** browser rendering.)

These two are the **TIER-0** cheap layer (no browser). `crawl` then **classifies** each app for the
gated headless pass (`is_js_rendered`, recorded in `crawl_class.json`): it compares the raw `<a href>`
count of the stored root page + the crawley surface against the JS-parsed (`-fx`) count, plus
thin-shell framework markers (Next/Nuxt/Angular). The validated signal (crawler benchmark) is that
headless **only** pays off when the non-headless link surface is small yet JS-parse finds far more —
a React/"finto-SPA" with a healthy link surface is traditional and skips the browser. **No framework
label / `is_spa` heuristic** — that was unreliable (a "React" app can behave traditionally).

**`crawl_headless`** is the **TIER-1** pass: headless katana
(`-hl -nos -jc -jsl -xhr -fx -iqp -fs fqdn -ct`, bundled rod chromium, `-aff` OFF) run **only** on the
JS-rendered bucket. It renders the SPA and extracts JS-built routes + XHR/fetch URLs link-crawling
can't reach, storing bodies under `responses/headless/` (mined offline like the rest). Browser RAM
(1-5 GB/host) is the scale constraint, so concurrent headless processes are capped **process-wide** by
a module `BoundedSemaphore` (`HEADLESS_PARALLELISM`, since the `ThreadPoolTaskRunner` runs every stage
in one process), and `-ct` bounds each host. Its `endpoints_headless.txt` is folded into the loop-2
`build_wordlist` (like `endpoints_js.txt`), and its `-srd` store joins the "already have" set so
`fetch_delta` doesn't re-download it.

A separate downloader is justified only for URLs neither crawl-stored — and only over that delta:
the `fetch_delta` step (`passive_delta` + httpx `-srd`) downloads the live delta — passive
(gau/urlfinder) **+ crawley** URLs minus what katana already stored (`responses/index.txt`), static
assets dropped — into `responses/osint/`. `mine_responses` then mines the store **offline** (jsluice
over the stored JS bodies) → JS endpoints (`endpoints_js.txt`, folded into the content_discovery
wordlist) + secrets (`secrets.jsonl`). This is where the "fetch once" design pays off — no re-fetching.

`build_wordlist` (`wordlist` step) is therefore **pure offline**: it tokenizes `endpoints.txt`
(+ `endpoints_headless.txt` when the headless pass ran) into
path segments, filename basenames and parameter names (`tokenize_urls`) and merges any tech-specific
static lists for the cluster's detected tech (`wordlists.tech_role_paths` → `wl_global/<role>.txt`,
best-effort). Output: the per-app `scans/<app_id>/wl_custom/seed.txt`.

`content_discovery` is the one Loop 2 step that *must* make new requests — forced browsing finds
UNLINKED paths, which by definition aren't in any downloaded body. `feroxbuster --smart` (auto-tune
soft-404 calibration + collect-words/backups + link extraction/recursion) over the app's
**representative host only** (`best_host`, like screenshot) — a group is one app by construction, so
forced-browsing every host would re-fuzz the same backend (double traffic; the scanme.nmap.org hang)
— with a combined wordlist (`wl_custom/seed.txt` first, then the resolved global list
`wordlists.role_path(activity, "content")` — see role resolution above) and tech-derived extensions
(`tech_extensions`). `--smart` means the wordlist-feedback loop is built in — don't hand-roll it.
Output: `scans/<app_id>/content_discovery.jsonl` (`parse_ferox` keeps the `response` records).
Politeness on live infra is `--smart` (auto-tune adapts the rate **down** when the target
errors/times out) + low `-t`/`-L`/`--timeout` (`FEROX_THREADS`/`FEROX_SCAN_LIMIT`/`FEROX_TIMEOUT`) —
**not** `--rate-limit`, which is mutually exclusive with `--smart` (and per-directory). A
**`--time-limit`** (`FEROX_TIME_LIMIT`, total scan wall-clock) is mandatory: `--timeout` is only
per-request, so a throttling target can drive `--smart`'s auto-tune into an unbounded backoff
livelock that hangs the whole pipeline — `--time-limit` is the hard cap that breaks it (it exits
gracefully, keeping partial results).

**Specialized per-stack scanners are split by output role** (so they land in the right loop):
- `tech_enum` (loop 2, before content_discovery) runs scanners whose output is **surface that feeds
  enum**. Today: `shortscan` (IIS/ASP.NET 8.3 short-name enumeration). It builds a `shortutil` rainbow
  table from the seed + global list so shortscan resolves leaked 8.3 names to real filenames, then
  `parse_shortscan` harvests those as fuzz words → `wl_custom/shortnames.txt`, merged into the combined
  wordlist. Best-effort dispatch keyed on detected tech (no-op if tech unmatched / binary absent).
- `tech_vulnscan` (loop 3, gated, planned) runs scanners whose output is **findings-only** (`wpprobe`,
  nuclei tech-tags, `nikto`, …).

## Adding a pipeline (checklist)

- [ ] Create `src/pipt/pipelines/<name>/` with a `PIPELINE` object satisfying the `Pipeline` protocol.
- [ ] Reads/writes **only** via `Activity` / `AppWorkspace` — no path literals.
- [ ] Each tool output written **once**: intermediate → `raw/<tool>/`; terminal artifact → canonical
      name directly (no verbatim raw↔canonical copy); derived → canonical only.
- [ ] Activity stages (`per_app=False`) for breadth; per-app stages grouped into loops by `phase`.
      Within a loop use `needs`; across loops rely on the barrier (no cross-loop `needs`).
- [ ] `cluster(activity) -> list[str]` creates the app groups, keyed on a stable hash of cluster identity.
- [ ] Network stages tagged `net`.
- [ ] Register it in `load_pipeline`.

## Recon environment gotchas

- **`httpx` on PATH is the pyenv shim — use `~/go/bin/httpx`** (handled via the `HTTPX` constant in
  recon tasks). Other tools (subfinder, dnsx, naabu, tlsx, mapcidr, shuffledns, katana, nerva,
  assetfinder, gau, urlfinder, subjack, …) are in `~/go/bin`; feroxbuster in `~/.local/bin`.
- Trusted resolvers: `/opt/resolvers/resolvers-trusted.txt`.
- **EyeWitness (optional, `screenshot` step)** — a Selenium app, **installed** at `/opt/EyeWitness`
  with its own venv (`/opt/EyeWitness/.venv`, selenium ≥4.45 → Selenium Manager auto-provisions
  chromedriver; runs `--headless=new`, no Xvfb/sudo needed). `_eyewitness_cmd` resolves it
  automatically (PIPT_EYEWITNESS override › `eyewitness` on PATH › `_EYEWITNESS_DIR` = `/opt/EyeWitness`);
  if it ever goes missing
  the step just runs the httpx screenshot and skips EyeWitness. It's fed ONE URL (best host) via a
  one-line `-f` file — the `-f` report path writes `Requests.csv` (which `--single` skips), and that
  CSV's "Default Creds" column is what we parse. Headless katana uses the bundled rod chromium, NOT
  system chrome (`-sc`/`-system-chrome` hangs for katana here — but works for httpx -screenshot).
- Recon tunables (rates, port counts, honeypot threshold, crawl depths, wordlist constants) are at the
  top of `pipelines/recon/tasks.py` — tuned conservatively for live infra; don't bump blindly.
- **Authorized test scope only:** `https://ginandjuice.shop/` (PortSwigger demo), `scanme.nmap.org`
  (Nmap-sanctioned).

## Pin to keep

`fastapi<0.137` is pinned in `pyproject.toml` — Prefect 3.7.x's ephemeral server crashes on
FastAPI 0.137+ (`del router.routes`). Do not drop it.
