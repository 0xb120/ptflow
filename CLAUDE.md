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
    asset_discovery/  raw/<tool>/  <canonical files>      # BREADTH (+ takeovers_scope.jsonl)
    <app_id>/                            # one clustered app group (per-app loops)
      meta.json  hosts.txt  endpoints.txt  subs.txt  takeover.txt  …
      screenshot.png                     #   root-page screenshot (or screenshot.failed)
      endpoints_js.txt  secrets.jsonl    #   mine_responses (jsluice over the stored JS)
      content_discovery.jsonl            #   feroxbuster forced-browse results
      wl/seed.txt                        #   per-app CUSTOM wordlist (loop 2, offline)
      responses/                         #   downloaded HTML/JS corpus (katana/httpx -srd) — mined offline
      raw/<tool>/  (incl. raw/js/ extracted JS bodies)
  findings/hypotheses.jsonl              # dormant agent fan-in output
  poc/  tmp/  logs/
  wl/                                    # GLOBAL/shared wordlists (or links to SecLists & co.)
```

Two `wl/` scopes: the activity-level `wl/` holds shared/global lists; each app's
`scans/<app_id>/wl/` holds the wordlists generated for that app.

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

### Stable app ids

`scans/<app_id>/` is keyed on a hash of the cluster *identity* — never a mutable string.
recon hashes `Title|Content-Length|Webserver`; the example stub hashes a fabricated signature.

## The two pipelines

- **`example`** — stub tasks (deterministic fake IPs/services, no external binaries). Dependency-free;
  this is what the test suite and CI exercise.
- **`recon`** — the REAL ProjectDiscovery toolchain (`pipelines/recon/tasks.py`), a faithful port of
  bash recon scripts (`scope2surface.sh` breadth, `surfagr.sh` clustering). Stages:
  - **Breadth** (activity scope): `expand` → `resolve` → `portscan` → `httpx` ∥ `nerva`; plus
    `takeover_scope` (nuclei `-tags takeover` over resolved subdomains, ∥) → `cluster` fan-out.
  - **Loop 1 — enumeration** (`phase=1`): `screenshot` (root-page shot of the cluster's best host, ∥) ;
    `passive_probe` → `crawl` (SPA clusters get `-headless`, see `is_spa`) ; `subenum` ; `takeover`
    (← crawl + subenum).
  - **Loop 2 — content discovery** (`phase=2`): `wordlist` (offline) → `tech_enum` (surface-generating
    per-stack scanners) ; `fetch_delta` (OSINT delta) → `mine_responses` (offline JS/secret mining) ;
    both feed `content_discovery` (feroxbuster forced browsing). See below.
  - **Loop 3 — vuln scan** (gated, planned): `tech_vulnscan` — finding-only per-stack scanners
    (`wpprobe`, nuclei tech-tags, `nikto`, …). Specialized scanners are split between loops by output
    role: **surface → `tech_enum`** (loop 2, feeds enum); **findings → `tech_vulnscan`** (loop 3).

### Fetch once, mine offline

The **crawler is the downloader for the linked surface** — don't fetch the same bytes twice. Loop 1
`crawl` runs `katana -jc -jsl -kf all -srd <responses/>` (depth ≥3 for `-kf`): it parses JS endpoints
and known files inline (so `endpoints.txt` is already JS-enriched) **and** stores every response body
under `scans/<app_id>/responses/`. Downstream steps mine that corpus offline rather than re-fetching.
A separate downloader is justified only for URLs the crawl never reached — and only over that delta:
the `fetch_delta` step (`passive_delta` + httpx `-srd`) downloads the live OSINT delta (passive
gau/urlfinder URLs minus what the crawl already requested, static assets dropped) into
`responses/osint/`. `mine_responses` then mines the store **offline** (jsluice over the stored JS
bodies) → JS endpoints (`endpoints_js.txt`, folded into the content_discovery wordlist) + secrets
(`secrets.jsonl`). This is where the "fetch once" design pays off — no re-fetching.

`build_wordlist` (`wordlist` step) is therefore **pure offline**: it tokenizes `endpoints.txt` into
path segments, filename basenames and parameter names (`tokenize_urls`) and merges any tech-specific
static lists keyed on the cluster's detected tech (`select_tech_wordlists`, best-effort — no-op if
`WORDLIST_DIR` is absent). Output: the per-app `scans/<app_id>/wl/seed.txt`.

`content_discovery` is the one Loop 2 step that *must* make new requests — forced browsing finds
UNLINKED paths, which by definition aren't in any downloaded body. `feroxbuster --smart` (auto-tune
soft-404 calibration + collect-words/backups + link extraction/recursion) over the app's hosts, with
a combined wordlist (`wl/seed.txt` first, then a global SecLists list — `CONTENT_WORDLIST`, default
`/opt/wordlist/SecLists/Discovery/Web-Content/raft-medium-directories.txt`) and tech-derived extensions
(`tech_extensions`). `--smart` means the wordlist-feedback loop is built in — don't hand-roll it.
Output: `scans/<app_id>/content_discovery.jsonl` (`parse_ferox` keeps the `response` records).
Politeness on live infra is `--smart` (auto-tune adapts the rate **down** when the target
errors/times out) + low `-t`/`-L`/`--timeout` (`FEROX_THREADS`/`FEROX_SCAN_LIMIT`/`FEROX_TIMEOUT`) —
**not** `--rate-limit`, which is mutually exclusive with `--smart` (and per-directory).

**Specialized per-stack scanners are split by output role** (so they land in the right loop):
- `tech_enum` (loop 2, before content_discovery) runs scanners whose output is **surface that feeds
  enum**. Today: `shortscan` (IIS/ASP.NET 8.3 short-name enumeration). It builds a `shortutil` rainbow
  table from the seed + global list so shortscan resolves leaked 8.3 names to real filenames, then
  `parse_shortscan` harvests those as fuzz words → `wl/shortnames.txt`, merged into the combined
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
- Recon tunables (rates, port counts, honeypot threshold, crawl depths, wordlist constants) are at the
  top of `pipelines/recon/tasks.py` — tuned conservatively for live infra; don't bump blindly.
- **Authorized test scope only:** `https://ginandjuice.shop/` (PortSwigger demo), `scanme.nmap.org`
  (Nmap-sanctioned).

## Pin to keep

`fastapi<0.137` is pinned in `pyproject.toml` — Prefect 3.7.x's ephemeral server crashes on
FastAPI 0.137+ (`del router.routes`). Do not drop it.
