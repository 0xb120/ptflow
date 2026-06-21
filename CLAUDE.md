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

- `<pipeline>` is `example` or `recon` (see below). `-v`/`--verbose` logs the exact command,
  streams each tool's stderr live, and dumps its stdout.
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
    asset_discovery/  raw/<tool>/  <canonical files>      # BREADTH phase
    <app_id>/                            # one clustered app group (per-app loops)
      meta.json  hosts.txt  services.jsonl  endpoints.txt  subs.txt  …
      wl/seed.txt                        #   per-app CUSTOM wordlist (loop 2, offline)
      responses/                         #   downloaded HTML/JS corpus (katana -srd) — mined offline
      raw/<tool>/
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
  bash recon scripts (`scope2surface.sh` breadth, `surfagr.sh` clustering). Its per-app loops:
  - **Loop 1 — enumeration** (`phase=1`): `passive_probe` → `crawl`, `subenum`, `takeover`.
  - **Loop 2 — content discovery** (`phase=2`): `wordlist` (offline) ∥ `fetch_delta` (downloads the
    OSINT delta; see below). `content_discovery` (fuzzing) and `tech_enum` are planned next.

### Fetch once, mine offline

The **crawler is the downloader for the linked surface** — don't fetch the same bytes twice. Loop 1
`crawl` runs `katana -jc -jsl -kf all -srd <responses/>` (depth ≥3 for `-kf`): it parses JS endpoints
and known files inline (so `endpoints.txt` is already JS-enriched) **and** stores every response body
under `scans/<app_id>/responses/`. Downstream steps mine that corpus offline rather than re-fetching.
A separate downloader is justified only for URLs the crawl never reached — and only over that delta:
the `fetch_delta` step (`passive_delta` + httpx `-srd`) downloads the live OSINT delta (passive
gau/urlfinder URLs minus what the crawl already requested, static assets dropped) into
`responses/osint/`. Brute-forced hits (from future `content_discovery`) are the other such delta.

`build_wordlist` (`wordlist` step) is therefore **pure offline**: it tokenizes `endpoints.txt` into
path segments, filename basenames and parameter names (`tokenize_urls`) and merges any tech-specific
static lists keyed on the cluster's detected tech (`select_tech_wordlists`, best-effort — no-op if
`WORDLIST_DIR` is absent). Output: the per-app `scans/<app_id>/wl/seed.txt`.

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
