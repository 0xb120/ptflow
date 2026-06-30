# pipt — Prefect scaffolding for automated pentest pipelines

A reusable framework (`core/`) hosting pluggable `pipelines/<name>/`. **Files on
disk are the only state — no database.** A breadth asset-discovery phase feeds a
clustering step that fans out into per-app depth loops. The recon pipeline runs
those loops **surface-first, DAST-first**: map the explorable surface (OSINT/crawl)
and DAST *that* for low-hanging fruit, then guess/fuzz, then DAST the guessed surface
— each phase separated by a global barrier. Each DAST pass runs alongside an offline
**known-CVE lookup** that correlates the enumerated software (server/tech/services/libs)
against a local vuln DB.

## Quickstart

```bash
uv sync --all-groups
uv run pipt run example <activity-name> ./scope.txt --root /path/to/parent
# output goes under  <parent>/<activity-name>/   (--root defaults to the cwd)

uv run ruff check . && uv run ty check src/ && uv run pytest   # dev gate
```

## Commands

The CLI (`pipt`) has two subcommands: **`run`** (run a pipeline) and **`serve`**
(start the observability UI). Run via `uv run pipt …`.

### `pipt run` — run a pipeline over a scope

```bash
uv run pipt run <pipeline> <activity> <scope.txt> [--root DIR] [-v] [--resume] [--observe [API_URL]]
```

Positional arguments:

| Arg          | What it is |
|--------------|------------|
| `<pipeline>` | Which pipeline to run: **`example`** (dependency-free stub tasks — fake IPs/services, no external binaries; what the test suite and CI exercise) or **`recon`** (the real ProjectDiscovery toolchain). |
| `<activity>` | Name of the workspace directory created for this run. **All state lives on disk under it** — there is no database. |
| `<scope.txt>`| Input scope file (domains / URLs / IPs, one per line). |

Options:

| Flag | What it does |
|------|--------------|
| `--root DIR` | Parent directory for the activity. Output goes to `<root>/<activity>/`. Default: the current directory. |
| `-v`, `--verbose` | Surface the exact command and full stdout/stderr of every tool on the console. The complete run log is **always** persisted to `<activity>/logs/run.log` regardless of this flag. |
| `--resume` | Skip stages that a prior run of this activity already finished (`.state/<stage>.done` markers). Markers are invalidated automatically if the scope changes. |
| `--observe [API_URL]` | Stream this run to the Prefect UI (run graph + task states + per-stage logs). `API_URL` defaults to the local server (`http://127.0.0.1:4200/api`); start it first with `pipt serve`. |
| `--config PATH` | TOML file of operator knobs (profile, oast, tool paths, wordlists, …) instead of scattered env vars. See [`pipt.toml.example`](pipt.toml.example) and [Environment variables](#environment-variables). |
| `--set KEY=VALUE` | Override one config knob, repeatable — highest precedence (e.g. `--set oast=on --set profile=home`). |

Exit codes: **`0`** all stages OK · **`1`** one or more stages failed (CI/automation signal) · **`130`** interrupted with Ctrl-C — partial results are saved; resume with `--resume`.

```bash
# dry run with no external tools — exercises the scaffolding end to end
uv run pipt run example demo ./scope.txt -v

# the real recon toolchain against an authorized scope
echo "https://ginandjuice.shop/" > scope.txt
uv run pipt run recon ginandjuice ./scope.txt -v

# with a config file of operator knobs + a one-off override (precedence: --set > env > file > default)
cp pipt.toml.example pipt.toml      # then edit it
uv run pipt run recon ginandjuice ./scope.txt --config pipt.toml --set oast=on
```

### `pipt serve` — Prefect server + UI (observability)

```bash
pipt serve
```

Starts the Prefect server (UI + API) in the **foreground** at <http://127.0.0.1:4200> — run it
in its own terminal. It is **pure telemetry** (run graph, task states, per-stage timings, logs);
the pipeline's state stays on disk and runs identically without it. To see a run in the UI, add
`--observe` to a `pipt run` in another terminal:

```bash
pipt serve                                                  # terminal 1
uv run pipt run recon ginandjuice ./scope.txt --observe     # terminal 2
```

### Install & dev gate

```bash
uv sync --all-groups                                          # install (incl. dev/lint/test groups)
uv run ruff check . && uv run ty check src/ && uv run pytest  # the full dev gate
uv run pytest tests/core/test_orchestrator.py                 # run one test file
```

## Environment variables

These operator knobs (read by the **`recon`** pipeline; the `example` pipeline ignores them) can be set
in a **config file** (`--config pipt.toml`, see [`pipt.toml.example`](pipt.toml.example)) or as `PIPT_*`
environment variables. **Precedence: `--set KEY=VALUE` (CLI, repeatable) > `PIPT_*` env var > config
file > default.** The CLI applies the resolved values **before** the pipeline is imported and snapshots
the effective config (secrets redacted) to `<activity>/config.toml` for reproducibility (re-feedable
with `--config`). The table below lists each `PIPT_*` var; the equivalent config-key is in
[`pipt.toml.example`](pipt.toml.example) (e.g. `PIPT_HTTP_HEADER` → `http_header`, `PIPT_SQLMAP` →
`tools.sqlmap`, `PIPT_WL_<ROLE>` → `wordlists.roles.<role>`). If you use env vars **directly** (not via
config), set them **before** launching — `PIPT_PROFILE` / `PIPT_NET_LIMIT` are resolved at import time.
The ~119 internal tuning constants (caps/timeouts/thresholds) are **not** exposed here — they stay as
expert defaults in the code; `profile` is the bundle for the rate-sensitive ones.

### Load & rate

| Variable | Values / default | What it does |
|----------|------------------|--------------|
| `PIPT_PROFILE` | `wide` (default) · `home` | Rate profile. `wide` = full bandwidth; `home` throttles the heavy hitters (naabu `-rate` 300 vs 1000, nuclei `-rl` 50 vs 150, feroxbuster `-t`/`-L`) to spare a domestic line/router. The active profile is logged at run start. |
| `PIPT_NET_LIMIT` | integer · default `10` (or `4` when `PIPT_PROFILE=home`) | Global cap on concurrent **network** stages (per-app *and* spanning), so the aggregate uplink load stays bounded. In-process, no Prefect server needed. |

### Auth & crawl behavior

| Variable | Values / default | What it does |
|----------|------------------|--------------|
| `PIPT_HTTP_HEADER` | `Name: value` headers, multiple separated by newlines or `;;` | Operator session headers/cookies threaded into katana/httpx/nuclei (`-H`), arjun (`--headers`) and x8 (`-H`) so the crawl/fetch/fuzz/DAST reach the **authenticated** surface. |
| `PIPT_RECRAWL` | `on` (default) · `preview` · `off` | The `recrawl` stage: `on` crawls fuzzing-discovered entry points into new territory; `preview` writes/logs the seeds (`raw/recrawl/seeds.txt`) **without** crawling; `off` skips it. |
| `PIPT_DEEP_DIVE` | truthy to enable · default off | Opt-in stage-3 content-discovery **deep dive** (huge Assetnote *manual* lists at full depth, on a few high-value hosts only). Off by default — it costs hours/host. |
| `PIPT_OAST` | truthy to enable · default off | Opt-in **blind-XSS via OAST**: dalfox `-b` fires blind payloads at an `interactsh-client` (≥1.3) run alongside the dalfox passes; each request gets a unique callback so a **synchronous** hit correlates per-request. Off by default (adds the interactsh dependency and, by default, routes callbacks through the public oast servers — a RoE/privacy note). |
| `PIPT_INTERACTSH_SERVER` | public oast servers | Self-hosted interactsh server(s) for OAST, so callbacks don't transit third-party infra. |
| `PIPT_INTERACTSH_TOKEN` | — | Auth token for a protected/self-hosted interactsh server. |

### Tool & path overrides

| Variable | Default | What it does |
|----------|---------|--------------|
| `PIPT_NUCLEI_DAST_TEMPLATES` | `~/nuclei-templates/dast` | Directory of nuclei `-dast` fuzzing templates. The DAST steps skip (best-effort) if it (or nuclei) is absent. |
| `PIPT_SQLMAP` | `/opt/sqlmap-dev/sqlmap.py` | Path to the `sqlmap.py` script for the `sqli`/`sqli_full` scanners (run via the venv interpreter). Best-effort: the step skips if absent. (dalfox, for `xss`/`xss_full`, is resolved from `~/go/bin`.) |
| `PIPT_SEARCH_VULNS` | `~/.local/bin/search_vulns` | Path to the `search_vulns` binary used by the CVE-lookup steps (offline, local DB). Build/refresh the DB out-of-band: `search_vulns -u`. |
| `PIPT_EYEWITNESS` | auto (`eyewitness` on PATH › `/opt/EyeWitness` venv) | Full EyeWitness launch command override for the optional `screenshot` EyeWitness pass. |

### Wordlists (resolved by ROLE, nothing hardcoded)

| Variable | What it does |
|----------|--------------|
| `PIPT_WORDLISTS` | `:`-separated search directories for global wordlists, prepended to the common locations (e.g. `/usr/share/seclists`). |
| `PIPT_WL_<ROLE>` | Absolute path that pins a specific role's list, overriding discovery. Resolution order per role: BYO (`wl_global/<role>.txt`) › `PIPT_WL_<ROLE>` › discovery under `PIPT_WORDLISTS`/SecLists › unresolved (the step degrades gracefully). Roles include `content`, `params`, the staged `an_*`/`mn_*` Assetnote lists, and the CMS lists `wordpress`/`drupal`/`joomla`. |

> For the *why* behind these knobs (rate-profile rationale, the deep-dive gating, the staged
> wordlist strategy, …) see **[CLAUDE.md](CLAUDE.md)** — the single source of truth.

## Documentation

Architecture, the workspace contract, conventions, and project notes live in
**[CLAUDE.md](CLAUDE.md)** — the single source of truth.

Views of the recon pipeline's flow — **all auto-generated from the code** by
`pipt.pipelines.recon.flowmeta` and regenerated by a hook on any change under `src/pipt/pipelines/`
(commands or execution order), so they never drift:

- **[docs/pipeline-flow.html](docs/pipeline-flow.html)** — the detailed band "spec sheet": bands,
  parallelism, barriers, per-step commands/outputs/notes. Open it in a browser.
- **[docs/pipeline-map.html](docs/pipeline-map.html)** — a conceptual **flowchart** you can
  **pan/zoom and scroll both ways** (open in a browser; renders Mermaid, needs a connection). Each
  node shows the step and its commands; bands/phases and global barriers at a glance.
- **[docs/pipeline-map.md](docs/pipeline-map.md)** — the same flowchart as a Markdown ```mermaid
  block (renders on GitHub).

## Authorized test scope

```
https://ginandjuice.shop/   # PortSwigger demo
scanme.nmap.org             # Nmap-sanctioned
```
