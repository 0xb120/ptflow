# ptflow — Prefect scaffolding for automated pentest pipelines

A reusable framework (`core/`) hosting pluggable `pipelines/<name>/`. **Files on
disk are the only state — no database.** A breadth asset-discovery phase feeds a
clustering step that fans out into per-app depth loops. The external pipeline runs
those loops **surface-first, DAST-first**: map the explorable surface (OSINT/crawl)
and DAST *that* for low-hanging fruit, then guess/fuzz, then DAST the guessed surface
— each phase separated by a global barrier. Deterministic risk ranking and coverage quotas choose
high-value requests within each cap; unused app budget is transferred to richer surfaces without
increasing the engagement total. Offline **known-CVE lookup** correlates enumerated software
(server/tech/services/libs) against a local vuln DB.

## Quickstart

```bash
uv sync --all-groups
uv run ptflow run example <activity-name> ./scope.txt --root /path/to/parent
# output goes under  <parent>/<activity-name>/   (--root defaults to the cwd)

uv run ruff check . && uv run ty check src/ && uv run pytest   # dev gate
```

## Commands

The CLI (`ptflow`) exposes pipeline execution and inspection commands plus the offline detection
benchmark evaluator. Run it via `uv run ptflow …`.

### `ptflow run` — run a pipeline over a scope

```bash
uv run ptflow run <pipeline> <activity> <scope.txt> [--root DIR] [-v] [--resume] [--observe [API_URL]]
```

Positional arguments:

| Arg          | What it is |
|--------------|------------|
| `<pipeline>` | Which pipeline to run: **`example`** (dependency-free stub tasks — fake IPs/services, no external binaries; what the test suite and CI exercise) or **`external`** (the real ProjectDiscovery toolchain). |
| `<activity>` | Name of the workspace directory created for this run. **All state lives on disk under it** — there is no database. |
| `<scope.txt>`| Input scope file (domains / URLs / IPs, one per line). |

Options:

| Flag | What it does |
|------|--------------|
| `--root DIR` | Parent directory for the activity. Output goes to `<root>/<activity>/`. Default: the current directory. |
| `-v`, `--verbose` | Surface the exact command and full stdout/stderr of every tool on the console. The complete run log is **always** persisted to `<activity>/logs/run.log` regardless of this flag. |
| `--resume` | Skip stages that a prior run of this activity already finished (`.state/<stage>.done` markers). Markers are invalidated automatically if scope, effective configuration, or the pipeline graph/artifact contract changes. Older workspaces without config/pipeline fingerprints rerun once, then resume normally. |
| `--observe [API_URL]` | Stream this run to the Prefect UI (run graph + task states + per-stage logs). `API_URL` defaults to the local server (`http://127.0.0.1:4200/api`); start it first with `ptflow serve`. |
| `--config PATH` | TOML file of operator knobs (profile, oast, tool paths, wordlists, …) instead of scattered env vars. See [`ptflow.toml.example`](ptflow.toml.example) and [Environment variables](#environment-variables). |
| `--set KEY=VALUE` | Override one config knob, repeatable — highest precedence (e.g. `--set oast=on --set profile=home`). |
| `--ai` | Enable the optional LLM layer; equivalent to `--set ai.enabled=on`. Select a provider/model in `[ai]` or use a preset from [`configs/ai/`](configs/ai/). |

Exit codes: **`0`** all stages OK · **`1`** one or more stages failed (CI/automation signal) · **`130`** interrupted with Ctrl-C — partial results are saved; resume with `--resume`.

Every run initializes `coverage.json` under the activity directory with run/stage coverage
(resume/disabled/failure status and invalidation reason, config/pipeline hashes, logical dependencies,
observed artifact I/O, command outcomes,
caps/drops, risk-selection distributions (source, method, authority, content type and parameter
location), limits, and dependency inventory). Safe per-request ranking audits live under each app's
`raw/ranking/`; they contain shapes and reasons, never header/body/query values. After every app group completes the phase-2 surface
DAST, the global `surface_checkpoint` writes an isolated snapshot under
`checkpoints/surface/findings/` plus the early deterministic `reports/report-surface.md` / `.json`,
before the long guessing/deep loops start. The terminal fan-in later writes the authoritative
`reports/report.md` and `reports/report.json` over all normalized/deduplicated findings. With `--ai`,
the optional narrative remains separate in `reports/report-ai.md`; it never overwrites either
deterministic report. Each normalized finding exposes the common evidence contract (`finding_id`,
`class`, `target`, `request_ref`, `confidence`, `detector`, `verification_method`, `evidence_refs` and
`control_evidence_refs`) while preserving the native scanner details. When a pipeline composes
follow-up runs, the parent also writes
`reports/composition.json` and a summary-only `reports/report-composed.md` / `.json`: these record
parent/child lineage, state and aggregate counts while linking—never copying—the authoritative reports.

```bash
# dry run with no external tools — exercises the scaffolding end to end
uv run ptflow run example demo ./scope.txt -v

# the real external toolchain against an authorized scope
echo "https://ginandjuice.shop/" > scope.txt
uv run ptflow run external ginandjuice ./scope.txt -v

# with a config file of operator knobs + a one-off override (precedence: --set > env > file > default)
cp ptflow.toml.example ptflow.toml      # then edit it
uv run ptflow run external ginandjuice ./scope.txt --config ptflow.toml --set oast=on
```

### `ptflow serve` — Prefect server + UI (observability)

```bash
ptflow serve
```

Starts the Prefect server (UI + API) in the **foreground** at <http://127.0.0.1:4200> — run it
in its own terminal. It is **pure telemetry** (run graph, task states, per-stage timings, logs);
the pipeline's state stays on disk and runs identically without it. To see a run in the UI, add
`--observe` to a `ptflow run` in another terminal:

```bash
ptflow serve                                                  # terminal 1
uv run ptflow run external ginandjuice ./scope.txt --observe     # terminal 2
```

### `ptflow doctor` — verify external dependencies are installed

```bash
uv run ptflow doctor [<pipeline>]     # default: external
```

Checks that every external tool and dataset the pipeline needs is present on the host — turning
"are the requirements installed?" into a verifiable gate when provisioning a new workstation (the
org installer is `/opt/custom-tools/org/install-offsec-tools.sh`). Prints a grouped ✓/✗ report
(CORE tools / OPTIONAL tools / datasets) and **exits `1` if a CORE tool is missing** (missing
optional tools/datasets are warnings → exit `0`). It shares the `requirements()` manifest with the
run-time `preflight` summary, so the two never disagree. Honours `PTFLOW_*` path overrides.

### `ptflow evaluate` — measure detection quality against a golden set

```bash
uv run ptflow evaluate <activity-dir> <manifest.json> [--output PATH]
```

Compares a completed activity with a versioned benchmark manifest, entirely offline. It evaluates
expected and negative findings, HTTP request shapes and correlated OAST callbacks, then writes
`<activity>/reports/evaluation.json` by default. The machine report includes TP/FP/FN, precision and
recall globally and per class, confidence distribution, surface coverage and observed run cost.

Exit codes: **`0`** benchmark passed · **`1`** detection/coverage regression · **`2`** invalid manifest
or missing input. The versioned contract smoke test can be run with:

```bash
uv run ptflow evaluate \
  benchmarks/m0-smoke/activity \
  benchmarks/m0-smoke/manifest.json \
  --output /tmp/ptflow-m0-evaluation.json
```

### Install the CLI for the current user

The project already publishes the `ptflow` console entry point. Install it once with uv to make
`ptflow` available from any directory, without prefixing every command with `uv run`:

```bash
cd /path/to/ptflow
uv tool install --editable .
ptflow --help
```

The editable install is recommended for a development checkout: Python source changes are picked up
without reinstalling the tool. Re-run the install after changing project metadata or dependencies.
Use `uv tool install .` instead when you want an independent snapshot of the current checkout.

If uv reports that its executable directory is not on `PATH`, run `uv tool update-shell` and restart
the shell. This installs only the Python CLI and its Python dependencies; binaries and datasets used
by the real pipelines still need to be provisioned separately and can be checked with `ptflow doctor`.

### Configuration files and locations

`ptflow` currently loads a TOML file **only** when it is passed explicitly with `--config`; it does
not auto-discover `ptflow.toml` in the current directory or a user-level config under `~/.config`.
The recommended location convention is:

| Location | Intended use |
|----------|--------------|
| `~/.config/ptflow/config.toml` (or `$XDG_CONFIG_HOME/ptflow/config.toml`) | Personal defaults shared by runs. Pass it explicitly with `--config`. |
| `./ptflow.toml` | Settings specific to the current engagement or project. |
| `<activity>/config.toml` | Auto-generated snapshot of the effective settings used by that run. |

For example, a globally installed CLI can use personal defaults from any working directory:

```bash
ptflow run external audit /path/to/scope.txt \
  --root /path/to/output \
  --config ~/.config/ptflow/config.toml
```

Configuration precedence is `--set` > `PTFLOW_*` environment variables > `--config` file > code
defaults. `~` is expanded in both the `--config` filename and path-valued settings. Relative paths,
including `./ptflow.toml`, the scope file, and relative paths stored in TOML, are interpreted from the
directory where `ptflow` is invoked—not from the package checkout or the TOML file's directory. Use
absolute paths or `~` for shared configuration, tool, dataset, and wordlist paths.

After a run, the effective non-default configuration is written to `<activity>/config.toml` for
reproducibility. It can be fed back through `--config`; secret values such as HTTP headers and
Interactsh tokens are stored as `<redacted>` and must be restored before reuse.

### Install & dev gate

```bash
uv sync --all-groups                                          # install (incl. dev/lint/test groups)
uv run ruff check . && uv run ty check src/ && uv run pytest  # the full dev gate
uv run pytest tests/core/test_orchestrator.py                 # run one test file
```

## Environment variables

These operator knobs (read by the real pipelines; the `example` pipeline ignores them) can be set
in a **config file** (`--config ptflow.toml`, see [`ptflow.toml.example`](ptflow.toml.example)) or as `PTFLOW_*`
environment variables. **Precedence: `--set KEY=VALUE` (CLI, repeatable) > `PTFLOW_*` env var > config
file > default.** The CLI applies the resolved values **before** the pipeline is imported and snapshots
the effective config (secrets redacted) to `<activity>/config.toml` for reproducibility (re-feedable
with `--config`). The table below lists each `PTFLOW_*` var; the equivalent config-key is in
[`ptflow.toml.example`](ptflow.toml.example) (e.g. `PTFLOW_HTTP_HEADER` → `http_header`, `PTFLOW_SQLMAP` →
`tools.sqlmap`, `PTFLOW_WL_<ROLE>` → `wordlists.roles.<role>`). If you use env vars **directly** (not via
config), set them **before** launching — `PTFLOW_PROFILE` / `PTFLOW_NET_LIMIT` are resolved at import time.
The ~119 internal tuning constants (caps/timeouts/thresholds) are **not** exposed here — they stay as
expert defaults in the code; `profile` is the bundle for the rate-sensitive ones.

### Load & rate

| Variable | Values / default | What it does |
|----------|------------------|--------------|
| `PTFLOW_PROFILE` | `wide` (default) · `home` | Rate profile. `wide` = full bandwidth; `home` throttles the heavy hitters (naabu `-rate` 300 vs 1000, nuclei `-rl` 50 vs 150, feroxbuster `-t`/`-L`) to spare a domestic line/router. The active profile is logged at run start. |
| `PTFLOW_NET_LIMIT` | integer · default `10` (or `4` when `PTFLOW_PROFILE=home`) | Global cap on concurrent **network** stages (per-app *and* spanning), so the aggregate uplink load stays bounded. In-process, no Prefect server needed. |
| `PTFLOW_EXTERNAL_PORTSCAN_MODE` | `balanced` (default) · `exhaustive` | Both modes start with curated ~250 web ports + a bounded top-1000 barrier. `exhaustive` additionally runs full-65535 as a spanning pass: new web apps go to a nested `webscan`, while the remaining late non-HTTP sockets are fingerprinted with nerva and correlated against the local CVE DB. |
| `PTFLOW_EXTERNAL_PORTSCAN_DEADLINE_SECONDS` | positive integer · default `900` | Hard wall-clock budget for the common pre-cluster top-1000 pass. Partial results are preserved on timeout and status is written to `asset_discovery/canonical/portscan_coverage.json`. The exhaustive spanning pass remains unbounded. |

### Auth & crawl behavior

| Variable | Values / default | What it does |
|----------|------------------|--------------|
| `PTFLOW_HTTP_HEADER` | `Name: value` headers, multiple separated by newlines or `;;` | **webscan only.** Operator session headers/cookies threaded into the web scanning tools so crawl/fetch/fuzz/DAST reach the **authenticated** surface. Ignored by `external` to avoid spraying auth across broad discovery. |
| `PTFLOW_RECRAWL` | `on` (default) · `preview` · `off` | The `recrawl` stage: `on` crawls fuzzing-discovered entry points into new territory; `preview` writes/logs the seeds (`raw/recrawl/seeds.txt`) **without** crawling; `off` skips it. |
| `PTFLOW_DEEP_DIVE` | truthy to enable · default off | Opt-in stage-3 content-discovery **deep dive** (huge Assetnote *manual* lists at full depth, on a few high-value hosts only). Off by default — it costs hours/host. |
| `PTFLOW_OAST` | truthy to enable · default off | Enables Dalfox blind-XSS through `interactsh-client` (≥1.3). Nuclei DAST no longer filters OAST templates: every template in enabled packs runs, using Nuclei's Interactsh session. |
| `PTFLOW_INTERACTSH_SERVER` | public oast servers | Self-hosted interactsh server(s) for OAST, so callbacks don't transit third-party infra. |
| `PTFLOW_INTERACTSH_TOKEN` | — | Auth token for a protected/self-hosted interactsh server. |

### Optional AI providers

Install `uv sync --extra ai`, then use one of the ready configurations in
[`configs/ai/`](configs/ai/). The default provider is local Ollama; a model must always be selected
explicitly. `--ai` is equivalent to `--set ai.enabled=on`, while a preset can enable itself.

| Variable | Values / default | What it does |
|----------|------------------|--------------|
| `PTFLOW_AI` | truthy to enable · default off | Enables contextual wordlists, policy-gated CVE PoC interpretation, secret-lead triage, cross-finding hypotheses, and `reports/report-ai.md` in `external` and `webscan`. |
| `PTFLOW_AI_PROVIDER` | `ollama` (default, local) · `ollama-cloud` · `openrouter` · `huggingface` · `openai-compatible` · legacy `openai` / `claude-code` | Selects the runtime backend. Named providers supply their standard endpoint. |
| `PTFLOW_AI_MODEL` | required | Provider-specific model ID, kept explicit for reproducibility. |
| `PTFLOW_AI_BASE_URL` | provider default | Overrides the endpoint; required for `openai-compatible`. |
| `PTFLOW_AI_CACHE` | `on` | Reuses validated outputs from `<activity>/ai/cache/` for identical prompts/configuration. |
| `PTFLOW_AI_CONCURRENCY` | `2` | Maximum simultaneous LLM requests in the process. |
| `PTFLOW_AI_TIMEOUT_SECONDS` / `PTFLOW_AI_MAX_RETRIES` | `180` / `2` | Provider request timeout and transport retries. |
| `PTFLOW_AI_MAX_CALLS` | `50` | Run-wide provider-call budget; cache hits do not consume it. |
| `PTFLOW_AI_MAX_INPUT_TOKENS` / `PTFLOW_AI_MAX_OUTPUT_TOKENS` | `250000` / `30000` | Run-wide token budgets; estimates are used when a provider omits usage. |
| `PTFLOW_AI_MAX_COST` | `0` (disabled) | Run-wide cost ceiling when the provider exposes cost metadata. |
| `PTFLOW_AI_REMOTE_SECRETS` | `redacted` | Hosted-provider secret policy: `off`, `redacted`, or explicit `full`. |

Each stage (`wordlist`, `cve_poc`, `secret_triage`, `triage`, `report`) can override `enabled`, `provider`,
`model`, `base_url`, and `max_output_tokens` under `[ai.stages.<name>]`; see the hybrid
[`mixed.toml`](configs/ai/mixed.toml) setup. Provider usage is recorded without prompts or outputs in
`<activity>/ai/usage.jsonl`.

Credentials stay in standard environment variables and are never stored in the TOML snapshot:
`OLLAMA_API_KEY` for Ollama Cloud, `OPENROUTER_API_KEY` for OpenRouter, `HF_TOKEN` for Hugging Face,
and `OPENAI_API_KEY` for a generic compatible endpoint. Hosted providers receive assessment evidence,
but secret values are redacted by default, including when consolidated secret findings feed later
triage/report stages. Confirm the engagement's data-handling rules or use local Ollama.

### Tool & path overrides

| Variable | Default | What it does |
|----------|---------|--------------|
| `PTFLOW_NUCLEI_DAST_TEMPLATES` | `~/nuclei-templates/dast` | Directory of nuclei `-dast` fuzzing templates. The DAST steps skip (best-effort) if it (or nuclei) is absent. |
| `PTFLOW_DAST_PACKS` | JSON array · official + bundled stable pack | Ordered local template packs (`name`, `path`, `source`, optional `revision`/`enabled`). This supersedes the legacy single directory when set. `@ptflow/stable` and `@ptflow/experimental` resolve bundled packs. |
| `PTFLOW_DAST_AGGRESSION` | `high` | Global Nuclei fuzz aggression. `high` includes all payload groups declared by every template. |
| `PTFLOW_DAST_FUZZ_PARAM_FREQUENCY` | `10000` | High repeated-parameter ceiling so common parameter names are not suppressed across the request corpus. |
| `PTFLOW_SQLMAP` | `/opt/sqlmap-dev/sqlmap.py` | Path to the `sqlmap.py` script for the `sqli`/`sqli_full` scanners (run via the venv interpreter). Best-effort: the step skips if absent. (dalfox, for `xss`/`xss_full`, is resolved from `~/go/bin`.) |
| `PTFLOW_SEARCH_VULNS` | `~/.local/bin/search_vulns` | Path to the `search_vulns` binary used by the CVE-lookup steps (offline, local DB). Build/refresh the DB out-of-band: `search_vulns -u`. |
| `PTFLOW_EYEWITNESS` | auto (`eyewitness` on PATH › `/opt/EyeWitness` venv) | Full EyeWitness launch command override for the optional `screenshot` EyeWitness pass. |

### Nuclei DAST rules

DAST resolves multiple local packs before every scan and executes every template in every enabled pack,
without tag/ID filters or phase-specific policies. The exact pack hashes, effective revisions, global
aggression/frequency, and template IDs are written to `raw/dast/template-selection*.json`; every
finding carries `ptflow_dast.pack`, `pack_revision`, and `selection="all"`. Missing packs degrade
best-effort during a pipeline run, while explicit validation is strict:

```bash
ptflow dast validate --config ptflow.toml
ptflow dast list --config ptflow.toml
# Explicit official-pack refresh, before a run (never concurrently with it):
nuclei -ut && ptflow dast validate --config ptflow.toml
```

Custom rules belong in a dedicated local pack. Use unique IDs, one file per request part
(`query`, `body`, `header`, `cookie`), request-part tags, bounded `max-request`, exact markers, and
positive plus negative calibration cases. The bundled examples live under
`src/ptflow/data/nuclei-dast/`; their OAST variants use exact Interactsh correlation.

```bash
pytest tests/dast/test_custom_templates.py -q  # live positive + negative calibration corpus
```

### Wordlists (resolved by ROLE, nothing hardcoded)

| Variable | What it does |
|----------|--------------|
| `PTFLOW_WORDLISTS` | `:`-separated search directories for global wordlists, prepended to the common locations (e.g. `/usr/share/seclists`). |
| `PTFLOW_WL_<ROLE>` | Absolute path that pins a specific role's list, overriding discovery. Resolution order per role: BYO (`wl_global/<role>.txt`) › `PTFLOW_WL_<ROLE>` › discovery under `PTFLOW_WORDLISTS`/SecLists › unresolved (the step degrades gracefully). Roles include `subdomains` (active shuffledns only for `*.domain` scope entries), `content`, `params`, the staged `an_*`/`mn_*` Assetnote lists, and the CMS lists `wordpress`/`drupal`/`joomla`. |

> For the *why* behind these knobs (rate-profile rationale, the deep-dive gating, the staged
> wordlist strategy, …) see **[CLAUDE.md](CLAUDE.md)** — the single source of truth.

## Documentation

Architecture, the workspace contract, conventions, and project notes live in
**[CLAUDE.md](CLAUDE.md)** — the single source of truth.

Views of each pipeline's flow — **all auto-generated from the code** by `ptflow.core.flowdocs` and
regenerated by a hook on any change under `src/ptflow/pipelines/` (commands or execution order), so
they never drift. Every pipeline gets three `docs/<name>-pipeline-*` views (`external`, `internal`,
`webscan` today); the `example` stub is exempt. For the **external** pipeline:

- **[docs/external-pipeline-flow.html](docs/external-pipeline-flow.html)** — the detailed band "spec
  sheet": bands, parallelism, barriers, per-step commands/outputs/notes. Open it in a browser.
- **[docs/external-pipeline-map.html](docs/external-pipeline-map.html)** — a conceptual **flowchart**
  you can **pan/zoom and scroll both ways** (open in a browser; renders Mermaid, needs a connection).
  Each node shows the step and its commands; bands/phases and global barriers at a glance.
- **[docs/external-pipeline-map.md](docs/external-pipeline-map.md)** — the same flowchart as a Markdown
  ```mermaid block (renders on GitHub).

The **internal** ([flow](docs/internal-pipeline-flow.html) · [map](docs/internal-pipeline-map.md)) and
**webscan** ([flow](docs/webscan-pipeline-flow.html) · [map](docs/webscan-pipeline-map.md)) pipelines
have the same three views under their own `docs/<name>-pipeline-*` names.

## Doc-sync hook (optional)

This repo ships a post-merge hook that auto-updates documentation after a merge to `main`
(regenerates the flow maps + a headless Claude agent refreshes the prose docs, as one reviewable
`docs: auto-sync` commit). Activate once with:

```bash
git config core.hooksPath .githooks
```

Skip it for a given merge with `PTFLOW_NO_DOC_SYNC=1 git merge …`. See CLAUDE.md → "Documentation automation".

## Authorized test scope

```
https://ginandjuice.shop/   # PortSwigger demo
scanme.nmap.org             # Nmap-sanctioned
```
