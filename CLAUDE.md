# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Single source of truth.** Architecture, commands, conventions, the workspace
> contract, and ongoing project notes all live in this file. Keep it aligned with
> the code, and put new documentation notes here rather than creating new doc files.
> Inherits the toolkit-wide contract at `/opt/custom-tools/CONVENTIONS.md`.

## What this is

**ptflow** is a reusable **Prefect ≥3** scaffolding (`core/`) hosting pluggable pentest
`pipelines/<name>/`. **Files on disk are the only state — there is no database.** A
pipeline runs an asset-discovery (breadth) phase over the whole scope, clusters the
results into "application groups", then runs one or more per-app **loops** (depth)
that fan out under Prefect.

> **Terminal step = deterministic `consolidate` (done); agent seam dormant by default.** The real
> terminal fan-in is now `consolidate` (`pipelines/external/tasks.consolidate`, an optional `Pipeline`
> hook the orchestrator calls like `preflight`): it lifts every app group's per-app findings into the
> activity-level `<activity>/findings/<type>.jsonl`, one file per finding TYPE (`cve`/`dast` fold
> their surface+deep passes). The old agent stage (`core/agent.py`, `HypothesisProvider`) still runs
> as a **dormant** `StubProvider` fan-in beside it by default — its real (LLM-backed) implementation
> was parked; the opt-in `--ai` layer now provides it (`ai_triage`), so don't treat the seam as
> permanently inert, and leave the seam in place.

## Commands

```bash
uv sync --all-groups                                   # install (incl. dev/lint/test groups)
uv run ptflow run <pipeline> <activity> <scope.txt> [--root DIR] [-v] [--resume]
                                                       # output → <root>/<activity>/ (root defaults to cwd)
                                                       # --resume: skip stages a prior run finished (same scope)
                  [--config ptflow.toml] [--set KEY=VALUE ...]   # operator knobs (see "Run config")
uv run ptflow doctor [<pipeline>]                      # verify a pipeline's external tools + datasets
                                                       # are installed (default: external); exit 1 if a
                                                       # CORE tool is missing (CI/provisioning gate)
uv run ptflow steps <pipeline> [--config ptflow.toml] [--set KEY=VALUE ...] [-v]
                                                       # list every step grouped by band + its
                                                       # effective on/off state (live view; -v adds
                                                       # phase/scope/net/needs). Read-only, exit 0.
uv run ruff check . && uv run ty check src/ && uv run pytest   # the full dev gate
uv run pytest tests/core/test_orchestrator.py          # one file
uv run pytest tests/core/test_scope.py::test_classify  # one test
```

- `<pipeline>` is `example`, `external`, `internal`, or `webscan` (see below). Every external command (routed through
  `tools.run`/`tools.pipe`) is logged, and the full run log — every command + output — is persisted
  to `<activity>/logs/run.log` regardless of console verbosity. `-v`/`--verbose` additionally surfaces
  commands and live tool stdout/stderr on the console.
  - The "ptflow" logger level is always DEBUG; the *console* handler is raised to INFO without `-v`,
    so the file (DEBUG) captures the full record while the console stays quiet. `is_verbose()` (not
    the logger level) gates console-only behaviour like streaming a tool's stderr.
  - `tools.run` logs a WARNING on any non-zero exit, so a broken tool (bad flag, crash) can't
    masquerade as a clean empty result — the failure shows on the console even without `-v`.
- Ruff runs with `select = ["ALL"]`; respect the `ignore`/`per-file-ignores` in `pyproject.toml`
  rather than adding blanket `# noqa`. `ty` is the type checker (not mypy).

### Run config (operator knobs)

The **operator-facing** knobs (the `PTFLOW_*` env vars: `profile`, `oast`, `net_limit`, `http_header`,
`recrawl`, `deep_dive`, tool paths, wordlist dir/roles, interactsh server/token, `ai.enabled`/`ai.model`/
`ai.base_url`/`ai.provider`) can be set in an
optional TOML file (`--config ptflow.toml`; see `ptflow.toml.example` for the annotated template) instead of
scattered env vars. Resolution is `core/runconfig.py` (pure `resolve()` + thin `apply()`/`snapshot()`),
loaded by the CLI's `_run`. **Precedence: `--set KEY=VALUE` (CLI, repeatable) > `PTFLOW_*` env var >
config file > code default.** The CLI writes the resolved knobs into `os.environ` **before** importing
the pipeline (its constants read `PTFLOW_*` at import) — so `orchestrate`/`load_pipeline` are imported
*inside* `cli._run`, after `runconfig.apply()`; the existing env reads stay the single consumption point
(no constant re-plumbed). The effective values (secrets — `http_header`/`interactsh.token` — redacted)
are snapshotted to `<activity>/config.toml` for reproducibility (re-feedable with `--config`). Enums
(`profile`, `recrawl`) are validated and unknown keys warned (config errors exit 2). **Deliberately NOT
in config:** the ~119 internal tuning constants (caps/rates/timeouts/thresholds) — they stay as expert
defaults in code, with `profile` (`wide`/`home`) the bundle for the rate-sensitive ones. Env vars keep
working unchanged (config is additive/optional). `core/config.py` (the `Config`/`CONFIG` structural
dataclass: `fanout`/`retries`) is a SEPARATE concern — don't conflate it with `runconfig`.

**Per-step on/off toggles (debug).** A sparse `[steps.<pipeline>]` table disables named stages for a
run — `dast = false` under `[steps.external]`, or the one-off `--set steps.external.dast=off` (precedence
`--set` > config file; no env layer). Only listed steps change; everything else stays ON. Step names are
validated against the pipeline's **live `stages`** (unknown name → config error, exit 2; a
malformed key missing the pipeline segment — `steps.dast` instead of `steps.external.dast` — is
flagged as an unknown config key, not silently ignored), so the config
can't reference a deleted/renamed step — that, plus the live `ptflow steps <pipeline>` view, is how the
feature stays in sync with the code (nothing generated to drift). Mechanically the resolved set FILTERS
`pipeline.stages` before the DAG is built (`orchestrator._run_dag`); this needs no `needs` rewrite because
`topo_order`/`_submit_dag` already ignore missing dependency names and stages read on-disk inputs
tolerantly — a disabled step's dependents still run, degrading on absent inputs (a WARNING at run start
lists them). Disabled steps are recorded in `<activity>/config.toml`. Non-`Stage` hooks (`cluster`,
`consolidate`, `provider`, `report`, `followups`) are not toggleable.

### Checking dependencies (`ptflow doctor`)

`ptflow doctor [<pipeline>]` (default `external`) verifies the host has every external tool + dataset
the pipeline needs, so "are the requirements installed?" becomes a **verifiable gate** for provisioning
new workstations (the org installer is `/opt/custom-tools/org/install-offsec-tools.sh`). It prints a
grouped ✓/✗ report (CORE tools / OPTIONAL tools / datasets) and **exits `1` iff a CORE tool is missing**
(missing optional tools/datasets are warnings, exit `0`) — the CI/automation signal.

- **Single source of truth (`core/requirements.py` + a `requirements()` hook).** The pure checker
  (`Requirement`/`CheckResult`/`Report` + `check()`/`render_report()`, unit-tested via injected
  resolve/version callables) is fed a manifest a pipeline exposes via a **duck-typed `requirements()`
  hook** (same convention as `preflight`/`consolidate`/`followups` — read by `getattr`, off the
  Protocol). `external`'s `tasks.requirements()` builds it from the `_CORE_TOOLS`/`_OPTIONAL_TOOLS`
  dicts + the non-PATH tools (sqlmap/EyeWitness, checked by absolute path) + the on-disk datasets
  (`nuclei-templates/dast`, resolvers), and **`preflight()` renders from the SAME manifest** — so the
  run-time summary and `doctor` can't drift. A pipeline with no hook (e.g. `example`) is a graceful pass.
- **When you add a tool**, add it to `_CORE_TOOLS`/`_OPTIONAL_TOOLS` (or, for a non-PATH tool/dataset,
  to the tail of `requirements()`); `preflight` + `doctor` pick it up automatically. A version floor
  goes on the `Requirement` (`min_version` + `version_args`, e.g. interactsh-client ≥1.3); an
  unparseable version is treated as OK (never a false failure). Datasets are OPTIONAL (the pipeline
  degrades best-effort), so they warn but never fail the gate.
- **All three real pipelines declare the hook:** `external` and `internal` each build their manifest
  from their OWN `_CORE_TOOLS`/`_OPTIONAL_TOOLS` (+ external's non-PATH tools/datasets). `webscan`
  reuses external's manifest but **NARROWS the CORE set to its depth toolchain** (`_DEPTH_CORE` =
  httpx/katana/feroxbuster/nuclei) — external's breadth/OSINT tools are demoted to optional (via
  `dataclasses.replace`), so a webscan-only host doesn't FAIL the gate for tools webscan never runs
  (same coverage, reclassified — nothing dropped). `example` has no hook → graceful pass. **Honours
  `PTFLOW_*` env overrides** (the tool-path constants read them at import) but **not** `--config`/`--set` (v1).

## Observability (Prefect UI)

Observability uses the framework's own GUI — the Prefect server + dashboard — kept **optional** so the
"files on disk are the only state" invariant holds: the server is pure telemetry (run graph, task
states, per-stage timings, logs, history); the pipeline's state stays on disk and runs identically
without it (ephemeral).

```bash
ptflow serve                                             # start the Prefect server + UI → http://127.0.0.1:4200
uv run ptflow run external <activity> <scope.txt> --observe # stream THIS run to that UI (run graph + states + logs)
```

- **`ptflow serve`** wraps `prefect server start` (foreground; its own terminal). The UI reads the local
  SQLite (`~/.prefect/prefect.db`), so even plain runs show up there — but `--observe` is preferred.
- **`--observe [API_URL]`** (default the local server) redirects *this run* to the persistent server via
  `temporary_settings` (env set post-import is too late — Prefect would still spin a throwaway ephemeral
  server and contend on the SQLite). No global profile/config change; it also captures the `ptflow` logger
  so per-stage logs land on the run.
- The run graph is **readable + phase-grouped** because `_submit_dag` gives each task a per-stage
  `name`/`task_run_name` (`crawl[<app_id>]`) and a band tag (`breadth`/`spanning`/`post-cluster`/`loop:N`)
  via `with_options`; the flow run is named `<pipeline>:<activity>`. Cosmetic in ephemeral mode; the
  payoff is in the UI.
- *Why not Prefect's native result-cache/retry for resume instead of the `.state` markers:* see
  the resume design — our stages return nothing (they communicate via disk), and the cache store would
  live outside the activity workspace, breaking the file-as-only-state invariant.

## Documentation automation

Two mechanisms keep docs current; both are best-effort and never block work:

- **Flow maps (edit-time, deterministic):** the Claude Code PostToolUse hook `.claude/hooks/regen-flowmap.sh`
  regenerates `docs/<pipeline>-pipeline-*` when a file under `src/ptflow/pipelines/` is edited (see "Pipeline
  flow map" below).
- **Post-merge doc-sync (agent-driven):** the versioned git hook `.githooks/post-merge` → `.githooks/doc-sync.sh`
  runs after a merge that lands on `main`. It regenerates the flow-map docs (`ptflow.core.flowdocs`) and runs a
  **headless Claude agent** (`claude -p`, tools limited to Read/Edit/Grep/Glob, no Bash, under a timeout) to update
  the PROSE docs (`CLAUDE.md`, `README.md`, `ptflow.toml.example`) to reflect the merged change — committing
  everything as one isolated `docs: auto-sync after merge …` follow-up you should review. The agent is
  *instructed* to edit only those prose files; the hook itself **stages and commits only** documentation
  paths (the generated maps + those three files), so code, tests, and `docs/superpowers/**` are never
  committed by it. **One-time activation:** `git config core.hooksPath .githooks`.
  Knobs: `PTFLOW_NO_DOC_SYNC=1` (skip a merge), `PTFLOW_DOC_SYNC_TIMEOUT` (agent seconds, default 300),
  `CLAUDE_BIN` (override the binary). It skips gracefully when `claude` is unavailable (the deterministic
  regeneration is still committed) and when the merge touched no `src/`.

## Architecture

**Orchestration is a dependency DAG** (`core/orchestrator.py`). The flow is:
1. **activity stages** (`per_app=False`) run once over the whole scope as a DAG;
2. **`pipeline.cluster(activity)`** is the fan-out pivot — it groups discovery output into
   `scans/<app_id>/` dirs and returns the list of `app_id`s;
3. **per-app loops** run in order (see below);
4. the **agent** stage runs once as a fan-in (the dormant `StubProvider` by default; the real
   LLM-backed provider, `ai_triage`, when AI is enabled).

**Spanning stages** (`spanning=True`, activity-scope) don't block the breadth→cluster barrier:
they're launched once their breadth `needs` are done and awaited only at the fan-in, so they run
**∥ clustering + all the per-app loops** — for a long whole-scope scan (`nuclei_scope`) that hides
its cost behind the per-app work instead of serializing in front of it.

**Post-cluster spanning stages** (`cluster_scope=True`, activity-scope) are the same idea but
triggered **after `cluster`**: launched once the groups exist (so they read every group via
`activity.list_apps()`), run **∥ the per-app loops**, joined at the fan-in. Used for a cross-group
batch that wants one invocation over all groups — e.g. `screenshot`, one host per group in a single
httpx/EyeWitness run → one unified gallery.

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

An activity-scope `Stage(after_phase=N)` is a first-class **checkpoint** at that seam: it runs only
after every app group completed loop N, is awaited before loop N+1, and receives normal Prefect state,
coverage telemetry and step toggles. Checkpoints are deliberately regenerated on `--resume`: a failed
phase stage may have succeeded on the continuation, invalidating the prior snapshot. `external` and `webscan` use
`surface_checkpoint` after phase 2 to publish the early deterministic surface report.

Concurrency: `ThreadPoolTaskRunner(max_workers=N)` caps total in-flight stages **across all
apps**. Intra-app parallelism therefore competes with fan-out width — only parallelize slow,
network-bound steps. Network stages (`Stage.net`, the default; offline ones set `net=False`) are
tagged `net`. Two in-process caps gate them (module `BoundedSemaphore`s in `orchestrator.py`,
acquired in `_run_stage` in fixed order net→fan-out so they can't deadlock):
- **`_FANOUT_SLOTS`** = `fanout.max_workers` — per-app chain cap (the pool is sized larger, fan-out +
  spanning headroom, so spanning runs ∥ the loops; this re-imposes the real fan-out limit).
- **`_NET_SLOTS`** = **`PTFLOW_NET_LIMIT`** (else `4` when `PTFLOW_PROFILE=home`, else `fanout.net_limit`)
  — GLOBAL network-concurrency cap over per-app **and** spanning, so the aggregate uplink load stays
  bounded (a home line / consumer router can choke). In-process (no Prefect server dependency), unlike
  the native `net`-tag limit (`prefect concurrency-limit create net N`) which needs a persistent server
  to be reliable. Complements the rate profile — aggregate load ≈ concurrency × per-tool rate.

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
  asset_discovery/  raw/<tool>/  <canonical files>         # BREADTH (activity-scope) — TOP-LEVEL, not
                                                           #   under scans/ (subdomains.txt, tls_names.txt,
                                                           #   httpx_full_metadata.jsonl, excluded_cdn.jsonl,
                                                           #   naabu_web.txt [fast/httpx], naabu_full.txt
                                                           #   [spanning], nerva_full_metadata.jsonl, …)
                                                           #   scope_gate: inscope_{subdomains,tls_names,ips,
                                                           #   domain_ip_map}.txt (RoE-authorized set the active
                                                           #   stages read) + excluded_out_of_scope.jsonl (audit)
  .state/  <stage>.done  scope.sha        # --resume markers (skip completed stages; invalidated on scope change)
  scans/                                 # ONLY per-app group workspaces (no special-cased breadth dir)
    <app_id>/                            # one clustered app group (per-app loops)
      meta.json  hosts.txt  endpoints.txt  subs.txt  takeover.txt  …
      endpoints_passive.txt  endpoints_crawley.txt   #   discovery sources fetch_delta downloads
      crawl_class.json                   #   JS-render verdict + signals (gates crawl_headless)
      endpoints_headless.txt             #   gated headless crawl (JS-rendered apps only)
      screenshot.png                     #   per-group shot, reconciled from the batched run (or screenshot.failed)
      screenshot.json                    #   per-group fingerprint (status/title/server/tech/header_signals)
      default_creds.jsonl                #   EyeWitness signature-based default-cred leads (optional)
      endpoints_js.txt                   #   mine_responses (jsluice endpoints, round-0 seed)
      content_discovery.jsonl            #   feroxbuster forced-browse results (merge of all fixpoint rounds)
      secrets.jsonl                      #   secret fleet, run ONCE at content_discovery's tail (full corpus)
      requests_crawl.jsonl  requests_headless.jsonl  requests_api.jsonl  requests_recrawl.jsonl  #   FULL requests
      requests.jsonl                     #   request_catalog (PHASE 1): EXPLORABLE-surface catalog (phase-2 DAST input)
      requests_xref.jsonl                #   xref_catalog (PHASE 2): cross-group surface sidecar — OTHER in-scope groups' requests whose host is THIS group's (dast/xss/sqli read requests.jsonl ∪ this)
      requests_full.jsonl                #   request_catalog_full (PHASE 4): + guessed surface (param_fuzz/dast_full input)
      raw/recrawl/seeds.txt              #   recrawl: new-territory seeds (PTFLOW_RECRAWL on=crawl [default] · preview=list only)
      params.jsonl                       #   param_fuzz: hidden params, ALL locations {url,param,loc:query|body|json|header}
      findings/tilde_enum.jsonl  findings/dast.jsonl  findings/dast_full.jsonl  findings/wpprobe.jsonl  #   per-app findings (shortscan; DAST surface/deep; wpprobe WP CVEs); consolidate lifts up
      findings/xss.jsonl  findings/xss_full.jsonl  findings/sqli.jsonl  findings/sqli_full.jsonl   #   dedicated scanners (dalfox XSS / sqlmap SQLi), surface+deep; consolidate folds by type
      findings/cve.jsonl  findings/cve_full.jsonl    #   cve_lookup (PHASE 2) / cve_lookup_full (PHASE 4): known CVEs on enumerated software
      findings/secrets_triage.jsonl      #   ai_secret_triage (--ai, PHASE 4): LLM real/FP verdicts on secrets.jsonl leads, SIDECAR (never mutates secrets.jsonl)
      raw/cve/seen.txt                   #   cve_lookup: (product,version) covered in PHASE 2 → PHASE 4 reports only the delta
      wl_custom/seed.txt  wl_custom/round*.txt   #   per-app GENERATED wordlists (seed offline; round N = fuzzed delta)
      wl_custom/ai_seed.txt              #   ai_wordlist (--ai, PHASE 2): LLM-suggested candidate tokens, folded into content_discovery's wordlist
      responses/  responses/headless/  responses/discovered/round*/   # downloaded corpus (katana/httpx -srd) — mined offline
      raw/<tool>/  # provenance + tool scratch: raw/extracted/ (mined bodies),
                   #   raw/httpx/{screenshot,osint,discovered}, raw/katana/{crawl,headless},
                   #   raw/subjack/candidates.txt, raw/shortscan/rainbow*.txt,
                   #   raw/api_spec/ (spec probe+store), raw/dast/{input,input_full}.jsonl (nuclei -im jsonl input)
  findings/cve.jsonl  findings/dast.jsonl  findings/xss.jsonl  findings/sqli.jsonl  findings/tilde_enum.jsonl  findings/wpprobe.jsonl  findings/secrets.jsonl  findings/takeover.jsonl  findings/default_creds.jsonl
                                         #   CONSOLIDATE output — per-app findings lifted up by TYPE (each record stamped app_id;
                                         #   cve/dast fold surface+deep). nuclei_scope.jsonl is the whole-scope nuclei finding.
  findings/secrets_triage.jsonl          # CONSOLIDATE output — ai_secret_triage verdicts lifted by app_id (--ai; empty/absent when AI is off)
  findings/hypotheses.jsonl              # agent fan-in output (StubProvider by default; --ai revives it as ai_triage, correlating consolidated findings)
  report.md  report.json                 # deterministic OFFLINE report: severity-normalized, deduped findings + evidence/PoC source paths
  checkpoints/surface/findings/          # phase-2 snapshot: cve/dast/xss/sqli surface + takeover
  report-surface.md  report-surface.json # early deterministic report, before guessing/deep DAST
  coverage.json                          # per-run/stage coverage: status, deps, observed I/O, commands, caps/drops, requirements, limits
  report-ai.md                           # --ai terminal narrative report (separate; never overwrites deterministic report)
  screenshots/screenshot/screenshot.html # UNIFIED gallery — one batched httpx run, 1 host/group (+ eyewitness/report.html)
  poc/  tmp/  logs/
  wl_global/                             # shared/global INPUT wordlists (SecLists & co.)
```

Two wordlist scopes (deliberately distinct names): `<activity>/wl_global/` is the
shared/global INPUT lists; `scans/<app_id>/wl_custom/` is the wordlists GENERATED for
that app from its own corpus (`Activity.wl_global` / `AppWorkspace.wl_custom`).

**Global wordlists are resolved by ROLE, not hardcoded** (`pipelines/external/wordlists.py`). The
`provision_wl` breadth stage resolves each role (`subdomains`, `content`, `wordpress`, `drupal`, `joomla`) to a
concrete file and symlinks it into `wl_global/<role>.txt`; steps then read by role
(`wordlists.role_path(activity, "content")`). Resolution order: BYO (`wl_global/<role>.txt` already
present) › explicit env `PTFLOW_WL_<ROLE>` › discovery (first candidate filename under a search dir;
search dirs = env `PTFLOW_WORDLISTS` ++ common locations like `/usr/share/seclists`) › unresolved →
the step degrades to the generated `wl_custom` (the pipeline never fails for missing wordlists).
This keeps it independent of WHICH collection, WHERE it's installed, and whether it's installed.

### Write each tool output exactly once

This is the load-bearing convention; a verbatim raw↔canonical copy is the bug it forbids.
**LOCATION ENCODES ROLE — one home per file, no copies** (see `core/paths.py` docstrings):
- **Intermediate / tool scratch / a tool's own `-w`/`@`-file input** → `raw/<tool>/...` (provenance).
  Multi-mode tools nest: `raw/<tool>/<mode>/` (e.g. `raw/httpx/{screenshot,osint,discovered}`,
  `raw/katana/{crawl,headless}`). A tool's `-w` input file (subjack candidates) and offline-mining
  scratch (shortscan rainbow, extracted bodies in `raw/extracted/`) are provenance — they go to `raw/`.
- **Terminal artifact** (output *is* a downstream-read file, e.g. `httpx_full_metadata.jsonl`,
  `subdomains.txt`, `tls_names.txt`) → write **straight to its canonical name**, no raw copy.
- **Final deliverable** (no code reads it, but it's a result — e.g. `secrets.jsonl`,
  `content_discovery.jsonl`, `screenshot.png`, breadth `domain_ip_map.txt`/`nerva_full_metadata.jsonl`)
  → canonical too; write-only-by-code is expected for a deliverable, not dead code.
- **Derived artifact** (in-memory merge/dedup/filter, e.g. `unique_ips.txt`, the wordlist) → canonical only.
- **`wl_custom/` is wordlist PRODUCTS only** (`seed`/`shortnames`/`round*`); tool scratch → `raw/`.
- **Nothing downstream ever reads `raw/`** — consumers read fixed canonical names (a stage may re-read
  its own `raw/` within the same call).

In external, `_run(tool, cmd, *, stdin, dest, label)` enforces this: it writes a tool's stdout to
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
stable under minority membership changes. It's rendered **pseudo-readable** as `<slug>-<hash8>`
(`_app_id`/`_slug`): the slug is the anchor's apex (favicon-anchored) or host (host-anchored) for
at-a-glance recognition (`ginandjuice.shop-1a2b3c4d`, `scanme.nmap.org-…`), the 8-hex anchor hash
keeps it unique+stable even when the slug repeats. `meta.json` records `id_anchor` + `signature` for
debuggability, plus **`body_by_host`** (url → response-body sha256) — the active scanners
(`crawl`/`crawl_headless`/`content_discovery`) read it via `_scan_hosts`/`dedup_by_body` to scan one
host per distinct body (collapse same-backend aliases, keep distinct environments). `passive_probe`,
`subenum` and `takeover` deliberately stay on ALL hosts (per-domain/apex/hostname data differs). It
also records **`headers_by_host`** (url → httpx's `header` dict, captured via `-irh`) for later
reasoning, plus **`header_signals`** — a curated, gate-on-able view (`cache` · `cdn:*` · `backend:*` ·
`stack:*` · `waf:*` · `hsts`/`csp`, via `header_signals()`) unioned over the group, the header analog
of `tech` for dispatching per-stack tools. Oversized groups log a WARNING (`CLUSTER_MAX_HOSTS`). The
residual (same-apex hosts
with a coincidentally-identical favicon/fingerprint, e.g. a corporate template) is what a future
`recluster` deep-path confirmation pass would resolve. The example stub still hashes a fabricated sig.

## The pipelines

- **`example`** — stub tasks (deterministic fake IPs/services, no external binaries). Dependency-free;
  this is what the test suite and CI exercise.
- **`external`** — the REAL ProjectDiscovery toolchain (`pipelines/external/tasks.py`), a faithful port of
  bash recon scripts (`scope2surface.sh` breadth, `surfagr.sh` clustering). Stages:
  - **Breadth** (activity scope): `provision_wl` (resolve global wordlist roles → `wl_global/`) ∥
    `expand` (passive wildcard enum) → `subdomain_bruteforce` (shuffledns, only explicit `*.domain`
    scope entries; waits for both passive enum and wordlist provisioning) → `resolve` → `scope_gate`
    (offline RoE authorization gate — filters discovery down to the
    authorized `inscope_*` set before any active scan; see the scope-gate note in "External design
    decisions" below) → `portscan`
    (FAST: ~250 curated web ports `WEB_PORTS` → honeypot filter → `naabu_web.txt`) → `httpx`
    → `cluster` fan-out. The expensive **full 65535-port scan is off the critical path**:
    `portscan_full` (**spanning**, after `portscan`) → `naabu_full.txt` → `nerva` (**spanning**)
    run ∥ clustering + the loops, joined at the fan-in. `httpx` only needs the fast top-1k web set,
    so the ~15-min full scan no longer serializes in front of all web work. Plus `nuclei_scope` —
    another **spanning** whole-scope full-template nuclei scan (one process, one global `-rl` over
    deduped subdomains + webapps) launched after `httpx`, running ∥ everything, joined at the fan-in
    (`findings/nuclei_scope.jsonl`). Template updates are explicit/out-of-band (`nuclei -ut` before the
    activity), so the spanning process cannot mutate the official pack while parallel DAST passes hash
    and load it. It scans with `-duc`. Per-app would multiply traffic on shared backends, so it's
    whole-scope, not per-app.
  - **Post-cluster spanning**: `screenshot` (`cluster_scope`) — ONE batched httpx `-ss -svrc` run over
    a single best-host candidate per group → the unified gallery `screenshots/screenshot/screenshot.html`
    (+ OPTIONAL one EyeWitness run → `report.html` + default-cred leads). Reconciled per group by URL.
    Runs ∥ the loops (no longer a loop-1 step). See "Unified screenshot" below.
    The per-app loops are a **surface-first, DAST-first** escalation in four phases: map only what's
    really there and DAST *that* (fast, high-signal findings) BEFORE sinking hours into guessing; then
    fuzz, then DAST the guessed surface. The clean split (explorable vs guessed) also keeps each DAST
    pass scoped — phase 4 fuzzes only the delta, never re-DASTing the surface phase 2 already covered.
  - **Loop 1 — explorable surface** (`phase=1`, NO guessing): `passive_probe` → `crawl` (katana ∥
    crawley + JS-render classification, see below) → `crawl_headless` (gated TIER-1 headless, ∥
    takeover) ; `subenum` ; `takeover` (← crawl + subenum) ; `fetch_delta` (OSINT delta) →
    `mine_responses` (offline: extract the corpus + jsluice endpoints) ; `api_spec` (∥, well-known
    OpenAPI/Swagger/GraphQL → `requests_api.jsonl`). The tail `request_catalog` (offline) assembles the
    **EXPLORABLE-surface** request catalog `requests.jsonl` — crawl/headless **full requests**
    (`requests_crawl/headless.jsonl` — method/body/form/xhr, not bare URLs) + `requests_api.jsonl` +
    shapes mined from the **crawl** corpus + URL-only sources as GET. No guessed surface yet.
  - **Loop 2 — DAST the explorable surface** (`phase=2`, low-hanging fruit): the head `xref_catalog`
    (offline `net=False`) assembles the **cross-group surface sidecar** `requests_xref.jsonl` — requests/
    endpoints discovered while crawling OTHER in-scope groups whose host belongs to THIS group (via
    `_cross_group_surface`), so the fast pass tests the cross-group surface too, not only phase 4 (the
    1→2 barrier makes the peer read race-free). Then `dast` (← `xref_catalog`) runs **nuclei
    `-dast -im jsonl`** over `requests.jsonl` ∪ `requests_xref.jsonl`, fuzzing the **observed** params
    (query/path/header/cookie/**body**) → `findings/dast.jsonl`. Fast, high-signal findings on the real
    attack surface before any fuzzing; no hidden-param discovery (that's guessing → phase 4). `cve_lookup`
    runs **∥ `dast`** (same phase, offline `net=False`, no `xref_catalog` need — it reads enumerated
    software, not the catalog): known-CVE correlation of the enumerated software (web server + tech +
    non-HTTP service banners + corpus libs) against `search_vulns`' local DB → `findings/cve.jsonl`. See
    "CVE lookup" below. `xss` (dalfox) ∥ `sqli` (sqlmap) also run here (← `xref_catalog`) — **dedicated
    scanners** over the same surface set → `findings/xss.jsonl` / `findings/sqli.jsonl`. See "Dedicated
    vuln scanners" below.
  - **Surface checkpoint** (`after_phase=2`, activity-scope, offline): after the global phase-2 barrier,
    `surface_checkpoint` consolidates only the mature phase-1/2 findings (CVE/DAST/XSS/SQLi surface +
    takeover) into `checkpoints/surface/findings/<type>.jsonl` and publishes `report-surface.md` /
    `report-surface.json`. It excludes phase-3/4 outputs and spanning stages that have not joined yet;
    the terminal report remains authoritative and later folds surface + deep findings.
  - **Loop 3 — guessing / surface expansion** (`phase=3`): `wordlist` (offline seed from JS/body/seed)
    → `tech_enum` (surface-generating per-stack scanners) → `content_discovery` — feroxbuster forced
    browsing run as a bounded **fixpoint** (fuzz → download → mine → fuzz the new token delta), which
    also runs the secret fleet ONCE at the end over the complete corpus → `recrawl` (re-seeds katana on
    fuzzing-discovered entry points into un-crawled territory).
  - **Loop 4 — DAST the guessed surface** (`phase=4`, detailed): `request_catalog_full` (offline)
    rebuilds the catalog INCLUDING the guessed surface (`requests_full.jsonl` — + recrawl +
    content_discovery hits + shapes from the fuzz-downloaded corpus) ; `param_fuzz` discovers hidden
    params across **all locations** (query · body · json · header — arjun `-m` ∥ x8
    `-X`/`--data-type`/`--headers`), not GET-only, over the full catalog → `params.jsonl` ; `dast_full`
    runs nuclei `-dast` over the **delta** (full catalog minus the surface catalog) + synthesized
    requests for the discovered params → `findings/dast_full.jsonl`. `cve_lookup_full` runs **∥
    `dast_full`** (offline): re-mines the EXPANDED corpus (the phase-3 crawl grew it) for software and
    reports only the **delta** vs the phase-2 pass → `findings/cve_full.jsonl`. `xss_full` (dalfox) ∥
    `sqli_full` (sqlmap) run the dedicated scanners over the **same delta** (`request_catalog_full` +
    `param_fuzz`) → `findings/xss_full.jsonl` / `findings/sqli_full.jsonl` — the dalfox/sqlmap analog of
    `dast_full`. See "Request catalog & DAST" + "CVE lookup" + "Dedicated vuln scanners" below.
  - **Loop 4 — vuln scan** (gated): `tech_vulnscan` — finding-only per-stack scanners, gated on the
    detected tech, run ∥ the rest of loop 4. Today: `wpprobe` (WordPress plugin/theme → known CVE via
    its local Wordfence DB) on WordPress groups only → `findings/wpprobe.jsonl` (`consolidate` lifts it).
    More finding-only scanners (nuclei tech-tags, `nikto`, …) dispatch here. Specialized scanners are
    split between loops by output role: **surface → `tech_enum`** (loop 3, feeds enum); **findings →
    `tech_vulnscan`** (loop 4).
- **`internal`** — internal-network pentest (`pipelines/internal/tasks.py`): an **IP/CIDR-only** scope
  swept **per-subnet** for classic perimeter low-hanging fruit. Maps onto the same breadth→cluster→loop
  grammar with the **subnet as the fan-out unit** (not a web app) — zero `core/` changes. Stages:
  - **Breadth** (activity scope, ONE rate-controlled pass): `expand` (mapcidr: CIDR → candidate IPs,
    offline `net=False`) → `discover` (nmap `-sn` ping sweep → `asset_discovery/live_hosts.txt`; falls
    back to all candidates when ICMP is filtered) → `portscan` (naabu over the curated `INTERNAL_PORTS`
    set → `asset_discovery/ports.jsonl`). Whole-scope + rate-controlled on purpose — one global sweep is
    gentler on fragile legacy/OT gear and switches than N per-subnet floods (aggregate load ≈ concurrency
    × rate; `PTFLOW_PROFILE=home` throttles naabu, same lever as external).
  - **Spanning** (whole-scope, ∥ cluster + the loops, joined at the fan-in — OFF the critical path so the
    heavy full scan never serializes in front of the per-subnet work): `portscan_full` (naabu full 65535 →
    `asset_discovery/ports_full.jsonl`) → `nuclei_scope` (full-template nuclei over every discovered socket,
    ONE rate-limited process → `<activity>/findings/nuclei_scope.jsonl`); PLUS the full-port CVE chain
    `fingerprint_full` (nerva over the full-port **delta** — sockets beyond the fast `INTERNAL_PORTS` set →
    `asset_discovery/services_full.jsonl`) → `cve_lookup_full` (search_vulns over that delta's software,
    OFFLINE `net=False` → `<activity>/findings/cve_full.jsonl`, activity-level like `nuclei_scope`). This is
    how inventory/CVE — and web-service detection for the hand-off — reach services on **non-standard ports**
    the curated fast set misses. **Why spanning, not a per-app loop-3:** `portscan_full` is awaited only at
    the fan-in (it runs ∥ the loops), so a per-app phase-3 stage reading `ports_full.jsonl` would race it —
    no barrier guarantees it present. `consolidate` runs AFTER the spanning join, so the web aggregation
    reads the full-port set safely; the full-port CVE lives at activity scope (the gemini of `nuclei_scope`).
  - **`cluster`** — `assign_hosts` (pure, unit-tested) partitions the LIVE hosts by the **scope entry
    that contains them**: the CIDR from the scope file, **longest-prefix wins** on overlap, a bare IP is
    a /32; only entries with ≥1 live host become groups. `app_id` = the filesystem-safe CIDR slug
    (`10.0.1.0-24`, `192.168.5.10-32`). Writes each group's `meta.json`/`hosts.txt` + its slice of
    `ports.jsonl` → `scans/<subnet>/` = the per-subnet compartmentalisation. So the whole-scope scan and
    the per-subnet output folders are NOT in tension — breadth scans once, `cluster` slices by subnet.
  - **Loop 1 — inventory** (`phase=1`): `fingerprint` — `nerva --json` over the group's `ip:port` set
    (nmap `-sV` is the drop-in alternative) → `services.jsonl`.
  - **Loop 2 — low-hanging fruit + enumeration** (`phase=2`, all ∥ save one intra-loop dep, gated on the
    breadth-scan ports, best-effort, NON-destructive — no brute-force/relay/coercion, those are future):
    `cve_lookup` (search_vulns, OFFLINE) · `smb_checks` (signing/SMBv1/null-session/guest/`Pwn3d!` + share
    enum + metadata spider) · `ad_enum` (null-session RID cycling + pass-pol) · `adcs_checks` (enum_ca CA
    discovery + ESC8) · **`kerberoast_asrep`** (nxc `--asreproast`, no-cred — `needs` ad_enum's userlist, an
    INTRA-loop dep) · **`datastore_checks`** (ONE nmap NSE run: unauth Redis/MongoDB/Memcached + MSSQL
    exposure; Elasticsearch is HTTP → left to the hand-off) · `snmp_checks` (onesixtyone + snmpwalk loot,
    UDP/161 over all hosts) · `ldap_checks` (nxc signing/CBT + ldapsearch anon bind/account dump) ·
    `ftp_checks` · `telnet_checks` · `nfs_checks` · `rsync_checks` · `netbios_checks` (137/UDP) · `dns_checks`
    (reverse-zone AXFR) · `remote_desktop` (RDP/VNC scrying). Each → `scans/<subnet>/findings/<check>.jsonl`.
    (Whole-scope `nuclei` is the spanning `nuclei_scope`, not a per-subnet `nuclei_net`.)
  - **`consolidate`** lifts the per-subnet findings to `<activity>/findings/<type>.jsonl` (one file per
    finding TYPE, each record stamped `app_id`), same deterministic terminal fan-in as external, AND
    aggregates web services into `<activity>/web_targets.txt` (`scheme://ip:port`, https for a TLS
    port/banner — pure `web_targets_from`): each group's fast-set services (`ports.jsonl`/`services.jsonl`)
    **unioned with the whole-scope full-port scan** (`ports_full.jsonl` + `fingerprint_full`'s
    `services_full.jsonl`), so a web server on a NON-standard port — recognised via its fingerprint banner —
    reaches the external hand-off too. (`nuclei_scope`/`cve_full` are already activity-level → not lifted.)
  - **web hand-off (pipeline COMPOSITION)** — after the sweep, `internal.followups(activity)` (a
    duck-typed `Pipeline` hook, like `consolidate`/`preflight`, returning `list[Followup]` from
    `core/stage.py`) hands `web_targets.txt` to the **`webscan`** pipeline (see below) as a **nested
    sub-activity** `<activity>/web_recon/`. The CLI runs each `Followup` as a **separate top-level
    `orchestrate()`**, NOT a nested Prefect subflow — so each pipeline stays a clean flow with its own
    runner/teardown and files-as-only-state holds (the hand-off crosses via the on-disk scope artifact).
    **OPT-IN** via `PTFLOW_INTERNAL_WEB_HANDOFF` (default OFF): a full web-depth scan per service is long.
    The aggregation artifact is always written; only the auto-run is gated.

  **Design decisions:** grouping keys on the **scope CIDR** (the operator's own compartmentalisation),
  not an arbitrary /24; the flow is **forward-only / acyclic** — a first-check sweep has no lateral
  movement, so the orchestrator's no-cycle constraint doesn't bite (a credentialed re-entry / lateral
  chain would need a different model, deliberately out of scope). **Status: SKELETON** — breadth,
  `cluster`, `fingerprint`, `cve_lookup` and `smb_checks`/`snmp_checks` are real (their pure parsers +
  `assign_hosts` unit-tested; e2e-smoke on loopback); `ldap_checks` and the corpus-less `cve_lookup` banner
  extraction — plus the newer `kerberoast_asrep` (nxc `--asreproast` output) / `datastore_checks` (nmap NSE)
  parsers — are **best-effort/minimal** and want live internal testing (their pure parsers ARE unit-tested;
  the tool-output formats vary by version). Natural next levers: reuse external's `collect_software` for CVE,
  richer share/perms parsing for SMB. Destructive/active checks (brute-force, responder/relay, coercion) and
  credentialed auth
  (a future `PTFLOW_CREDS`) are deliberately **opt-in, not yet wired**. `internal` ships its own flow map
  (`pipelines/internal/flowmeta.py` → `docs/internal-pipeline-*`), like every non-stub pipeline.
- **`webscan`** — external's web-DEPTH loops over a **PRE-AGGREGATED web target list** (`pipelines/webscan/
  pipeline.py`). This is the "dedicated external profile" the `internal` hand-off targets: given a list of
  known web services (`scheme://host[:port]`, e.g. an internal run's `web_targets.txt`), it runs external's
  crawl → catalog → DAST → fuzz depth, **skipping** scope EXPANSION (`expand`/`resolve` — subdomain/DNS/
  TLS/OSINT), active NETWORK scan (`portscan`/`portscan_full`/`nerva`/`nuclei_scope`), and per-app OSINT
  (`passive_probe`/`subenum`/`takeover`/`fetch_delta` — gau/urlfinder/subfinder/DNS). **It REUSES external's
  task functions unchanged** — only the breadth is replaced by one `ingest` step
  (`external.tasks.ingest_httpx`: httpx over the target list with **`-nfs`** so the explicit http/https +
  port is honoured, → the same `httpx_full_metadata.jsonl` `cluster()`/the loops consume) and the stage
  graph is curated (its own `Stage` objects wrap external's functions with rewired `needs`). Dropped stages'
  artifacts are simply absent; external's **tolerant reads** (`read_lines`/`read_jsonl` → `[]`) degrade the
  depth loops cleanly. **external itself is untouched** (no mode-conditionals sprinkled through it — a
  sibling pipeline was chosen over an external mode flag precisely to keep the proven external DAG pristine and
  match the pluggable-pipeline model). *Design decisions:* (1) sibling pipeline, NOT an external mode — one
  place holds the web-mode composition, external stays single-purpose; (2) `-nfs` here (honour input scheme)
  is correct where every target carries an explicit scheme+port, the inverse of external discovery's
  https-default (external design note); (3) largely EGRESS-FREE with OSINT gone, but two external internals
  still call out — `content_discovery`'s trufflehog `--results=verified` validates hits against the
  credential's PROVIDER (external) — mind it on an air-gapped engagement. Verified end-to-end on a
  loopback server: `ingest` (scheme+port honoured) → `cluster` → all four depth loops (the catalog
  captured a POST form + query params), no expansion/OSINT artifacts written. It ships its own flow map
  (`pipelines/webscan/flowmeta.py` → `docs/webscan-pipeline-*`), reusing external's `FLOWMETA` + adding
  only the `ingest` step.

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
in one process), and `-ct` bounds each host. Its `endpoints_headless.txt` is folded into the phase-3
`build_wordlist` (like `endpoints_js.txt`), and its `-srd` store joins the "already have" set so
`fetch_delta` doesn't re-download it.

A separate downloader is justified only for URLs neither crawl-stored — and only over that delta:
the `fetch_delta` step (`passive_delta` + httpx `-srd`) downloads the live delta — passive
(gau/urlfinder) **+ crawley** URLs minus what katana already stored (`responses/index.txt`), static
assets dropped — into `responses/osint/`. `mine_responses` then mines the store **offline** for
**endpoints only**: it extracts every response body to `raw/extracted/` (JS as `.js`, rest as `.html`,
via idempotent `_extract_bodies`), and runs jsluice over the JS for endpoints (`endpoints_js.txt`,
folded into the round-0 content_discovery wordlist). The **secret-scanning fleet does NOT run here** —
it's deferred to the tail of `content_discovery`, so it scans the corpus *after* the fixpoint has
downloaded the fuzz-discovered bodies too (see below). This is where the "fetch once" design pays
off — no re-fetching.

`build_wordlist` (`wordlist` step) is therefore **pure offline** and emits the **CUSTOM layer only**:
it tokenizes `endpoints.txt` (+ `endpoints_headless.txt` when the headless pass ran) into path
segments, filename basenames and parameter names (`tokenize_urls`) → `scans/<app_id>/wl_custom/seed.txt`.
**App-derived tokens only** — the global staged lists (OLFA + Assetnote) are NOT folded into the seed;
they're added later by `content_discovery`'s staged combine, so "custom" stays genuinely custom.

### Wordlist strategy — a STAGED escalation (`content_discovery`)

Content discovery fuzzes a **staged** wordlist, not one flat list. The split is in two passes; lists
resolve by ROLE (`wordlists.py` / `wl_global/`), and a missing role just drops its stage.

**Pass A** (every scanned host) — `build_content_wordlist` reads roles and hands `(lines, cap)` layers
to the pure `assemble_wordlist` (custom full+first, then each layer truncated to its top-`cap`):
- **stage 0 custom** — `wl_custom/seed.txt` + `tech_enum` shortnames + `mine_responses` JS tokens. Full.
- **stage 0 `content`** = **`onelistforallmicro.txt`** (OLFA grab-bag — ranks juicy/anomalous paths like
  `old/wp-login.php`, backups high). Full (~37k).
- **stage 1 `an_directories`** = Assetnote `httparchive_directories_1m` — real web paths, frequency-ordered,
  fresh monthly, ~97% additive over OLFA. Top-**`STAGE1_CAP`** (30k) head.
- **stage 2** — the per-stack language list(s) matched by detected tech (`roles_for_tech` +
  `STAGE2_TECH_ROLES`), top-**`STAGE2_CAP`** (30k). Gated on the fingerprint — never php on a .NET site;
  a tech that matches nothing skips stage 2. Mapping: php→`an_php` · asp.net/iis/coldfusion→`an_aspx` ·
  java/jsp/tomcat/jboss/spring→`an_jsp` · server-side JS (node/express/next/nuxt) **and** python
  (django/flask/fastapi)→`an_apiroutes` (their surface is API routes, not a server-page extension).
  Client-side react/vue/angular are deliberately NOT mapped (they say nothing about the backend), and
  python has no dedicated Assetnote list so it leans on `an_apiroutes` + the `.py` extension + the
  generic stages.
- **stage 2b `STAGE2B_ROLES`** = `an_txt` + `an_xml` (robots/security.txt; sitemap/opensearch). Small → full.

**Stage 3 — the deep dive** (`_deep_dive`) is a SEPARATE pass, **OPT-IN via env `PTFLOW_DEEP_DIVE`**
(off by default — these lists cost hours/host). It runs the huge Assetnote *manual* lists at full depth
(`DEEP_DIVE_DEPTH`=3) on the few **high-value** hosts, gated per stack (`DEEPDIVE_TECH_ROLES`): php→`mn_php`
(3M)+`mn_phpmillion` (1M) · asp.net→`mn_aspx`/`mn_asp`/`mn_cfm` · java→`mn_jsp`/`mn_do` · plus the generic
`mn_html` (4M) on every qualifying host (js/python have no dedicated manual list → generic only). These are
nearly disjoint from the `an_*` heads (≈1% overlap), so it's a complete rake. Gated tight: a host qualifies
only if Pass A already found ≥ `DEEP_DIVE_MIN_HITS`
(50) results on it, at most `DEEP_DIVE_MAX_HOSTS` (2) richest hosts per app, under a `DEEP_DIVE_DEADLINE_S`
(3600s) budget + per-host `DEEP_DIVE_TIME_LIMIT` (30m). Its hits merge into `content_discovery.jsonl`; it
does **not** download bodies (the secret fleet already scans the Pass-A corpus).

*Why staged, not one list / not mode-based:* the lists are ~frequency-ordered, so a top-N cap keeps the
high-signal head and drops the blow-up tail (`an_directories` is 684k, `mn_*` are 1–4M). Per-stack gating
puts the right language list in front instead of fuzzing all of them; the deep dive's huge near-disjoint
lists only pay off on a genuinely content-rich host, so they're opt-in + tight-gated. This replaced the
earlier `auto/targeted/broad` mode (`resolve_wl_mode`/`combine_wordlist`) — the staged caps + fingerprint
gating subsume it. *(Detected-tech CMS `wordpress`/`drupal`/`joomla` roles + `tech_role_paths` remain as
resolution infra, currently unwired into the fuzz wordlist.)*

New roles are resolved exactly like the others (BYO › `PTFLOW_WL_<ROLE>` › discovery under
`PTFLOW_WORDLISTS`/SecLists), so the lists live wherever you point `PTFLOW_WORDLISTS` — nothing hardcoded.

`content_discovery` is the one phase-3 step that *must* make new requests — forced browsing finds
UNLINKED paths, which by definition aren't in any downloaded body. It runs `feroxbuster --smart`
(auto-tune soft-404 calibration + collect-words/backups + link extraction/recursion) over the group's
hosts **deduped by response body** (`_scan_hosts` → `dedup_by_body`): same-backend aliases (domain+IP,
http+https) collapse to one (no re-fuzz; the scanme.nmap.org hang), but distinct environments
(staging vs test — different body) are each fuzzed, since env-specific files differ. `crawl` and
`crawl_headless` use the same `_scan_hosts` selection. The round-0 wordlist is the **staged combine**
described above (`build_content_wordlist`) plus tech-derived extensions (`tech_extensions`); the
opt-in stage-3 deep dive (`_deep_dive`) escalates on high-value hosts.
`--smart` means feroxbuster's *intra-run* wordlist-feedback is built in — don't
hand-roll it. **But that recursion is link-only**: it never parses a discovered JS file for API
routes, nor tokenizes new params. So `content_discovery` wraps it in a bounded **cross-tool fixpoint**
(`_content_rounds`): after round 0, each feedback round downloads feroxbuster's new 2xx/3xx hits into
`responses/discovered/round<r>/`, mines them (jsluice + `tokenize_urls`), and fuzzes ONLY the new
token delta. It converges via four independent stops — no new fuzz words (wordlist-fixpoint), no new
URLs (url-fixpoint), per-app wall-clock budget (`CONTENT_DEADLINE_S`), diminishing returns
(`< MIN_NEW_TOKENS`) — under a hard `CONTENT_FEEDBACK_ROUNDS` cap; a token is never re-fuzzed, a URL
never re-downloaded (`seen` from the `-srd` store indices via `_all_store_indices`). Then the secret
fleet runs ONCE over the complete corpus (`_scan_secrets`): jsluice ∥ gitleaks ∥ trufflehog
(`--results=verified`) ∥ detect-secrets, merged+deduped (`merge_secrets`) → `secrets.jsonl`.
Output: `scans/<app_id>/content_discovery.jsonl` (`parse_ferox` keeps the `response` records, merged
across rounds by `merge_ferox_by_url`).
Politeness on live infra is `--smart` (auto-tune adapts the rate **down** when the target
errors/times out) + low `-t`/`-L`/`--timeout` (`FEROX_THREADS`/`FEROX_SCAN_LIMIT`/`FEROX_TIMEOUT`) —
**not** `--rate-limit`, which is mutually exclusive with `--smart` (and per-directory). A
**`--time-limit`** (`FEROX_TIME_LIMIT`, total scan wall-clock) is mandatory: `--timeout` is only
per-request, so a throttling target can drive `--smart`'s auto-tune into an unbounded backoff
livelock that hangs the whole pipeline — `--time-limit` is the hard cap that breaks it (it exits
gracefully, keeping partial results).

**Specialized per-stack scanners are split by output role** (so they land in the right loop) — but a
scanner can be **DUAL-ROLE** and emit both; the role just decides which loop its *surface* drives:
- `tech_enum` (phase 3, before content_discovery) runs scanners whose output is **surface that feeds
  enum**. Today: `shortscan` (IIS/ASP.NET 8.3 short-name enumeration). It builds a `shortutil` rainbow
  table from the seed + global list so shortscan resolves leaked 8.3 names to real filenames, then
  `parse_shortscan` harvests those as fuzz words → `wl_custom/shortnames.txt`, merged into the combined
  wordlist. shortscan is **dual-role**: the IIS 8.3 enumeration is itself an information-disclosure
  finding, so from the SAME run `parse_shortscan_findings` emits it → the per-app findings folder
  `scans/<app_id>/findings/tilde_enum.jsonl` (`AppWorkspace.findings`; a per-app dir keeps the fan-out
  race-free). The `consolidate` terminal step lifts per-app `findings/` into the activity-level
  `<activity>/findings/<type>.jsonl` (see "Consolidate" below). Best-effort dispatch keyed on detected tech
  (no-op if tech unmatched / binary absent).
- `tech_vulnscan` (loop 4, gated) runs scanners whose output is **findings-only**. Today: `wpprobe`
  (WordPress plugin/theme enumeration → known CVE via its local Wordfence DB) — dispatched ONLY when
  the group's tech says WordPress (whole-word `_tech_match`), one stealthy scan per distinct-body host,
  `parse_wpprobe` → one record per (component, version, CVE) → `findings/wpprobe.jsonl`. Best-effort
  (skips if the binary is absent / tech unmatched); auth passthrough + a per-host wall-clock cap. Future:
  nuclei tech-tags, `nikto`, ….

### Request catalog & DAST — full requests, not bare URLs (the GET-only fix)

A bare URL can only describe a GET query, so a URL-list-driven fuzzer (reconftw, and the old
`param_fuzz`) can never reach **POST/JSON/body/header** params. The DAST passes fix this with a
**request catalog**: per-request records `{method, url, headers, body, params:[{name,loc}], raw, sources}`
where `raw` is the full HTTP/1.1 request **nuclei `-im jsonl` fuzzes on every part**. `raw` mirrors
katana's own request object (`{request:{endpoint, raw, header, body}}`), so nuclei ingests it natively;
`build_raw_request` (pure) constructs `raw` for synthesized requests.

**The catalog is built TWICE** (`_assemble_catalog(include_guessed=…)`, one shared core): the phase-1
`request_catalog` writes the **EXPLORABLE-surface** catalog `requests.jsonl` (crawl/headless/API +
crawl-corpus shapes + URL-only GETs — no guessed surface); the phase-4 `request_catalog_full` writes the
**full** catalog `requests_full.jsonl` (additionally folds in `requests_recrawl.jsonl`, the
content_discovery 2xx hits, and the shapes mined from the now-extended fuzz corpus). Two distinct
artifacts so write-once holds and each DAST pass reads exactly its scope.

- **The data was already crawled, just discarded.** katana (`-fx` forms, `-xhr`) and headless katana
  emit method/body/form/xhr in their JSONL; `parse_katana` kept only the URL. Now `crawl`/`crawl_headless`
  drop `-omit-raw` (keep `-omit-body`) and `parse_katana_requests` writes `requests_crawl/headless.jsonl`.
- **`request_catalog`** (phase 1, offline, net=False) merges those + `requests_api.jsonl` (from `api_spec`)
  + **shapes mined from the crawl corpus** + the URL-only sources (passive/crawley/jsluice, as GET) →
  `requests.jsonl`, scheme-normalized (`_working_schemes`, incl. the http fallback) + in-scope-filtered,
  deduped by request shape (`request_key` = method + `path_template`; `merge_requests` unions
  params/sources, then **`normalize_request` realigns** each merged record's `url`/`body`/`raw` to its
  unioned params — see the realignment design note). The `raw` is scheme-agnostic (path + Host), so only
  the `url` field is re-schemed.
  **Dead-endpoint drop:** GET shapes whose path the corpus only ever saw as **404/410** (`dead_url_keys`
  over the `-srd` index statuses — offline, no new traffic) are removed, so DAST/param_fuzz don't burn
  payloads on malformed passive/archive URLs (`/about</a>`, `/)`) or phantom JS routes (`/catalog/filter`
  → 404). GET-only + body-less: a discovered POST/form/XHR/JSON shape (its status never recorded) is
  always kept. A path is dead only if EVERY observation was 404/410 — one 2xx/3xx (or 401/403/405 =
  exists) keeps it, so a parameterized endpoint that 404s for the crawled value but 200s for another stays.
- **`request_catalog_full`** (phase 4, offline, net=False) re-runs that assembly with the guessed surface
  folded in (`requests_recrawl.jsonl` + content_discovery 2xx + the re-extracted fuzz corpus, incl.
  feroxbuster-found shapes) → `requests_full.jsonl`. It reads phase-1 + phase-3 artifacts across the
  barriers, so it sees the COMPLETE corpus. Feeds `param_fuzz` + `dast_full`.
- **Closing the fuzzing→DAST gap (shapes are mostly on disk already).** A feroxbuster/jsluice discovery
  entered the catalog as a bare GET — losing its real method/body. So `request_catalog` MINES request
  shapes from the already-downloaded corpus (no re-fetch — "fetch once"): `jsluice_requests` recovers the
  method/contentType/bodyParams jsluice already extracts from fetch/XHR calls (we kept only the URL,
  same mistake as katana); `html_form_requests` (`_FormParser`, stdlib) turns `<form>` elements in the
  stored HTML bodies into POST/GET requests — **including the unlinked pages feroxbuster found**, whose
  forms katana `-fx` never saw. Relative URLs resolve against each body's source URL (a `stem→url` map
  from the `-srd` indices; `_extract_bodies` names files `<stored-stem>.{js,html}`).
- **`recrawl`** (phase 3, after `content_discovery`) handles the residual: a discovered entry point into
  **un-crawled territory** (e.g. an unlinked `/debugging` that opens a sub-app) needs a real crawl, not
  just body-mining. `select_recrawl_seeds` picks a **2xx** discovered URL whose **top-level path segment**
  no crawled URL uses — conservative: a new sub-dir UNDER an already-crawled region does NOT seed (one
  shallow seed per new top-level segment, static/JS/out-of-scope dropped, capped). It re-seeds katana
  there (one pass, depth-bounded) and stores the bodies into the corpus so `request_catalog_full` mines
  them. `PTFLOW_RECRAWL` ∈ `off|preview|on`, **default `on`**; `preview` writes/logs the seeds
  (`raw/recrawl/seeds.txt`) WITHOUT crawling (to review them). Bounded even when on (few shallow seeds,
  depth 2, `-ct` cap), one pass — never a crawl⇄fuzz loop.
- **`api_spec`** (phase 1, ∥) probes well-known OpenAPI/Swagger JSON paths + GraphQL endpoints on the
  group's hosts; `expand_openapi` (pure; OpenAPI v3 `servers`/`requestBody` + Swagger v2 `basePath`/
  `in:body`) turns each operation into a full request (path param → `1`, query/header recorded, body
  skeleton) → `requests_api.jsonl`. The richest method+body+param source a crawler/GET-fuzzer can't see.

`param_fuzz` (phase 4) finds the **hidden parameters across ALL locations** (query · body · json ·
header), not GET-only, over the FULL catalog (`requests_full.jsonl`) so it probes the fuzzing-discovered
endpoints too. `arjun` (`~/.local/bin/arjun`, `-m GET/POST/JSON`) and `x8` (`~/.cargo/bin/x8`, prebuilt —
system cargo too old to compile it; `-X` method · `--data-type json` · `--headers` mode) run **∥ and are
merged** by `(url, param, loc)` → `params.jsonl` (query≠body are distinct injection points). It reads the
catalog: QUERY discovery over every endpoint shape (`select_param_endpoints`, deduped by `path_template`,
cap `PARAM_MAX_ENDPOINTS`); BODY+JSON over the endpoints the crawl saw with a body (`select_body_targets`)
topped up from the query set (cap `PARAM_MAX_BODY_ENDPOINTS`); HEADER over a small subset (`x8` only —
arjun has no header mode; cap `PARAM_MAX_HEADER_ENDPOINTS`). The flat `(tool, location)` matrix runs in a
bounded pool (`PARAM_FANOUT`), each best-effort under the per-tool wall-clock cap. Politeness: low
`-t`/`-W`/`-c`, `--rate-limit`/`-d`, `--one-worker-per-host`. Wordlist = `params` role, custom-first.
A param reflection-discovered on **≥`PARAM_GLOBAL_RATIO` (75%) of the endpoints tested at its location**
(and on ≥`PARAM_GLOBAL_MIN_HITS`) is a **site-wide reflection artifact**, not N hidden params —
`collapse_global_params` folds it to ONE host-level record (`scope:"site-wide"`) so `build_fuzz_requests`
doesn't spray a fuzz request onto every endpoint (and DAST doesn't re-fire the same low-value hit per
endpoint). Verified: ginandjuice echoes `?category=` into a `Set-Cookie` header on every path, so x8
flagged `category` on all 50 query endpoints → now one record. Endpoint-specific params are untouched.

**DAST runs in two passes** (shared `_run_dast`), both **`nuclei -dast -im jsonl`** fuzzing
query/path/header/cookie/**body** per template `part`, best-effort and capped at `DAST_MAX_REQUESTS`
(reconftw DEEP_LIMIT analog). Template selection is a structured **multi-pack, all-template** layer:
default packs are ProjectDiscovery `~/nuclei-templates/dast` plus bundled `@ptflow/stable`;
`dast.packs` adds/replaces local official/custom/engagement packs without accepting raw shell flags.
`PTFLOW_NUCLEI_DAST_TEMPLATES` remains the legacy single-pack fallback. Both passes execute every
template in every enabled pack without tag/ID filters, with global `dast.aggression` (default `high`)
and `dast.fuzz_param_frequency` (default `10000`). Nuclei OAST templates are active too;
`PTFLOW_OAST` remains the separate opt-in gate for Dalfox blind-XSS.
- **`dast`** (phase 2) over the explorable-surface set (`_surface_request_set` = `requests.jsonl` **∪**
  the cross-group sidecar `requests_xref.jsonl`) with its **observed** params → `findings/dast.jsonl`
  (input `raw/dast/input.jsonl`). The fast low-hanging-fruit pass.
- **`dast_full`** (phase 4) over the **delta** (`_delta_request_set` = `requests_full.jsonl` shapes NOT
  already in `requests.jsonl` **nor** `requests_xref.jsonl`, keyed by `request_key`) + `build_fuzz_requests`
  (the discovered hidden params injected into concrete requests per location) → `findings/dast_full.jsonl`
  (input `raw/dast/input_full.jsonl`). It does NOT re-DAST the surface phase 2 already covered (including
  the cross-group surface).

Both passes **dedup their findings by INJECTION POINT** (`dedup_dast_findings`) before writing — one
record per `(template-id, host, path, fuzzing_position, fuzzing_method)` (path WITHOUT the query, since
the payload lives there). nuclei emits one hit per fuzzed request, so a template that fires across many
synthesized variants of the same endpoint (the param-sprayed catalog, http+https of one host) would
otherwise count as N findings for ONE issue. Per-pass dedup suffices: `dast_full` fuzzes only the
`request_key`-disjoint delta, so the same injection point can't recur across the two passes. Non-fuzzing
records key on `(template-id, matched-at)` so unrelated hits never merge.

Before scanning, nuclei `-tl` resolves the complete enabled-pack list once per process. Each pass persists an
exact manifest (`raw/dast/template-selection.json` / `template-selection-full.json`) with pack paths,
content hashes, configured/effective revisions, global execution settings, and template IDs. Findings
carry `ptflow_dast.{pack,pack_revision,selection}` with `selection="all"`.
`ptflow dast validate [--config ...]` strictly validates all enabled packs and rejects duplicate IDs;
`ptflow dast list` lists the complete selection. Bundled custom templates live under
`src/ptflow/data/nuclei-dast/stable`, one file per `query`/`body`/`header`/`cookie` part; the in-band
rules are covered by a live positive/negative Nuclei corpus in `tests/dast/test_custom_templates.py`.

Whole-scope full-template nuclei stays `nuclei_scope` (breadth, ∥ everything); these are the per-app
fuzzing passes. Per-app findings → `consolidate` (terminal fan-in) lifts them. arjun/x8/api_spec provenance in
their `raw/` dirs.

**Auth passthrough is webscan-only.** `PTFLOW_HTTP_HEADER` is ignored while `external` runs, so broad
discovery never sprays a session cookie across unrelated assets. In `webscan`, `_auth_headers` /
`_header_flags` thread operator session headers/cookies into the web scanners (katana/httpx/nuclei,
feroxbuster/crawley, arjun/x8, dalfox/sqlmap, wpprobe) so crawl/fetch/fuzz/DAST reach the
**authenticated** surface (where most POST/JSON lives).

### Dedicated vuln scanners — dalfox (XSS) ∥ sqlmap (SQLi), surface + delta

nuclei `-dast`'s generic templates are weak detectors (run-analysis: on a deliberately-vulnerable target
they fired only `cookie-injection`/`crlf-injection` and missed the real SQLi/XSS). `xss`/`sqli` (phase 2)
and `xss_full`/`sqli_full` (phase 4) are the **dedicated** complement — the same surface/delta split as
`dast`/`dast_full`, sharing `_surface_request_set`/`_delta_request_set`. Both tools consume the catalog's
**`raw`** request (one process per request, Burp/ZAP raw via dalfox `file --rawdata` / sqlmap `-r`), so
**every param location** is tested (query/body/json/header/cookie), not GET-only — the payoff of the
full-request catalog over a URL list.

- **No gf-style candidate routing** (deliberately rejected — reconftw's `gf xss`/`gf sqli` guess the vuln
  class from the param NAME, on GET URLs, missing and wasting both ways). The ONLY filter is `_has_params`
  (a request must have something to fuzz); **each tool's own engine decides** — dalfox by reflection +
  context, sqlmap by its `--smart` heuristic (thorough tests only on a positive heuristic) + boolean/
  error/union/time-based. sqlmap thus catches the blind/time-based SQLi nuclei's error-based template misses.
- **Bounded + best-effort**: candidates capped at `VULN_MAX_REQUESTS`, a `VULN_FANOUT`-wide process pool,
  a per-request `VULN_TOOL_TIMEOUT` (TimeoutExpired → that one request yields nothing, the stage keeps the
  rest — the arjun/x8/feroxbuster livelock lesson). Skip cleanly if the binary is absent.
- **Parsers** (pure, unit-tested): `parse_dalfox` (dalfox `--format jsonl` PoC records → `type:xss`,
  severity/param/payload/evidence/cwe/`matched-at`) and `parse_sqlmap` (the stable `Parameter:`/`Type:`/
  `Title:`/`Payload:` result block → one `type:sqli` record per (param, technique) + back-end DBMS).
- Per-app `findings/xss{,_full}.jsonl` + `findings/sqli{,_full}.jsonl` → `consolidate` lifts them by TYPE
  (`xss` folds surface+deep, `sqli` likewise — same as cve/dast). Tools: dalfox `~/go/bin/dalfox`; sqlmap
  `/opt/sqlmap-dev/sqlmap.py` (override `PTFLOW_SQLMAP`, invoked via `sys.executable`).
- **OAST / blind XSS** (OPT-IN `PTFLOW_OAST`, best-effort): dalfox `-b` fires blind payloads at an
  interactsh callback — the hit lands on the interactsh SERVER, not dalfox's output. So `_run_dalfox`
  runs an `interactsh-client` (`~/go/bin`, **≥1.3** — older can't decrypt) for the pass via the
  teardown-tracked `tools.spawn`/`tools.stop`, gives EACH request a unique callback subdomain
  (`-b https://b<i>.<domain>` — the per-request runner = per-request correlation), then `_oast_drain`
  stops the client and `correlate_oast` matches each interaction's `full-id` (`<marker>.<unique-id>`)
  back to its request → a `poc_kind:"blind"` finding (deduped by marker+protocol; bare-domain interactsh
  noise ignored). **Synchronous callbacks only** — a truly-stored/delayed XSS fires after the run, out of
  scope (a persistent receiver would break files-as-only-state). Self-host via `PTFLOW_INTERACTSH_SERVER`/
  `PTFLOW_INTERACTSH_TOKEN`, else the public oast servers (a RoE/privacy note: callbacks transit PD infra).

### CVE lookup — known CVEs on enumerated software (offline correlation, two passes)

`cve_lookup` (phase 2) and `cve_lookup_full` (phase 4) are the gemini of the two DAST passes: where DAST
*actively fuzzes*, these *passively correlate* the ENUMERATED software against `search_vulns`' LOCAL
vuln DB (NVD + GHSA + Exploit-DB + Metasploit + EPSS) — **fully offline (`net=False`, no target
traffic)**, so they run ∥ the DAST without contending for the network cap. They complement nuclei (which
is active + template-coverage-limited), especially for non-HTTP services where templates are thin.

- **Software sources** (`collect_software`, pure): web server (`Server` header), app tech (wappalyzer
  `tech` in `meta.json`), non-HTTP **service banners** (nerva `metadata.banner` — SSH/ftp/db, mapped to
  the app's hosts by hostname/IP), and **libs mined from the crawl corpus**: JS lib banners + HTML
  `<meta generator>` (`_corpus_software`) **plus versioned ASSET references** (`mine_asset_versions`) —
  the lib version is often only in the filename/CDN path (`jquery-3.6.0.min.js`, `/npm/vue@2.6.14/`,
  `ajax/libs/angularjs/1.8.2/`), so it's mined from both the body heads (`<script src>`) AND the fetched
  URLs in the `-srd` store (`_corpus_urls`). A curated product map keys it (precision-first: an unknown
  `foo-1.2.3.js` never fabricates a product; the token must be word-bounded + version-adjacent, so
  `jquery` never claims `jquery-ui-1.13.2`). **Version-pinned only** (`_norm_version`, ≥ X.Y).
- **Why two passes:** the structured sources (tech/Server/nerva) are fixed at cluster, but the **corpus
  grows** between the phase-1 crawl and the phase-3 `content_discovery`/`recrawl` downloads — so the
  phase-4 pass re-mines the expanded corpus and reports only the **delta** vs phase 2 (the covered
  `(product,version)` set is recorded in `raw/cve/seen.txt`). Without the corpus mining the two passes
  would be identical.
- **Matching:** `search_vulns -q "<Product Version>" -f json --ignore-general-product-vulns
  --use-created-product-ids`. cpe_search sometimes can't map a free-text version to an indexed CPE
  (verified: `OpenSSH 6.6.1` → no match), so **`--use-created-product-ids`** makes search_vulns
  SYNTHESIZE a product ID at the **exact** version and do its CPE version-range ("between") check there.
  We deliberately do NOT query a coarser version (a "ladder") — that asks about a DIFFERENT version and
  falsely adds/drops exact-version-pinned CVEs (verified: `OpenSSH 6.6` adds 3 CVEs that don't apply to
  6.6.1). The flag is a no-op for products that already match and never fabricates a match (unknown
  product → 0). `_search_vulns_query` is **memoized process-wide** so the fan-out doesn't re-query.
- **Output:** `findings/cve.jsonl` / `findings/cve_full.jsonl` — `{cve, cvss, epss, cisa_kev, exploited,
  exploits, cwe, hosts, sources, cpe, description}`, sorted for triage (known-exploited/KEV first, then
  CVSS). Best-effort: skips if `search_vulns` / its DB is absent.
- **DB provisioning (out-of-band):** `search_vulns -u` downloads the prebuilt local DB (or
  `--full-update` rebuilds it); the stage never builds it during a run. Override the binary with
  `PTFLOW_SEARCH_VULNS`. *(The CVE quality lever is version detection — nerva covers services well; httpx
  `tech` often lacks versions, so version-less software is skipped. The corpus mining now also recovers
  versioned asset filenames/CDN paths (`mine_asset_versions`), the most common place a JS-lib version
  actually appears; a curated WordPress/CMS plugin-path miner is the natural next extension.)*

### Consolidate — the deterministic terminal fan-in

`consolidate` (`tasks.consolidate`, an OPTIONAL `Pipeline` hook the orchestrator calls after every
loop + spanning join, like `preflight`) lifts every app group's per-app findings into the
activity-level `<activity>/findings/<type>.jsonl` — **one file per finding TYPE**, every record
stamped with its `app_id` for traceability. It's fully OFFLINE (reads on-disk artifacts only) and
idempotent (overwrites each run / `--resume`). Sources (`_CONSOLIDATE_SOURCES` + the takeover lines):

- `findings/cve.jsonl` ← per-app `findings/cve.jsonl` + `findings/cve_full.jsonl` (surface+deep folded)
- `findings/dast.jsonl` ← per-app `findings/dast.jsonl` + `findings/dast_full.jsonl`
- `findings/xss.jsonl` ← per-app `findings/xss.jsonl` + `findings/xss_full.jsonl` (dalfox surface+deep)
- `findings/sqli.jsonl` ← per-app `findings/sqli.jsonl` + `findings/sqli_full.jsonl` (sqlmap surface+deep)
- `findings/tilde_enum.jsonl` ← per-app `findings/tilde_enum.jsonl`
- `findings/secrets.jsonl` ← per-app `secrets.jsonl`
- `findings/default_creds.jsonl` ← per-app `default_creds.jsonl`
- `findings/takeover.jsonl` ← per-app `takeover.txt` lines → `{app_id, type, evidence, source}` records

An empty TYPE writes no file (no clutter). The whole-scope `findings/nuclei_scope.jsonl` is already an
activity-level finding and is left untouched. The agent seam (`findings/hypotheses.jsonl`) runs
separately and is kept in place — dormant (`StubProvider`) by default, LLM-backed (`ai_triage`)
when AI is enabled. A `consolidate` failure is isolated (logged + counted), never aborting the run.

## Adding a pipeline (checklist)

- [ ] Create `src/ptflow/pipelines/<name>/` with a `PIPELINE` object satisfying the `Pipeline` protocol.
- [ ] Reads/writes **only** via `Activity` / `AppWorkspace` — no path literals.
- [ ] Each tool output written **once**: intermediate → `raw/<tool>/`; terminal artifact → canonical
      name directly (no verbatim raw↔canonical copy); derived → canonical only.
- [ ] Activity stages (`per_app=False`) for breadth; per-app stages grouped into loops by `phase`.
      Within a loop use `needs`; across loops rely on the barrier (no cross-loop `needs`).
- [ ] `cluster(activity) -> list[str]` creates the app groups, keyed on a stable hash of cluster identity.
- [ ] Network stages tagged `net`.
- [ ] Register it in `load_pipeline` **and** add its name to `pipelines.PIPELINE_NAMES`.
- [ ] Give it a flow map (the standard, see below): create `pipelines/<name>/flowmeta.py` with a
      `FLOWMETA` (a `StepMeta` per stage) + `SPEC` (`MapSpec`), and expose it via a `flowmap_spec()`
      hook on the `Pipeline`. The dev gate fails otherwise (only the `example` stub is exempt).

## Pipeline flow map (auto-generated, always current) — a per-pipeline STANDARD

**Every pipeline ships a flow map** (the `example` stub excepted). `ptflow.core.flowdocs` writes THREE
self-contained, always-up-to-date `docs/<name>-pipeline-*` views for each pipeline that declares the
standard — `external`, `internal`, `webscan` today. A git diff of any of them shows exactly how that
flow changed:
- **`docs/<name>-pipeline-flow.html`** — the detailed band "spec sheet" (bands, parallelism, barriers,
  per-step commands/outputs/notes; external's centerpiece is the content-discovery fixpoint).
- **`docs/<name>-pipeline-map.html`** — a conceptual **flowchart** (Mermaid) you can pan/zoom and scroll
  on both axes; each node shows the step + its commands. Mermaid loads from a CDN (needs a connection).
- **`docs/<name>-pipeline-map.md`** — the same flowchart as a GitHub-renderable ```mermaid block.

- **Structure is derived from code, not hand-drawn.** `core/flowmap.py` lays out the band spec sheet
  via longest-path layering; `core/mermaidmap.py` emits the Mermaid flowchart (both generic,
  pipeline-agnostic, from the `Stage` objects — `needs`/`phase`/`per_app`/`spanning`/`cluster_scope`/
  `net` — plus the `MapSpec`). Output is deterministic (no timestamps).
- **A pipeline joins the standard via a duck-typed `flowmap_spec() -> MapSpec` hook** (same convention
  as `requirements()`/`consolidate()`/`preflight()` — read via `getattr`, off the Protocol). It returns
  the pipeline's `SPEC` (a `MapSpec` bundling title/thesis/`FLOWMETA`/phase_labels/pivot/fanin). A
  pipeline with no hook (the `example` stub) is skipped gracefully by `flowdocs` and exempted by the gate.
- **Per-step prose/commands/outputs live in `pipelines/<name>/flowmeta.py`** (`FLOWMETA` + `SPEC`).
  This is the ONE thing you maintain by hand: **when you add or change a step, add/adjust its
  `StepMeta`.** `webscan`'s `flowmeta.py` reuses external's `FLOWMETA` (it runs external's functions),
  adding only its one webscan-only step (`ingest`).
- **The dev gate enforces the standard.** `tests/pipelines/test_flowmap.py` is parametrized over every
  registered pipeline (`pipelines.PIPELINE_NAMES`, minus the `example` stub): each must expose the hook,
  every `Stage` must have a `StepMeta`, and all three views must render. So a new pipeline that forgets
  its map — or a new stage without a `StepMeta` — fails the gate; the maps can't silently drift.
- **A hook regenerates them automatically.** `.claude/settings.json` runs `.claude/hooks/regen-flowmap.sh`
  (PostToolUse · Edit/Write/MultiEdit) which re-runs `python -m ptflow.core.flowdocs` (ALL pipelines)
  whenever a file under `src/ptflow/pipelines/` changes (where commands and execution order live).
  Regenerate by hand any time with: `uv run python -m ptflow.core.flowdocs`. (Edits to the generators
  themselves in `core/` aren't watched by the hook — regenerate manually after those.)

## External environment gotchas

- **`httpx` on PATH is the pyenv shim — use `~/go/bin/httpx`** (handled via the `HTTPX` constant in
  external tasks). Other tools (subfinder, dnsx, naabu, tlsx, mapcidr, shuffledns, katana, nerva,
  assetfinder, gau, urlfinder, subjack, …) are in `~/go/bin`; feroxbuster in `~/.local/bin`.
- Trusted resolvers: `/opt/resolvers/resolvers-trusted.txt`.
- **DAST (`dast`/`dast_full`)** uses structured local packs and always runs every template in every
  enabled pack (see `ptflow.toml.example`). Default = official `~/nuclei-templates/dast` + bundled
  PTFlow stable pack; the old `PTFLOW_NUCLEI_DAST_TEMPLATES` path remains a fallback. Validate/list
  the complete selection with `ptflow dast`.
- **Dedicated scanners (`xss`/`sqli`/`xss_full`/`sqli_full`)** use **dalfox** (`~/go/bin/dalfox`) and
  **sqlmap** (`/opt/sqlmap-dev/sqlmap.py`, override `PTFLOW_SQLMAP`, run via `sys.executable` — it's a
  python script, not a PATH binary). Both make target requests; best-effort (skip if absent). No DB to
  provision. Tunables (`VULN_MAX_REQUESTS`/`VULN_FANOUT`/`VULN_TOOL_TIMEOUT`/`SQLMAP_LEVEL`/`SQLMAP_RISK`)
  at the top of `tasks.py`.
- **OAST / blind XSS (`PTFLOW_OAST=on`, opt-in)** uses **`interactsh-client`** (`~/go/bin`, **≥1.3** — the
  1.2.x decrypt format is incompatible with today's public oast servers, verified: interactions arrive
  but unmarshal as binary garbage). Default public servers; self-host with `PTFLOW_INTERACTSH_SERVER`/
  `PTFLOW_INTERACTSH_TOKEN`. Catches only synchronous callbacks (see "Dedicated vuln scanners"); off by default.
- **CVE lookup (`cve_lookup`/`cve_lookup_full`)** uses `search_vulns` (`~/.local/bin/search_vulns`,
  override `PTFLOW_SEARCH_VULNS`) against its LOCAL DB. **Build/refresh the DB out-of-band:**
  `search_vulns -u` (prebuilt download) or `--full-update` (rebuild) — never during a run. The step
  skips best-effort if the binary or DB is absent. Offline once built (no target traffic).
- **WordPress vuln scan (`tech_vulnscan` → `wpprobe`)** uses `wpprobe` (`~/go/bin/wpprobe`,
  Chocapikk/wpprobe) against its LOCAL Wordfence DB. **Build/refresh out-of-band:** `wpprobe update-db`
  (and `wpprobe update` for the binary) — never during a run. Runs ONLY on WordPress app groups,
  best-effort (skips if absent). Makes target requests (stealthy REST enumeration, `--rate-limit`).
- **Auth passthrough (`webscan` only)** — set `PTFLOW_HTTP_HEADER` to one or more `Name: value`
  session headers/cookies (separated by newlines or `;;`) to reach the authenticated surface. Ignored
  by `external`; in `webscan`, threaded into the web scanning tools. Set it *before* launching.
- **EyeWitness (optional, `screenshot` step)** — a Selenium app, **installed** at `/opt/EyeWitness`
  with its own venv (`/opt/EyeWitness/.venv`, selenium ≥4.45 → Selenium Manager auto-provisions
  chromedriver; runs `--headless=new`, no Xvfb/sudo needed). `_eyewitness_cmd` resolves it
  automatically (PTFLOW_EYEWITNESS override › `eyewitness` on PATH › `_EYEWITNESS_DIR` = `/opt/EyeWitness`);
  if it ever goes missing
  the step just keeps the httpx gallery and skips EyeWitness. It's fed ALL candidate URLs (one best
  host per group) via a single `-f` file — ONE batched run (the `-f` report path writes `Requests.csv`,
  which `--single` skips), and that CSV's "Default Creds" column is what we parse, splitting the leads
  back per group by URL. Headless katana uses the bundled rod chromium, NOT system chrome
  (`-sc`/`-system-chrome` hangs for katana here — but works for httpx -screenshot).
- External tunables (rates, port counts, honeypot threshold, crawl depths, wordlist constants) are at the
  top of `pipelines/external/tasks.py` — tuned conservatively for live infra; don't bump blindly.
- **Rate profile** (env **`PTFLOW_PROFILE`** ∈ `wide|home`, default `wide`, resolved at import — set it
  *before* launching): `wide` = today's rates (real bandwidth); `home` throttles naabu `-rate`
  (300 vs 1000 — the full-port packet flood that exhausts a consumer NAT/router), nuclei `-rl`
  (50 vs 150) and feroxbuster `-t`/`-L`, for a domestic line. Aggregate load ≈ concurrency × rate,
  so the per-tool rate is the real lever (a `net` concurrency cap alone won't tame the single
  full-port/nuclei stages). The active profile is logged at run start (preflight).
- **AI layer (opt-in, `--ai` / `PTFLOW_AI=on` / `[ai].enabled=true`)** — adds four best-effort LLM
  functions via a **provider-agnostic** `core/ai/` seam (`LLMClient` Protocol + `make_client()`).
  **`PTFLOW_AI_PROVIDER`** selects `ollama` (default, local endpoint
  `http://127.0.0.1:11434/v1`), `ollama-cloud` (`https://ollama.com/v1`, `OLLAMA_API_KEY`),
  `openrouter`, `huggingface`, or an arbitrary
  `openai-compatible` endpoint. All use the `openai` SDK from the optional `ai` extra; named hosted
  providers read `OLLAMA_API_KEY` / `OPENROUTER_API_KEY` / `HF_TOKEN`, while `PTFLOW_AI_MODEL` is
  always explicit.
  `claude-code` remains a legacy opt-in backend isolated in `ai-claude`; it is no longer installed or
  selected by default. Structured output is **hybrid**: native schema support first, falling back to
  prompt+validate+retry. Every call returns `LLMResult`; managed clients add per-activity cache,
  usage telemetry (`ai/usage.jsonl`), run budgets, timeout/retry and bounded concurrency. Provider,
  model, endpoint, enablement and output cap can be overridden for each of `wordlist`,
  `secret_triage`, `triage`, and `report`; `configs/ai/mixed.toml` demonstrates hybrid routing.
  Triage/report consume normalized stable finding IDs and discard unsupported references. Hosted
  secret handling defaults to redacted (`ai.remote_secrets=off|redacted|full`) across both secret
  triage and downstream prompts. Ready configurations live in `configs/ai/`. Stages: `ai_wordlist` (phase 2 →
  `wl_custom/ai_seed.txt`, folded by
  `build_content_wordlist`), `ai_secret_triage` (phase 4 → sidecar `findings/secrets_triage.jsonl`),
  `ai_triage` (revives the agent seam → `findings/hypotheses.jsonl`, correlating consolidated findings),
  `ai_report` (terminal `report()` hook → `report-ai.md`). Per-app AI stages are marked `net=False`
  because they make no target traffic; hosted providers still make outbound API calls. All are
  additive and failure-isolated. Remote providers receive redacted assessment evidence by default,
  so their use remains RoE/data-handling sensitive. `external` and `webscan` share all four AI
  functions; with AI off, both pipelines' stage lists remain identical to their deterministic
  defaults. The active roadmap is in `docs/next-steps.md`.
- **Authorized test scope only:** `https://ginandjuice.shop/` (PortSwigger demo), `scanme.nmap.org`
  (Nmap-sanctioned).

## External design decisions (the *why*, and what was rejected)

The architecture sections above say *what* the external pipeline does; this records *why* — and the
alternatives deliberately rejected — so they aren't re-litigated. Newest first.

- **The early surface report is a first-class global checkpoint, not a terminal hook or a per-app
  report.** `Stage(after_phase=2)` is scheduled only after every app finishes loop 2 and is awaited before
  loop 3, so the snapshot is race-free across groups. It writes to an isolated checkpoint namespace
  rather than activity `findings/`, preventing partial phase-2 consolidation from contaminating the
  final fan-in. Whole-scope spanning outputs are intentionally absent because they may still be running.
  A rerun replaces every checkpoint JSONL before rendering, so an empty category cannot survive as stale
  early evidence. The same stage is present in `external` and `webscan`; `internal` has no four-phase web
  depth loop and therefore no surface checkpoint.

- **A per-scope authorization gate (`scope_gate`) enforces the RoE boundary at the discovery→active-scan
  seam — an offline stage between `resolve` and `portscan`.** External discovery *harvests names it never
  verifies against the authorized scope*: `expand` pulls candidates from TLS-SAN (`tlsx -san -cn`), reverse
  DNS (`dnsx -ptr`) and `subfinder`/`assetfinder`, then `resolve` writes them all — so a SAN/PTR name on a
  **third-party apex** (a shared cert, a cloud provider's PTR) and any IP it resolves to flowed straight into
  the active stages. The only prior hygiene was CDN-heuristic (`naabu -exclude-cdn` + `split_cdn_ip_records`),
  which is not authorization-based — a non-CDN third party (an ALB, a third-party apex from a SAN) passed
  straight through. This is an RoE/legal problem (observed live: Google `142.250.x`, AWS ALB `34.x`), so the
  gate derives an **allowlist** from the scope file and keeps only authorized assets. **Membership (four
  rules, in `core/scope.py`):** an asset is in scope if (1) its name is an exact `domain`/`url` host (a bare
  `acme.com` authorizes itself, NOT `app.acme.com`); (2) its name matches a `*.apex` wildcard (apex + every
  depth); (3) its IP is inside an explicit scope `net` (`ip`/`cidr`); or (4) its resolved IP is inside an
  explicit scope `net` — the **IP→names pivot** that recovers SAN/PTR/vhost names on an IP-only scope (a
  common external PT where the client gives IPs and no DNS; a naive domain allowlist would drop every
  recovered name). *Decisions:* (a) a recovered name resolving **off** the authorized IPs is dropped (no
  Host-header/SNI pinning in v1); (b) recovering a name does **not** auto-expand to its apex; and
  **anti-transitivity** — rule 4 uses ONLY the explicitly-listed nets, so domain-derived IPs are scanned but
  never authorize further names (otherwise domain→IP→new-names→new-IPs would chain-expand scope). *Why offline
  / complements CDN filters:* the gate makes no target traffic (`net=False`) — it keeps domain-derived IPs in
  the set and lets the existing `naabu -exclude-cdn`/`split_cdn_ip_records` drop the CDN ones, so it needs no
  CDN classification of its own. *Why a new stage + `inscope_*` files (not overwrite in place):* write-once —
  `scope_gate` is the **single writer** of `inscope_subdomains.txt`/`inscope_tls_names.txt`/`inscope_ips.txt`/
  `inscope_domain_ip_map.txt` + the RoE audit `excluded_out_of_scope.jsonl`; `expand`/`resolve` keep writing
  their raw discovery record, and the active stages (`portscan`/`portscan_full`/`httpx`/`nuclei_scope` + the
  CVE software collector's `domain_ip_map` read) are rewired to read the `inscope_*` set. An **empty allowlist**
  (malformed/empty scope) drops everything and logs a WARNING rather than silently scanning all-or-nothing.
  *Why no PSL/`tldextract`:* the confirmed semantics need only exact-match + suffix-match + stdlib `ipaddress`
  — so `classify` was also tightened to be IPv6-aware and reject bad octets (`999.0.0.1` → `domain`) instead of
  the old IPv4-only regexes. *Scope of change:* external only — `webscan` (uses `ingest`, not `expand`/`resolve`)
  and `internal` (its own IP/CIDR model) are untouched. *Rejected:* Host-header/SNI pinning to scan a recovered
  name against a specific authorized IP when public DNS diverges (v1 drops it — roadmap); a zero-traffic early
  `cdncheck` on `unique_ips.txt` (marginal over `naabu -exclude-cdn`); opt-in apex auto-expansion of recovered
  hosts; the PSL/`tldextract` dependency (unneeded). See
  `docs/superpowers/specs/2026-07-05-scope-gate-design.md`.

- **Cross-group discovered surface reaches phase 2, not only phase 4 — via a per-app `xref_catalog`
  stage, made race-free by the loop barrier.** The 2026-07-04 cross-group routing (`_cross_group_surface`)
  folded endpoints discovered while crawling group A that belong to another in-scope group B into **B's
  phase-4** full catalog (`requests_full.jsonl`), so only the heavy phase-4 pass tested them — a real,
  immediately-DASTable cross-group endpoint got no fast, high-signal phase-2 finding. Fix: a new per-app
  phase-2 stage `xref_catalog` (head of loop 2, `net=False`) writes a per-group **sidecar**
  `requests_xref.jsonl` from `_cross_group_surface` (peers' phase-1 discovery whose host ∈ this group,
  finalized by the extracted `_finalize_catalog` — scheme-normalize + in-scope + dead-drop). Phase-2
  `dast`/`xss`/`sqli` (`needs=("xref_catalog",)`) read the surface set via `_surface_request_set`
  (`requests.jsonl` ∪ `requests_xref.jsonl`); the phase-4 delta (`_delta_request_set`) subtracts BOTH
  keysets so nothing is double-tested. *Why race-free:* the per-app loop barrier (`_run_loops` awaits every
  phase-1 future across ALL groups before submitting any phase-2 stage) guarantees every group finished
  phase 1 — the same guarantee `request_catalog_full` already relies on one barrier later, so a phase-2
  stage can read any peer's phase-1 output safely. *Why a per-app `Stage`, not an activity-level pool at
  the 1→2 barrier* (the prior spec's "Approach 3"): the barrier already settles all phase-1 output, so a
  per-app stage symmetric to the phase-4 fold needs **zero `core/` change** — `--resume`, per-step toggles,
  and the flow map come for free. *Why a sidecar file, not folded into `requests.jsonl`:* write-once (one
  writer per artifact) — `request_catalog` owns `requests.jsonl`, `xref_catalog` owns `requests_xref.jsonl`.
  *Why `request_catalog_full` still folds `_cross_group_surface`* (unchanged): `param_fuzz` reads
  `requests_full.jsonl` directly (not the delta), so keeping the fold there lets it keep probing cross-group
  endpoints for hidden params — a distinct analysis from DAST, no regression. *RoE-safe by construction:*
  inherits `_cross_group_surface`'s `host ∈ ws.hosts` filter (an in-scope group's hosts only — no scope
  expansion). *Applies to `webscan` too* (it reuses external's functions, inheriting the `StepMeta`).
  *Rejected:* the activity-level discovered-surface pool (heavier than the barrier needs); re-DASTing the
  cross-group surface in phase 4 as well (double-test — the delta subtraction is the cure). *Roadmap
  (deferred):* re-crawling routed endpoints from the owning group, scope-expansion for an in-scope host that
  never clustered, cross-run persistence. See
  `docs/superpowers/specs/2026-07-05-phase2-cross-group-coverage-design.md`.

- **The catalog REALIGNS `raw` to the unioned params after the merge (`normalize_request`), and seeds a
  non-blank value.** A run-analysis (`ptflow-recon-20260630`) found the phase-2 surface scanners testing
  nothing: sqlmap exited in ~1s with "no testable parameter", DAST produced 2 low-value records, and the
  dedicated dalfox/sqlmap found 0 SQLi / 0 XSS on three deliberately-vulnerable targets — including
  ginandjuice, whose known SQLi/XSS live on `/catalog?category=`. Root cause: `merge_requests` dedups by
  `request_key` (method + path_template, query-insensitive) with **first-wins** on `url`/`raw` but
  **union** on `params`. When the param-LESS variant of a shape won (a bare `/catalog` from a URL-only
  source beating the html-form variant carrying `category`/`searchTerm`), the merged record advertised
  params that its `raw` — what nuclei `-im jsonl` / dalfox `--rawdata` / sqlmap `-r` actually fuzz — never
  contained. `build_raw_request` only ever read the URL's existing query string, never the `params` list.
  Blast radius on that run: query params missing from `raw` in 4/6 (ginandjuice), 3/8 (vulnweb), 8/8 (zero)
  surface GET shapes. Fix: `merge_requests` now calls `normalize_request` on each merged record — it folds
  every `loc=query` param into the URL query, every `loc=body`/`json` param into the body, and rebuilds
  `raw` to match. Each param gets its **observed value** (now captured by `request_params`/`_qs_pairs` as a
  `value` field that survives the merge, preferring a non-blank one) or **`PARAM_SEED_VALUE`** (`"1"`) — a
  non-empty token fuzzes better than a bare `name=` (sqlmap's heuristic/boolean tests, dalfox's reflection
  probes). *Why realign at the merge, not in the scanners:* one choke point feeds `dast`/`xss`/`sqli` +
  their `_full` passes + the persisted `requests.jsonl`, so the catalog on disk is itself correct +
  debuggable; idempotent, so re-merging in `dast_requests` (catalog + `build_fuzz_requests`) also seeds the
  synthesized param requests. *Why leave a param-LESS record untouched:* it returns the rec unchanged,
  preserving an authoritative `raw` (e.g. katana's own, with its real headers) — only records advertising
  query/body/json params are rebuilt, and those were broken anyway. *Why a value at all (fix #2):* an empty
  `?category=` is a weaker seed; observed values (`productId=3`) are reused, the rest get `1`. *Verified:*
  on the analyzed run's records `/catalog` → `GET /catalog?category=1&searchTerm=1`, `/vulnerabilities` →
  `?ref=1`, while `?postId=4`/`?productId=3` keep their observed values. *Rejected:* fixing it inside each
  scanner runner (three+ call sites, and the persisted catalog would stay wrong); rebuilding `raw` from the
  `headers` dict for every record (would drop headers only present in katana's authoritative raw — so
  untouched-when-paramless instead); dropping the value seed (empty `name=` under-tests sqlmap/dalfox).
  *Open:* the efficacy TUNING this unblocks but doesn't itself solve — sqlmap level/risk, ensuring the real
  injection points sit within `VULN_MAX_REQUESTS`, and the `category` site-wide-collapse interaction that
  can move a real injection point off its endpoint.

- **OAST/blind-XSS is within-run + best-effort (synchronous callbacks only), correlated per-request via
  the per-request runner.** dalfox `-b` fires blind payloads at an interactsh callback, but the hit lands
  on the interactsh SERVER, not dalfox's output. `_run_dalfox` (PTFLOW_OAST on) runs an `interactsh-client`
  for the pass (teardown-tracked `tools.spawn`/`stop`), gives each request a unique callback subdomain
  `b<i>.<domain>`, then `_oast_drain` → `correlate_oast` matches each interaction's `full-id`
  (`<marker>.<unique-id>`) back to the request. *Why per-request subdomains, not one callback:* dalfox
  `-b` is one URL per invocation and we already run one process per request, so a unique prefix gives
  per-request attribution for free (verified: interactsh preserves the prefix in `full-id`); one shared
  callback would only say "some request fired". *Why synchronous-only:* a truly-stored XSS fires when an
  admin later views the payload — minutes/days after a ~40-min run; receiving that needs a PERSISTENT
  callback+correlation service living past the run, which breaks files-as-only-state. We capture what
  fires during the run (the scan's own request triggers a server-side render) and explicitly punt the
  rest. *Why opt-in:* it adds the interactsh dependency + (default) routes callbacks through PD's public
  oast servers (a RoE/privacy consideration); self-host via `PTFLOW_INTERACTSH_SERVER`. *Tool floor:*
  interactsh-client **≥1.3** — 1.2.x can't decrypt the current public servers (interactions arrive but
  unmarshal as binary garbage; verified before/after the upgrade). *Verified end-to-end:* register →
  callback → decode → correlate → `poc_kind:"blind"` finding on the right request. *Rejected:* one
  shared callback (no per-param attribution); a persistent stored-XSS receiver (architectural misfit);
  relying on nuclei's interactsh alone (it covers some OOB but not blind-XSS-specific payloads).

- **Dedicated scanners (dalfox/sqlmap) complement nuclei -dast, fed the catalog's raw requests, with NO
  gf-style routing.** A run-analysis proved nuclei `-dast`'s generic templates miss real bugs (only
  `cookie-injection`/`crlf-injection` fired on a deliberately-vulnerable target; the reflected XSS was
  quote-filtered, the SQLi was blind/no-error). `xss`/`sqli` (phase 2) + `xss_full`/`sqli_full` (phase 4)
  add dalfox + sqlmap on the same surface/delta split as `dast`/`dast_full` (shared
  `_surface_request_set`/`_delta_request_set`). *Why no gf routing:* reconftw pipes `gf xss`/`gf sqli`
  (regex on the param NAME) into the tools — a guess that both misses (a SQLi on `category` isn't in the
  list) and wastes (an `id` that's safe), and operates on GET URLs only. Instead the ONLY filter is
  `_has_params` and **each tool's own engine decides** (dalfox reflection+context · sqlmap `--smart`).
  *Why feed `raw` (not URL lists):* both ingest a Burp/ZAP raw request (dalfox `file --rawdata`, sqlmap
  `-r`), so every param location is tested (query/body/json/header/cookie) — the payoff of the
  full-request catalog; sqlmap's time-based detection catches the blind SQLi nuclei missed. *Why one
  process per request:* raw mode is one request per invocation; bounded by `VULN_MAX_REQUESTS` + a
  `VULN_FANOUT` pool + per-request `VULN_TOOL_TIMEOUT` (a slow target can't hang the loop — the
  arjun/x8/feroxbuster lesson). *Why parse stdout (sqlmap) not a session file:* the `Parameter:/Type:/
  Title:/Payload:` block is stable and version-proof; on timeout that request just yields nothing
  (best-effort). *Verified:* both run end-to-end on ginandjuice (consume `raw`, parse, write
  `findings/{xss,sqli}{,_full}.jsonl`); `consolidate` folds surface+deep by type. *Rejected:* gf-pattern
  routing (the user explicitly called it "falsato"); evidence-based candidate selection (reflection for
  XSS, dynamism for SQLi) — deferred, the user chose "every parameterized request is a candidate" for now;
  ghauri/crlfuzz (a later best-effort layer). *Open:* detection TUNING (sqlmap level/risk, ensuring the
  real SQLi endpoints are in the candidate cap) — the integration is done; efficacy is the next lever.

- **A param "found" on ~every tested endpoint is collapsed as a SITE-WIDE reflection, not sprayed.**
  Run-analysis traced the phase-4 `?category=`-on-everything spray to its source: `param_fuzz` reported
  `category` on exactly 50 endpoints (= `PARAM_MAX_ENDPOINTS`, *all* selected), all from **x8** with
  `reason:"Reflected"`. The cause is a REAL global target behavior — ginandjuice echoes `?category=`
  into a `Set-Cookie` header on **every** path (verified by canary: `/about?category=X` →
  `set-cookie: category=X`; the value does NOT hit the body, so it's a header reflection; unknown random
  params do NOT echo, so it's specific to the app's real param). Reflection-based discovery (x8) sees the
  echo everywhere → flags the param on all tested endpoints → `build_fuzz_requests` synthesizes one
  request per endpoint → DAST re-fires `cookie-injection`/`crlf-injection` per request. ONE issue,
  multiplied. `collapse_global_params` folds a `(param, loc)` found on ≥75% of the endpoints tested at
  that location (and ≥5 hits) into one host-level record (`scope:"site-wide"`). *Why at param_fuzz, not
  DAST:* fixing it at the source cuts the synthesized-request explosion AND the downstream DAST
  inflation — the DAST injection-point dedup is the safety net, this is the cure. *Why 75% + a min-hits
  floor:* a real hidden param is endpoint-specific (productId on 2, searchTerm on 3); only an artifact
  approaches "all". The min-hits floor stops a tiny tested set (3/3) from tripping the ratio. *Why keep
  one record (not drop entirely):* it IS a real low-sev finding (cookie/header injection) — worth one
  host-level note, just not 50. *Verified:* ginandjuice params 65→16 (category 50→1), zero 14→3 (a
  mojibake noise param on 12/15 header endpoints collapsed), vulnweb 45→45 (all endpoint-specific —
  untouched, no over-collapse). *Rejected:* dropping the param outright (loses a real finding); a
  per-param allowlist (brittle); keying on response-similarity instead of the hit-ratio (heavier, and
  the ratio is already a clean signal). *Open:* x8's reflection detector itself could suppress this with
  better calibration — out of our control; the collapse is the pragmatic guard.

- **DAST findings are deduped by INJECTION POINT, not emitted one-per-fuzzed-request.** A run-analysis
  showed `findings/dast.jsonl` reporting 80 hits that were really 2 templates (`cookie-injection` info +
  `crlf-injection` low) re-firing across many synthesized variants of the same endpoints. `nuclei -dast`
  emits one record per fuzzed request, so the param-sprayed catalog (and http+https of one host)
  multiplies one issue into a pile. `dedup_dast_findings` keeps one record per
  `(template-id, host, path, fuzzing_position, fuzzing_method)` — path WITHOUT the query (the payload is
  in it), first full record wins (keeps a concrete `matched-at`). *Why per-pass (in `_run_dast`) not in
  `consolidate`:* `dast_full` fuzzes only the `request_key`-disjoint delta, so a given injection point
  appears in exactly one pass — per-pass dedup is complete, and `consolidate` just concatenates. *Why
  not key on the param NAME:* nuclei v3.8 exposes `fuzzing_position` but not the fuzzed param name as a
  field, and parsing it out of `matched-at` is payload-/position-specific and fragile; `(host, path,
  position)` is the robust injection-point identity. *Why not drop the path (collapse a template to one
  per host):* that over-merges real per-endpoint bugs (SQLi on `/catalog/product` ≠ on `/blog/post`) —
  precision over a smaller count. *Result with the dead-drop:* ginandjuice dast_full 80 → 18 on a fresh
  run. The surviving cookie/crlf are low-value reflections; **hard-suppressing those info/low templates
  is a SEPARATE opt-in lever, deliberately not done here** (dedup ≠ severity policy). *Rejected:*
  emitting raw nuclei output (the misleading 82); a severity/template allowlist baked into the dedup
  (conflates two concerns).

- **The request catalog drops dead (404/410) GET endpoints, decided OFFLINE from the `-srd` index
  statuses.** A run-analysis showed ~20–60% of a catalog was malformed passive/archive URLs
  (`/about</a>`, `/)`, gau Wayback junk) and phantom JS routes (`/catalog/filter` → 404) that DAST then
  fuzzed for nothing — and the only "findings" were `cookie-injection`/`crlf-injection` reflections
  firing on those 404 pages. `dead_url_keys` reads the status already recorded in every katana/httpx
  `-srd` index line (`<file> <url> (<code> <reason>)`) and drops GET shapes whose path was seen ONLY as
  404/410. *Why offline:* the statuses are already on disk from the crawl/fetch_delta/content_discovery
  downloads — so `request_catalog`/`request_catalog_full` stay `net=False` (no probe, no invariant
  change). *Why GET-only + body-less:* we only ever recorded GET statuses (gau/katana/ferox are GET); a
  discovered POST/form/XHR/JSON shape has no recorded status, so dropping it on a GET 404 could kill a
  real endpoint — keep all non-GET. *Why "only-ever-404" not "any-404":* a parameterized endpoint can
  404 for the crawled value yet 200 for another (`/catalog/product?productId=3` 200, bare 404), so one
  non-dead observation (2xx/3xx, or 401/403/405 = exists) keeps the path — precision over recall.
  *Verified:* on the analyzed run it dropped 51 (ginandjuice), 13 (testaspnet), 263 (zero — a parked
  44-byte page whose 413-URL catalog was almost all stale passive 404s) while keeping `/catalog`,
  `/catalog/product`, `/blog/post`. *Coverage caveat:* a catalog URL never fetched (no index entry) has
  unknown status and is kept — an active liveness probe would close that, but it'd add traffic and break
  the offline invariant, so it's deferred. *Rejected:* keying on the full URL incl. query (the phase-4
  `?category=`-sprayed variants never exactly match the fetched value → garbage survives); an httpx
  liveness probe at catalog time (network + invariant break); syntactic-only garbage filtering (misses
  well-formed-but-dead URLs like `/ads.txt`, and the user's criterion is the 404 itself).

- **`tech_vulnscan` is the findings-only dual of `tech_enum`, gated on detected tech; first scanner is
  `wpprobe` for WordPress.** A per-app phase-4 stage that dispatches finding-only per-stack scanners
  keyed on the cluster's `tech` (whole-word `_tech_match`), run ∥ the rest of loop 4. `wpprobe` (one
  stealthy scan per distinct-body host) maps detected WP plugins/themes+versions to known CVEs via its
  LOCAL Wordfence DB; `parse_wpprobe` emits one record per (component, version, CVE) →
  `findings/wpprobe.jsonl`, lifted by `consolidate`. *Why phase 4 / findings-only:* it's the documented
  split — surface-generating scanners feed enum in loop 3 (`tech_enum`), finding-only scanners run in
  loop 4; wpprobe produces findings, not fuzz surface. *Why gate on tech, when wpprobe self-checks for
  WordPress:* the operator asked for it scoped to WordPress groups, and the gate avoids a wasted scan +
  GitHub self-update call on every non-WP group. *Why offline DB / out-of-band provisioning:* same as
  `search_vulns` — `wpprobe update-db` builds the local Wordfence DB; the stage never builds it during a
  run (best-effort skip if absent). *Why one scan per distinct-body host* (not best_host, not all): same
  `_scan_hosts` dedup the other active scanners use — staging vs test may run different plugins. *Why a
  per-host wall-clock cap* (`WPPROBE_TIMEOUT`): the arjun/x8/feroxbuster lesson — a slow target must not
  hang the loop; keep partial. *Rejected:* `-f` batch over the group's hosts (its multi-site JSON shape
  is ambiguous vs the clean single-object `-u`); bruteforce/hybrid mode (noisy on live infra — stealthy
  REST enumeration is the polite default); emitting a finding for a detected-but-not-vulnerable plugin
  (that's enumeration surface, not a finding — `tech_vulnscan` is findings-only).

- **`consolidate` is the deterministic terminal fan-in, organized by finding TYPE — not the agent.**
  An optional `Pipeline` hook (`tasks.consolidate`, called via `getattr` like `preflight`) lifts
  per-app findings into `<activity>/findings/<type>.jsonl`, one file per TYPE, each record stamped
  `app_id`. *Why one file per TYPE, folding cve+cve_full / dast+dast_full:* the surface/deep split is
  a pipeline-PHASE artifact, not a finding-type distinction — an operator triages by "the CVEs", "the
  DAST hits", so the activity view is by type; the per-app phase files stay split on disk (write-once).
  *Why a `getattr` hook, not a `Pipeline` Protocol method:* keeps the orchestrator pipeline-agnostic
  (the example pipeline has no `consolidate` → skipped), same pattern as `preflight`. *Why keep the
  dormant agent call too:* "leave the seam in place" — `StubProvider` → `hypotheses.jsonl` still runs
  beside consolidate (parked, harmless), so reviving the Claude agent later is a drop-in. *Why
  failure-isolated:* a terminal aggregation must never sink a run's results — a raise is logged +
  counted, not propagated. *Rejected:* removing the agent seam (the guidance is to keep it); a single
  `findings/all.jsonl` with a `type` field (the operator asked for per-type files); making consolidate
  a `Stage` (it's a whole-activity fan-in after the last barrier, like the agent — not a per-app/
  spanning stage, so it sits in the orchestrator terminal, not the DAG).

- **Known-CVE lookup is OFFLINE correlation of enumerated software, in two passes mirroring the DAST.**
  `cve_lookup` (phase 2, ∥ `dast`) and `cve_lookup_full` (phase 4, ∥ `dast_full`) feed `search_vulns`'
  local DB (NVD+GHSA+ExploitDB+EPSS) the software we ALREADY enumerated — web server, wappalyzer tech,
  nerva service banners, libs mined from the crawl corpus — and emit `findings/cve{,_full}.jsonl`. *Why
  offline/`net=False`:* it reads the local DB, makes no target requests, so it overlaps the active DAST
  for free (no net-cap contention). *Why two passes, not one:* the structured sources are fixed at
  cluster but the **corpus grows** between the phase-1 and phase-3 crawls, so the phase-4 pass re-mines
  it and reports only the delta (`raw/cve/seen.txt`); a single pass would miss libs in fuzz-downloaded
  bodies. *Why per-app, not whole-scope `spanning`:* the operator asked for it tied to the two crawls /
  ∥ the two DASTs — that's the per-app phase model, not a once-over-everything spanning stage; a
  process-wide memo cache (`(product,version)→CVEs`) recovers the dedup a whole-scope pass would give.
  *Why version-pinned + `--use-created-product-ids`, NOT a version ladder:* cpe_search can fail to map an
  exact version to an indexed CPE (`OpenSSH 6.6.1` → no match), so the flag synthesizes a product ID at
  the EXACT version and lets search_vulns do the version-range check there. A "ladder" (query a coarser
  `6.6`) was REJECTED — it asks about a different version and falsely adds/drops exact-version-pinned
  CVEs (verified: `6.6` adds 3 that don't apply to `6.6.1`). We still drop version-less software
  (precision-first). *Why search_vulns over alternatives:*
  it's offline (local DB), multi-source, takes plain product strings (no CPE-building), JSON out — vs
  nmap-`vulners` (reconftw: needs `nmap -sV` + network) which we don't run. *Rejected:* a whole-scope
  spanning stage (loses the crawl-timed two-pass + per-app attribution); querying version-less products
  (noisy general-product CVEs — `--ignore-general-product-vulns`); building the DB during a run (slow,
  network — it's out-of-band). *Corpus version mining* now covers JS-lib banners, `<meta generator>`
  AND versioned asset filenames/CDN paths (`mine_asset_versions`, over body heads + fetched `-srd`
  URLs) — the version is most often in the filename, not a banner. *Open:* a curated CMS plugin-path
  miner (WordPress `/wp-content/plugins/<slug>/<ver>/`); nerva IP-only records whose IP isn't in
  `domain_ip_map.txt` (the bracketed-IP parse bug is fixed — IP attribution now works).

- **Per-app loops are surface-first, DAST-first — four phases, not three.** Map only the EXPLORABLE
  surface (OSINT/crawl, no guessing) and DAST *that* first, THEN guess/fuzz, THEN DAST the guessed
  surface. The phases: (1) explorable surface — passive/crawl/headless + `fetch_delta`/`mine_responses` +
  `api_spec`, tail `request_catalog` → `requests.jsonl`; (2) `dast` over that surface (low-hanging fruit);
  (3) guessing — `wordlist`→`tech_enum`→`content_discovery` fixpoint→`recrawl`; (4) `request_catalog_full`
  (`requests_full.jsonl`)→`param_fuzz`→`dast_full`. *Why:* high-signal findings on the REAL attack
  surface arrive fast — across the whole scope (the phase barrier) — before sinking hours into fuzzing;
  the explorable/guessed split also keeps each DAST scoped. *Why `mine_responses` (extract + jsluice) is
  phase 1, not phase 3:* `request_catalog` mines POST/form/XHR shapes from the extracted corpus, so
  without it the phase-2 DAST degrades to GET-only on the surface — defeating the full-request design.
  *Why `wordlist` (the seed) IS phase 3:* its only consumers are `content_discovery`/`tech_enum`/
  `param_fuzz` (all phase 3+) — it's pure fuzzing-prep, so it belongs with the guessing, reading the
  phase-1 corpus across the barrier. *Why two catalog stages + two DAST stages* (not one re-run): a stage
  owns one artifact (write-once), so the surface catalog (`requests.jsonl`) and the full catalog
  (`requests_full.jsonl`) are distinct files with distinct writers; same for `findings/dast.jsonl` vs
  `dast_full.jsonl`. *Why `dast_full` fuzzes only the DELTA* (full minus surface, by `request_key`) + the
  param-injection requests: phase 2 already covered the surface, so re-DASTing it is wasted nuclei work;
  the hidden params are new injection points so they're always included. *Rejected:* the literal
  three-phase reading (fuzz is terminal) — it drops DAST coverage of the fuzzing-discovered surface, a
  regression vs the old single end-of-pipeline DAST; running `param_fuzz` in phase 2 — it's guessing
  (brute-forces param names), so it belongs after the low-hanging-fruit pass. *(Supersedes the old Loop
  1 enumeration / Loop 2 content-discovery / Loop 3 catalog+param+DAST layout.)*

- **DAST fuzzes FULL requests, not bare URLs — via a request catalog fed to nuclei `-im jsonl`.** A URL
  list only carries a GET query, so reconftw and the old `param_fuzz` could fuzz nothing but query
  params. The catalog (`requests.jsonl`) records `{method, headers, body, params:[{name,loc}], raw}` and
  nuclei `-im jsonl` builds each fuzzed request from `raw` (the authoritative field — empty `raw` →
  "failed to read method line"), fuzzing query/path/header/cookie/**body** per template `part`. *How we
  got the data:* katana already discovers forms (`-fx`), XHR (`-xhr`) and request bodies — `parse_katana`
  threw all but the URL away; we now drop `-omit-raw` and keep it. *Verified empirically* (the format was
  reverse-engineered from nuclei's parse error + confirmed with `-dast -dfp`: a synthesized `POST` body
  engages `sqli`/`xss` fuzz points — see the `nuclei-dast-jsonl` memory). *Why a catalog stage* (not
  inline in dast): `param_fuzz` and `dast` both read it; one writer (`request_catalog`), many readers,
  respecting write-once. *Why build `raw` ourselves* rather than depend on katana's: identical builder
  serves synthesized requests (param discovery, OpenAPI expansion); `raw` is path+Host so it's
  scheme-agnostic (only `url` is re-schemed). *Rejected:* `-im openapi` as a second nuclei run (api_spec
  expands specs into the one jsonl catalog instead); feeding nuclei bare URLs (`-im list` — GET query only).

- **Param discovery covers ALL locations (query · body · json · header), gated by the catalog.** arjun
  (`-m GET/POST/JSON`) and x8 (`-X` · `--data-type json` · `--headers`) natively discover params in every
  location; the old `param_fuzz` artificially restricted to GET. Query discovery runs over every endpoint
  shape; body/json target the endpoints the crawl saw with a body (`select_body_targets`) topped up from
  the query set (probe hidden POST params); header is x8-only. Merged by `(url, param, loc)` — query≠body
  are distinct injection points. *Why catalog-driven:* trying every method on every endpoint multiplies
  request load; the catalog says where bodies actually are. *Politeness:* tight per-location caps
  (`PARAM_MAX_*`), bounded `(tool, location)` fan-out, per-tool wall-clock cap. *Why nuclei-dast-only* for
  the DAST itself: it's runnable today (templates installed, zero extra deps); dalfox/sqlmap/etc. remain a
  future best-effort layer like shortscan/eyewitness.

- **Scan scheme = the one that WORKS for the scanners, not httpx's https guess.** httpx (breadth) is
  fed bare hosts, defaults to https, and *ignores the input scheme* — and its Go TLS happily
  handshakes a legacy endpoint (unsafe renegotiation / weak DH) that rustls/OpenSSL scanners refuse,
  so `hosts.txt` came out `https://` and feroxbuster/arjun/x8 then reached **nothing** (`-k` is
  cert-only; no flag fixes it). Three complementary mechanisms fix this. **(1) Honor an explicit scope
  scheme:** `cluster` re-applies the operator's `http://`/`https://` onto the group's hosts
  (`_scheme_pins` + `force_scheme`), at OUTPUT only — clustering keys on scheme-independent signals
  and the id anchor on `url_host`, so pinning never shifts a group/`app_id`. **(2) Reach the working
  scheme automatically** where no scheme was given (discovered subdomains): feroxbuster detects a
  total transport failure from its `statistics` record (`ferox_transport_failed`: successes 0 &
  errors > 0 — distinct from "found nothing" and from a `--time-limit` kill, which emits no stats)
  and retries the round over http; param_fuzz can't do the same reactively (arjun/x8 fail the
  handshake **silently** — no signal, indistinguishable from a clean 0-param result), so it instead
  routes targets to the empirically-reached scheme (`_working_schemes`: `hosts.txt` scheme overridden
  by `content_discovery.jsonl` hit URLs, which already carry feroxbuster's http fallback). **(3) Probe
  BOTH schemes in breadth (`httpx -nf`):** the breadth fingerprint runs httpx with `-no-fallback`, so
  every host:port is probed over http AND https — not just the first that answers. Without it an
  HTTPS-only alt port (a UniFi/Tomcat admin console on :8443/:8843) is silently missed: httpx probes
  `http://host:port`, the TLS server returns 400 to the plaintext request (a *valid* HTTP response, so
  the http→https fallback never fires), and the real webapp never enters `httpx_full_metadata.jsonl`.
  This CORRECTS the earlier "httpx's https probe succeeds regardless" assumption — true for schemeless
  hostnames (where the https default works), FALSE for alt ports answering http with a 400 (verified on
  a live UniFi controller: default → `http://:8443` 400 only; `-nf` → also `https://:8443` 302). `-nf`
  doubles a record only when both schemes genuinely respond (a plain-http :8080 stays single); `cluster()`
  reads the full metadata (not the deduped `unique_webapps.txt`), so the recovered https record is
  clustered/crawled with the right scheme, and `-fr` follows its redirect so it keeps a distinct
  signature. *Why not `-nfs` on httpx:* `-nfs` (honor input scheme) flips *every* schemeless discovered
  host to http (kills the https default) — it's right only for `webscan`'s ingest, where every target
  carries an explicit scheme. *Why not a
  curl/openssl preflight probe:* extra per-host network cost on the healthy path; the reactive
  detect-and-fallback pays only on actual failure. *Rejected:* leaving it to `-k` (cert-only, no
  effect); `OPENSSL_CONF` legacy-renegotiation (feroxbuster is rustls, unaffected; the server also
  has a weak DH key — two strikes).

- **Content discovery is a bounded cross-tool FIXPOINT, not a single feroxbuster pass.** Round 0 is
  the classic `--smart` forced-browse; then `_content_rounds` feeds feroxbuster's NEW 2xx/3xx hits
  back through download → mine (jsluice + tokenize) → fuzz the new token delta, until convergence.
  *Why:* feroxbuster's own recursion is **link-only** — it never parses a fuzz-discovered JS file for
  API routes or harvests new params, so a `/api/v2/...` route hidden in a forced-browsed `app.js`
  was previously never fuzzed. The fixpoint closes that loop. *How it can't run away:* four
  independent stops (no-new-words, no-new-urls, per-app wall-clock `CONTENT_DEADLINE_S`,
  diminishing-returns `< MIN_NEW_TOKENS`) under a hard `CONTENT_FEEDBACK_ROUNDS` cap; the token
  frontier is monotone and finite (grows only from newly-downloaded bodies) so it converges, and a
  token is never re-fuzzed / a URL never re-downloaded (`seen` from the `-srd` indices). *Why inside
  the one stage* (not a new `content_recurse` stage, nor an orchestrator-level loop): the iteration
  is a *recon-domain* convergence decision with mutable per-round state, not a generic orchestration
  concern — folding it keeps content_discovery.jsonl a single owned artifact and leaves the
  per_app_loops "run each phase once, ascending, barrier between" contract untouched. *Rejected:* a
  separate `content_recurse` stage (two jsonl artifacts, re-pays feroxbuster startup); repeating the
  whole phase-2 loop at the orchestrator (breaks write-once + the loop model for one pipeline's need);
  unbounded depth (live-infra politeness — the deadline + round cap are mandatory). *Profile:*
  Balanced — 2 feedback rounds, ~15 min/app. Deep rounds use `DEEP_FEROX_TIME_LIMIT`; round 0 keeps
  the full `FEROX_TIME_LIMIT`.

- **Secret mining is a CONCURRENT multi-tool fleet, merged — not a sequential pipeline — and runs
  ONCE at the END of content discovery.** `_scan_secrets` (the tail of `content_discovery`) extracts
  ALL response bodies (not just `.js`) to `raw/extracted/` and runs jsluice + gitleaks + trufflehog
  (`--results=verified`) + detect-secrets **in parallel** (`_secret_fleet`, ThreadPoolExecutor), then
  `merge_secrets` dedups across them (`sources`/`verified`) → `secrets.jsonl`. *Why at the end, not in
  `mine_responses`:* `mine_responses` runs **before** the fuzzing, so a fleet there never sees the
  feroxbuster-discovered files — a blind spot. Running it after the fixpoint's downloads complete the
  corpus (idempotent `_extract_bodies` having extended `raw/extracted/` each round) closes that gap;
  `mine_responses` keeps only the cheap jsluice-endpoint extraction that seeds round 0. *Why parallel,
  not a pipeline:* the scanners are independent (same corpus in, no data flows between them) and
  I/O/network-bound — sequential would just sum their times for zero benefit. *Why each tool:* they
  cover different mechanisms — jsluice (JS AST, precise), gitleaks (regex over **any** file → catches
  secrets in HTML/inline scripts jsluice's `.js`-only view misses), trufflehog (provider-verified,
  near-zero FP), detect-secrets (entropy, hashes-only leads). *Caveats baked in:* best-effort (skip if
  a binary is absent); trufflehog verification makes network calls to the credential's **provider**
  (not the target); detect-secrets needs `--all-files` run from the corpus CWD (default scans only
  git-tracked files); cross-tool dedup is best-effort (a redacted/hashed hit won't merge with a
  raw-value one). FP noise is the risk → prefer `verified`, treat the rest as leads.

- **Response headers captured as a structured signal, gated like `tech`.** httpx `-irh` emits a
  ready `header` dict (no parsing); `cluster()` stores `headers_by_host` (raw, for ad-hoc reasoning)
  + `header_signals` (curated: `cache`/`cdn:*`/`backend:*`/`stack:*`/`waf:*`/`hsts`/`csp`) in
  `meta.json`, so per-stack stages can dispatch tools on header presence (e.g. a cache probe when
  `cache ∈ signals`) the same way they do on `tech`. *Why `-irh` not `-irr`:* `-irh` gives the
  structured dict without the inline response **body** that `-irr` embeds — that body is heavy and
  already in the `responses/` store (nothing read it inline), so `-irr` was swapped out. *Rejected:*
  headers as a clustering EDGE — they're volatile (Date/Set-Cookie/request-ids) → noise/over-split;
  they're a per-app gating signal, not a grouping key.

- **Active scanners target one host per distinct response body — not all-hosts, not best_host.**
  `crawl`/`crawl_headless`/`content_discovery` go through `_scan_hosts` → `dedup_by_body` (keyed on
  the per-host `body_sha256` recorded in `meta.json`). *Why:* a group is one app, so same-backend
  aliases (a domain **and** its IP, http+https) are pure re-scan — that caused a ~2h feroxbuster hang
  re-fuzzing `scanme.nmap.org` twice (hostname + IP). But two hosts with *different* bodies are
  distinct environments (e.g. `staging.` vs `test.` of one app) whose linked content and env-specific
  files genuinely differ, so both must be scanned. *Rejected:* `best_host` (shipped briefly — too
  aggressive, loses the staging/test deltas); all-hosts (re-fuzzes identical backends).
  `passive_probe`/`subenum`/`takeover` deliberately stay on **all** hosts — they key on
  domain/apex/hostname, where the data really does differ. (Supersedes a planned host-per-IP dedup.)

- **feroxbuster gets a `--time-limit` (total wall-clock cap).** *Why:* `--timeout` is per-request
  only; a target that throttles under `--smart` (scanme.nmap.org) drove feroxbuster's auto-tune into
  an unbounded backoff *livelock* — sleeping, 0 CPU, no output — that hung the whole pipeline for
  hours with no way out. `--time-limit` is `--smart`-compatible and exits gracefully keeping partial
  results. *Rejected for now:* a subprocess-`timeout` backstop and a general per-tool cap in `_run`
  (deferred — `--time-limit` covers the observed failure).

- **Unified screenshot: ONE batched run post-cluster, not per-group.** `screenshot` is a
  `cluster_scope` (post-cluster spanning) step: it picks one `best_host` per group, builds a
  `url→app_id` map, and runs httpx `-ss … -j` **once** over all candidates → the tools' NATIVE
  aggregate output is the unified gallery (`screenshots/screenshot/screenshot.html` +
  `index_screenshot.txt` + `vision_recon_clusters.json`). The same run **fingerprints** each candidate
  (`-sc -cl -title -td -server -ip -favicon -irh`, EyeWitness-style) — captured from the `-j` stream,
  reconciled by URL, written per group to `scans/<app_id>/screenshot.json` (+ a consolidated
  `screenshots/screenshot/fingerprints.jsonl`), so a screenshot ships with its status/title/server/
  tech/header_signals, not just a PNG.
  EyeWitness (optional, best-effort like shortscan/wpprobe) runs **once** over the same `-f` URL list →
  its own `report.html` + `Requests.csv`. *Why batched:* the per-group design produced N trivial
  1-site reports and N **Selenium startups** (EyeWitness is heavy); one run gives the unified view for
  free and amortizes the browser cost. *Reconciliation (the key bit):* we choose the candidates, so
  `url→app_id` is ours; the `-srd` `index_screenshot.txt` ([file,url], parsed by `_store_index`) and
  EyeWitness's `Requests.csv` (URL↔shot↔creds) map each result **by URL** (`reconcile_by_url`,
  trailing-slash-insensitive) back to `scans/<app_id>/screenshot.png` + per-group `default_creds.jsonl`
  — no hash-guessing. Per-group PNGs are COPIED (the gallery keeps its own); default-cred hits are
  **signature-based leads**, not verified logins. EyeWitness via `-f` (not `--single`) because **only
  the `-f` path writes `Requests.csv`**. `cluster_scope` keeps it ∥ the loops, race-free (reads only
  meta/hosts, writes distinct filenames). *Rejected:* a hand-built HTML gallery (the tools already emit
  one); per-host screenshots (one candidate/group = the right overview granularity).

- **Clustering is precision-first and keys on app identity, never infrastructure.** *Why:* over-merge
  (fusing different apps) is a **correctness** bug here — a group shares one `endpoints.txt`/`hosts`,
  cross-fuzzes, and one screenshot represents it — whereas over-split is only wasted work. So the
  union-find uses only app-identity signals (redirect-final, exact body, apex-scoped favicon +
  fingerprint) and *when in doubt does not merge*. *Rejected:* the old exact `Title|CL|Webserver` key
  (brittle: drifts on a token, collides on blank titles); **cert** and **ip+header+tech** edges (infra
  — one cert/box fronts distinct apps → over-merge); DBSCAN/embedding clustering (non-deterministic,
  breaks the stable `app_id` contract); LSH/simhash near-dup and a `recluster` deep-path pass
  (deferred, not needed yet).

- **Gated headless crawl keyed on a *measured* JS-render signal, not a framework label.** `crawl`
  classifies each app (`is_js_rendered`: raw `<a href>` vs the JS-parsed/crawley surface + thin-shell
  markers, recorded in `crawl_class.json`); `crawl_headless` renders only the JS bucket, RAM-capped by
  a process-wide semaphore. *Why:* the benchmark showed framework labels lie (a "React" app can behave
  traditionally), and headless RAM (1-5 GB/host) is the scale constraint. *Rejected:* the old `is_spa`
  framework-keyword heuristic (removed); a Prefect per-stage concurrency tag for the RAM cap (the
  semaphore works because `ThreadPoolTaskRunner` is one process); `-sc`/system-chrome (hangs for
  katana here — uses the bundled rod chromium). It was a slip-of-the-tongue "nuclei -headless" → the
  intent was katana crawling.

- **Two crawlers run in parallel (`katana ∥ crawley`); no SPA detection.** *Why:* the benchmark's best
  coverage/cost knee was katana-fx + crawley; crawley adds form-POST/asset URLs katana-fx misses at
  ~zero marginal cost in parallel. katana is the downloader (`-srd` store for offline mining); crawley
  is pure URL discovery → its URLs join the `fetch_delta` candidates. SPA handling moved to the gated
  headless pass above, so the old SPA-detection + katana `-headless` branch was removed.

## Pin to keep

`fastapi<0.137` is pinned in `pyproject.toml` — Prefect 3.7.x's ephemeral server crashes on
FastAPI 0.137+ (`del router.routes`). Do not drop it.
