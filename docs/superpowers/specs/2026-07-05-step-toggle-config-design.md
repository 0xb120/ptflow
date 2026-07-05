# Design — Per-step on/off toggles (debug knob)

- **Date:** 2026-07-05
- **Status:** Approved (design); pending implementation plan
- **Scope:** core (`runconfig`, `orchestrator`, `cli`) + a new `ptflow steps` subcommand. Pipeline-agnostic
  (works for `external`/`internal`/`webscan`; the stub `example` too). No pipeline task code changes.

## 1. Motivation

Today there is **no first-class way to run a pipeline with a specific step disabled** (e.g. skip `nuclei_scope`
or `dast`). The stage graph is a static class attribute (`ExternalPipeline.stages`, a `tuple[Stage, ...]`);
the only conditional inclusion is the AI layer (`*(_AI_STAGES if _AI else ())`). The orchestrator always
iterates the full `pipeline.stages`. Indirect levers exist (best-effort self-skip when a tool/dataset is
absent — e.g. pointing `PTFLOW_NUCLEI_DAST_TEMPLATES` at a missing dir disables `dast`/`dast_full`; but
`nuclei_scope` has no such guard) but they are hacks, per-step, and not uniform.

The operator wants a **debug-oriented** way to turn individual steps on/off, driven by config, that **cannot
go stale** relative to the code, plus a **convenient way to view all steps** of a pipeline.

## 2. Goals / Non-goals

**Goals:**
- Disable one or more named steps of the pipeline being run, via the existing config mechanism
  (`ptflow.toml` + `--set`), with the established precedence (`--set` > config file).
- **Sparse** semantics: only list what you disable; every step not named stays ON.
- **Cannot reference a deleted/renamed step:** step names are validated against the pipeline's live
  `stages` at run time; an unknown name is a hard config error. This is what keeps the feature
  "always in sync with the code" — there is no hand-maintained list of steps to drift.
- A `ptflow steps <pipeline>` subcommand that lists **every** step (grouped by band), showing the
  **effective** on/off state given the same `--config`/`--set`. This live view IS the always-current
  reference (it reads `stages` directly — nothing to regenerate or gate).
- Reuse the proven safety property that filtering a stage out of the list is already safe (below).

**Non-goals:**
- **Enabling** steps that are conditionally excluded from `stages` (the AI stages appear only under
  `--ai`/`PTFLOW_AI`). Toggles only *filter the current set*; they never construct stages. Turning a
  present step "on" is a no-op; turning an absent one "on" is an unknown-name error.
- Toggling the non-`Stage` hooks/methods: `cluster` (the fan-out pivot), `consolidate`, `provider`,
  `report`, `followups`. These are not `Stage`s and are out of scope by construction.
- A `PTFLOW_*` env layer for individual steps (the env layer exists to feed import-time constants; step
  toggles filter stages at run time, so env adds nothing). Could be added later as a convenience
  (`PTFLOW_STEPS_DISABLE="dast,nuclei_scope"`), explicitly deferred.
- Rewriting downstream `needs` when a step is disabled (unnecessary — see §4).
- A checked-in generated reference file + anti-drift gate (that pattern is for the flow-map docs; here the
  live `ptflow steps` command replaces the need for a file — it cannot drift).

## 3. Operator surface

Per-pipeline table in the existing `ptflow.toml` (sparse):

```toml
[steps.external]
dast = false
nuclei_scope = false
```

One-off from the CLI (the debug ergonomics that motivated integrating into `runconfig`):

```bash
uv run ptflow run external act scope.txt --set steps.external.dast=off --set steps.external.nuclei_scope=off
```

- Values coerce with the existing bool rule (`_TRUE = {1, on, true, yes}` → on; anything else → off).
- Keys are `steps.<pipeline>.<step_name>` in both the file (`[steps.external]` flattens to
  `steps.external.<name>`) and `--set`, so one config file can hold toggles for multiple pipelines and the
  mental model is uniform. Only the table matching the pipeline being run is consulted.
- Sparse: an unlisted step is ON. `dast = true` is an explicit no-op; `dast = false` disables.

## 4. Filtering mechanics & safety (why it needs no `needs` rewrite)

Disabling a step = **filtering it out of the stage list** before orchestration. This is already safe:

- `topo_order` resolves deps with `if dep in by_name` (orchestrator.py) — a missing dependency name is
  simply skipped.
- `_submit_dag` wires `wait_for` with `[futs[n] for n in stage.needs if n in futs]` — a missing dep is
  skipped, no `KeyError`.
- Stages communicate only via on-disk artifacts and read them tolerantly (`read_lines`/`read_jsonl` → `[]`).

So a downstream consumer of a disabled step still runs; it just finds empty/absent inputs and degrades. This
is exactly the mechanism `webscan` already relies on ("dropped stages' artifacts are simply absent; external's
tolerant reads degrade the depth loops cleanly").

**Dependency-impact warning (debug aid):** at run start (and in `ptflow steps`), if a disabled step is named
in any surviving step's `needs` (transitively), emit a WARNING listing the impacted dependents (e.g. disabling
`crawl` → `crawl_headless, takeover, request_catalog, …` run with absent inputs). Non-blocking — it is the
operator's debug choice; we surface it, we don't prevent it.

## 5. Plumbing

**`core/runconfig.py`** — step toggles are NOT a `Knob` (no `PTFLOW_*` env, not read at import). Add:
- Recognition of the dynamic `steps.` prefix in `resolve()` so `steps.*` keys are not warned as unknown
  (mirrors the existing `_ROLES_PREFIX` handling).
- A pure resolver `resolve_disabled_steps(config, sets, pipeline, stage_names) -> frozenset[str]`:
  - flattens the file config + parses `--set` (reuse `_flatten`/`_parse_overrides`);
  - selects keys under `steps.<pipeline>.`, coerces the value as bool, collects the names whose value is
    off (disabled);
  - **validates** each named step against `stage_names`; an unknown name raises `ConfigError` (exit 2) with
    a message listing the valid names. Precedence `--set` > file (an override wins over the file entry).
  - Pure/unit-testable (config, sets, stage_names all passed in).
- `snapshot()` additionally records the disabled steps (e.g. `steps.external.dast = "off"` lines) for
  reproducibility (re-feedable with `--config`).

**`core/orchestrator.py`** — `orchestrate(...)` gains `disabled_steps: frozenset[str] = frozenset()`. At the
top it computes `effective = [s for s in pipeline.stages if s.name not in disabled_steps]` and uses
`effective` everywhere it currently reads `pipeline.stages` (activity / spanning / cluster_scope selection and
the `_run_loops(...)` call). `_run_stage` re-derives a stage by name only for stages that were submitted, so
disabled stages are never looked up — no change needed there. Emits the dependency-impact WARNING (§4).

**`cli.py`** — in `_run`: after `runconfig.resolve/apply` and `load_pipeline`, resolve the disabled set with
the pipeline's `stage_names` and pass it to `orchestrate(...)`. The `ConfigError` path already maps to exit 2.
Add the `steps` subcommand (§6). Followup runs (`internal → webscan`) pass their own resolved disabled set for
their pipeline (same helper; a followup's steps live under its own `[steps.<pipeline>]`).

## 6. `ptflow steps` subcommand (visualization)

`ptflow steps <pipeline> [--config PATH] [--set KEY=VALUE ...] [-v]`:
- Loads the pipeline, resolves the disabled set (same helper as the run path, so the view matches a run
  exactly), and prints every step grouped by **band**, in DAG order, with `●` (active) / `○` (disabled):

```
external — 34 step (2 disabilitati)

breadth        ● provision_wl   ● expand   ● resolve   ● portscan   ● httpx
spanning       ○ nuclei_scope   ● portscan_full   ● nerva
post-cluster   ● screenshot
loop 1         ● passive_probe  ● crawl  ● crawl_headless  ● subenum  ● takeover  …
loop 2         ○ dast   ● xss   ● sqli   ● cve_lookup
loop 3         ● wordlist  ● tech_enum  ● content_discovery  ● recrawl  ● cloud_assets
loop 4         ● request_catalog_full  ● param_fuzz  ● dast_full  …

○ = disabilitato   ● = attivo
⚠ dast è off → i suoi consumer restano attivi ma leggeranno input vuoti.
```

- Band derivation reuses the same classification as `_stage_tags` (breadth / spanning / post-cluster /
  `loop:<phase>`); consider extracting a small shared `stage_band(stage) -> str` pure helper so the CLI view
  and the Prefect tags cannot diverge.
- `-v` adds columns `phase` / `per_app` / `net` / `needs` per step; default view stays compact.
- Reads `stages` live → always current, no generated file, no gate. Exit 0.

## 7. Error handling

- Unknown step name (file or `--set`) → `ConfigError`, message lists valid step names for that pipeline,
  CLI exits 2 (the existing config-error path).
- `steps.` with no pipeline segment, or a pipeline segment that isn't the one being run: keys for other
  pipelines are ignored for the run (they belong to a different `[steps.<other>]`); a malformed
  `steps.<name>` (missing pipeline) is treated as unknown → warned by the existing unknown-key path (it
  won't match `steps.<pipeline>.`). The `steps` command validates only against the requested pipeline.
- Disabling every step / disabling breadth steps that feed `cluster` (e.g. `httpx`) is allowed (debug), and
  results in an empty per-app fan-out; the dependency-impact warning covers it. Not special-cased.

## 8. Testing

- **Resolver (pure):** precedence `--set` > file; sparse defaults (unlisted → not disabled); bool coercion;
  unknown-name → `ConfigError`; correct disabled `frozenset`; multi-pipeline file (only the run's table
  consulted).
- **Orchestrator:** a disabled stage is not submitted; its dependents still run (no `KeyError`); `effective`
  filtering applied to activity/spanning/cluster_scope/loops. Exercised on the `example` pipeline (the CI
  pipeline).
- **`steps` command:** parametrized over `PIPELINE_NAMES` (like the flow-map gate) — the output lists every
  `Stage` of each pipeline; disabled steps render as `○`; deterministic output.
- **Snapshot:** disabled steps appear in `<activity>/config.toml`.
- No new anti-drift gate: sync is structural (view + validation both read `stages` live).

## 9. Docs

- `CLAUDE.md`: extend the "Run config" section with the `[steps.<pipeline>]` table + `--set steps.…`
  precedence, and document the `ptflow steps` subcommand under "Commands". Note it is debug-oriented and that
  disabling a mid-DAG step degrades (does not break) its dependents.
- `ptflow.toml.example`: add a commented `[steps.external]` block with a couple of examples.

## 10. Rejected alternatives

- **Dedicated separate steps file + new flag** — rejected: a second file + flag, and no free `--set` one-off
  (the debug ergonomics that motivated integrating into `runconfig`).
- **Materialized file listing every step (option B in brainstorming)** — rejected by the operator in favor of
  sparse (A): more drift-resistant (new steps enter ON automatically; nothing to regenerate).
- **Checked-in generated reference file + gate** — unnecessary once the `steps` command reads `stages` live;
  a file could drift, the command cannot.
- **Rewriting downstream `needs` on disable** — unnecessary; `topo_order`/`_submit_dag` already tolerate
  missing deps and reads are tolerant.
- **Making toggles a `Knob` (`PTFLOW_*`)** — wrong layer: they filter stages at run time, not feed an
  import-time constant.
