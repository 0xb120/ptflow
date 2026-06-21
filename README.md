# pipt — Prefect scaffolding for automated pentest pipelines

Reusable framework (`core/`) hosting pluggable `pipelines/<name>/`. **Files on disk
are the only state — no database.** Orchestration is **phased-hybrid**: an
asset-discovery (breadth) phase runs once over the whole scope, the results are
clustered into "application groups", then per-group enumeration (depth) fans out
under Prefect, and a terminal agent stage proposes hypotheses.

## Setup

```bash
uv sync --all-groups
```

## Run

```bash
uv run pipt run example <activity-name> ./scope.txt --root /path/to/parent
# output goes under  <parent>/<activity-name>/   (--root defaults to the cwd)
```

## Workspace layout

```
<activity>/
  scope.txt
  scope/        scope_init.txt  scope_urls.txt  scope_dns.txt  scope_ip.txt
  scans/
    asset_discovery/   hosts.jsonl              raw/<tool>/
    <app_hash>/        meta.json  hosts.txt  services.jsonl   raw/<tool>/
  findings/     hypotheses.jsonl          # agent output (global)
  poc/   tmp/   wl/   logs/
```

- `raw/<tool>/` holds raw tool dumps; consolidated outputs use fixed canonical
  names (`scope/scope_dns.txt`, `scans/asset_discovery/hosts.jsonl`,
  `scans/<app_hash>/services.jsonl`, …) that downstream stages read directly.
- `scans/<app_hash>/` = one clustered group of "equal applications".

## Code layout

- `src/pipt/core/` — config, paths, workspace (meta), tools, scope, stage, agent, orchestrator.
- `src/pipt/pipelines/<name>/` — `pipeline.py` (declares Stages + `cluster` + `provider`), `tasks.py`.

## Adding a pipeline

1. Create `src/pipt/pipelines/<name>/` with a `PIPELINE` object (see `example/`).
2. Declare stages with `Mode.BREADTH` (asset discovery) / `Mode.DEPTH` (per-group enum).
3. Implement `cluster(activity) -> list[app_id]` (groups discovery output into `scans/<hash>/`).
4. Provide a `HypothesisProvider` via `provider()`.
5. Register it in `pipelines/__init__.py::load_pipeline`.

## Global rate governor (optional, needs a Prefect server)

Every network task is tagged `net`. Cap activity-wide traffic with:

```bash
uv run prefect concurrency-limit create net 10
```

## Dev

```bash
uv run ruff check . && uv run ty check src/ && uv run pytest
```

## Testing scope

You can use the targets below for testing purposes:

```
https://ginandjuice.shop/
scanme.nmap.org
```
