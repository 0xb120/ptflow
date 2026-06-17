# pipt — Prefect scaffolding for automated pentest pipelines

Reusable framework (`core/`) hosting pluggable `pipelines/<name>/`. Raw files on
disk are the source of truth; a light SQLite DB is a rebuildable projection
populated by a **serialized** ingest. Orchestration is **phased-hybrid**: breadth
stages run once over the whole scope (barrier), then depth stages fan out per
target under Prefect.

## Setup

```bash
uv sync --all-groups
```

## Run

```bash
uv run pipt run example demo ./scope.txt --root ./scans      # multi/single target
uv run pipt run example demo ./scope.txt --no-aggregate      # enumerate overlaps per target
uv run pipt ingest demo --root ./scans                       # rebuild DB from raw
```

## Layout

- `db/schema.sql` — core light schema: `target`, `host`, `service`, `host_target`, `hypothesis`.
- `src/pipt/core/` — config, paths, workspace, tools, db, ingest, stage, agent, orchestrator.
- `src/pipt/pipelines/<name>/` — `pipeline.py` (declares Stages), `tasks.py`, `schema.sql` (extension), optional `ingest.py`.

## Adding a pipeline

1. Create `src/pipt/pipelines/<name>/` with a `PIPELINE` object (see `example/`).
2. Declare stages with `Mode.BREADTH` / `Mode.DEPTH`.
3. Add domain tables in `schema.sql` and role→table handlers in `ingest_handlers()`.
4. Register it in `pipelines/__init__.py::load_pipeline`.

## Global rate governor (optional, needs a Prefect server)

Every network task is tagged `net`. Cap engagement-wide traffic with:

```bash
uv run prefect concurrency-limit create net 10
```

## Dev

```bash
uv run ruff check . && uv run ty check src/ && uv run pytest
```
