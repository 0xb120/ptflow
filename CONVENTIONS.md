# CONVENTIONS — pipt output & workspace contract

Inherits the toolkit contract (see /opt/custom-tools/CONVENTIONS.md) and extends it
with the SQLite layer. Rules for every new pipeline:

1. **Paths are a contract.** Only via `Engagement` / `TargetWorkspace`. No literals.
2. **No step reads from `raw/`.** Tools write `raw/<tool>/`; a normalize step promotes
   to a canonical JSONL artifact and appends a `manifest.jsonl` row (role → path).
3. **Raw on disk is the source of truth.** SQLite is a rebuildable projection
   (`pipt ingest`). Fan-out workers NEVER write the DB — only the serialized ingest does.
4. **Stable ids.** `target_id = "t_" + sha1(normalized)[:6]`. Never key on a mutable string.
5. **Declarative stages.** Each stage declares `Mode.BREADTH` (one invocation over all
   targets, barrier) or `Mode.DEPTH` (per-target fan-out).
6. **DB = core + extension.** Core tables in `db/schema.sql`; domain tables in
   `pipelines/<name>/schema.sql`. Keep `hypothesis` core-clean (FK only to `service`).

## Checklist for a new pipeline

- [ ] Reads/writes only via `Engagement`/`TargetWorkspace`.
- [ ] Tools write `raw/<tool>/`, promote to canonical JSONL, append a manifest row.
- [ ] Stages declared with the right `Mode`.
- [ ] Domain tables in the pipeline's `schema.sql`; role→table handlers in `ingest_handlers()`.
- [ ] Registered in `load_pipeline`.
- [ ] Network tasks tagged `net`.
