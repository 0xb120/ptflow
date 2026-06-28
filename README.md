# pipt — Prefect scaffolding for automated pentest pipelines

A reusable framework (`core/`) hosting pluggable `pipelines/<name>/`. **Files on
disk are the only state — no database.** A breadth asset-discovery phase feeds a
clustering step that fans out into per-app depth loops. The recon pipeline runs
those loops **surface-first, DAST-first**: map the explorable surface (OSINT/crawl)
and DAST *that* for low-hanging fruit, then guess/fuzz, then DAST the guessed surface
— each phase separated by a global barrier.

## Quickstart

```bash
uv sync --all-groups
uv run pipt run example <activity-name> ./scope.txt --root /path/to/parent
# output goes under  <parent>/<activity-name>/   (--root defaults to the cwd)

uv run ruff check . && uv run ty check src/ && uv run pytest   # dev gate
```

## Documentation

Architecture, the workspace contract, conventions, and project notes live in
**[CLAUDE.md](CLAUDE.md)** — the single source of truth.

## Authorized test scope

```
https://ginandjuice.shop/   # PortSwigger demo
scanme.nmap.org             # Nmap-sanctioned
```
