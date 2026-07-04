# Design — Cross-group endpoint routing (external, phase 4)

- **Date:** 2026-07-04
- **Status:** Approved (design); pending implementation plan
- **Scope:** external pipeline. Intra-run, in-scope-only routing at the phase-4 full catalog.

## 1. Motivation

When the external pipeline crawls one application group (say `attack.com`), its frontend often references
API endpoints on a **different in-scope host** (say `api.company.com/v1/...`). katana (`-jsl`/`-jc`/`-xhr`)
and jsluice **do capture** those cross-domain endpoints — they land in the discovering group's
`endpoints*.txt` / `requests_crawl.jsonl` with method/body. But `_assemble_catalog` filters the catalog to
`in_scope = {url_host(h) for h in read_lines(ws.hosts)}` — the **discovering group's own hosts only** — so
`catalog_records` **drops** every cross-domain endpoint. Meanwhile `api.company.com`, clustered as its own
group (different apex → precision-first no-merge, correct), crawls itself and finds nothing (an API backend
has no linked HTML surface). Net effect: the real attack surface of `api.company.com` — discoverable *only*
from `attack.com`'s JS — is captured, then discarded, and never tested.

This is confirmed in code: the endpoints exist in the discovering group's discovery artifacts *before*
`catalog_records`'s per-group in-scope filter (`tasks.py`, `_assemble_catalog` / `catalog_records`).

**Case handled:** both hosts are in the **same run's scope** (the operator listed both; `api.company.com`
is already its own in-scope app group). This is pure intra-run **routing** — no scope expansion, no RoE
decision. Cross-run propagation and out-of-scope hosts are explicitly out of scope (see Roadmap).

## 2. Goals / Non-goals

**Goals:**
- Endpoints/requests discovered while crawling group A that belong to another in-scope group B are
  **routed into B's phase-4 catalog** (`requests_full.jsonl`), so B's phase-4 scanners
  (`dast_full`/`param_fuzz`/`xss_full`/`sqli_full`) test them, **attributed to B** (via `consolidate`'s
  `app_id` stamping).
- RoE-safe by construction: only endpoints whose host is owned by an existing (in-scope) group are routed;
  an endpoint to a host that is not any group's host stays dropped, exactly as today.

**Non-goals (Roadmap):**
- Phase-2 (fast surface) coverage of cross-group endpoints (would need an activity-level pool at the
  phase-1→2 barrier — "Approach 3").
- Re-crawling routed endpoints from the owning group (expansion + body download).
- Scope expansion for an in-scope host that never became a group (e.g. an API backend httpx didn't mark
  live at root) — its endpoints are dropped for now.
- Cross-run persistence (separate `ptflow run` invocations).

## 3. Design

### 3.1 `_cross_group_surface(activity, ws)` — new helper

```python
def _cross_group_surface(activity: Activity, ws: AppWorkspace) -> list[dict]:
```
Returns **request records** discovered in **other** groups whose host belongs to `ws` (group B). It
returns a single `list[dict]` — NOT a `(records, urls)` tuple — so provenance survives uniformly:
harvested bare endpoints are converted to GET records here (via `_url_to_get_request`), rather than
returned as bare strings that would lose their origin when merged into the flat `get_urls` list.

- `mine = {url_host(h) for h in tools.read_lines(ws.hosts)}` — the hosts owned by `ws`.
- For each `other in activity.list_apps()` with `other.root.name != ws.root.name`:
  - **Request records** from `other.canonical("requests_crawl.jsonl")`, `requests_headless.jsonl`,
    `requests_api.jsonl` whose `url_host(rec["url"]) in mine` — each with `"xref:<other.root.name>"`
    appended to its `sources` list (provenance).
  - **Bare endpoints** from `other.canonical("endpoints.txt")`, `endpoints_js.txt`,
    `endpoints_headless.txt` whose `url_host(u) in mine` → converted to GET records via
    `_url_to_get_request(u, f"xref:{other.root.name}")`.
- Pure-ish (reads disk only, no network); order preserved; dedup happens later in `merge_requests`.

Rationale for reading the **derived** discovery files (not re-mining another group's raw corpus): the
cross-domain endpoints are already extracted into `endpoints*.txt` (jsluice via `mine_responses`) and
`requests_crawl.jsonl` (katana request shapes). Harvesting the derived files is sufficient and avoids
re-mining another group's `raw/extracted/` corpus.

### 3.2 `_assemble_catalog(activity, ws, *, include_guessed)` — signature extended

- Add the `activity` parameter (both call sites already have it).
- **Only when `include_guessed=True`** (the phase-4 full catalog): append `_cross_group_surface(activity,
  ws)` (a `list[dict]`) to `request_recs` **before** the existing `catalog_records(...)` call. `get_urls`
  is unchanged (B's own).
- The existing `in_scope = {url_host(h) for h in read_lines(ws.hosts)}` filter is **unchanged** — it now
  *keeps* the routed records (their host is in `ws`'s hosts) and drops anything else. `merge_requests`
  dedups routed records against B's own by request shape.
- Phase-1 surface catalog (`include_guessed=False`) is **unchanged** — no cross-group harvest (other
  groups' phase-1 crawl is concurrent and not reliably present).

### 3.3 Call sites
- `request_catalog(activity, app_id)` → `_assemble_catalog(activity, ws, include_guessed=False)`.
- `request_catalog_full(activity, app_id)` → `_assemble_catalog(activity, ws, include_guessed=True)`.

## 4. Invariants / correctness

- **RoE:** routing is bounded to `{ws.hosts}` (hosts of an existing in-scope group). An endpoint to a host
  that is no group's host matches no `ws` and is never routed → dropped, as today. No scope expansion.
- **Timing:** `request_catalog_full` is phase 4; the phase-1 and phase-3 barriers guarantee every group's
  crawl/discovery artifacts are on disk. So `_cross_group_surface` reads complete, settled files (no race).
- **Attribution:** routed endpoints enter B's `requests_full.jsonl` → B's phase-4 scanners test them →
  `consolidate` stamps `app_id = B`. Correct home + correct attribution.
- **Dead-drop:** `dead_url_keys` uses B's own `-srd` index statuses; a routed endpoint has no status in B's
  index → treated as unknown → **kept** (the drop only removes paths seen *only* as 404/410). Correct — B
  has not probed them yet.
- **Scheme:** `catalog_records` re-schemes `url` via `_working_schemes(ws)` (B's map, which covers B's
  hosts) — routed URLs for B's hosts are schemed consistently with B's other requests.
- **Write-once / additive:** no new files; `requests_full.jsonl` is B's existing artifact, now assembled
  from a superset of inputs. Nothing mutated or deleted.

## 5. Edge cases
- **In-scope host with no group** (API backend not clustered as a live webapp): its endpoints are dropped
  (no owning `ws` matches). Documented limitation; Roadmap covers scope-expansion.
- **Same endpoint discovered by multiple groups + B itself:** `merge_requests` dedups by request shape
  (`request_key`), unioning `params`/`sources` — no duplication; provenance accumulates.
- **Large scope (many groups):** `_cross_group_surface` is O(groups) file reads per group → O(groups²)
  total at phase 4. Discovery files are small; acceptable. A cap is not added now (noted if it ever bites).

## 6. Testing

Pure/injectable, no network:
- `_cross_group_surface`: group A's `endpoints.txt`/`requests_crawl.jsonl` reference B's host → harvest
  returns exactly those; an endpoint to a host owned by no group → not returned; B's own artifacts are
  not double-harvested (only `other != ws`); provenance tag present.
- `_assemble_catalog`: with `include_guessed=True`, B's catalog includes the routed endpoint; with
  `include_guessed=False` (phase 1) it does not.
- Regression: existing `request_catalog`/`request_catalog_full` behavior for a single-group activity is
  unchanged (no other groups → `_cross_group_surface` returns empty).

## 7. Roadmap (deferred; record in the `recon-backlog` memory)
- Phase-2 coverage via an activity-level discovered-surface pool at the phase-1→2 barrier (Approach 3).
- Re-crawl routed endpoints from the owning group (expansion).
- Scope-expansion / group creation for an in-scope host that never clustered as a webapp.
- Cross-run persistence of discovered surface.

## 8. Open questions
None — approach (phase-4 routing), the no-group-host decision (drop for now), and the `xref` provenance
tag are all resolved.
