# Design — Cross-group endpoint coverage in phase 2 (external + webscan)

- **Date:** 2026-07-05
- **Status:** Approved (design); pending implementation plan
- **Scope:** external + webscan pipelines. Intra-run, in-scope-only routing extended from phase 4 to
  phase 2 (the fast DAST-the-surface pass).

## 1. Motivation

The 2026-07-04 cross-group routing (`_cross_group_surface`) routes endpoints discovered while crawling
group A that belong to another in-scope group B into **B's phase-4 full catalog** (`requests_full.jsonl`),
so B's phase-4 scanners test them. But phase 2 — the fast "DAST the explorable surface / low-hanging
fruit" pass (`dast`/`xss`/`sqli` over `requests.jsonl`) — has **no cross-group data**: the routed surface
only reaches B in phase 4. So a real, immediately-DASTable cross-group endpoint (an API route referenced
from A's JS, living on B's host) is not tested until the heavy phase-4 pass — losing the fast, high-signal
finding on the true attack surface that phase 2 exists to produce.

The prior spec deferred this as "Approach 3: an activity-level discovered-surface pool at the phase-1→2
barrier." **That framing was heavier than necessary.** The per-app loop barriers are *between* loops:
`_run_loops` awaits **every** phase-1 future across **all** groups before submitting any phase-2 stage.
So at the start of phase 2, every group's phase-1 discovery artifacts are complete and settled — and a
**per-app phase-2 stage can read any other group's phase-1 output race-free**, exactly as
`request_catalog_full` (phase 4) already reads peers. No orchestrator/`core` change is needed; the feature
is a new per-app stage, symmetric to the existing phase-4 fold.

## 2. Goals / Non-goals

**Goals:**
- Endpoints/requests discovered in group A that belong to another in-scope group B are **routed into B's
  phase-2 surface set**, so B's phase-2 scanners (`dast`/`xss`/`sqli`) test them, attributed to B (via
  `consolidate`'s `app_id` stamping).
- No cross-group surface is **double-tested** across the two passes: phase 4 stops re-DASTing what phase 2
  now covers, while `param_fuzz` keeps probing the cross-group endpoints for hidden params (a distinct
  analysis — no regression).
- Zero `core/` changes — a per-app `Stage`, so `--resume`, per-step toggles, and the flow map come for free.
- RoE-safe by construction (inherits `_cross_group_surface`'s `host ∈ ws.hosts` filter).

**Non-goals (Roadmap, unchanged from the prior spec):**
- Re-crawling routed endpoints from the owning group (expansion + body download).
- Scope expansion for an in-scope host that never became a group.
- Cross-run persistence (separate `ptflow run` invocations).

## 3. Design

### 3.1 `_finalize_catalog(ws, request_recs, get_urls) -> (list[dict], int)` — extracted helper

Extract the **tail** of `_assemble_catalog` (everything after the input assembly) into a shared helper so
the new stage reuses the exact scheme-normalize + in-scope filter + dead-drop logic instead of duplicating
it:

```python
def _finalize_catalog(ws: AppWorkspace, request_recs: list[dict], get_urls: list[str]) -> tuple[list[dict], int]:
    in_scope = {url_host(h) for h in tools.read_lines(ws.hosts)}
    schemes = _working_schemes(ws)
    catalog = catalog_records(request_recs, get_urls, in_scope, schemes)
    dead = dead_url_keys(ln for idx in _all_store_indices(ws) for ln in tools.read_lines(idx))
    kept = [r for r in catalog
            if not (r.get("method", "GET").upper() == "GET" and not r.get("body")
                    and _url_pathkey(r.get("url") or "") in dead)]
    return kept, len(catalog) - len(kept)
```

`_assemble_catalog` keeps its corpus-mining (jsluice/forms) and `include_guessed` input assembly, then
calls `_finalize_catalog` and returns `(kept, n_mined, n_dropped)` as before. **No behavior change** to
`_assemble_catalog` — pure extraction.

### 3.2 `xref_catalog(activity, app_id)` — new per-app phase-2 task

```python
def xref_catalog(activity: Activity, app_id: str) -> None:
    """PHASE 2 (head) — assemble the CROSS-GROUP surface catalog (requests_xref.jsonl): requests/endpoints
    discovered in OTHER in-scope groups whose host belongs to THIS group, so phase-2 dast/xss/sqli test the
    cross-group surface on the fast pass, not only phase 4. Safe: the 1→2 barrier guarantees every group
    finished phase 1, so reading peers' discovery artifacts is race-free. Offline (net=False)."""
    ws = activity.app(app_id)
    records = _cross_group_surface(activity, ws)
    catalog, n_dead = _finalize_catalog(ws, records, [])
    n = tools.write_jsonl(ws.canonical("requests_xref.jsonl"), catalog)
    log.info("  → xref_catalog (%s) — %d cross-group request shape(s) (dropped %d dead/404)"
             " → requests_xref.jsonl", app_id, n, n_dead)
```

- Writes `scans/<app_id>/requests_xref.jsonl` (new canonical per-app file, one writer — write-once holds).
- Single-group activity → `_cross_group_surface` returns `[]` → an empty file is written (a legible resume
  marker; tolerant reads make it a no-op downstream).

### 3.3 Phase-2 consumers — `_surface_request_set` reads both files

```python
def _surface_request_set(ws: AppWorkspace, *, cap: int) -> list[dict]:
    catalog = [*tools.read_jsonl(ws.canonical("requests.jsonl")),
               *tools.read_jsonl(ws.canonical("requests_xref.jsonl"))]
    return dast_requests(catalog, [], cap=cap)
```

`dast_requests` already runs `merge_requests`, so a cross-group shape that coincides with one of B's own is
deduped by `request_key` (params/sources unioned). All three phase-2 stages (`dast`/`xss`/`sqli`) read
through this one function → they all gain coverage from a single change.

### 3.4 Phase-4 delta — subtract the xref keys (no double-test)

```python
def _delta_request_set(ws: AppWorkspace, *, cap: int) -> list[dict]:
    surface_keys = {request_key(r) for r in tools.read_jsonl(ws.canonical("requests.jsonl"))}
    surface_keys |= {request_key(r) for r in tools.read_jsonl(ws.canonical("requests_xref.jsonl"))}
    delta = [r for r in tools.read_jsonl(ws.canonical("requests_full.jsonl"))
             if request_key(r) not in surface_keys]
    return dast_requests(delta, tools.read_jsonl(ws.canonical("params.jsonl")), cap=cap)
```

`dast_full`/`xss_full`/`sqli_full` now skip the cross-group surface phase 2 covered. **`request_catalog_full`
is unchanged** — it still folds `_cross_group_surface` into `requests_full.jsonl`, so `param_fuzz` (which
reads `requests_full.jsonl` directly, not the delta) keeps probing cross-group endpoints for hidden params.

### 3.5 Wiring

- `external/pipeline.py`:
  - Add `Stage("xref_catalog", tasks.xref_catalog, per_app=True, phase=2, net=False)`.
  - `dast`, `xss`, `sqli` gain `needs=("xref_catalog",)` (avoids the intra-group phase-2 race — within a
    loop, ordering is by `needs`). `cve_lookup` and `ai_wordlist` are unchanged (they don't read the
    request catalog).
- `external/flowmeta.py`: add a `StepMeta` for `xref_catalog`.
- `webscan/pipeline.py`: add `Stage("xref_catalog", external.xref_catalog, per_app=True, phase=2, net=False)`
  and the same `needs=("xref_catalog",)` on its `dast`/`xss`/`sqli`. Its flow map reuses external's
  `FLOWMETA`, so the `StepMeta` is inherited — no webscan flowmeta change.

## 4. Data flow

```
phase 1 (all groups): crawl / crawl_headless / api_spec / mine_responses → endpoints*.txt,
                       requests_crawl|headless|api.jsonl, request_catalog → requests.jsonl
      ‖ global barrier 1 → 2  (every group finished phase 1)
phase 2, per group B: xref_catalog → requests_xref.jsonl  (peers' surface with host ∈ B, tagged xref:<A>)
                      dast / xss / sqli  read  requests.jsonl ∪ requests_xref.jsonl
      ‖ barrier 2 → 3 → 4
phase 4, per group B: request_catalog_full → requests_full.jsonl (still folds cross-group, for param_fuzz)
                      dast_full / xss_full / sqli_full  test  requests_full.jsonl − (requests.jsonl ∪ requests_xref.jsonl)
                      param_fuzz  probes  requests_full.jsonl (incl. cross-group) for hidden params
```

## 5. Invariants / correctness

- **Timing / no race:** `xref_catalog` is phase 2; the 1→2 barrier (`_run_loops` awaits all phase-1 futures
  before submitting phase 2) guarantees every group's phase-1 discovery files are complete on disk. Same
  guarantee `request_catalog_full` relies on at phase 4, one barrier later.
- **Intra-group ordering:** `dast`/`xss`/`sqli` `needs=("xref_catalog",)`, so `requests_xref.jsonl` is
  written before they read it (within B's phase-2 DAG).
- **Scheme at phase 2:** `_working_schemes(ws)` reads `content_discovery.jsonl` (phase 3), absent at phase
  2 → falls back to the `hosts.txt` scheme. This is identical to what `request_catalog` does at phase 1
  (content_discovery also absent then). Consistent, verified against the code.
- **Dead-drop:** `_finalize_catalog` uses B's own `-srd` index statuses; a routed endpoint B never fetched
  has unknown status → **kept** (drop removes only paths seen *only* as 404/410). Correct.
- **RoE:** routing is bounded to `{ws.hosts}` (hosts of an existing in-scope group). An endpoint to a host
  that is no group's host matches no `ws` → dropped, as today. No scope expansion.
- **Attribution:** routed endpoints enter B's `requests_xref.jsonl` → B's phase-2 scanners test them →
  `consolidate` stamps `app_id = B`.
- **Write-once / additive:** `requests_xref.jsonl` is a new file with one writer; `requests.jsonl` and
  `requests_full.jsonl` are untouched. With AI off / single group the DAG's *behavior* on existing files is
  unchanged (the new stage writes an empty sidecar; `_surface_request_set` tolerant-reads it → same set).

## 6. Edge cases

- **Single-group activity:** `_cross_group_surface` → `[]` → empty `requests_xref.jsonl`; `_surface_request_set`
  and `_delta_request_set` behave exactly as before.
- **Same endpoint discovered by multiple groups + B itself:** `merge_requests` dedups by `request_key`,
  unioning `params`/`sources` — no duplication; provenance (`xref:<A>`, `xref:<C>`) accumulates.
- **Large scope (many groups):** `xref_catalog` is O(groups) reads per group → O(groups²) total across the
  phase-2 fan-out (parallelized). Discovery files are small; same order as the existing phase-4 fold. No cap
  added now (noted if it ever bites).
- **`xref_catalog` failure:** isolated by the orchestrator's `_await` (logged + counted, never aborts);
  `requests_xref.jsonl` absent → tolerant reads → phase 2 degrades to `requests.jsonl` only.

## 7. Testing (TDD)

Pure/injectable, no network:
- `_finalize_catalog`: records + get_urls on a tmp `ws` → scheme-normalized, in-scope-filtered, dead-dropped
  catalog; a GET path seen only as 404 in the `-srd` index is dropped, a POST/body shape is kept.
- `_surface_request_set`: with both `requests.jsonl` and `requests_xref.jsonl` present, the set is their
  merge; a shape present in both collapses to one (params/sources unioned).
- `_delta_request_set`: a shape present in `requests_xref.jsonl` is **excluded** from the phase-4 delta; a
  genuinely new full-catalog shape is included.
- `xref_catalog`: two app workspaces on disk — group A's `endpoints.txt`/`requests_crawl.jsonl` reference
  B's host → B's `requests_xref.jsonl` contains exactly those, tagged `xref:<A>`; B's own artifacts are not
  double-harvested; a single-group activity yields an empty file.
- Regression: `_assemble_catalog` output unchanged after the `_finalize_catalog` extraction (existing tests
  cover this).
- Flow-map gate (`tests/pipelines/test_flowmap.py`, parametrized over external + webscan) auto-covers the
  `StepMeta` presence for `xref_catalog` in both pipelines.

## 8. Roadmap (deferred; already recorded in the `recon-backlog` memory)

- Re-crawl routed endpoints from the owning group (expansion).
- Scope-expansion / group creation for an in-scope host that never clustered as a webapp.
- Cross-run persistence of discovered surface.

## 9. Open questions

None — approach A (per-app phase-2 stage), the sidecar file (`requests_xref.jsonl`, write-once), the
phase-4 double-test avoidance (subtract xref keys from the delta, keep folding for `param_fuzz`), and
including webscan are all resolved.
