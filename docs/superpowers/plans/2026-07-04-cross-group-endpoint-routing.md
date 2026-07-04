# Cross-group Endpoint Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route endpoints/requests discovered while crawling one external app group into the phase-4 catalog of the *other* in-scope group that actually owns those hosts, so an API backend's surface (only discoverable from another group's frontend JS) gets tested and attributed correctly.

**Architecture:** A new pure-ish helper `_cross_group_surface(activity, ws)` harvests, from every *other* app group's derived discovery artifacts, the request records / endpoints whose host belongs to `ws`, tagged `xref:<origin>`. `_assemble_catalog` gains an `activity` parameter and, **only in the phase-4 full-catalog path** (`include_guessed=True`), appends that harvest to `request_recs` before the existing per-group in-scope `catalog_records` filter (which then keeps them, since their host is in `ws`'s hosts).

**Tech Stack:** Python 3.11, `uv`, `ruff` (select ALL), `ty`, `pytest`. External pipeline (`src/ptflow/pipelines/external/tasks.py`).

## Global Constraints

- **Routing happens ONLY at phase 4** (`_assemble_catalog(..., include_guessed=True)`, called by `request_catalog_full`). The phase-1 surface catalog (`request_catalog`, `include_guessed=False`) is **unchanged** — it must NOT harvest cross-group (other groups' phase-1 crawl is concurrent).
- **RoE-safe by construction:** only endpoints whose host is owned by an existing in-scope group (`ws`'s hosts) are routed. A host owned by NO group (third-party / not-clustered) is never routed — dropped exactly as today. No scope expansion.
- `_cross_group_surface(activity, ws) -> list[dict]` returns **request records** (bare endpoints converted to GET via `_url_to_get_request`), each with `"xref:<origin app_id>"` appended to `sources`. It reads only OTHER groups' derived discovery files (`requests_crawl.jsonl`, `requests_headless.jsonl`, `requests_api.jsonl`, `endpoints.txt`, `endpoints_js.txt`, `endpoints_headless.txt`) — no re-mining of raw corpora, no network.
- **Additive / write-once:** no new artifacts; `requests_full.jsonl` is B's existing file, now assembled from a superset of inputs. Nothing mutated or deleted.
- `url_host(url)` strips scheme, path, AND port — the `mine` host-set and all comparisons use it (consistent with the existing `in_scope` set).
- Repo gate: `uv run ruff check .` (select ALL) && `uv run ty check src/` && `uv run pytest` — all pass. Do NOT add a `# noqa` unless a rule actually fires (unused → RUF100).
- **Do all work on a `feat/xref-routing` branch** (branch before the first commit — the repo default branch is `main`).

---

### Task 1: `_cross_group_surface` helper

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (add the helper + two module constants immediately BEFORE `_assemble_catalog`, which is at ~line 3733)
- Test: `tests/pipelines/test_external_tasks.py` (add tests)

**Interfaces:**
- Consumes (all already in `tasks.py`): `url_host(url) -> str`; `_url_to_get_request(url: str, source: str) -> dict`; `tools.read_lines`/`tools.read_jsonl`; `AppWorkspace.hosts`, `AppWorkspace.canonical(name)`, `AppWorkspace.root.name`; `Activity.list_apps() -> list[AppWorkspace]`.
- Produces: `_cross_group_surface(activity: Activity, ws: AppWorkspace) -> list[dict]` — request records owned by `ws` harvested from other groups, tagged `xref:<origin>`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/pipelines/test_external_tasks.py` (the top of the file already imports `tasks`, `tools`, and `Activity`; if `Activity` is not imported there, add `from ptflow.core.paths import Activity`):
```python
def test_cross_group_surface_routes_by_owning_host(tmp_path):
    act = Activity.named("xref1", root=tmp_path).ensure()
    a = act.app("attack.com-aaaa").ensure()
    b = act.app("api.company.com-bbbb").ensure()
    tools.write_lines(a.hosts, ["https://attack.com"])
    tools.write_lines(b.hosts, ["https://api.company.com"])
    # discovered under A: one endpoint on B's host, one on a host owned by no group
    tools.write_lines(a.canonical("endpoints_js.txt"),
                      ["https://api.company.com/v1/users", "https://third.example/x"])
    tools.write_jsonl(a.canonical("requests_crawl.jsonl"),
                      [{"method": "POST", "url": "https://api.company.com/v1/login",
                        "headers": {}, "body": "u=1", "params": [], "raw": "r", "sources": ["katana"]}])
    routed = tasks._cross_group_surface(act, b)
    urls = {r["url"] for r in routed}
    assert "https://api.company.com/v1/users" in urls   # endpoint routed into B
    assert "https://api.company.com/v1/login" in urls    # request routed into B
    assert "https://third.example/x" not in urls         # no group owns it → dropped (RoE)
    login = next(r for r in routed if r["url"].endswith("/login"))
    assert login["method"] == "POST"                     # request shape preserved
    assert any(s.startswith("xref:attack.com") for s in login["sources"])  # provenance tag


def test_cross_group_surface_excludes_own_group(tmp_path):
    act = Activity.named("xref2", root=tmp_path).ensure()
    b = act.app("b").ensure()
    tools.write_lines(b.hosts, ["https://api.company.com"])
    tools.write_lines(b.canonical("endpoints_js.txt"), ["https://api.company.com/self"])
    # only B exists; its own artifacts must not be harvested
    assert tasks._cross_group_surface(act, b) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /opt/ptflow && uv run pytest tests/pipelines/test_external_tasks.py -k cross_group_surface -v`
Expected: FAIL — `AttributeError: module ... has no attribute '_cross_group_surface'`.

- [ ] **Step 3: Add the helper**

In `src/ptflow/pipelines/external/tasks.py`, immediately BEFORE `def _assemble_catalog(...)`, add:
```python
# Cross-group endpoint routing: discovery artifacts (JS/XHR/crawl-derived) that can carry a reference to
# a DIFFERENT in-scope group's host — e.g. attack.com's frontend calling api.company.com's API.
_XREF_REQUEST_FILES = ("requests_crawl.jsonl", "requests_headless.jsonl", "requests_api.jsonl")
_XREF_ENDPOINT_FILES = ("endpoints.txt", "endpoints_js.txt", "endpoints_headless.txt")


def _cross_group_surface(activity: Activity, ws: AppWorkspace) -> list[dict]:
    """Request records discovered in OTHER app groups whose host belongs to `ws` — cross-group routing
    that carries an API host's surface (only discoverable from another group's frontend JS) into that
    host's OWN group. Returns request records (bare endpoints converted to GET via _url_to_get_request),
    each with `xref:<origin app_id>` appended to `sources`. Reads only other groups' DERIVED discovery
    artifacts (no re-mining, no network). RoE-safe: only hosts owned by `ws` are kept, so a host that is
    no group's host is never routed. Pure-ish (reads disk only)."""
    mine = {url_host(h) for h in tools.read_lines(ws.hosts)}
    if not mine:
        return []
    out: list[dict] = []
    for other in activity.list_apps():
        origin = other.root.name
        if origin == ws.root.name:
            continue
        tag = f"xref:{origin}"
        for fname in _XREF_REQUEST_FILES:
            for rec in tools.read_jsonl(other.canonical(fname)):
                if url_host(rec.get("url") or "") in mine:
                    out.append({**rec, "sources": [*(rec.get("sources") or []), tag]})
        for fname in _XREF_ENDPOINT_FILES:
            for u in tools.read_lines(other.canonical(fname)):
                if url_host(u) in mine:
                    out.append(_url_to_get_request(u, tag))
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /opt/ptflow && uv run pytest tests/pipelines/test_external_tasks.py -k cross_group_surface -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Lint & type-check**

Run: `cd /opt/ptflow && uv run ruff check src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py && uv run ty check src/`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
cd /opt/ptflow && git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(external): _cross_group_surface — harvest other groups' discovered endpoints by owning host"
```

---

### Task 2: Wire cross-group routing into the phase-4 catalog

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` — `_assemble_catalog` signature + body (~line 3733), and its two call sites `request_catalog` (~3791) and `request_catalog_full` (~3806)
- Test: `tests/pipelines/test_external_tasks.py` (add integration tests)

**Interfaces:**
- Consumes: `_cross_group_surface(activity, ws) -> list[dict]` (Task 1).
- Produces: `_assemble_catalog(activity: Activity, ws: AppWorkspace, *, include_guessed: bool) -> tuple[list[dict], int, int]` — now takes `activity` and, when `include_guessed=True`, folds cross-group routed records into the catalog.

- [ ] **Step 1: Write the failing integration tests**

Add to `tests/pipelines/test_external_tasks.py`:
```python
def test_request_catalog_full_routes_cross_group(tmp_path):
    act = Activity.named("xref3", root=tmp_path).ensure()
    a = act.app("attack.com-aaaa").ensure()
    b = act.app("api.company.com-bbbb").ensure()
    tools.write_lines(a.hosts, ["https://attack.com"])
    tools.write_lines(b.hosts, ["https://api.company.com"])
    tools.write_lines(a.canonical("endpoints_js.txt"), ["https://api.company.com/v1/users"])
    # phase-4 full catalog for B must include the endpoint discovered under A
    tasks.request_catalog_full(act, "api.company.com-bbbb")
    full = [r["url"] for r in tools.read_jsonl(b.canonical("requests_full.jsonl"))]
    assert any("api.company.com/v1/users" in u for u in full)
    # phase-1 surface catalog for B must NOT route cross-group
    tasks.request_catalog(act, "api.company.com-bbbb")
    surface = [r["url"] for r in tools.read_jsonl(b.canonical("requests.jsonl"))]
    assert not any("api.company.com/v1/users" in u for u in surface)


def test_request_catalog_full_single_group_unchanged(tmp_path):
    # a lone group has no other groups to harvest from → routing is a no-op
    act = Activity.named("xref4", root=tmp_path).ensure()
    b = act.app("only").ensure()
    tools.write_lines(b.hosts, ["https://api.company.com"])
    tools.write_lines(b.canonical("endpoints_js.txt"), ["https://api.company.com/own"])
    tasks.request_catalog_full(act, "only")
    full = [r["url"] for r in tools.read_jsonl(b.canonical("requests_full.jsonl"))]
    assert any("api.company.com/own" in u for u in full)   # its own endpoint still present
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /opt/ptflow && uv run pytest tests/pipelines/test_external_tasks.py -k "routes_cross_group or single_group_unchanged" -v`
Expected: FAIL — `test_request_catalog_full_routes_cross_group` fails its first assertion (B's full catalog does not yet contain A's cross-group endpoint).

- [ ] **Step 3: Extend `_assemble_catalog`'s signature and body**

In `src/ptflow/pipelines/external/tasks.py`, change the `_assemble_catalog` definition line from:
```python
def _assemble_catalog(ws: AppWorkspace, *, include_guessed: bool) -> tuple[list[dict], int, int]:
```
to:
```python
def _assemble_catalog(activity: Activity, ws: AppWorkspace, *, include_guessed: bool) -> tuple[list[dict], int, int]:
```
Then, inside the `if include_guessed:` block, add the cross-group harvest line (right after the existing `requests_recrawl.jsonl` line):
```python
    if include_guessed:
        request_recs += tools.read_jsonl(ws.canonical("requests_recrawl.jsonl"))  # re-seed crawl (if on)
        request_recs += _cross_group_surface(activity, ws)  # endpoints discovered in OTHER in-scope groups
        get_urls += [r["url"] for r in tools.read_jsonl(ws.canonical("content_discovery.jsonl"))
                     if r.get("url") and 200 <= (r.get("status") or 0) < 300]  # noqa: PLR2004
```
(Leave the rest of `_assemble_catalog` — the `catalog_records(...)` call, dead-drop, return — unchanged. The existing `in_scope`/`catalog_records` filter keeps the routed records because their host is in `ws`'s hosts.)

- [ ] **Step 4: Update both call sites**

`request_catalog` (~line 3791): change
```python
    catalog, n_mined, n_dead = _assemble_catalog(ws, include_guessed=False)
```
to
```python
    catalog, n_mined, n_dead = _assemble_catalog(activity, ws, include_guessed=False)
```
`request_catalog_full` (~line 3806): change
```python
    catalog, n_mined, n_dead = _assemble_catalog(ws, include_guessed=True)
```
to
```python
    catalog, n_mined, n_dead = _assemble_catalog(activity, ws, include_guessed=True)
```

- [ ] **Step 5: Fix any other direct callers**

Run: `cd /opt/ptflow && grep -rn "_assemble_catalog(" src/ tests/`
Expected: the only callers are the two functions edited in Step 4 (plus the definition). If any test calls `_assemble_catalog(ws, ...)` directly, update it to pass `activity` first: `_assemble_catalog(activity, ws, include_guessed=...)`.

- [ ] **Step 6: Run the new tests + the external-tasks file**

Run: `cd /opt/ptflow && uv run pytest tests/pipelines/test_external_tasks.py -v`
Expected: PASS (the two new integration tests + all pre-existing external-tasks tests).

- [ ] **Step 7: Full gate**

Run: `cd /opt/ptflow && uv run ruff check . && uv run ty check src/ && uv run pytest`
Expected: all green. Fix any fallout (e.g. a `ty` complaint on the new parameter, or a stray direct caller found in Step 5) and re-run.

- [ ] **Step 8: Regenerate the flow-map docs (a hook may already have)**

Run: `cd /opt/ptflow && uv run python -m ptflow.core.flowdocs && git status docs/`
Expected: no `docs/` change (this feature adds no Stage and no `StepMeta` — `request_catalog`/`request_catalog_full` are existing stages; only their internal assembly changed). If `docs/` shows a diff, review it — it should be empty; commit it only if a legitimate regeneration occurred.

- [ ] **Step 9: Commit**

```bash
cd /opt/ptflow && git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(external): route cross-group discovered endpoints into the phase-4 full catalog"
```

---

## Self-Review

**Spec coverage** (spec §3 → tasks):
- §3.1 `_cross_group_surface(activity, ws) -> list[dict]`, tagged `xref:<origin>`, request+endpoint files, own-group excluded, RoE drop → Task 1 ✓
- §3.2 `_assemble_catalog(activity, ws, *, include_guessed)`, cross-group merged only when `include_guessed=True`, phase-1 unchanged → Task 2 (Steps 3–4) ✓
- §3.3 both call sites pass `activity` → Task 2 Step 4; other callers → Step 5 ✓
- §4 invariants: RoE (host-owned filter), attribution (into B's `requests_full.jsonl`), dead-drop/scheme handled by the unchanged `catalog_records` path, write-once (no new files) → covered; the `test_request_catalog_full_routes_cross_group` exercises the phase-4-only + routing behavior end-to-end ✓
- §5 edge cases: host with no group → dropped (Task 1 test asserts `third.example` excluded); own-group not double-harvested (Task 1 test); single-group no-op (Task 2 test) ✓
- §6 testing: pure helper + integration, no network → both tasks ✓

**Placeholder scan:** none — every step has exact code/commands.

**Type consistency:** `_cross_group_surface(activity: Activity, ws: AppWorkspace) -> list[dict]` (Task 1) is consumed in Task 2 Step 3 with the same signature. `_assemble_catalog(activity, ws, *, include_guessed)` is defined and called consistently across Steps 3–4. `_url_to_get_request(url, source)` and `url_host(url)` are used with their real signatures (verified in `tasks.py`).
