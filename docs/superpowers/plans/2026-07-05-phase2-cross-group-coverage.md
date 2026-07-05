# Phase-2 Cross-Group Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route cross-group discovered endpoints into each group's phase-2 surface set (not only phase 4), so the fast `dast`/`xss`/`sqli` pass tests the cross-group attack surface too.

**Architecture:** A new per-app phase-2 stage `xref_catalog` writes a per-group sidecar `requests_xref.jsonl` by harvesting other in-scope groups' phase-1 discovery (via the existing `_cross_group_surface`). It is race-free because the 1→2 loop barrier guarantees every group finished phase 1. The phase-2 consumers read `requests.jsonl ∪ requests_xref.jsonl`; the phase-4 delta subtracts the xref keys so nothing is double-tested. No `core/` change.

**Tech Stack:** Python 3.12+, Prefect ≥3, `uv`, `ruff` (select=ALL), `ty` (type checker, not mypy), `pytest`.

## Global Constraints

- Dev gate (must pass before any task is done): `uv run ruff check . && uv run ty check src/ && uv run pytest`.
- Ruff runs `select = ["ALL"]`; respect existing `ignore`/`per-file-ignores` in `pyproject.toml` — do NOT add blanket `# noqa`.
- Write each tool/stage output **exactly once**: `requests_xref.jsonl` is a new canonical per-app file with ONE writer (`xref_catalog`). Never write path literals — paths come from `Activity`/`AppWorkspace` (`ws.canonical("...")`).
- Stages communicate only through on-disk artifacts; tolerant reads (`tools.read_jsonl`/`read_lines` → `[]`) everywhere.
- Keep pure transforms module-level and unit-testable apart from subprocess plumbing.
- When you add/change a step, add/adjust its `StepMeta` in the pipeline's `flowmeta.py` (the flow-map gate enforces it); regenerate docs with `uv run python -m ptflow.core.flowdocs`.
- Test file for external tasks: `tests/pipelines/test_external_tasks.py`. Test convention: imports inside the test function, `Activity.named(name, root=tmp_path).ensure()`, `act.app(app_id).ensure()`, `tools.write_lines`/`tools.write_jsonl`.
- Branch: `feat/phase2-xref-coverage` (already created; the design spec is committed there).

---

### Task 1: Extract `_finalize_catalog` (pure refactor, no behavior change)

Extract the tail of `_assemble_catalog` (scheme-normalize + in-scope filter + `catalog_records` + dead-drop) into a shared helper so `xref_catalog` (Task 2) reuses it verbatim instead of duplicating the dead-drop logic.

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (`_assemble_catalog`, around lines 3766-3813)
- Test: `tests/pipelines/test_external_tasks.py`

**Interfaces:**
- Produces: `_finalize_catalog(ws: AppWorkspace, request_recs: list[dict], get_urls: list[str]) -> tuple[list[dict], int]` — returns `(kept_catalog, n_dropped_dead)`.
- `_assemble_catalog(activity, ws, *, include_guessed)` keeps its signature and its `(kept, n_mined, n_dead)` return.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_finalize_catalog_reschemes_filters_scope_and_drops_dead(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("finalize", root=tmp_path).ensure()
    ws = act.app("app").ensure()
    ws.responses.mkdir(parents=True, exist_ok=True)
    tools.write_lines(ws.hosts, ["https://a.com"])
    (ws.responses / "index.txt").write_text("/s/1 https://a.com/dead (404 Not Found)\n")
    recs = [
        {"method": "GET", "url": "https://a.com/dead",
         "raw": "GET /dead HTTP/1.1\r\nHost: a.com\r\n\r\n", "sources": ["katana"]},
        {"method": "GET", "url": "https://a.com/live",
         "raw": "GET /live HTTP/1.1\r\nHost: a.com\r\n\r\n", "sources": ["katana"]},
    ]
    kept, n_dead = tasks._finalize_catalog(ws, recs, ["https://out-of-scope.example/x"])
    shapes = {(r["method"], tasks._url_pathkey(r["url"])) for r in kept}
    assert ("GET", "a.com/dead") not in shapes          # dead GET dropped
    assert ("GET", "a.com/live") in shapes              # alive GET kept
    assert not any("out-of-scope.example" in r["url"] for r in kept)  # in-scope filter
    assert n_dead == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_finalize_catalog_reschemes_filters_scope_and_drops_dead -v`
Expected: FAIL with `AttributeError: module 'ptflow.pipelines.external.tasks' has no attribute '_finalize_catalog'`

- [ ] **Step 3: Add `_finalize_catalog` and rewire `_assemble_catalog`**

In `src/ptflow/pipelines/external/tasks.py`, add the helper immediately **before** `_assemble_catalog`:

```python
def _finalize_catalog(ws: AppWorkspace, request_recs: list[dict], get_urls: list[str]) -> tuple[list[dict], int]:
    """Turn assembled request records + URL-only GETs into the final per-app catalog: scheme-normalize
    to the empirically-reachable scheme (_working_schemes), in-scope-filter to ws.hosts, dedup by shape
    (catalog_records), then DROP GET shapes whose path the corpus only ever saw as 404/410 (dead_url_keys
    — a discovered POST/form/XHR/JSON shape, status never recorded, is always kept). Returns (kept catalog,
    count dropped as dead). Pure-ish (reads disk only)."""
    in_scope = {url_host(h) for h in tools.read_lines(ws.hosts)}
    schemes = _working_schemes(ws)
    catalog = catalog_records(request_recs, get_urls, in_scope, schemes)
    dead = dead_url_keys(ln for idx in _all_store_indices(ws) for ln in tools.read_lines(idx))
    kept = [r for r in catalog
            if not (r.get("method", "GET").upper() == "GET" and not r.get("body")
                    and _url_pathkey(r.get("url") or "") in dead)]
    return kept, len(catalog) - len(kept)
```

Then replace the tail of `_assemble_catalog` — remove the `in_scope`/`schemes` locals at the top of its body and the final `catalog`/`dead`/`kept`/`return` block, so the body ends:

```python
    if include_guessed:
        request_recs += tools.read_jsonl(ws.canonical("requests_recrawl.jsonl"))  # re-seed crawl (if on)
        request_recs += _cross_group_surface(activity, ws)  # endpoints discovered in OTHER in-scope groups
        get_urls += [r["url"] for r in tools.read_jsonl(ws.canonical("content_discovery.jsonl"))
                     if r.get("url") and 200 <= (r.get("status") or 0) < 300]  # noqa: PLR2004
    kept, n_dead = _finalize_catalog(ws, request_recs, get_urls)
    return kept, len(mined), n_dead
```

(Leave the corpus-mining block — `bodies`/`source_urls`/`js_files`/`mined`/`request_recs`/`get_urls` — intact; only the two `in_scope`/`schemes` lines move into `_finalize_catalog`, and the final `catalog_records`/dead-drop block is replaced by the `_finalize_catalog` call.)

- [ ] **Step 4: Run tests to verify pass + no regression**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_finalize_catalog_reschemes_filters_scope_and_drops_dead tests/pipelines/test_external_tasks.py::test_assemble_catalog_drops_dead_get_keeps_post -v`
Expected: both PASS (the second is the untouched-behavior regression guard).

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "refactor(xref): extract _finalize_catalog from _assemble_catalog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `xref_catalog` task function

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (add function after `request_catalog_full`, ~line 3844)
- Test: `tests/pipelines/test_external_tasks.py`

**Interfaces:**
- Consumes: `_cross_group_surface(activity, ws) -> list[dict]` (existing), `_finalize_catalog` (Task 1).
- Produces: `xref_catalog(activity: Activity, app_id: str) -> None` — writes `scans/<app_id>/requests_xref.jsonl`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_xref_catalog_routes_other_groups_surface(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("xref-cat", root=tmp_path).ensure()
    a = act.app("attack.com-aaaa").ensure()
    b = act.app("api.company.com-bbbb").ensure()
    tools.write_lines(a.hosts, ["https://attack.com"])
    tools.write_lines(b.hosts, ["https://api.company.com"])
    tools.write_lines(a.canonical("endpoints_js.txt"), ["https://api.company.com/v1/users"])
    tools.write_jsonl(a.canonical("requests_crawl.jsonl"),
                      [{"method": "POST", "url": "https://api.company.com/v1/login",
                        "headers": {}, "body": "u=1", "params": [], "raw": "r", "sources": ["katana"]}])
    tasks.xref_catalog(act, "api.company.com-bbbb")
    routed = tools.read_jsonl(b.canonical("requests_xref.jsonl"))
    urls = {r["url"] for r in routed}
    assert any("api.company.com/v1/users" in u for u in urls)   # endpoint routed into B
    assert any("api.company.com/v1/login" in u for u in urls)   # request routed into B
    login = next(r for r in routed if r["url"].endswith("/login"))
    assert login["method"] == "POST"                            # shape preserved
    assert any(s.startswith("xref:attack.com") for s in login["sources"])  # provenance


def test_xref_catalog_single_group_is_empty(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("xref-cat-solo", root=tmp_path).ensure()
    b = act.app("only").ensure()
    tools.write_lines(b.hosts, ["https://api.company.com"])
    tools.write_lines(b.canonical("endpoints_js.txt"), ["https://api.company.com/own"])
    tasks.xref_catalog(act, "only")
    assert tools.read_jsonl(b.canonical("requests_xref.jsonl")) == []  # no other groups → empty
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_xref_catalog_routes_other_groups_surface tests/pipelines/test_external_tasks.py::test_xref_catalog_single_group_is_empty -v`
Expected: FAIL with `AttributeError: ... has no attribute 'xref_catalog'`

- [ ] **Step 3: Implement `xref_catalog`**

In `src/ptflow/pipelines/external/tasks.py`, add after `request_catalog_full`:

```python
def xref_catalog(activity: Activity, app_id: str) -> None:
    """PHASE 2 (head) — assemble the CROSS-GROUP surface catalog (requests_xref.jsonl): requests/endpoints
    discovered in OTHER in-scope groups whose host belongs to THIS group, so the phase-2 dast/xss/sqli
    pass tests the cross-group surface on the FAST pass, not only in phase 4 (request_catalog_full).

    Safe by the loop barrier: the global 1→2 barrier guarantees every group finished phase 1, so reading
    peers' discovery artifacts is race-free (same guarantee request_catalog_full relies on at phase 4).
    Offline (net=False). A lone group has no peers → an empty sidecar (tolerant reads make it a no-op)."""
    ws = activity.app(app_id)
    catalog, n_dead = _finalize_catalog(ws, _cross_group_surface(activity, ws), [])
    n = tools.write_jsonl(ws.canonical("requests_xref.jsonl"), catalog)
    log.info("  → xref_catalog (%s) — %d cross-group request shape(s) (dropped %d dead/404)"
             " → requests_xref.jsonl", app_id, n, n_dead)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_xref_catalog_routes_other_groups_surface tests/pipelines/test_external_tasks.py::test_xref_catalog_single_group_is_empty -v`
Expected: both PASS

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(xref): xref_catalog stage — cross-group surface sidecar for phase 2

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `_surface_request_set` reads `requests.jsonl` ∪ `requests_xref.jsonl`

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (`_surface_request_set`, ~line 4012)
- Test: `tests/pipelines/test_external_tasks.py`

**Interfaces:**
- Modifies: `_surface_request_set(ws, *, cap) -> list[dict]` — now merges the surface catalog with the xref sidecar (consumed unchanged by `dast`/`xss`/`sqli`).

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_surface_request_set_merges_xref_sidecar(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("surface-xref", root=tmp_path).ensure()
    ws = act.app("app").ensure()
    tools.write_lines(ws.hosts, ["https://a.com"])
    tools.write_jsonl(ws.canonical("requests.jsonl"),
                      [{"method": "GET", "url": "https://a.com/own",
                        "raw": "GET /own HTTP/1.1\r\nHost: a.com\r\n\r\n", "params": [], "sources": ["katana"]}])
    tools.write_jsonl(ws.canonical("requests_xref.jsonl"),
                      [{"method": "GET", "url": "https://a.com/routed",
                        "raw": "GET /routed HTTP/1.1\r\nHost: a.com\r\n\r\n", "params": [],
                        "sources": ["xref:other"]}])
    got = {tasks._url_pathkey(r["url"]) for r in tasks._surface_request_set(ws, cap=100)}
    assert "a.com/own" in got       # own surface still present
    assert "a.com/routed" in got    # cross-group surface folded in
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_surface_request_set_merges_xref_sidecar -v`
Expected: FAIL — `a.com/routed` not in the set (the sidecar is not read yet).

- [ ] **Step 3: Modify `_surface_request_set`**

Replace the body of `_surface_request_set` in `src/ptflow/pipelines/external/tasks.py`:

```python
def _surface_request_set(ws: AppWorkspace, *, cap: int) -> list[dict]:
    """The EXPLORABLE-surface request set (phase 2): the surface catalog (requests.jsonl) UNIONED with the
    cross-group sidecar (requests_xref.jsonl — peers' surface owned by this group, from xref_catalog),
    deduped by shape and capped. Shared by `dast` and the surface vuln scanners (xss/sqli)."""
    catalog = [*tools.read_jsonl(ws.canonical("requests.jsonl")),
               *tools.read_jsonl(ws.canonical("requests_xref.jsonl"))]
    return dast_requests(catalog, [], cap=cap)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_surface_request_set_merges_xref_sidecar -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(xref): phase-2 scanners read the cross-group sidecar

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `_delta_request_set` subtracts xref keys (no phase-4 double-test)

**Files:**
- Modify: `src/ptflow/pipelines/external/tasks.py` (`_delta_request_set`, ~line 4018)
- Test: `tests/pipelines/test_external_tasks.py`

**Interfaces:**
- Modifies: `_delta_request_set(ws, *, cap) -> list[dict]` — phase-4 delta now excludes shapes already in `requests_xref.jsonl` (consumed unchanged by `dast_full`/`xss_full`/`sqli_full`).

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_delta_request_set_excludes_xref_covered_shapes(tmp_path):
    from ptflow.core import tools
    from ptflow.core.paths import Activity

    act = Activity.named("delta-xref", root=tmp_path).ensure()
    ws = act.app("app").ensure()
    tools.write_lines(ws.hosts, ["https://a.com"])
    tools.write_jsonl(ws.canonical("requests.jsonl"), [])
    tools.write_jsonl(ws.canonical("params.jsonl"), [])
    # a cross-group shape phase 2 already covered, plus a genuinely new full-catalog shape
    tools.write_jsonl(ws.canonical("requests_xref.jsonl"),
                      [{"method": "GET", "url": "https://a.com/routed",
                        "raw": "GET /routed HTTP/1.1\r\nHost: a.com\r\n\r\n", "params": [], "sources": ["xref:o"]}])
    tools.write_jsonl(ws.canonical("requests_full.jsonl"), [
        {"method": "GET", "url": "https://a.com/routed",
         "raw": "GET /routed HTTP/1.1\r\nHost: a.com\r\n\r\n", "params": [], "sources": ["xref:o"]},
        {"method": "GET", "url": "https://a.com/guessed",
         "raw": "GET /guessed HTTP/1.1\r\nHost: a.com\r\n\r\n", "params": [], "sources": ["feroxbuster"]},
    ])
    got = {tasks._url_pathkey(r["url"]) for r in tasks._delta_request_set(ws, cap=100)}
    assert "a.com/routed" not in got      # already covered in phase 2 via the sidecar → not re-tested
    assert "a.com/guessed" in got         # genuinely new guessed surface → in the delta
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_delta_request_set_excludes_xref_covered_shapes -v`
Expected: FAIL — `a.com/routed` IS in the delta (xref keys not subtracted yet).

- [ ] **Step 3: Modify `_delta_request_set`**

Replace the body of `_delta_request_set` in `src/ptflow/pipelines/external/tasks.py`:

```python
def _delta_request_set(ws: AppWorkspace, *, cap: int) -> list[dict]:
    """The GUESSED-surface DELTA request set (phase 4): full-catalog shapes NOT already covered by the
    phase-2 surface — the surface catalog (requests.jsonl) OR the cross-group sidecar (requests_xref.jsonl,
    which phase-2 dast/xss/sqli already tested) — keyed by request_key, PLUS the synthesized requests for
    the discovered hidden params (params.jsonl), deduped and capped. Shared by `dast_full` and the deep
    vuln scanners (xss_full/sqli_full) so the "delta, not the whole catalog" rule lives in ONE place."""
    surface_keys = {request_key(r) for r in tools.read_jsonl(ws.canonical("requests.jsonl"))}
    surface_keys |= {request_key(r) for r in tools.read_jsonl(ws.canonical("requests_xref.jsonl"))}
    delta = [r for r in tools.read_jsonl(ws.canonical("requests_full.jsonl"))
             if request_key(r) not in surface_keys]
    return dast_requests(delta, tools.read_jsonl(ws.canonical("params.jsonl")), cap=cap)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_delta_request_set_excludes_xref_covered_shapes -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/pipelines/external/tasks.py tests/pipelines/test_external_tasks.py
git commit -m "feat(xref): phase-4 delta subtracts the cross-group sidecar (no double-test)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Wire `xref_catalog` into external (stage graph + flow map)

**Files:**
- Modify: `src/ptflow/pipelines/external/pipeline.py` (phase-2 stages, ~lines 68-77)
- Modify: `src/ptflow/pipelines/external/flowmeta.py` (add a `StepMeta`)
- Regenerate: `docs/external-pipeline-*` and `docs/webscan-pipeline-*` (deterministic; via `flowdocs`)
- Test: `tests/pipelines/test_external_tasks.py` + the existing flow-map gate `tests/pipelines/test_flowmap.py`

**Interfaces:**
- Consumes: `tasks.xref_catalog` (Task 2).
- Produces: an `xref_catalog` `Stage` at `phase=2`; `dast`/`xss`/`sqli` gain `needs=("xref_catalog",)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_external_phase2_wires_xref_catalog():
    from ptflow.pipelines.external.pipeline import PIPELINE

    stages = {s.name: s for s in PIPELINE.stages}
    assert "xref_catalog" in stages
    assert stages["xref_catalog"].phase == 2
    assert stages["xref_catalog"].per_app and not stages["xref_catalog"].net
    for name in ("dast", "xss", "sqli"):
        assert "xref_catalog" in stages[name].needs, f"{name} must depend on xref_catalog"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_external_phase2_wires_xref_catalog -v`
Expected: FAIL — `xref_catalog` not in stages.

- [ ] **Step 3: Add the stage and rewire needs**

In `src/ptflow/pipelines/external/pipeline.py`, in the phase-2 block, add the stage as the head and add `needs` to the three scanners (leave `cve_lookup` unchanged):

```python
        # --- loop 2 (phase 2): DAST the explorable surface (+ cross-group) — low-hanging fruit ---
        Stage("xref_catalog", tasks.xref_catalog, per_app=True, phase=2, net=False),
        Stage("dast", tasks.dast, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("xss", tasks.xss, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("sqli", tasks.sqli, needs=("xref_catalog",), per_app=True, phase=2),
```

(Match the existing surrounding comment style; keep `cve_lookup` and any `ai_*` stages as they are.)

- [ ] **Step 4: Add the `StepMeta`**

In `src/ptflow/pipelines/external/flowmeta.py`, add an entry to `FLOWMETA` (place it just before `"dast"`):

```python
    "xref_catalog": StepMeta(
        summary="FASE 2 (testa) — assembla il CATALOGO CROSS-GRUPPO (requests_xref.jsonl): richieste/"
                "endpoint scoperti in ALTRI gruppi in-scope il cui host appartiene a QUESTO gruppo, così "
                "dast/xss/sqli testano la superficie cross-gruppo sul passaggio VELOCE, non solo in FASE 4. "
                "Sicuro grazie alla barriera 1→2 (tutti i gruppi hanno finito la FASE 1 → lettura race-free).",
        commands=(
            "# _cross_group_surface(activity, ws): dagli ALTRI gruppi le richieste/endpoint con host ∈ ws.hosts",
            "#   (taggate xref:<origine>) → _finalize_catalog (scheme raggiungibile · in-scope · dead-drop 404)",
        ),
        outputs=("requests_xref.jsonl",),
        notes=("offline (net=False) · RoE-safe (solo host di gruppi in-scope) · gruppo solo ⇒ sidecar vuoto",),
    ),
```

- [ ] **Step 5: Regenerate the flow-map docs**

Run: `uv run python -m ptflow.core.flowdocs`
Expected: updates `docs/external-pipeline-*` and `docs/webscan-pipeline-*` (deterministic — no timestamps).

- [ ] **Step 6: Run the wiring test + the flow-map gate**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_external_phase2_wires_xref_catalog tests/pipelines/test_flowmap.py -v`
Expected: PASS (the gate confirms every Stage — including `xref_catalog` — has a `StepMeta` and all views render).

- [ ] **Step 7: Commit**

```bash
git add src/ptflow/pipelines/external/pipeline.py src/ptflow/pipelines/external/flowmeta.py docs/external-pipeline-* docs/webscan-pipeline-* tests/pipelines/test_external_tasks.py
git commit -m "feat(xref): wire xref_catalog into external phase 2 + flow map

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Wire `xref_catalog` into webscan + full dev gate

**Files:**
- Modify: `src/ptflow/pipelines/webscan/pipeline.py` (phase-2 stages, ~lines 60-63)
- Regenerate: `docs/webscan-pipeline-*` (if not already current from Task 5)
- Test: `tests/pipelines/test_external_tasks.py` + full dev gate

**Interfaces:**
- Consumes: `external.xref_catalog` (Task 2), the `StepMeta` from Task 5 (inherited via `{**_ext.FLOWMETA}`).
- Produces: an `xref_catalog` `Stage` at `phase=2` in webscan; its `dast`/`xss`/`sqli` gain `needs=("xref_catalog",)`.

- [ ] **Step 1: Write the failing test**

Add to `tests/pipelines/test_external_tasks.py`:

```python
def test_webscan_phase2_wires_xref_catalog():
    from ptflow.pipelines.webscan.pipeline import PIPELINE

    stages = {s.name: s for s in PIPELINE.stages}
    assert "xref_catalog" in stages
    assert stages["xref_catalog"].phase == 2 and stages["xref_catalog"].per_app
    for name in ("dast", "xss", "sqli"):
        assert "xref_catalog" in stages[name].needs, f"webscan {name} must depend on xref_catalog"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/pipelines/test_external_tasks.py::test_webscan_phase2_wires_xref_catalog -v`
Expected: FAIL — `xref_catalog` not in webscan stages.

- [ ] **Step 3: Add the stage and rewire needs**

In `src/ptflow/pipelines/webscan/pipeline.py`, in the phase-2 block:

```python
        Stage("xref_catalog", external.xref_catalog, per_app=True, phase=2, net=False),
        Stage("dast", external.dast, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("xss", external.xss, needs=("xref_catalog",), per_app=True, phase=2),
        Stage("sqli", external.sqli, needs=("xref_catalog",), per_app=True, phase=2),
```

(Leave `cve_lookup` unchanged.)

- [ ] **Step 4: Regenerate the flow-map docs**

Run: `uv run python -m ptflow.core.flowdocs`
Expected: `docs/webscan-pipeline-*` now include the `xref_catalog` node.

- [ ] **Step 5: Run the full dev gate**

Run: `uv run ruff check . && uv run ty check src/ && uv run pytest`
Expected: ruff clean, ty clean, all tests PASS (including both wiring tests and the parametrized flow-map gate for external + webscan).

- [ ] **Step 6: Commit**

```bash
git add src/ptflow/pipelines/webscan/pipeline.py docs/webscan-pipeline-* tests/pipelines/test_external_tasks.py
git commit -m "feat(xref): wire xref_catalog into webscan phase 2

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Post-implementation (outside the task loop)

- Update `CLAUDE.md`: the phase-2 loop description (add `xref_catalog`), the workspace-layout note for `requests_xref.jsonl`, and a design-decision entry (phase-2 cross-group coverage via a per-app stage — barrier makes it race-free; phase-4 delta subtracts the sidecar; `param_fuzz` still folds cross-group). Note: the post-merge doc-sync hook may draft some of this; review it.
- Update the `recon-backlog` memory (#17): mark "phase-2 coverage" DONE, leaving re-crawl / scope-expansion / cross-run persistence deferred.
- The design spec's roadmap item is now implemented — no further spec change needed.
```
