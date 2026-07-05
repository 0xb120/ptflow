# Per-step on/off toggles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator disable named pipeline steps for a run (debug), via the existing `ptflow.toml` + `--set`, and view every step's effective on/off state with a new `ptflow steps` subcommand.

**Architecture:** A sparse `[steps.<pipeline>]` config table (values on/off) resolves to a `frozenset[str]` of disabled step names, validated against the pipeline's live `stages` (unknown name → hard error). `orchestrate()` passes it to the `_run_dag` flow, which filters `pipeline.stages` before building the DAG. Filtering is safe with no `needs` rewrite — `topo_order`/`_submit_dag` already ignore missing dependency names and stages read on-disk inputs tolerantly. The `ptflow steps` command reads `stages` live, so the view is always current (nothing generated to drift).

**Tech Stack:** Python 3.12+, argparse CLI, tomllib config, Prefect 3 flows/tasks, pytest, ruff (`select=ALL`), ty type checker, uv.

## Global Constraints

- Dev gate must stay green: `uv run ruff check . && uv run ty check src/ && uv run pytest`.
- Ruff runs `select = ["ALL"]`; respect the `ignore`/`per-file-ignores` in `pyproject.toml`. CLI `print()` needs `# noqa: T201`; function-local imports use `# noqa: PLC0415` (both already used in `cli.py`).
- Config precedence is fixed: `--set` (CLI) > `PTFLOW_*` env > config file > code default. Step toggles honour `--set` > config file (no env layer).
- Only strings cross the Prefect flow/task boundary — pass disabled steps as a `tuple[str, ...]`.
- Do not modify pipeline task code (`pipelines/*/tasks.py`) or add/remove any `Stage`; this feature is pipeline-agnostic core plumbing. (No flow-map regeneration needed — no stage graph changes.)
- Keep pure/testable functions module-level and free of Prefect imports (so the `steps` command stays fast and the helpers are unit-testable).

---

### Task 1: Pure stage-graph helpers in `core/stage.py`

Add three Prefect-free helpers next to `Stage`, and route the orchestrator's existing band logic through one of them so the Prefect UI tags and the `steps` view can't diverge.

**Files:**
- Modify: `src/ptflow/core/stage.py` (imports at line 5; add helpers after the `Stage` dataclass, before `Followup` at line 62)
- Modify: `src/ptflow/core/orchestrator.py:100-111` (`_stage_tags` uses the new `stage_band`)
- Test: `tests/core/test_stage.py`, `tests/core/test_orchestrator.py`

**Interfaces:**
- Produces:
  - `stage_band(stage: Stage) -> str` → `"breadth" | "spanning" | "post-cluster" | "loop:<phase>"`
  - `enabled_stages(stages: Sequence[Stage], disabled: Collection[str]) -> list[Stage]`
  - `impacted_dependents(stages: Sequence[Stage], disabled: Collection[str]) -> list[str]` (sorted)

- [ ] **Step 1: Write the failing tests** in `tests/core/test_stage.py` (append):

```python
def test_stage_band_classifies():
    from ptflow.core.stage import Stage, stage_band
    assert stage_band(Stage("a", lambda *_: None)) == "breadth"
    assert stage_band(Stage("b", lambda *_: None, spanning=True)) == "spanning"
    assert stage_band(Stage("c", lambda *_: None, cluster_scope=True)) == "post-cluster"
    assert stage_band(Stage("d", lambda *_: None, per_app=True, phase=2)) == "loop:2"


def test_enabled_stages_filters():
    from ptflow.core.stage import Stage, enabled_stages
    stages = [Stage("a", lambda *_: None), Stage("b", lambda *_: None)]
    assert [s.name for s in enabled_stages(stages, {"a"})] == ["b"]


def test_impacted_dependents_transitive():
    from ptflow.core.stage import Stage, impacted_dependents
    a = Stage("a", lambda *_: None)
    b = Stage("b", lambda *_: None, needs=("a",))
    c = Stage("c", lambda *_: None, needs=("b",))
    d = Stage("d", lambda *_: None)  # independent
    assert impacted_dependents([a, b, c, d], {"a"}) == ["b", "c"]


def test_impacted_dependents_none_when_independent():
    from ptflow.core.stage import Stage, impacted_dependents
    assert impacted_dependents([Stage("a", lambda *_: None), Stage("b", lambda *_: None)], {"a"}) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_stage.py -k "band or enabled or impacted" -v`
Expected: FAIL with `ImportError: cannot import name 'stage_band'` (etc.)

- [ ] **Step 3: Add the helpers** to `src/ptflow/core/stage.py`. First widen the import at line 5:

```python
from collections.abc import Callable, Collection, Sequence
```

Then insert after the `Stage` dataclass (after line 59, before `class Followup` at line 62):

```python
def stage_band(stage: Stage) -> str:
    """The stage's execution band (pure) — the SINGLE source for both the Prefect UI tags and the
    `ptflow steps` view, so the two can't diverge. breadth | spanning | post-cluster | loop:<phase>."""
    if stage.spanning:
        return "spanning"
    if stage.cluster_scope:
        return "post-cluster"
    if stage.per_app:
        return f"loop:{stage.phase}"
    return "breadth"


def enabled_stages(stages: Sequence[Stage], disabled: Collection[str]) -> list[Stage]:
    """The stages left after removing the disabled ones (pure). Safe WITHOUT rewiring `needs`:
    topo_order/_submit_dag ignore a missing dependency name, and stages read on-disk inputs
    tolerantly — a surviving consumer of a removed stage just finds empty/absent inputs."""
    return [s for s in stages if s.name not in disabled]


def impacted_dependents(stages: Sequence[Stage], disabled: Collection[str]) -> list[str]:
    """Surviving stages that transitively depend (via `needs`) on a disabled stage — the ones that
    will run with empty/absent inputs (pure, sorted). Only `needs`-declared, same-scope edges are
    modeled; cross-loop consumers that read another loop's artifacts across the barrier are NOT
    declared in Stage metadata, so they aren't captured here."""
    by_name = {s.name: s for s in stages}
    disabled_set = set(disabled)
    memo: dict[str, bool] = {}

    def needs_disabled(name: str) -> bool:
        if name in memo:
            return memo[name]
        memo[name] = False  # cycle guard (the DAG shouldn't have any) — overwritten below
        stage = by_name.get(name)
        result = stage is not None and any(
            dep in disabled_set or needs_disabled(dep) for dep in stage.needs
        )
        memo[name] = result
        return result

    return sorted(s.name for s in stages if s.name not in disabled_set and needs_disabled(s.name))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_stage.py -k "band or enabled or impacted" -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Route `_stage_tags` through `stage_band`.** In `src/ptflow/core/orchestrator.py`, add `stage_band` to the stage import (find the existing `from ptflow.core.stage import ...` line and include `stage_band`; if only `Stage` is imported, make it `from ptflow.core.stage import Stage, enabled_stages, impacted_dependents, stage_band`). Replace the body of `_stage_tags` (lines 100-111):

```python
def _stage_tags(stage: Stage) -> list[str]:
    """Band tag for the Prefect UI (so task runs group/filter by phase in the dashboard), plus the
    `net` tag for network stages (offline ones omit it). Pure — derived from the Stage's flags."""
    band = stage_band(stage)
    return ["net", band] if stage.net else [band]
```

- [ ] **Step 6: Run the existing band test to confirm no regression**

Run: `uv run pytest tests/core/test_orchestrator.py -k "stage_tags" -v`
Expected: PASS (`test_stage_tags_by_band`, `test_stage_tags_omit_net_for_offline`)

- [ ] **Step 7: Add the filter-tolerance test** to `tests/core/test_orchestrator.py` (append):

```python
def test_enabled_stages_topo_tolerates_removed_dep():
    from ptflow.core.stage import Stage, enabled_stages
    a = Stage("a", lambda *_: None)
    b = Stage("b", lambda *_: None, needs=("a",))
    kept = enabled_stages([a, b], {"a"})
    order = [s.name for s in orchestrator.topo_order(kept)]
    assert order == ["b"]  # 'b' survives; its now-missing dep 'a' is ignored, no KeyError
```

- [ ] **Step 8: Run it**

Run: `uv run pytest tests/core/test_orchestrator.py -k "tolerates_removed_dep" -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/ptflow/core/stage.py src/ptflow/core/orchestrator.py tests/core/test_stage.py tests/core/test_orchestrator.py
git commit -m "feat(steps): pure stage-graph helpers (band/filter/impacted-dependents)"
```

---

### Task 2: `resolve_disabled_steps` + `steps.` prefix in `runconfig`

Resolve the disabled-step set from config + `--set`, validated against the live stage names, and stop `resolve()` from warning `steps.*` keys as unknown typos.

**Files:**
- Modify: `src/ptflow/core/runconfig.py` (line 17 import; line 32 add `_STEPS_PREFIX`; line 165 unknown-key check; add `resolve_disabled_steps` after `resolve()` at line 181)
- Test: `tests/core/test_runconfig.py`

**Interfaces:**
- Consumes: `_flatten`, `_parse_overrides`, `_coerce`, `ConfigError` (existing in the module)
- Produces: `resolve_disabled_steps(config: Mapping[str, Any], sets: Iterable[str] | None, pipeline: str, stage_names: Collection[str]) -> frozenset[str]`

- [ ] **Step 1: Write the failing tests** in `tests/core/test_runconfig.py` (append):

```python
def test_resolve_disabled_steps_sparse_and_precedence():
    config = {"steps": {"external": {"dast": False, "cve_lookup": True}}}
    names = {"dast", "cve_lookup", "httpx"}
    # config: dast off, cve_lookup on; --set turns httpx off and flips cve_lookup off (--set wins)
    out = runconfig.resolve_disabled_steps(
        config, ["steps.external.httpx=off", "steps.external.cve_lookup=off"], "external", names)
    assert out == frozenset({"dast", "httpx", "cve_lookup"})


def test_resolve_disabled_steps_unlisted_stay_enabled():
    assert runconfig.resolve_disabled_steps({}, None, "external", {"dast", "httpx"}) == frozenset()


def test_resolve_disabled_steps_unknown_name_raises():
    with pytest.raises(runconfig.ConfigError):
        runconfig.resolve_disabled_steps(
            {"steps": {"external": {"nope": False}}}, None, "external", {"dast"})


def test_resolve_disabled_steps_scopes_to_pipeline():
    config = {"steps": {"internal": {"smb_checks": False}}}  # a DIFFERENT pipeline's table
    assert runconfig.resolve_disabled_steps(config, None, "external", {"dast"}) == frozenset()


def test_resolve_does_not_warn_steps_prefix(caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="ptflow")
    runconfig.resolve({"steps": {"external": {"dast": False}}}, {}, None)
    assert "steps.external.dast" not in caplog.text  # recognized prefix, not a "unknown key" typo warning
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_runconfig.py -k "disabled_steps or steps_prefix" -v`
Expected: FAIL (`AttributeError: module 'ptflow.core.runconfig' has no attribute 'resolve_disabled_steps'`, and the prefix test fails on the warning)

- [ ] **Step 3: Implement.** In `src/ptflow/core/runconfig.py`:

Widen the import at line 17:

```python
from collections.abc import Collection, Iterable, Mapping
```

Add the prefix constant after line 32 (`_ROLES_PREFIX = ...`):

```python
_STEPS_PREFIX = "steps."   # dynamic: steps.<pipeline>.<step> → per-step on/off (filters pipeline.stages)
```

In `resolve()`, change the unknown-key guard (line 165) to also accept the steps prefix:

```python
            if key not in _BY_PATH and not key.startswith((_ROLES_PREFIX, _STEPS_PREFIX)):
```

Add the resolver after `resolve()` (after line 181):

```python
def resolve_disabled_steps(config: Mapping[str, Any], sets: Iterable[str] | None,
                           pipeline: str, stage_names: Collection[str]) -> frozenset[str]:
    """The steps to DISABLE for `pipeline`, from the `[steps.<pipeline>]` config table + `--set
    steps.<pipeline>.<step>=off` (precedence --set > config), validated against the pipeline's LIVE
    stage names. Sparse: only a step set to a falsey value is disabled; an unlisted step stays on.
    Pure. Raises ConfigError on an unknown step name (so a stale/renamed step can't be referenced)."""
    flat = _flatten(config)
    overrides = _parse_overrides(sets)
    prefix = f"{_STEPS_PREFIX}{pipeline}."
    names = {k[len(prefix):] for src in (flat, overrides) for k in src if k.startswith(prefix)}
    disabled: set[str] = set()
    for name in names:
        if name not in stage_names:
            valid = ", ".join(sorted(stage_names))
            msg = f"unknown step '{name}' for pipeline '{pipeline}' — valid: {valid}"
            raise ConfigError(msg)
        key = f"{prefix}{name}"
        raw = overrides[key] if key in overrides else flat[key]  # --set wins over config
        if _coerce("bool", raw) == "off":
            disabled.add(name)
    return frozenset(disabled)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_runconfig.py -k "disabled_steps or steps_prefix" -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/core/runconfig.py tests/core/test_runconfig.py
git commit -m "feat(steps): resolve_disabled_steps + steps.* config prefix"
```

---

### Task 3: `snapshot()` records disabled steps

Persist the disabled steps into `<activity>/config.toml` for reproducibility, re-feedable with `--config`.

**Files:**
- Modify: `src/ptflow/core/runconfig.py:195-206` (`snapshot`)
- Test: `tests/core/test_runconfig.py`

**Interfaces:**
- Produces: `snapshot(activity_dir: Path, resolved: Iterable[Resolved], *, disabled_keys: Iterable[str] = ()) -> Path | None` — `disabled_keys` are fully-qualified dotted keys (e.g. `steps.external.dast`).

- [ ] **Step 1: Write the failing tests** in `tests/core/test_runconfig.py` (append):

```python
def test_snapshot_records_disabled_steps(tmp_path):
    resolved = runconfig.resolve({"profile": "home"}, {}, None)
    out = runconfig.snapshot(tmp_path, resolved, disabled_keys=["steps.external.dast"])
    text = out.read_text()
    assert 'profile = "home"' in text
    assert 'steps.external.dast = "off"' in text


def test_snapshot_disabled_only_still_writes(tmp_path):
    out = runconfig.snapshot(tmp_path, [], disabled_keys=["steps.external.dast"])
    assert out is not None
    assert 'steps.external.dast = "off"' in out.read_text()


def test_snapshot_nothing_set_returns_none(tmp_path):
    assert runconfig.snapshot(tmp_path, [], disabled_keys=[]) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_runconfig.py -k "snapshot" -v`
Expected: FAIL (`disabled_keys` is an unexpected keyword argument)

- [ ] **Step 3: Implement.** Replace `snapshot` (lines 195-206) in `src/ptflow/core/runconfig.py`:

```python
def snapshot(activity_dir: Path, resolved: Iterable[Resolved], *,
             disabled_keys: Iterable[str] = ()) -> Path | None:
    """Write the effective run config to ``<activity>/config.toml`` (secrets redacted) for
    reproducibility — re-feedable with ``--config``. Includes disabled steps as ``steps.<pipeline>.<step>
    = "off"`` lines. Returns the path, or None if nothing was set."""
    rows = sorted(resolved, key=lambda r: r.path)
    steps = sorted(disabled_keys)
    if not rows and not steps:
        return None
    lines = ["# ptflow — effective run config (auto-generated; secrets redacted).",
             "# Re-feed with:  ptflow run <pipeline> <activity> <scope> --config config.toml", ""]
    lines += [f"{r.path} = {_toml_quote('<redacted>' if r.secret else r.value)}" for r in rows]
    lines += [f"{k} = {_toml_quote('off')}" for k in steps]
    out = activity_dir / "config.toml"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_runconfig.py -k "snapshot" -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/core/runconfig.py tests/core/test_runconfig.py
git commit -m "feat(steps): snapshot records disabled steps for reproducibility"
```

---

### Task 4: Orchestrator filtering + impacted-dependents warning

Thread the disabled set through `orchestrate()` → the `_run_dag` flow, filter `pipeline.stages` before building the DAG, and log which steps are off + which surviving steps depend on them.

**Files:**
- Modify: `src/ptflow/core/orchestrator.py:247-294` (`_run_dag`) and `:342-396` (`orchestrate`)
- Test: covered by Task 1's `test_enabled_stages_topo_tolerates_removed_dep` (the pure seam) + Task 8's e2e run (the flow wiring, which needs Prefect and isn't unit-tested here, matching the suite's convention of not driving full flows).

**Interfaces:**
- Consumes: `enabled_stages`, `impacted_dependents` (Task 1)
- Produces:
  - `_run_dag(pipeline_name: str, activity_name: str, root: str | None, *, resume: bool, disabled: tuple[str, ...] = ()) -> int`
  - `orchestrate(pipeline, activity_name, scope_file, *, root=None, resume=False, observe=None, disabled_steps: frozenset[str] = frozenset()) -> tuple[Path, int]`

- [ ] **Step 1: Edit `_run_dag`.** In `src/ptflow/core/orchestrator.py`, change the signature (line 248):

```python
def _run_dag(pipeline_name: str, activity_name: str, root: str | None, *,
             resume: bool, disabled: tuple[str, ...] = ()) -> int:
```

Replace the stage-derivation block (lines 258-263) with a filtered version + the warning:

```python
    tools.clear_abort()  # fresh run (a prior aborted run in this process must not poison this one)
    pipeline = load_pipeline(pipeline_name)
    activity = Activity.named(activity_name, Path(root) if root else None)
    disabled_set = set(disabled)
    if disabled_set:
        log.info("▶ steps disabled: %s", ", ".join(sorted(disabled_set)))
        impacted = impacted_dependents(pipeline.stages, disabled_set)
        if impacted:
            log.warning("⚠ these steps depend on a disabled step and will run with absent inputs: %s",
                        ", ".join(impacted))
    stages = enabled_stages(pipeline.stages, disabled_set)
    activity_stages = [s for s in stages
                       if not s.per_app and not s.spanning and not s.cluster_scope]
    spanning_stages = [s for s in stages if s.spanning]
    cluster_scope_stages = [s for s in stages if s.cluster_scope]
```

(Note: the `tools.clear_abort()` line moves up to stay first; the original had it before `load_pipeline` — keep that order.)

- [ ] **Step 2: Use the filtered list for the per-app loops.** In the same function, change the `_run_loops` call (line 293) from `list(pipeline.stages)` to the filtered `stages`:

```python
        if app_ids:
            _run_loops(stages, app_ids,
                       pipeline_name, activity_name, root, failures, resume=resume)
```

- [ ] **Step 3: Edit `orchestrate`.** Add the parameter (after `observe` at line 349):

```python
def orchestrate(  # noqa: PLR0913
    pipeline: Pipeline,
    activity_name: str,
    scope_file: str,
    *,
    root: str | None = None,
    resume: bool = False,
    observe: str | None = None,
    disabled_steps: frozenset[str] = frozenset(),
) -> tuple[Path, int]:
```

Extend the docstring with one line before the closing `"""` (after the `observe` sentence at line 357):

```python
    `disabled_steps` names stages to filter out of this run (a debug knob resolved from
    `[steps.<pipeline>]` / `--set steps.<pipeline>.<step>=off`); its dependents still run (degrading on
    absent inputs)."""
```

Then thread it into the flow calls. Before `_go` (after line 377), bind the tuple:

```python
    disabled = tuple(sorted(disabled_steps))
    def _go() -> int:
        if observe:
            # redirect this run to the persistent server + let it capture the `ptflow` logger, scoped to
            # the run (no global profile/env mutation). temporary_settings overrides at runtime.
            with temporary_settings({PREFECT_API_URL: observe, PREFECT_LOGGING_EXTRA_LOGGERS: ["ptflow"]}):
                return run(pipeline.name, activity_name, root, resume=resume, disabled=disabled)
        return run(pipeline.name, activity_name, root, resume=resume, disabled=disabled)
```

- [ ] **Step 4: Verify the pure seam still passes and types check**

Run: `uv run pytest tests/core/test_orchestrator.py -v && uv run ty check src/`
Expected: PASS (all orchestrator tests, including `test_enabled_stages_topo_tolerates_removed_dep`); ty clean.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/core/orchestrator.py
git commit -m "feat(steps): filter disabled stages in _run_dag + warn impacted dependents"
```

---

### Task 5: CLI wiring in `_run`

Resolve the disabled set after loading the pipeline, pass it to `orchestrate`, and snapshot it — for the main run and each followup.

**Files:**
- Modify: `src/ptflow/cli.py:132-186` (`_run`)
- Test: exercised end-to-end in Task 8 (the `_run` path drives Prefect; no unit test here).

**Interfaces:**
- Consumes: `runconfig.resolve_disabled_steps` (Task 2), `runconfig.snapshot(..., disabled_keys=...)` (Task 3), `orchestrate(..., disabled_steps=...)` (Task 4)

- [ ] **Step 1: Rewrite the resolution + main-run block** in `_run` (replace lines 133-152, from the `try:` through the first `runconfig.snapshot(...)` call). Note the two changes: keep the parsed `config` in a variable, and resolve+pass+snapshot the disabled set:

```python
    setup_logging(verbose=args.verbose)
    # Resolve operator config (--set > env > file) and write it into os.environ BEFORE importing the
    # pipeline — its module-level constants read PTFLOW_* at import time.
    try:
        overrides = _apply_ai_flag(list(args.overrides or []), ai=args.ai)
        config = runconfig.load_config(args.config)
        resolved = runconfig.resolve(config, os.environ, overrides)
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    runconfig.apply(resolved)

    from ptflow.core.orchestrator import orchestrate  # noqa: PLC0415 (after runconfig.apply)
    from ptflow.core.paths import Activity  # noqa: PLC0415
    from ptflow.pipelines import load_pipeline  # noqa: PLC0415 (constants read PTFLOW_* at import)

    pipeline = load_pipeline(args.pipeline)
    try:
        disabled = runconfig.resolve_disabled_steps(
            config, overrides, pipeline.name, {s.name for s in pipeline.stages})
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    base, failures = orchestrate(
        pipeline, args.activity, args.scope, root=args.root,
        resume=args.resume, observe=args.observe, disabled_steps=disabled,
    )
    runconfig.snapshot(Path(base), resolved,
                       disabled_keys=[f"steps.{pipeline.name}.{n}" for n in sorted(disabled)])
    print(base)  # noqa: T201
```

- [ ] **Step 2: Rewrite the followup loop** (replace the `for fu in get_followups(...)` block, lines 168-183) to bind the followup pipeline and resolve its own disabled set:

```python
    get_followups = getattr(pipeline, "followups", None)
    if callable(get_followups):
        for fu in get_followups(Activity(Path(base))):
            fu_pipeline = load_pipeline(fu.pipeline)
            try:
                fu_disabled = runconfig.resolve_disabled_steps(
                    config, overrides, fu_pipeline.name, {s.name for s in fu_pipeline.stages})
            except runconfig.ConfigError as e:
                print(f"config error: {e}", file=sys.stderr)  # noqa: T201
                return 2
            fu_base, fu_failures = orchestrate(
                fu_pipeline, fu.activity, fu.scope, root=str(base),
                resume=args.resume, observe=args.observe, disabled_steps=fu_disabled,
            )
            runconfig.snapshot(Path(fu_base), resolved,
                               disabled_keys=[f"steps.{fu_pipeline.name}.{n}" for n in sorted(fu_disabled)])
            print(fu_base)  # noqa: T201
            if fu_failures < 0:
                return 130
            exit_code = exit_code or (1 if fu_failures else 0)
    return exit_code
```

- [ ] **Step 3: Verify types + lint on the CLI**

Run: `uv run ty check src/ && uv run ruff check src/ptflow/cli.py`
Expected: clean (no errors).

- [ ] **Step 4: Smoke-check the run help still parses**

Run: `uv run ptflow run --help`
Expected: prints usage including `--set` and `--ai` (unchanged) with exit 0.

- [ ] **Step 5: Commit**

```bash
git add src/ptflow/cli.py
git commit -m "feat(steps): wire disabled-step resolution into ptflow run (+ followups)"
```

---

### Task 6: `ptflow steps` subcommand + `render_steps`

Add the visualization command and its pure renderer.

**Files:**
- Modify: `src/ptflow/cli.py` (TYPE_CHECKING import; module-level `_BAND_ORDER`/`_band_sort_key`/`render_steps`; `steps` subparser in `main`; dispatch; `_steps` handler)
- Test: `tests/core/test_cli.py` (new)

**Interfaces:**
- Consumes: `runconfig.resolve_disabled_steps`, `load_pipeline`, `stage_band`/`impacted_dependents` (Task 1)
- Produces: `render_steps(pipeline: Pipeline, disabled: Collection[str], *, verbose: bool = False) -> str`; `ptflow steps <pipeline>` CLI command.

- [ ] **Step 1: Write the failing tests** in a new file `tests/core/test_cli.py`:

```python
from ptflow.cli import render_steps
from ptflow.pipelines import load_pipeline


def test_render_steps_all_active():
    out = render_steps(load_pipeline("example"), frozenset())
    assert "example — 3 step" in out
    assert "● discover" in out and "● scope_scan" in out and "● enum" in out
    assert "○ discover" not in out and "○ scope_scan" not in out and "○ enum" not in out


def test_render_steps_marks_disabled_and_impacted():
    out = render_steps(load_pipeline("example"), frozenset({"discover"}))
    assert "(1 disabilitati)" in out
    assert "○ discover" in out
    # scope_scan needs discover → it shows up in the impacted-dependents warning
    assert "scope_scan" in out.split("input assenti:")[1]


def test_render_steps_verbose_shows_needs_and_scope():
    out = render_steps(load_pipeline("example"), frozenset(), verbose=True)
    assert "needs=discover" in out
    assert "per_app" in out and "activity" in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_cli.py -v`
Expected: FAIL (`ImportError: cannot import name 'render_steps' from 'ptflow.cli'`)

- [ ] **Step 3: Add the TYPE_CHECKING import** to `src/ptflow/cli.py`. After the existing top-level imports (after `from ptflow.core.log import setup_logging`), add:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Collection

    from ptflow.core.stage import Pipeline
```

- [ ] **Step 4: Add the renderer** at module level in `src/ptflow/cli.py` (e.g. just above `def main`):

```python
_BAND_ORDER = ("breadth", "spanning", "post-cluster")


def _band_sort_key(band: str) -> tuple[int, int]:
    """Order bands breadth → spanning → post-cluster → loop:1 → loop:2 … (pure)."""
    if band in _BAND_ORDER:
        return (_BAND_ORDER.index(band), 0)
    phase = int(band.split(":", 1)[1]) if band.startswith("loop:") else 0
    return (len(_BAND_ORDER), phase)


def render_steps(pipeline: Pipeline, disabled: Collection[str], *, verbose: bool = False) -> str:
    """Render every step of `pipeline` grouped by band, with ● (active) / ○ (disabled) — the live,
    always-current step view. Pure: takes the resolved `disabled` set so it matches a run exactly.
    `verbose` adds each step's phase / scope / net / needs on its own line."""
    from ptflow.core.stage import impacted_dependents, stage_band  # noqa: PLC0415

    stages = list(pipeline.stages)
    disabled_set = set(disabled)
    groups: dict[str, list] = {}
    for s in stages:  # preserve declared order within each band
        groups.setdefault(stage_band(s), []).append(s)

    n_off = sum(1 for s in stages if s.name in disabled_set)
    header = f"{pipeline.name} — {len(stages)} step" + (f" ({n_off} disabilitati)" if n_off else "")
    lines = [header, ""]
    for band in sorted(groups, key=_band_sort_key):
        members = groups[band]
        if verbose:
            for s in members:
                mark = "○" if s.name in disabled_set else "●"
                bits = [f"phase={s.phase}", "per_app" if s.per_app else "activity",
                        "net" if s.net else "offline"]
                if s.needs:
                    bits.append("needs=" + ",".join(s.needs))
                lines.append(f"  {band:<13} {mark} {s.name:<22} [{' · '.join(bits)}]")
        else:
            cells = "   ".join(("○" if s.name in disabled_set else "●") + " " + s.name for s in members)
            lines.append(f"  {band:<13} {cells}")
    lines += ["", "○ = disabilitato   ● = attivo"]
    impacted = impacted_dependents(stages, disabled_set)
    if impacted:
        lines.append("⚠ dipendenti che gireranno con input assenti: " + ", ".join(impacted))
    return "\n".join(lines)
```

- [ ] **Step 5: Run the renderer tests to verify they pass**

Run: `uv run pytest tests/core/test_cli.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Add the `steps` subparser** in `main`, after the `doctor` subparser block (after line 84, before `args = parser.parse_args(argv)`):

```python
    steps = sub.add_parser(
        "steps", help="list a pipeline's steps and their effective on/off state",
    )
    steps.add_argument("pipeline")
    steps.add_argument(
        "--config", default=None, metavar="PATH",
        help="TOML file of operator knobs — reads its [steps.<pipeline>] table",
    )
    steps.add_argument(
        "--set", action="append", default=None, metavar="KEY=VALUE", dest="overrides",
        help="override a toggle, repeatable (e.g. --set steps.external.dast=off)",
    )
    steps.add_argument(
        "-v", "--verbose", action="store_true",
        help="also show each step's phase / scope / net / needs",
    )
```

- [ ] **Step 7: Add the dispatch** in `main`, after the `doctor` dispatch (after line 98 `return _doctor(args.pipeline)`):

```python
    if args.cmd == "steps":
        return _steps(args)
```

- [ ] **Step 8: Add the `_steps` handler** in `src/ptflow/cli.py` (e.g. after `_doctor`):

```python
def _steps(args: argparse.Namespace) -> int:
    """List a pipeline's steps grouped by band, with the effective on/off state given --config/--set.
    Reads the pipeline's live `stages`, so the view is always current (nothing generated to drift)."""
    from ptflow.pipelines import load_pipeline  # noqa: PLC0415

    try:
        config = runconfig.load_config(args.config)
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    pipeline = load_pipeline(args.pipeline)
    try:
        disabled = runconfig.resolve_disabled_steps(
            config, args.overrides, pipeline.name, {s.name for s in pipeline.stages})
    except runconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)  # noqa: T201
        return 2
    print(render_steps(pipeline, disabled, verbose=args.verbose))  # noqa: T201
    return 0
```

- [ ] **Step 9: Verify the command end-to-end**

Run: `uv run ptflow steps example` then `uv run ptflow steps example --set steps.example.discover=off -v`
Expected: first prints all 3 steps as `●` grouped by band; second marks `○ discover`, shows `(1 disabilitati)`, the `needs=discover` verbose detail on `scope_scan`, and the impacted-dependents warning naming `scope_scan`.

- [ ] **Step 10: Verify the unknown-step error path**

Run: `uv run ptflow steps example --set steps.example.nope=off; echo "exit=$?"`
Expected: prints `config error: unknown step 'nope' for pipeline 'example' — valid: discover, enum, scope_scan` and `exit=2`.

- [ ] **Step 11: Lint + types**

Run: `uv run ruff check src/ptflow/cli.py tests/core/test_cli.py && uv run ty check src/`
Expected: clean.

- [ ] **Step 12: Commit**

```bash
git add src/ptflow/cli.py tests/core/test_cli.py
git commit -m "feat(steps): ptflow steps subcommand + render_steps view"
```

---

### Task 7: Documentation

Document the toggles + command in `CLAUDE.md` and add a commented example to `ptflow.toml.example`.

**Files:**
- Modify: `CLAUDE.md` (the `## Commands` code block; the `### Run config (operator knobs)` section)
- Modify: `ptflow.toml.example`

- [ ] **Step 1: Add the `steps` command to `CLAUDE.md`.** In the `## Commands` fenced block, after the `uv run ptflow doctor ...` lines, add:

```bash
uv run ptflow steps <pipeline> [--config ptflow.toml] [--set KEY=VALUE ...] [-v]
                                                       # list every step grouped by band + its
                                                       # effective on/off state (live view; -v adds
                                                       # phase/scope/net/needs). Read-only, exit 0.
```

- [ ] **Step 2: Document the toggles in `CLAUDE.md`.** At the end of the `### Run config (operator knobs)` section, add a paragraph:

```markdown
**Per-step on/off toggles (debug).** A sparse `[steps.<pipeline>]` table disables named stages for a
run — `dast = false` under `[steps.external]`, or the one-off `--set steps.external.dast=off` (precedence
`--set` > config file; no env layer). Only listed steps change; everything else stays ON. Step names are
validated against the pipeline's **live `stages`** (unknown name → config error, exit 2), so the config
can't reference a deleted/renamed step — that, plus the live `ptflow steps <pipeline>` view, is how the
feature stays in sync with the code (nothing generated to drift). Mechanically the resolved set FILTERS
`pipeline.stages` before the DAG is built (`orchestrator._run_dag`); this needs no `needs` rewrite because
`topo_order`/`_submit_dag` already ignore missing dependency names and stages read on-disk inputs
tolerantly — a disabled step's dependents still run, degrading on absent inputs (a WARNING at run start
lists them). Disabled steps are recorded in `<activity>/config.toml`. Non-`Stage` hooks (`cluster`,
`consolidate`, `provider`, `report`, `followups`) are not toggleable.
```

- [ ] **Step 3: Add the example block to `ptflow.toml.example`.** Append at the end of the file:

```toml
# ── Per-step on/off toggles (debug) ─────────────────────────────────────────
# Disable named stages for a run. Sparse: only what you list changes; everything else stays ON.
# Names are validated against the pipeline's live stages — see them with `ptflow steps <pipeline>`.
# One-off equivalent:  --set steps.external.dast=off
# [steps.external]
# nuclei_scope = false      # skip the whole-scope nuclei spanning scan
# dast = false              # skip the phase-2 DAST (its dependents still run, on absent inputs)
```

- [ ] **Step 4: Verify the docs render (no broken fences) and nothing else regressed**

Run: `uv run ruff check . `
Expected: clean (docs aren't linted, but this confirms no stray code change slipped in).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md ptflow.toml.example
git commit -m "docs(steps): document per-step toggles + ptflow steps command"
```

---

### Task 8: Full dev gate + end-to-end verification

Confirm the whole gate is green and the feature works on a real pipeline run.

**Files:** none (verification only)

- [ ] **Step 1: Run the full dev gate**

Run: `uv run ruff check . && uv run ty check src/ && uv run pytest`
Expected: ruff clean, ty clean, all tests pass (including the new `test_stage.py`/`test_runconfig.py`/`test_orchestrator.py`/`test_cli.py` cases).

- [ ] **Step 2: End-to-end run of the `example` pipeline with a step disabled.** The example pipeline needs no external tools.

```bash
cd "$(mktemp -d)"
printf 'scanme.example\n' > scope.txt
uv run --project /opt/ptflow ptflow run example act scope.txt --set steps.example.scope_scan=off -v 2>&1 | tee run.log
```

Expected in the log: a line `▶ steps disabled: scope_scan`; the `▶ spanning (∥): ...` line does NOT list `scope_scan` (it's filtered out); the run completes (`✓ done → …`).

- [ ] **Step 3: Confirm the disabled stage did not run and is snapshotted**

```bash
ACT=$(ls -d act 2>/dev/null || echo act)
test ! -f "$ACT/.state/scope_scan.done" && echo "OK: scope_scan did not run"
grep -q 'steps.example.scope_scan = "off"' "$ACT/config.toml" && echo "OK: snapshotted"
test -f "$ACT/.state/discover.done" && echo "OK: discover (enabled) ran"
```

Expected: all three `OK:` lines print (disabled stage has no `.done` marker; the toggle is in `config.toml`; an enabled stage ran).

- [ ] **Step 4: Confirm `ptflow steps` reflects the same config file**

```bash
uv run --project /opt/ptflow ptflow steps example --config "$ACT/config.toml"
```

Expected: `scope_scan` renders as `○` (disabled), matching the run.

- [ ] **Step 5: Final commit (if any verification-only tweaks were needed; otherwise skip)**

```bash
git add -A && git commit -m "test(steps): e2e verification of per-step toggles on example pipeline" || echo "nothing to commit"
```

---

## Self-Review

**Spec coverage** (each spec section → task):
- §3 operator surface (`[steps.<pipeline>]` + `--set`, sparse, bool) → Task 2 (resolver) + Task 5 (wiring) + Task 7 (docs).
- §2 validation (unknown name → ConfigError, exit 2) → Task 2 (raise) + Task 5/6 (exit-2 mapping) + Task 6 Step 10 (verified).
- §4 filtering safety + impacted warning → Task 1 (`enabled_stages`/`impacted_dependents` + tolerance test) + Task 4 (wiring + warning).
- §5 plumbing (`steps.` prefix, `resolve_disabled_steps`, `orchestrate` param, snapshot) → Tasks 2, 3, 4, 5.
- §6 `ptflow steps` view (bands, ●/○, `-v`, live) → Task 6.
- §7 error handling (unknown name, other-pipeline keys ignored, disabling breadth allowed) → Task 2 (`scopes_to_pipeline` test) + Task 4 (warning); disabling breadth is not special-cased (allowed) — consistent with spec.
- §8 testing (resolver / orchestrator / command / snapshot; no new gate) → Tasks 1-3, 6, 8.
- §9 docs → Task 7.

**Placeholder scan:** no TBD/TODO; every code step shows full code; every command has an expected result. ✔

**Type consistency:** `resolve_disabled_steps` signature identical in Task 2 (def), Task 5, Task 6. `snapshot(..., disabled_keys=...)` identical in Task 3 (def) and Tasks 5. `orchestrate(..., disabled_steps=...)` and `_run_dag(..., disabled=...)` identical in Task 4 (def) and Task 5 (call). `stage_band`/`enabled_stages`/`impacted_dependents` signatures identical across Tasks 1, 4, 6. `render_steps(pipeline, disabled, *, verbose)` identical in Task 6 (def) and its tests. ✔

**Known limitation (documented, not a gap):** `impacted_dependents` models only `needs`-declared (same-scope) edges; cross-loop consumers that read another loop's artifacts across the barrier (e.g. `dast` reading `requests.jsonl`) are not flagged, because those dependencies aren't declared in `Stage` metadata. Matches spec §4.
