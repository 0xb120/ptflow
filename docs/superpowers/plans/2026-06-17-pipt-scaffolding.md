# PIPT Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable Prefect-based scaffolding that hosts multiple pentest pipelines, with raw files on disk as source of truth, a light SQLite projection populated by a serialized ingest, declarative breadth/depth phased-hybrid orchestration, an optional pre-enum dedup step, and a stubbed agent/vuln-hypothesis seam — plus a minimal example pipeline (stub tools) that exercises the whole thing end-to-end.

**Architecture:** A `core/` framework package (config, paths, workspace, tools, db, ingest, stage, agent, orchestrator) and `pipelines/<name>/` plugins. Depth stages fan out per-target via Prefect; only strings cross the Prefect task boundary (workers reconstruct objects from a pipeline registry + per-target `meta.json`). Workers write only raw + `manifest.jsonl`; a single serialized `ingest` upserts into SQLite at barriers. The DB is a rebuildable cache, never source of truth.

**Tech Stack:** Python ≥3.11, uv (build + runner), Prefect ≥3, stdlib `sqlite3`, ruff (`ALL`), ty, pytest.

## Global Constraints

- Python `requires-python = ">=3.11"`; `target-version = "py311"`.
- Dependencies: `prefect>=3.0` only (runtime). Dev groups: `ruff`, `ty`, `pytest`, `pytest-cov`.
- Build backend: `uv_build`. Package under `src/pipt/`. Console script: `pipt = "pipt.cli:main"`.
- ruff `select = ["ALL"]` with the same ignores as the reference pipeline: `D, COM812, ISC001, S603, S607, TC001, TC003, ERA001, ANN401, E501`. `line-length = 100`.
- SQLite always opened with `PRAGMA foreign_keys=ON`, `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=<config>`.
- No path literals in tasks/flows — paths only via `Engagement` / `TargetWorkspace`.
- No step reads from `raw/`; tools write `raw/<tool>/`, then promote to a canonical artifact and append a `manifest.jsonl` row.
- Stable `target_id` = `"t_" + sha1(normalized)[:6]`.
- Canonical inter-stage artifacts are JSONL (one JSON object per line).
- The DB is never written by fan-out workers — only by the serialized `ingest`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `pyproject.toml` | Project metadata, deps, ruff/ty config, console script |
| `src/pipt/__init__.py` | Package marker |
| `src/pipt/core/__init__.py` | Package marker |
| `src/pipt/core/config.py` | Frozen dataclass config + `CONFIG` singleton |
| `src/pipt/core/tools.py` | subprocess plumbing: `run`, `pipe`, `dedupe`, `read_lines`, `write_lines`, `require` |
| `src/pipt/core/scope.py` | `Target`, `classify`, `normalize`, `target_id`, `parse_scope`, `target_from_meta` |
| `src/pipt/core/paths.py` | `Engagement`, `TargetWorkspace` (all contract paths) |
| `src/pipt/core/workspace.py` | `manifest.jsonl` + `meta.json` helpers |
| `db/schema.sql` | Core light schema (target/host/service/host_target/hypothesis) |
| `src/pipt/core/db.py` | connect (WAL), `core_schema`, `init_schema`, upserts, query API |
| `src/pipt/core/ingest.py` | serialized ingest: manifest → handlers → upsert; core handlers |
| `src/pipt/core/stage.py` | `Mode` enum, `Stage` dataclass, `Pipeline` protocol, `Handler` type |
| `src/pipt/core/agent.py` | `HypothesisDraft`, `HypothesisProvider`, `StubProvider`, `propose_hypotheses` |
| `src/pipt/core/orchestrator.py` | `split_stages`, `assign_enum_hosts`, `_depth_flow`, `orchestrate` |
| `src/pipt/pipelines/__init__.py` | `load_pipeline(name)` registry |
| `src/pipt/pipelines/example/__init__.py` | Package marker |
| `src/pipt/pipelines/example/tasks.py` | stub `discover` (breadth) + `enum` (depth) |
| `src/pipt/pipelines/example/schema.sql` | one demo extension table |
| `src/pipt/pipelines/example/pipeline.py` | `ExamplePipeline` + `PIPELINE` |
| `src/pipt/cli.py` | `pipt run` / `pipt ingest` |
| `README.md`, `CONVENTIONS.md` | docs |
| `tests/...` | one test module per source module + one e2e test |

---

## Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/pipt/__init__.py`
- Create: `src/pipt/core/__init__.py`
- Create: `src/pipt/pipelines/__init__.py` (temporary stub, finalized in Task 9)
- Create: `tests/test_smoke.py`

**Interfaces:**
- Produces: an installable package `pipt`, working `uv run pytest` / `uv run ruff` / `uv run ty`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smoke.py
def test_package_imports():
    import pipt

    assert pipt is not None
```

- [ ] **Step 2: Create the project files**

```toml
# pyproject.toml
[project]
name = "pipt"
version = "0.1.0"
description = "Prefect scaffolding for automated pentest pipelines — raw-on-disk + light SQLite projection."
requires-python = ">=3.11"
dependencies = ["prefect>=3.0"]

[project.scripts]
pipt = "pipt.cli:main"

[build-system]
requires = ["uv_build"]
build-backend = "uv_build"

[dependency-groups]
dev = [{ include-group = "lint" }, { include-group = "test" }]
lint = ["ruff", "ty"]
test = ["pytest", "pytest-cov"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["ALL"]
ignore = ["D", "COM812", "ISC001", "S603", "S607", "TC001", "TC003", "ERA001", "ANN401", "E501"]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101", "ANN", "INP001", "PLR2004"]

[tool.ty.environment]
python-version = "3.11"
```

```python
# src/pipt/__init__.py
"""PIPT — Prefect scaffolding for automated pentest pipelines."""
```

```python
# src/pipt/core/__init__.py
"""Reusable framework core shared by all pipelines."""
```

```python
# src/pipt/pipelines/__init__.py
"""Pluggable pipelines. Finalized with load_pipeline() in a later task."""
```

- [ ] **Step 3: Sync and run the test**

Run: `uv sync --all-groups && uv run pytest tests/test_smoke.py -v`
Expected: PASS (1 test).

- [ ] **Step 4: Verify lint/type harness works**

Run: `uv run ruff check . && uv run ty check src/`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock src/ tests/
git commit -m "chore: scaffold pipt package (uv, ruff, ty, pytest)"
```

---

## Task 2: `core/config.py`

**Files:**
- Create: `src/pipt/core/config.py`
- Test: `tests/core/test_config.py`

**Interfaces:**
- Produces: `CONFIG` singleton with `CONFIG.fanout.max_workers: int`, `CONFIG.fanout.net_limit: int`, `CONFIG.retries.tool_retries: int`, `CONFIG.retries.tool_retry_delay_s: int`, `CONFIG.db.busy_timeout_ms: int`.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_config.py
from pipt.core.config import CONFIG, Config


def test_defaults():
    assert CONFIG.fanout.max_workers == 3
    assert CONFIG.fanout.net_limit == 10
    assert CONFIG.retries.tool_retries == 2
    assert CONFIG.db.busy_timeout_ms == 5000


def test_frozen():
    import dataclasses
    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        CONFIG.fanout.max_workers = 99  # type: ignore[misc]


def test_overridable_for_tests():
    cfg = Config()
    assert cfg.fanout.max_workers == 3
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pipt.core.config'`.

- [ ] **Step 3: Implement**

```python
# src/pipt/core/config.py
"""Centralized configuration — every tunable here, nothing hardcoded in tasks."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FanOut:
    max_workers: int = 3       # concurrent per-target depth chains (xargs -P 3 equivalent)
    net_limit: int = 10        # optional global Prefect concurrency limit on tag "net"


@dataclass(frozen=True)
class Retries:
    tool_retries: int = 2
    tool_retry_delay_s: int = 10


@dataclass(frozen=True)
class DB:
    busy_timeout_ms: int = 5000


@dataclass(frozen=True)
class Config:
    fanout: FanOut = field(default_factory=FanOut)
    retries: Retries = field(default_factory=Retries)
    db: DB = field(default_factory=DB)


CONFIG = Config()
"""Module-level singleton. Import and read; construct Config() to override in tests."""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_config.py -v && uv run ruff check src/pipt/core/config.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/config.py tests/core/test_config.py
git commit -m "feat(core): central config singleton"
```

---

## Task 3: `core/tools.py`

**Files:**
- Create: `src/pipt/core/tools.py`
- Test: `tests/core/test_tools.py`

**Interfaces:**
- Produces:
  - `dedupe(lines: Iterable[str]) -> list[str]` — stable first-seen dedup, strips, drops blanks.
  - `read_lines(path: Path) -> list[str]` — non-blank stripped lines, `[]` if missing.
  - `write_lines(path: Path, lines: Iterable[str]) -> int` — dedupe + write, returns count.
  - `run(cmd, *, stdin=None, check=False, timeout=None, cwd=None) -> str` — stdout.
  - `pipe(stages, *, stdin=None) -> str` — in-process `a | b | c`.
  - `require(*tools: str) -> None` — raise `ToolNotFoundError` if any missing on PATH.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_tools.py
from pipt.core import tools


def test_dedupe_preserves_order_strips_blanks():
    assert tools.dedupe(["b", " b ", "a", "", "a", "c"]) == ["b", "a", "c"]


def test_write_then_read_roundtrip(tmp_path):
    p = tmp_path / "out.txt"
    n = tools.write_lines(p, ["x", "x", "y"])
    assert n == 2
    assert tools.read_lines(p) == ["x", "y"]


def test_read_missing_returns_empty(tmp_path):
    assert tools.read_lines(tmp_path / "nope.txt") == []


def test_run_echoes_stdout():
    assert tools.run(["printf", "hello"]) == "hello"


def test_pipe_chains_processes():
    out = tools.pipe([["printf", "a\nb\na\n"], ["sort", "-u"]])
    assert out.splitlines() == ["a", "b"]


def test_require_raises_for_missing_tool():
    import pytest

    with pytest.raises(tools.ToolNotFoundError):
        tools.require("definitely-not-a-real-binary-xyz")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_tools.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/tools.py
"""Subprocess plumbing for external CLI tools — substrate for thin adapters."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

Command = Sequence[str]


class ToolNotFoundError(RuntimeError):
    """A required external tool is not on PATH."""


def require(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        msg = f"missing required tool(s): {', '.join(missing)}"
        raise ToolNotFoundError(msg)


def run(
    cmd: Command,
    *,
    stdin: str | None = None,
    check: bool = False,
    timeout: int | None = None,
    cwd: Path | None = None,
) -> str:
    proc = subprocess.run(
        list(cmd),
        input=stdin,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
        cwd=cwd,
    )
    return proc.stdout


def pipe(stages: Sequence[Command], *, stdin: str | None = None) -> str:
    if not stages:
        return ""
    procs: list[subprocess.Popen[bytes]] = []
    first = subprocess.Popen(
        list(stages[0]),
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    procs.append(first)
    for stage in stages[1:]:
        prev = procs[-1]
        nxt = subprocess.Popen(
            list(stage),
            stdin=prev.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if prev.stdout is not None:
            prev.stdout.close()
        procs.append(nxt)
    out, _ = procs[-1].communicate(input=stdin.encode() if stdin is not None else None)
    for p in procs[:-1]:
        p.wait()
    return out.decode(errors="replace")


def dedupe(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> int:
    deduped = dedupe(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(deduped) + ("\n" if deduped else ""), encoding="utf-8")
    return len(deduped)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_tools.py -v && uv run ruff check src/pipt/core/tools.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/tools.py tests/core/test_tools.py
git commit -m "feat(core): subprocess plumbing (run/pipe/dedupe helpers)"
```

---

## Task 4: `core/scope.py`

**Files:**
- Create: `src/pipt/core/scope.py`
- Test: `tests/core/test_scope.py`

**Interfaces:**
- Produces:
  - `Target` (frozen dataclass): `.raw: str`, `.kind: str`, `.normalized: str`, `.tid: str`.
  - `classify(token: str) -> str` → one of `domain|ip|cidr|url|wildcard`.
  - `normalize(token: str, kind: str) -> str`.
  - `target_id(normalized: str) -> str` → `"t_" + sha1(normalized)[:6]`.
  - `parse_scope(text: str) -> list[Target]` — dedup by `tid`, skip blanks/`#` comments.
  - `target_from_meta(meta: dict) -> Target`.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_scope.py
from pipt.core import scope


def test_classify():
    assert scope.classify("example.com") == "domain"
    assert scope.classify("https://a.example.com/x") == "url"
    assert scope.classify("*.example.com") == "wildcard"
    assert scope.classify("10.0.0.1") == "ip"
    assert scope.classify("10.0.0.0/24") == "cidr"


def test_normalize_url_and_wildcard():
    assert scope.normalize("https://A.Example.com/login", "url") == "a.example.com"
    assert scope.normalize("*.Example.com", "wildcard") == "example.com"
    assert scope.normalize("Example.COM", "domain") == "example.com"


def test_target_id_stable_and_prefixed():
    tid = scope.target_id("example.com")
    assert tid.startswith("t_")
    assert len(tid) == 8
    assert tid == scope.target_id("example.com")


def test_parse_scope_dedups_and_skips_comments():
    text = "example.com\n# comment\n\nhttps://example.com/path\nnmap.org\n"
    targets = scope.parse_scope(text)
    # example.com and https://example.com/path normalize to the same host -> one target
    norms = sorted(t.normalized for t in targets)
    assert norms == ["example.com", "nmap.org"]


def test_target_from_meta_roundtrip():
    t = scope.Target(raw="example.com", kind="domain", normalized="example.com", tid="t_abc123")
    assert scope.target_from_meta(t.__dict__) == t
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_scope.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/scope.py
"""Scope parsing: turn raw scope tokens into stable Target records."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str
    normalized: str
    tid: str


def classify(token: str) -> str:
    t = token.strip()
    if t.startswith(("http://", "https://")):
        return "url"
    if t.startswith("*."):
        return "wildcard"
    if _CIDR.match(t):
        return "cidr"
    if _IP.match(t):
        return "ip"
    return "domain"


def normalize(token: str, kind: str) -> str:
    t = token.strip().lower()
    if kind == "url":
        return t.split("://", 1)[1].split("/", 1)[0]
    if kind == "wildcard":
        return t[2:]
    return t


def target_id(normalized: str) -> str:
    return "t_" + hashlib.sha1(normalized.encode()).hexdigest()[:6]  # noqa: S324


def parse_scope(text: str) -> list[Target]:
    seen: dict[str, Target] = {}
    for line in text.splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        kind = classify(token)
        norm = normalize(token, kind)
        tid = target_id(norm)
        if tid not in seen:
            seen[tid] = Target(raw=token, kind=kind, normalized=norm, tid=tid)
    return list(seen.values())


def target_from_meta(meta: dict) -> Target:
    return Target(
        raw=meta["raw"],
        kind=meta["kind"],
        normalized=meta["normalized"],
        tid=meta["tid"],
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_scope.py -v && uv run ruff check src/pipt/core/scope.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/scope.py tests/core/test_scope.py
git commit -m "feat(core): scope parsing into stable Target records"
```

---

## Task 5: `core/paths.py`

**Files:**
- Create: `src/pipt/core/paths.py`
- Test: `tests/core/test_paths.py`

**Interfaces:**
- Produces:
  - `TargetWorkspace(root: Path)` with `.root`, `.meta`, `.manifest`, `.findings`, `.raw(tool) -> Path`, `.canonical(name) -> Path`, `.ensure() -> TargetWorkspace`.
  - `Engagement(base: Path)` with `.base`, classmethod `for_scan(scan_id, root=None)`, `.scope`, `.db`, `.surface`, `.surface_raw(tool)`, `.surface_manifest`, `.surface_canonical(name)`, `.targets`, `.target(tid) -> TargetWorkspace`, `.list_targets() -> list[TargetWorkspace]`, `.ensure() -> Engagement`.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_paths.py
from pipt.core.paths import Engagement, TargetWorkspace


def test_engagement_layout(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path)
    assert eng.base == tmp_path / "demo"
    assert eng.scope == tmp_path / "demo" / "scope.txt"
    assert eng.db == tmp_path / "demo" / "db" / "engagement.db"
    assert eng.surface_canonical("hosts.jsonl") == tmp_path / "demo" / "surface" / "hosts.jsonl"
    assert eng.surface_raw("discover") == tmp_path / "demo" / "surface" / "raw" / "discover"


def test_target_workspace_paths(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path)
    ws = eng.target("t_abc123")
    assert isinstance(ws, TargetWorkspace)
    assert ws.canonical("services.jsonl") == eng.targets / "t_abc123" / "services.jsonl"
    assert ws.raw("enum") == eng.targets / "t_abc123" / "raw" / "enum"
    assert ws.manifest == eng.targets / "t_abc123" / "manifest.jsonl"


def test_ensure_and_list_targets(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path).ensure()
    assert eng.surface.is_dir()
    assert eng.db.parent.is_dir()
    eng.target("t_aaa111").ensure()
    eng.target("t_bbb222").ensure()
    tids = sorted(ws.root.name for ws in eng.list_targets())
    assert tids == ["t_aaa111", "t_bbb222"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_paths.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/paths.py
"""Single source of truth for every path — no literal paths in tasks/flows."""

from __future__ import annotations

from pathlib import Path


class TargetWorkspace:
    """Per-target workspace (output of DEPTH stages). All paths derived."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def meta(self) -> Path:
        return self.root / "meta.json"

    @property
    def manifest(self) -> Path:
        return self.root / "manifest.jsonl"

    @property
    def findings(self) -> Path:
        return self.root / "findings"

    def raw(self, tool: str) -> Path:
        return self.root / "raw" / tool

    def canonical(self, name: str) -> Path:
        return self.root / name

    def ensure(self) -> TargetWorkspace:
        self.root.mkdir(parents=True, exist_ok=True)
        self.findings.mkdir(parents=True, exist_ok=True)
        return self


class Engagement:
    """Top-level engagement workspace (one scan_id)."""

    def __init__(self, base: Path) -> None:
        self.base = base

    @classmethod
    def for_scan(cls, scan_id: str, root: Path | None = None) -> Engagement:
        return cls((root or Path("scans")) / scan_id)

    @property
    def scope(self) -> Path:
        return self.base / "scope.txt"

    @property
    def db(self) -> Path:
        return self.base / "db" / "engagement.db"

    # --- surface (BREADTH output) ---
    @property
    def surface(self) -> Path:
        return self.base / "surface"

    def surface_raw(self, tool: str) -> Path:
        return self.surface / "raw" / tool

    @property
    def surface_manifest(self) -> Path:
        return self.surface / "manifest.jsonl"

    def surface_canonical(self, name: str) -> Path:
        return self.surface / name

    # --- targets (DEPTH output) ---
    @property
    def targets(self) -> Path:
        return self.base / "targets"

    def target(self, tid: str) -> TargetWorkspace:
        return TargetWorkspace(self.targets / tid)

    def list_targets(self) -> list[TargetWorkspace]:
        if not self.targets.exists():
            return []
        return [TargetWorkspace(d) for d in sorted(self.targets.iterdir()) if d.is_dir()]

    def ensure(self) -> Engagement:
        for d in (self.surface, self.targets, self.db.parent):
            d.mkdir(parents=True, exist_ok=True)
        return self
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_paths.py -v && uv run ruff check src/pipt/core/paths.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/paths.py tests/core/test_paths.py
git commit -m "feat(core): Engagement/TargetWorkspace path contract"
```

---

## Task 6: `core/workspace.py`

**Files:**
- Create: `src/pipt/core/workspace.py`
- Test: `tests/core/test_workspace.py`

**Interfaces:**
- Produces:
  - `record(manifest: Path, *, role: str, path: Path, tool: str, inputs: str | None = None) -> None`.
  - `latest(manifest: Path, role: str) -> Path | None`.
  - `roles(manifest: Path) -> dict[str, Path]` — role → latest absolute path.
  - `write_meta(meta_path: Path, data: dict) -> None`.
  - `read_meta(meta_path: Path) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_workspace.py
from pipt.core import workspace


def test_record_and_latest(tmp_path):
    m = tmp_path / "manifest.jsonl"
    art = tmp_path / "hosts.jsonl"
    art.write_text("{}\n")
    workspace.record(m, role="hosts", path=art, tool="discover")
    assert workspace.latest(m, "hosts") == art
    assert workspace.latest(m, "missing") is None


def test_latest_returns_most_recent(tmp_path):
    m = tmp_path / "manifest.jsonl"
    (tmp_path / "a.jsonl").write_text("")
    (tmp_path / "b.jsonl").write_text("")
    workspace.record(m, role="hosts", path=tmp_path / "a.jsonl", tool="t1")
    workspace.record(m, role="hosts", path=tmp_path / "b.jsonl", tool="t2")
    assert workspace.latest(m, "hosts") == tmp_path / "b.jsonl"


def test_roles_maps_each_role(tmp_path):
    m = tmp_path / "manifest.jsonl"
    workspace.record(m, role="hosts", path=tmp_path / "h.jsonl", tool="t")
    workspace.record(m, role="services", path=tmp_path / "s.jsonl", tool="t")
    rmap = workspace.roles(m)
    assert set(rmap) == {"hosts", "services"}
    assert rmap["hosts"] == tmp_path / "h.jsonl"


def test_meta_roundtrip(tmp_path):
    p = tmp_path / "meta.json"
    workspace.write_meta(p, {"tid": "t_abc123", "kind": "domain"})
    assert workspace.read_meta(p)["tid"] == "t_abc123"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_workspace.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/workspace.py
"""manifest.jsonl + meta.json helpers. Consumers query by role, never by filename."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()


def record(
    manifest: Path,
    *,
    role: str,
    path: Path,
    tool: str,
    inputs: str | None = None,
) -> None:
    manifest.parent.mkdir(parents=True, exist_ok=True)
    try:
        rel = path.relative_to(manifest.parent)
    except ValueError:
        rel = path
    row = {"role": role, "path": str(rel), "tool": tool, "inputs": inputs, "ts": _now()}
    with manifest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def roles(manifest: Path) -> dict[str, Path]:
    """role -> latest recorded absolute path (last write wins)."""
    out: dict[str, Path] = {}
    if not manifest.exists():
        return out
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        out[row["role"]] = manifest.parent / row["path"]
    return out


def latest(manifest: Path, role: str) -> Path | None:
    return roles(manifest).get(role)


def write_meta(meta_path: Path, data: dict[str, Any]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_meta(meta_path: Path) -> dict[str, Any]:
    return json.loads(meta_path.read_text(encoding="utf-8"))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_workspace.py -v && uv run ruff check src/pipt/core/workspace.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/workspace.py tests/core/test_workspace.py
git commit -m "feat(core): manifest + meta helpers"
```

---

## Task 7: `db/schema.sql` + `core/db.py`

**Files:**
- Create: `db/schema.sql`
- Create: `src/pipt/core/db.py`
- Test: `tests/core/test_db.py`

**Interfaces:**
- Produces:
  - `core_schema() -> str` — reads `db/schema.sql`.
  - `connect(db_path: Path) -> sqlite3.Connection` — WAL + FK + busy_timeout, `row_factory=sqlite3.Row`.
  - `init_schema(conn, *schema_texts: str) -> None` — executescript each.
  - `upsert_target(conn, *, tid, raw, kind) -> int`.
  - `upsert_host(conn, *, name, ip=None, source=None) -> int`.
  - `upsert_service(conn, *, ip, port, protocol=None, service=None, version=None, source=None) -> int`.
  - `link_host_target(conn, host_id: int, target_id: int) -> None`.
  - `insert_hypothesis(conn, *, title, service_id=None, subject=None, rationale=None, technique=None, confidence=None, source=None) -> int`.
  - `list_hosts(conn) -> list[sqlite3.Row]`, `list_services(conn) -> list[sqlite3.Row]`, `list_hypotheses(conn) -> list[sqlite3.Row]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_db.py
from pipt.core import db


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def test_pragmas_set(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_upsert_target_is_idempotent(tmp_path):
    conn = _fresh(tmp_path)
    a = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    b = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    assert a == b
    assert conn.execute("SELECT COUNT(*) FROM target").fetchone()[0] == 1


def test_upsert_host_enriches_ip(tmp_path):
    conn = _fresh(tmp_path)
    hid = db.upsert_host(conn, name="a.example.com", source="dns")
    again = db.upsert_host(conn, name="a.example.com", ip="10.0.0.1", source="dns")
    assert hid == again
    row = conn.execute("SELECT ip FROM host WHERE id=?", (hid,)).fetchone()
    assert row["ip"] == "10.0.0.1"


def test_upsert_service_unique_per_ip_port(tmp_path):
    conn = _fresh(tmp_path)
    s1 = db.upsert_service(conn, ip="10.0.0.1", port=443, source="naabu")
    s2 = db.upsert_service(conn, ip="10.0.0.1", port=443, version="1.0", source="fingerprintx")
    assert s1 == s2
    assert conn.execute("SELECT version FROM service WHERE id=?", (s1,)).fetchone()["version"] == "1.0"


def test_link_host_target_and_insert_hypothesis(tmp_path):
    conn = _fresh(tmp_path)
    tid_id = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    hid = db.upsert_host(conn, name="example.com")
    db.link_host_target(conn, hid, tid_id)
    db.link_host_target(conn, hid, tid_id)  # idempotent
    assert conn.execute("SELECT COUNT(*) FROM host_target").fetchone()[0] == 1
    sid = db.upsert_service(conn, ip="10.0.0.1", port=22)
    hyp = db.insert_hypothesis(conn, title="t", service_id=sid, confidence="low", source="stub")
    assert hyp > 0
    assert len(db.list_hypotheses(conn)) == 1
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_db.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Create the schema**

```sql
-- db/schema.sql — CORE light schema. Pipelines add domain tables via their own schema.sql.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS target (
  id          INTEGER PRIMARY KEY,
  tid         TEXT NOT NULL UNIQUE,
  raw         TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('domain','ip','cidr','url','wildcard')),
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS host (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,          -- FQDN or IP literal
  ip          TEXT,
  source      TEXT,                          -- dns|tls|ptr|subfinder|scope|stub
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS service (
  id          INTEGER PRIMARY KEY,
  ip          TEXT NOT NULL,
  port        INTEGER NOT NULL,
  protocol    TEXT,
  service     TEXT,
  version     TEXT,
  source      TEXT,                          -- naabu|fingerprintx|nerva|stub
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (ip, port)
);

CREATE TABLE IF NOT EXISTS host_target (
  host_id    INTEGER NOT NULL REFERENCES host(id)   ON DELETE CASCADE,
  target_id  INTEGER NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  PRIMARY KEY (host_id, target_id)
);

CREATE TABLE IF NOT EXISTS hypothesis (
  id          INTEGER PRIMARY KEY,
  service_id  INTEGER REFERENCES service(id) ON DELETE CASCADE,
  subject     TEXT,                          -- free pointer to pipeline entities, e.g. "webasset:<url>"
  title       TEXT NOT NULL,
  rationale   TEXT,
  technique   TEXT,
  confidence  TEXT CHECK (confidence IN ('low','medium','high')),
  source      TEXT,                          -- 'stub' | model name
  status      TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','confirmed','dismissed')),
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

- [ ] **Step 4: Implement `db.py`**

```python
# src/pipt/core/db.py
"""SQLite layer: WAL connection, schema init, idempotent upserts, read API.

The DB is a rebuildable projection of the raw files — it is NEVER written by
fan-out workers, only by the serialized ingest (see ingest.py).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from pipt.core.config import CONFIG

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CORE_SCHEMA = _PROJECT_ROOT / "db" / "schema.sql"


def core_schema() -> str:
    return _CORE_SCHEMA.read_text(encoding="utf-8")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA busy_timeout = {CONFIG.db.busy_timeout_ms}")
    return conn


def init_schema(conn: sqlite3.Connection, *schema_texts: str) -> None:
    for text in schema_texts:
        if text:
            conn.executescript(text)
    conn.commit()


def upsert_target(conn: sqlite3.Connection, *, tid: str, raw: str, kind: str) -> int:
    conn.execute(
        "INSERT INTO target(tid, raw, kind) VALUES(?,?,?) ON CONFLICT(tid) DO NOTHING",
        (tid, raw, kind),
    )
    return conn.execute("SELECT id FROM target WHERE tid=?", (tid,)).fetchone()[0]


def upsert_host(
    conn: sqlite3.Connection,
    *,
    name: str,
    ip: str | None = None,
    source: str | None = None,
) -> int:
    conn.execute(
        "INSERT INTO host(name, ip, source) VALUES(?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET ip=COALESCE(excluded.ip, host.ip), "
        "last_seen=CURRENT_TIMESTAMP",
        (name, ip, source),
    )
    return conn.execute("SELECT id FROM host WHERE name=?", (name,)).fetchone()[0]


def upsert_service(
    conn: sqlite3.Connection,
    *,
    ip: str,
    port: int,
    protocol: str | None = None,
    service: str | None = None,
    version: str | None = None,
    source: str | None = None,
) -> int:
    conn.execute(
        "INSERT INTO service(ip, port, protocol, service, version, source) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(ip, port) DO UPDATE SET "
        "protocol=COALESCE(excluded.protocol, service.protocol), "
        "service=COALESCE(excluded.service, service.service), "
        "version=COALESCE(excluded.version, service.version)",
        (ip, port, protocol, service, version, source),
    )
    return conn.execute("SELECT id FROM service WHERE ip=? AND port=?", (ip, port)).fetchone()[0]


def link_host_target(conn: sqlite3.Connection, host_id: int, target_id: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO host_target(host_id, target_id) VALUES(?,?)",
        (host_id, target_id),
    )


def insert_hypothesis(
    conn: sqlite3.Connection,
    *,
    title: str,
    service_id: int | None = None,
    subject: str | None = None,
    rationale: str | None = None,
    technique: str | None = None,
    confidence: str | None = None,
    source: str | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO hypothesis(service_id, subject, title, rationale, technique, confidence, source) "
        "VALUES(?,?,?,?,?,?,?)",
        (service_id, subject, title, rationale, technique, confidence, source),
    )
    return int(cur.lastrowid or 0)


def list_hosts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM host ORDER BY name").fetchall()


def list_services(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM service ORDER BY ip, port").fetchall()


def list_hypotheses(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM hypothesis ORDER BY id").fetchall()
```

- [ ] **Step 5: Run tests, lint, type-check**

Run: `uv run pytest tests/core/test_db.py -v && uv run ruff check src/pipt/core/db.py && uv run ty check src/`
Expected: PASS, no errors.

- [ ] **Step 6: Commit**

```bash
git add db/schema.sql src/pipt/core/db.py tests/core/test_db.py
git commit -m "feat(core): light SQLite schema + db layer (WAL, idempotent upserts)"
```

---

## Task 8: `core/ingest.py`

**Files:**
- Create: `src/pipt/core/ingest.py`
- Test: `tests/core/test_ingest.py`

**Interfaces:**
- Consumes: `db` upserts, `workspace.roles`, `Target`.
- Produces:
  - `Handler = Callable[[sqlite3.Connection, list[dict]], None]`.
  - `ingest_hosts(conn, records) -> None` — upsert host + link `host_target` by each record's `targets: [tid,...]`.
  - `ingest_services(conn, records) -> None` — upsert service.
  - `CORE_HANDLERS: dict[str, Handler]` = `{"hosts": ingest_hosts, "services": ingest_services}`.
  - `read_jsonl(path: Path) -> list[dict]`.
  - `ingest_manifest(conn, manifest_path: Path, handlers: dict[str, Handler]) -> None` — for each role with a handler, read its artifact, call the handler, commit.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_ingest.py
import json

from pipt.core import db, ingest, workspace


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def test_ingest_hosts_links_provenance(tmp_path):
    conn = _fresh(tmp_path)
    db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    db.upsert_target(conn, tid="t_bbb222", raw="nmap.org", kind="domain")
    conn.commit()
    ingest.ingest_hosts(
        conn,
        [{"name": "shared.example", "ip": "10.0.0.9", "source": "stub",
          "targets": ["t_aaa111", "t_bbb222"]}],
    )
    assert conn.execute("SELECT COUNT(*) FROM host").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM host_target").fetchone()[0] == 2


def test_ingest_manifest_dispatches_by_role(tmp_path):
    conn = _fresh(tmp_path)
    art = tmp_path / "services.jsonl"
    art.write_text(json.dumps({"ip": "10.0.0.1", "port": 443, "service": "https"}) + "\n")
    m = tmp_path / "manifest.jsonl"
    workspace.record(m, role="services", path=art, tool="enum")
    ingest.ingest_manifest(conn, m, ingest.CORE_HANDLERS)
    rows = db.list_services(conn)
    assert len(rows) == 1
    assert rows[0]["service"] == "https"


def test_ingest_manifest_ignores_unknown_roles(tmp_path):
    conn = _fresh(tmp_path)
    art = tmp_path / "weird.jsonl"
    art.write_text("{}\n")
    m = tmp_path / "manifest.jsonl"
    workspace.record(m, role="not_a_known_role", path=art, tool="x")
    ingest.ingest_manifest(conn, m, ingest.CORE_HANDLERS)  # must not raise
    assert db.list_services(conn) == []
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_ingest.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/ingest.py
"""Serialized single-writer ingest: raw/manifest artifacts -> SQLite upserts.

Workers never touch the DB. This runs serially at barriers, reads canonical
artifacts by role from a manifest, and upserts. Idempotent — rerunnable from raw.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

from pipt.core import db, workspace

Handler = Callable[[sqlite3.Connection, list[dict]], None]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def ingest_hosts(conn: sqlite3.Connection, records: list[dict]) -> None:
    for r in records:
        hid = db.upsert_host(conn, name=r["name"], ip=r.get("ip"), source=r.get("source"))
        for tid in r.get("targets", []):
            row = conn.execute("SELECT id FROM target WHERE tid=?", (tid,)).fetchone()
            if row is not None:
                db.link_host_target(conn, hid, row[0])


def ingest_services(conn: sqlite3.Connection, records: list[dict]) -> None:
    for r in records:
        db.upsert_service(
            conn,
            ip=r["ip"],
            port=r["port"],
            protocol=r.get("protocol"),
            service=r.get("service"),
            version=r.get("version"),
            source=r.get("source"),
        )


CORE_HANDLERS: dict[str, Handler] = {
    "hosts": ingest_hosts,
    "services": ingest_services,
}


def ingest_manifest(
    conn: sqlite3.Connection,
    manifest_path: Path,
    handlers: dict[str, Handler],
) -> None:
    for role, artifact in workspace.roles(manifest_path).items():
        handler = handlers.get(role)
        if handler is None:
            continue
        handler(conn, read_jsonl(artifact))
    conn.commit()
```

- [ ] **Step 4: Run tests, lint**

Run: `uv run pytest tests/core/test_ingest.py -v && uv run ruff check src/pipt/core/ingest.py`
Expected: PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/ingest.py tests/core/test_ingest.py
git commit -m "feat(core): serialized manifest-driven ingest + core handlers"
```

---

## Task 9: `core/stage.py` + pipeline registry

**Files:**
- Create: `src/pipt/core/stage.py`
- Modify: `src/pipt/pipelines/__init__.py`
- Test: `tests/core/test_stage.py`

**Interfaces:**
- Produces:
  - `Mode` enum: `Mode.BREADTH`, `Mode.DEPTH` (values `"breadth"`, `"depth"`).
  - `Stage` frozen dataclass: `.name: str`, `.mode: Mode`, `.run: Callable`, `.produces: tuple[str, ...] = ()`.
    - BREADTH `run` signature: `run(eng: Engagement, targets: list[Target]) -> None`.
    - DEPTH `run` signature: `run(eng: Engagement, target: Target) -> None`.
  - `Pipeline` Protocol: attrs `name: str`, `stages: Sequence[Stage]`; methods `extension_schema() -> str`, `ingest_handlers() -> dict[str, Handler]`, `provider() -> HypothesisProvider`.
  - `load_pipeline(name: str) -> Pipeline` (in `pipelines/__init__.py`); raises `ValueError` on unknown name.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_stage.py
import pytest

from pipt.core.stage import Mode, Stage


def test_stage_fields():
    s = Stage(name="discover", mode=Mode.BREADTH, run=lambda eng, targets: None, produces=("hosts",))
    assert s.mode is Mode.BREADTH
    assert s.produces == ("hosts",)


def test_load_pipeline_unknown_raises():
    from pipt.pipelines import load_pipeline

    with pytest.raises(ValueError, match="unknown pipeline"):
        load_pipeline("does-not-exist")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_stage.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `stage.py`**

```python
# src/pipt/core/stage.py
"""Stage abstraction (declarative breadth/depth) + Pipeline protocol."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import sqlite3

    from pipt.core.agent import HypothesisProvider
    from pipt.core.ingest import Handler


class Mode(Enum):
    BREADTH = "breadth"   # one invocation over all targets (barrier)
    DEPTH = "depth"       # per-target chain (fan-out)


@dataclass(frozen=True)
class Stage:
    name: str
    mode: Mode
    run: Callable[..., None]
    produces: tuple[str, ...] = field(default_factory=tuple)


class Pipeline(Protocol):
    name: str
    stages: Sequence[Stage]

    def extension_schema(self) -> str: ...
    def ingest_handlers(self) -> dict[str, Handler]: ...
    def provider(self) -> HypothesisProvider: ...
```

- [ ] **Step 4: Implement the registry**

```python
# src/pipt/pipelines/__init__.py
"""Pluggable pipelines registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipt.core.stage import Pipeline


def load_pipeline(name: str) -> Pipeline:
    if name == "example":
        from pipt.pipelines.example.pipeline import PIPELINE

        return PIPELINE
    msg = f"unknown pipeline: {name!r}"
    raise ValueError(msg)
```

- [ ] **Step 5: Run tests, lint**

Run: `uv run pytest tests/core/test_stage.py -v && uv run ruff check src/pipt/core/stage.py src/pipt/pipelines/__init__.py`
Expected: PASS, no lint errors. (The `example` import path resolves in Task 12; the unknown-name test does not import it.)

- [ ] **Step 6: Commit**

```bash
git add src/pipt/core/stage.py src/pipt/pipelines/__init__.py tests/core/test_stage.py
git commit -m "feat(core): Stage abstraction + Pipeline protocol + registry"
```

---

## Task 10: `core/agent.py`

**Files:**
- Create: `src/pipt/core/agent.py`
- Test: `tests/core/test_agent.py`

**Interfaces:**
- Consumes: `db.list_hosts`, `db.list_services`, `db.insert_hypothesis`.
- Produces:
  - `HypothesisDraft` frozen dataclass: `.title: str`, `.service_id: int | None = None`, `.subject: str | None = None`, `.rationale: str | None = None`, `.technique: str | None = None`, `.confidence: str | None = None`.
  - `HypothesisProvider` Protocol: attr `name: str`; method `propose(hosts, services) -> list[HypothesisDraft]`.
  - `StubProvider` implementing it (`name = "stub"`).
  - `propose_hypotheses(conn, provider: HypothesisProvider | None = None) -> int` — writes rows, commits, returns count.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_agent.py
from pipt.core import agent, db


def _fresh(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    return conn


def test_stub_proposes_one_per_service(tmp_path):
    conn = _fresh(tmp_path)
    db.upsert_service(conn, ip="10.0.0.1", port=22, service="ssh")
    db.upsert_service(conn, ip="10.0.0.1", port=443, service="https")
    conn.commit()
    n = agent.propose_hypotheses(conn)
    assert n == 2
    rows = db.list_hypotheses(conn)
    assert len(rows) == 2
    assert all(r["source"] == "stub" for r in rows)
    assert rows[0]["service_id"] is not None


def test_custom_provider_used(tmp_path):
    conn = _fresh(tmp_path)
    db.upsert_service(conn, ip="10.0.0.1", port=80)
    conn.commit()

    class P:
        name = "custom"

        def propose(self, hosts, services):  # noqa: ARG002
            return [agent.HypothesisDraft(title="x", confidence="high")]

    assert agent.propose_hypotheses(conn, P()) == 1
    assert db.list_hypotheses(conn)[0]["source"] == "custom"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_agent.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/agent.py
"""Vuln/exploitation hypothesis stage — seam + stub provider.

Input: inventory queried from the DB. Output: rows in `hypothesis`. The real
Claude-backed provider is a future drop-in behind HypothesisProvider.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pipt.core import db


@dataclass(frozen=True)
class HypothesisDraft:
    title: str
    service_id: int | None = None
    subject: str | None = None
    rationale: str | None = None
    technique: str | None = None
    confidence: str | None = None


class HypothesisProvider(Protocol):
    name: str

    def propose(
        self,
        hosts: Sequence[sqlite3.Row],
        services: Sequence[sqlite3.Row],
    ) -> list[HypothesisDraft]: ...


class StubProvider:
    """Placeholder provider: one low-confidence draft per service."""

    name = "stub"

    def propose(
        self,
        hosts: Sequence[sqlite3.Row],  # noqa: ARG002
        services: Sequence[sqlite3.Row],
    ) -> list[HypothesisDraft]:
        drafts: list[HypothesisDraft] = []
        for s in services:
            svc = s["service"] or "unknown"
            drafts.append(
                HypothesisDraft(
                    title=f"{svc} on {s['ip']}:{s['port']} — review for known CVEs",
                    service_id=s["id"],
                    technique="version-based CVE lookup",
                    confidence="low",
                )
            )
        return drafts


def propose_hypotheses(
    conn: sqlite3.Connection,
    provider: HypothesisProvider | None = None,
) -> int:
    prov = provider or StubProvider()
    drafts = prov.propose(db.list_hosts(conn), db.list_services(conn))
    for d in drafts:
        db.insert_hypothesis(
            conn,
            title=d.title,
            service_id=d.service_id,
            subject=d.subject,
            rationale=d.rationale,
            technique=d.technique,
            confidence=d.confidence,
            source=prov.name,
        )
    conn.commit()
    return len(drafts)
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest tests/core/test_agent.py -v && uv run ruff check src/pipt/core/agent.py && uv run ty check src/`
Expected: PASS, no errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/agent.py tests/core/test_agent.py
git commit -m "feat(core): agent hypothesis seam + stub provider"
```

---

## Task 11: `core/orchestrator.py`

**Files:**
- Create: `src/pipt/core/orchestrator.py`
- Test: `tests/core/test_orchestrator.py` (pure-logic units only; e2e run is Task 13)

**Interfaces:**
- Consumes: `Stage`, `Mode`, `Engagement`, `Target`, `db`, `ingest`, `workspace`, `agent.propose_hypotheses`, `scope`, `load_pipeline`, `tools.write_lines`.
- Produces:
  - `split_stages(stages) -> tuple[list[Stage], list[Stage]]` (breadth, depth).
  - `assign_enum_hosts(conn, *, aggregate: bool) -> dict[str, list[str]]` — tid → host names to enumerate. With `aggregate=True` each host goes to exactly one target (min tid); else to every target that discovered it.
  - `orchestrate(pipeline, scan_id, scope_file, *, root=None, aggregate=True) -> Path` — full run, returns `eng.base`.
  - `rebuild_db(scan_id, *, root=None, pipeline_name="example") -> Path` — wipe + re-ingest DB from raw/manifests.

- [ ] **Step 1: Write the failing test**

```python
# tests/core/test_orchestrator.py
from pipt.core import db, orchestrator
from pipt.core.stage import Mode, Stage


def test_split_stages():
    s1 = Stage(name="a", mode=Mode.BREADTH, run=lambda *a: None)
    s2 = Stage(name="b", mode=Mode.DEPTH, run=lambda *a: None)
    breadth, depth = orchestrator.split_stages([s1, s2])
    assert breadth == [s1]
    assert depth == [s2]


def _seed_shared_host(tmp_path):
    conn = db.connect(tmp_path / "e.db")
    db.init_schema(conn, db.core_schema())
    ta = db.upsert_target(conn, tid="t_aaa111", raw="example.com", kind="domain")
    tb = db.upsert_target(conn, tid="t_bbb222", raw="nmap.org", kind="domain")
    h_a = db.upsert_host(conn, name="only.example.com")
    h_b = db.upsert_host(conn, name="only.nmap.org")
    h_s = db.upsert_host(conn, name="shared.host")
    db.link_host_target(conn, h_a, ta)
    db.link_host_target(conn, h_b, tb)
    db.link_host_target(conn, h_s, ta)
    db.link_host_target(conn, h_s, tb)
    conn.commit()
    return conn


def test_assign_aggregate_enumerates_shared_once(tmp_path):
    conn = _seed_shared_host(tmp_path)
    assignment = orchestrator.assign_enum_hosts(conn, aggregate=True)
    all_hosts = [h for hosts in assignment.values() for h in hosts]
    assert all_hosts.count("shared.host") == 1


def test_assign_no_aggregate_enumerates_shared_twice(tmp_path):
    conn = _seed_shared_host(tmp_path)
    assignment = orchestrator.assign_enum_hosts(conn, aggregate=False)
    all_hosts = [h for hosts in assignment.values() for h in hosts]
    assert all_hosts.count("shared.host") == 2
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/core/test_orchestrator.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

```python
# src/pipt/core/orchestrator.py
"""Phased-hybrid orchestration: breadth (barrier) -> [dedup] -> depth (fan-out) -> ingest -> agent.

Only strings cross the Prefect task boundary: depth workers reconstruct the
Engagement, Target and Pipeline from (pipeline_name, scan_id, root, tid).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from prefect import flow, task
from prefect.task_runners import ThreadPoolTaskRunner

from pipt.core import db, ingest, scope, workspace
from pipt.core.agent import propose_hypotheses
from pipt.core.config import CONFIG
from pipt.core.paths import Engagement
from pipt.core.stage import Mode, Pipeline, Stage
from pipt.core.tools import write_lines
from pipt.pipelines import load_pipeline


def split_stages(stages: list[Stage]) -> tuple[list[Stage], list[Stage]]:
    breadth = [s for s in stages if s.mode is Mode.BREADTH]
    depth = [s for s in stages if s.mode is Mode.DEPTH]
    return breadth, depth


def assign_enum_hosts(conn: sqlite3.Connection, *, aggregate: bool) -> dict[str, list[str]]:
    rows = conn.execute(
        "SELECT h.name AS name, t.tid AS tid FROM host h "
        "JOIN host_target ht ON ht.host_id = h.id "
        "JOIN target t ON t.id = ht.target_id"
    ).fetchall()
    by_host: dict[str, list[str]] = {}
    for r in rows:
        by_host.setdefault(r["name"], []).append(r["tid"])
    assignment: dict[str, list[str]] = {}
    for host, tids in by_host.items():
        chosen = [min(tids)] if aggregate else tids
        for tid in chosen:
            assignment.setdefault(tid, []).append(host)
    return assignment


@task(tags=["net"])
def _run_depth_chain(pipeline_name: str, scan_id: str, root: str | None, tid: str) -> str:
    pipeline = load_pipeline(pipeline_name)
    eng = Engagement.for_scan(scan_id, Path(root) if root else None)
    target = scope.target_from_meta(workspace.read_meta(eng.target(tid).meta))
    _, depth = split_stages(list(pipeline.stages))
    for stage in depth:
        stage.run(eng, target)
    return tid


@flow(task_runner=ThreadPoolTaskRunner(max_workers=CONFIG.fanout.max_workers))
def _depth_flow(pipeline_name: str, scan_id: str, root: str | None, tids: list[str]) -> None:
    futures = [_run_depth_chain.submit(pipeline_name, scan_id, root, tid) for tid in tids]
    for fut in futures:
        fut.result(raise_on_failure=False)


def orchestrate(
    pipeline: Pipeline,
    scan_id: str,
    scope_file: str,
    *,
    root: str | None = None,
    aggregate: bool = True,
) -> Path:
    eng = Engagement.for_scan(scan_id, Path(root) if root else None).ensure()
    eng.scope.write_text(Path(scope_file).read_text(encoding="utf-8"), encoding="utf-8")
    targets = scope.parse_scope(eng.scope.read_text(encoding="utf-8"))

    conn = db.connect(eng.db)
    db.init_schema(conn, db.core_schema(), pipeline.extension_schema())
    for t in targets:
        db.upsert_target(conn, tid=t.tid, raw=t.raw, kind=t.kind)
        ws = eng.target(t.tid).ensure()
        workspace.write_meta(ws.meta, t.__dict__)
    conn.commit()

    handlers = {**ingest.CORE_HANDLERS, **pipeline.ingest_handlers()}
    breadth, _ = split_stages(list(pipeline.stages))

    # 1. BREADTH stages (single invocation over all targets) + ingest
    for stage in breadth:
        stage.run(eng, targets)
    ingest.ingest_manifest(conn, eng.surface_manifest, handlers)

    # 2. Pre-enum dedup barrier: write each target's enum input (hosts.txt)
    assignment = assign_enum_hosts(conn, aggregate=aggregate)
    for tid, hosts in assignment.items():
        ws = eng.target(tid)
        out = ws.canonical("hosts.txt")
        write_lines(out, hosts)
        workspace.record(ws.manifest, role="enum_input", path=out, tool="dedup", inputs="db:host")

    # 3. DEPTH fan-out per target (Prefect), then ingest
    _depth_flow(pipeline.name, scan_id, root, [t.tid for t in targets])
    for ws in eng.list_targets():
        ingest.ingest_manifest(conn, ws.manifest, handlers)

    # 4. Agent stage (terminal)
    propose_hypotheses(conn, pipeline.provider())

    conn.close()
    return eng.base


def rebuild_db(scan_id: str, *, root: str | None = None, pipeline_name: str = "example") -> Path:
    pipeline = load_pipeline(pipeline_name)
    eng = Engagement.for_scan(scan_id, Path(root) if root else None)
    if eng.db.exists():
        eng.db.unlink()
    conn = db.connect(eng.db)
    db.init_schema(conn, db.core_schema(), pipeline.extension_schema())
    for ws in eng.list_targets():
        if ws.meta.exists():
            t = scope.target_from_meta(workspace.read_meta(ws.meta))
            db.upsert_target(conn, tid=t.tid, raw=t.raw, kind=t.kind)
    conn.commit()
    handlers = {**ingest.CORE_HANDLERS, **pipeline.ingest_handlers()}
    ingest.ingest_manifest(conn, eng.surface_manifest, handlers)
    for ws in eng.list_targets():
        ingest.ingest_manifest(conn, ws.manifest, handlers)
    conn.close()
    return eng.base
```

- [ ] **Step 4: Run the pure-logic tests, lint, type-check**

Run: `uv run pytest tests/core/test_orchestrator.py -v && uv run ruff check src/pipt/core/orchestrator.py && uv run ty check src/`
Expected: PASS, no errors. (Full e2e run is exercised in Task 13.)

- [ ] **Step 5: Commit**

```bash
git add src/pipt/core/orchestrator.py tests/core/test_orchestrator.py
git commit -m "feat(core): phased-hybrid orchestrator + aggregate dedup + rebuild"
```

---

## Task 12: Example pipeline (stub tools)

**Files:**
- Create: `src/pipt/pipelines/example/__init__.py`
- Create: `src/pipt/pipelines/example/schema.sql`
- Create: `src/pipt/pipelines/example/tasks.py`
- Create: `src/pipt/pipelines/example/pipeline.py`
- Test: `tests/pipelines/test_example_tasks.py`

**Interfaces:**
- Consumes: `Engagement`, `Target`, `workspace.record`, `tools.read_lines`, `StubProvider`, `Stage`, `Mode`, `CORE_HANDLERS`.
- Produces:
  - `tasks.discover(eng, targets) -> None` — writes `surface/hosts.jsonl` (role `hosts`), records `{"name","ip","source":"stub","targets":[tid]}` (apex + `www.` host per target).
  - `tasks.enum(eng, target) -> None` — reads `targets/<tid>/hosts.txt`, writes `targets/<tid>/services.jsonl` (role `services`), one `{ip,port:443,protocol:"tcp",service:"https",version:"stub/1.0",source:"stub"}` per host.
  - `tasks.fake_ip(seed: str) -> str` — deterministic `10.x.y.z`.
  - `pipeline.PIPELINE: ExamplePipeline` — `name="example"`, stages `(discover BREADTH, enum DEPTH)`, `extension_schema()` reads `schema.sql`, `ingest_handlers()` returns `{}`, `provider()` returns `StubProvider()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/pipelines/test_example_tasks.py
import json

from pipt.core.paths import Engagement
from pipt.core.scope import Target
from pipt.pipelines.example import tasks


def test_discover_writes_hosts_jsonl(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path).ensure()
    t = Target(raw="example.com", kind="domain", normalized="example.com", tid="t_aaa111")
    tasks.discover(eng, [t])
    records = [json.loads(ln) for ln in eng.surface_canonical("hosts.jsonl").read_text().splitlines()]
    names = {r["name"] for r in records}
    assert names == {"example.com", "www.example.com"}
    assert all(r["targets"] == ["t_aaa111"] for r in records)


def test_enum_reads_hosts_txt_writes_services(tmp_path):
    eng = Engagement.for_scan("demo", root=tmp_path).ensure()
    t = Target(raw="example.com", kind="domain", normalized="example.com", tid="t_aaa111")
    ws = eng.target(t.tid).ensure()
    ws.canonical("hosts.txt").write_text("example.com\nwww.example.com\n")
    tasks.enum(eng, t)
    records = [json.loads(ln) for ln in ws.canonical("services.jsonl").read_text().splitlines()]
    assert len(records) == 2
    assert all(r["port"] == 443 for r in records)


def test_pipeline_object_shape():
    from pipt.pipelines.example.pipeline import PIPELINE

    assert PIPELINE.name == "example"
    assert [s.name for s in PIPELINE.stages] == ["discover", "enum"]
    assert "example_note" in PIPELINE.extension_schema()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/pipelines/test_example_tasks.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Create the package files**

```python
# src/pipt/pipelines/example/__init__.py
"""Minimal example pipeline (stub tools) — exercises the framework end-to-end."""
```

```sql
-- src/pipt/pipelines/example/schema.sql — demo extension table (exercises init_schema + extension).
CREATE TABLE IF NOT EXISTS example_note (
  id   INTEGER PRIMARY KEY,
  note TEXT
);
```

```python
# src/pipt/pipelines/example/tasks.py
"""Stub tools: no external scanners. Deterministic, so tests are stable."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from pipt.core import tools, workspace

if TYPE_CHECKING:
    from pipt.core.paths import Engagement
    from pipt.core.scope import Target


def fake_ip(seed: str) -> str:
    h = hashlib.sha1(seed.encode()).digest()  # noqa: S324
    return f"10.{h[0]}.{h[1]}.{h[2]}"


def _dump_jsonl(records: list[dict]) -> str:
    return "\n".join(json.dumps(r) for r in records) + ("\n" if records else "")


def discover(eng: Engagement, targets: list[Target]) -> None:
    """BREADTH stub: derive apex + www host per target, with target provenance."""
    records: list[dict] = []
    for t in targets:
        ip = fake_ip(t.normalized)
        records.append({"name": t.normalized, "ip": ip, "source": "stub", "targets": [t.tid]})
        records.append(
            {"name": f"www.{t.normalized}", "ip": ip, "source": "stub", "targets": [t.tid]}
        )
    raw = eng.surface_raw("discover")
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "out.jsonl").write_text(_dump_jsonl(records), encoding="utf-8")
    out = eng.surface_canonical("hosts.jsonl")
    out.write_text(_dump_jsonl(records), encoding="utf-8")
    workspace.record(eng.surface_manifest, role="hosts", path=out, tool="discover", inputs="scope")


def enum(eng: Engagement, target: Target) -> None:
    """DEPTH stub: 'fingerprint' each assigned host into a service row."""
    ws = eng.target(target.tid)
    hosts = tools.read_lines(ws.canonical("hosts.txt"))
    records = [
        {
            "ip": fake_ip(h.removeprefix("www.")),
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "version": "stub/1.0",
            "source": "stub",
        }
        for h in hosts
    ]
    raw = ws.raw("enum")
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "out.jsonl").write_text(_dump_jsonl(records), encoding="utf-8")
    out = ws.canonical("services.jsonl")
    out.write_text(_dump_jsonl(records), encoding="utf-8")
    workspace.record(ws.manifest, role="services", path=out, tool="enum", inputs="hosts.txt")
```

```python
# src/pipt/pipelines/example/pipeline.py
"""The example Pipeline object."""

from __future__ import annotations

from pathlib import Path

from pipt.core.agent import HypothesisProvider, StubProvider
from pipt.core.ingest import Handler
from pipt.core.stage import Mode, Stage
from pipt.pipelines.example import tasks

_SCHEMA = Path(__file__).parent / "schema.sql"


class ExamplePipeline:
    name = "example"
    stages = (
        Stage(name="discover", mode=Mode.BREADTH, run=tasks.discover, produces=("hosts",)),
        Stage(name="enum", mode=Mode.DEPTH, run=tasks.enum, produces=("services",)),
    )

    def extension_schema(self) -> str:
        return _SCHEMA.read_text(encoding="utf-8")

    def ingest_handlers(self) -> dict[str, Handler]:
        return {}

    def provider(self) -> HypothesisProvider:
        return StubProvider()


PIPELINE = ExamplePipeline()
```

- [ ] **Step 4: Run tests, lint, type-check**

Run: `uv run pytest tests/pipelines/test_example_tasks.py tests/core/test_stage.py -v && uv run ruff check src/pipt/pipelines && uv run ty check src/`
Expected: PASS (incl. the previously-deferred `load_pipeline("example")` path), no errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/pipelines/example tests/pipelines/test_example_tasks.py
git commit -m "feat(pipelines): minimal example pipeline with stub tools"
```

---

## Task 13: `cli.py` + end-to-end test

**Files:**
- Create: `src/pipt/cli.py`
- Test: `tests/test_e2e.py`

**Interfaces:**
- Consumes: `orchestrate`, `rebuild_db`, `load_pipeline`, `db`.
- Produces:
  - `main(argv: list[str] | None = None) -> int`.
  - CLI: `pipt run <pipeline> <scan_id> <scope> [--root DIR] [--no-aggregate]`; `pipt ingest <scan_id> [--root DIR] [--pipeline NAME]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_e2e.py
from pipt.cli import main
from pipt.core import db
from pipt.core.orchestrator import orchestrate, rebuild_db
from pipt.pipelines import load_pipeline


def _scope(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("example.com\nnmap.org\n")
    return p


def test_orchestrate_end_to_end(tmp_path):
    scope_file = _scope(tmp_path)
    base = orchestrate(
        load_pipeline("example"), "demo", str(scope_file), root=str(tmp_path / "scans"),
    )
    conn = db.connect(base / "db" / "engagement.db")
    assert conn.execute("SELECT COUNT(*) FROM target").fetchone()[0] == 2
    # 2 targets x (apex + www) = 4 hosts
    assert conn.execute("SELECT COUNT(*) FROM host").fetchone()[0] == 4
    assert conn.execute("SELECT COUNT(*) FROM service").fetchone()[0] >= 1
    assert conn.execute("SELECT COUNT(*) FROM hypothesis").fetchone()[0] >= 1
    # extension table exists
    conn.execute("SELECT COUNT(*) FROM example_note")


def test_rebuild_db_matches_run(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "scans")
    base = orchestrate(load_pipeline("example"), "demo", str(scope_file), root=root)
    conn = db.connect(base / "db" / "engagement.db")
    before = conn.execute("SELECT COUNT(*) FROM service").fetchone()[0]
    conn.close()
    rebuild_db("demo", root=root, pipeline_name="example")
    conn = db.connect(base / "db" / "engagement.db")
    after = conn.execute("SELECT COUNT(*) FROM service").fetchone()[0]
    assert after == before


def test_cli_run_and_ingest(tmp_path):
    scope_file = _scope(tmp_path)
    root = str(tmp_path / "scans")
    assert main(["run", "example", "demo", str(scope_file), "--root", root]) == 0
    assert main(["ingest", "demo", "--root", root, "--pipeline", "example"]) == 0
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_e2e.py -v`
Expected: FAIL (`ModuleNotFoundError: pipt.cli`).

- [ ] **Step 3: Implement**

```python
# src/pipt/cli.py
"""pipt CLI: run a pipeline, or rebuild the DB from raw."""

from __future__ import annotations

import argparse

from pipt.core.orchestrator import orchestrate, rebuild_db
from pipt.pipelines import load_pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pipt")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a pipeline over a scope")
    run.add_argument("pipeline")
    run.add_argument("scan_id")
    run.add_argument("scope")
    run.add_argument("--root", default=None)
    run.add_argument("--no-aggregate", action="store_true", help="enumerate overlapping assets per target")

    ing = sub.add_parser("ingest", help="rebuild the SQLite DB from raw/manifests")
    ing.add_argument("scan_id")
    ing.add_argument("--root", default=None)
    ing.add_argument("--pipeline", default="example")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        base = orchestrate(
            load_pipeline(args.pipeline),
            args.scan_id,
            args.scope,
            root=args.root,
            aggregate=not args.no_aggregate,
        )
        print(base)  # noqa: T201
        return 0

    if args.cmd == "ingest":
        base = rebuild_db(args.scan_id, root=args.root, pipeline_name=args.pipeline)
        print(base)  # noqa: T201
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the full suite, lint, type-check**

Run: `uv run pytest -v && uv run ruff check . && uv run ty check src/`
Expected: ALL PASS, no errors.

- [ ] **Step 5: Commit**

```bash
git add src/pipt/cli.py tests/test_e2e.py
git commit -m "feat: pipt CLI (run/ingest) + end-to-end test"
```

---

## Task 14: Docs (`README.md`, `CONVENTIONS.md`)

**Files:**
- Create: `README.md`
- Create: `CONVENTIONS.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Write `README.md`**

````markdown
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
````

- [ ] **Step 2: Write `CONVENTIONS.md`**

```markdown
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
```

- [ ] **Step 3: Commit**

```bash
git add README.md CONVENTIONS.md
git commit -m "docs: README + pipt conventions"
```

---

## Self-Review

**Spec coverage (against `2026-06-17-pipt-scaffolding-design.md`):**

| Spec item | Task(s) |
|-----------|---------|
| Framework core + pluggable pipelines (D1, §3) | 1–11 (core), 9/12 (registry+example) |
| Raw = truth, serialized ingest (D2, §6) | 8 (ingest), 11 (orchestrator calls it serially), 13 (rebuild test) |
| Breadth/depth declarative phased-hybrid (D3, §7) | 9 (Stage/Mode), 11 (split_stages, breadth-then-depth) |
| Aggregation = pre-enum dedup toggle (D4) | 11 (`assign_enum_hosts`), 13 (covered indirectly; unit-tested in 11) |
| Agent seam + stub (D5, §8) | 10 (agent), 11 (terminal stage), 13 (hypothesis rows asserted) |
| Tooling uv/ruff/ty/pytest/Prefect (D6) | 1 |
| Light DB core + per-pipeline extension (D7, §5) | 7 (core schema), 12 (example extension), 11 (init loads both) |
| Single + multi target (req 2) | 11/13 (N targets; N=1 works the same) |
| Parallel per-target enum (req 4) | 11 (`_depth_flow` fan-out) |
| CLI run/ingest (§9) | 13 |
| Workspace contract two levels (§4) | 5 (paths), 6 (manifest) |

No gaps found.

**Placeholder scan:** No `TBD`/`TODO`/"handle edge cases"/"similar to Task N"; every code step shows full code. ✓

**Type consistency check:**
- `Handler = Callable[[sqlite3.Connection, list[dict]], None]` — same in ingest.py (Task 8), stage.py import (Task 9), pipeline.py (Task 12). ✓
- `Stage(name, mode, run, produces)` — used identically in Tasks 9, 11, 12. ✓
- `propose_hypotheses(conn, provider=None) -> int` — defined Task 10, called Task 11. ✓
- `orchestrate(pipeline, scan_id, scope_file, *, root=None, aggregate=True)` — defined Task 11, called Tasks 13 (cli + e2e). ✓
- `load_pipeline(name) -> Pipeline` — defined Task 9, used Tasks 11, 13. ✓
- `target_from_meta(meta)` / `Target.__dict__` written as meta — meta written in Task 11 (`t.__dict__`), read back in Task 11 (`_run_depth_chain`) and `rebuild_db`. Keys match `Target` fields (raw/kind/normalized/tid). ✓

---

## Execution Handoff

Plan complete. Choose execution mode at the bottom of this conversation.
