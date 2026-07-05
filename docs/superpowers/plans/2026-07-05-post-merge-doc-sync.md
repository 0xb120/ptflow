# Post-merge doc-sync hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A versioned git `post-merge` hook that, after a merge landing on `main`, regenerates the generated flow-map docs and runs a headless Claude agent to update the prose docs, committed as one isolated `docs: auto-sync` follow-up.

**Architecture:** A thin `.githooks/post-merge` delegates to `.githooks/doc-sync.sh`, which runs five phases: guards → deterministic regen → merge-diff capture → agent prose update (headless `claude -p`, tool-restricted, timeout-bounded) → single scoped commit. Two env seams (`PTFLOW_DOC_SYNC_REGEN`, `CLAUDE_BIN`) make it hermetically testable via a pytest harness that drives a throwaway git repo with stub scripts.

**Tech Stack:** POSIX/bash shell, git hooks (`core.hooksPath`), Claude Code CLI (`claude -p`), Python `uv run python -m ptflow.core.flowdocs`, pytest (subprocess-driven), ruff (`select=ALL`), ty.

## Global Constraints

- Dev gate must stay green: `uv run ruff check . && uv run ty check src/ && uv run pytest`.
- The hook must NEVER fail or block a merge; `doc-sync.sh` always exits 0; every external call is guarded.
- Fires only when the merge result is on `main` (`git symbolic-ref --short -q HEAD` = `main`); other branches / detached HEAD → clean skip.
- Agent scope: may edit ONLY `CLAUDE.md`, `README.md`, `ptflow.toml.example`; never `docs/superpowers/**`, code, or tests. Agent tools limited to `Read Edit Grep Glob` (NO Bash).
- Commit stages ONLY: `docs/*-pipeline-*.html`, `docs/*-pipeline-*.md`, `CLAUDE.md`, `README.md`, `ptflow.toml.example` — never `docs/` broadly (would catch `docs/superpowers/**`).
- Env knobs (exact names): `PTFLOW_NO_DOC_SYNC` (any non-empty → skip all), `PTFLOW_DOC_SYNC_TIMEOUT` (seconds, default `300`), `CLAUDE_BIN` (default `claude`), `PTFLOW_DOC_SYNC_REGEN` (default `uv run python -m ptflow.core.flowdocs`; internal/test seam).
- Claude headless invocation (verified against `claude --version` 2.1.201): `claude -p --permission-mode acceptEdits --allowedTools "Read Edit Grep Glob"`, prompt on **stdin**, wrapped in `timeout`.
- ruff `tests/*` per-file-ignores today: `["S101", "ANN", "INP001", "PLR2004", "PLC0415", "SLF001"]` — the subprocess-driven test needs `S603`, `S607` added.

---

### Task 1: Hook scripts (guards + deterministic regen + commit) + hermetic test harness

Create the two shell scripts with everything EXCEPT the agent phase (added in Task 2), plus the pytest harness and the four non-agent tests. Add the ruff ignores the test needs.

**Files:**
- Create: `.githooks/post-merge`
- Create: `.githooks/doc-sync.sh`
- Create: `tests/test_doc_sync_hook.py`
- Modify: `pyproject.toml:37` (add `S603`, `S607` to `tests/*` per-file-ignores)

**Interfaces:**
- Produces: `.githooks/doc-sync.sh` reading env seams `PTFLOW_NO_DOC_SYNC`, `PTFLOW_DOC_SYNC_REGEN`, `CLAUDE_BIN`, `PTFLOW_DOC_SYNC_TIMEOUT`; commits `docs: auto-sync after merge <base>..<head>` when a doc path changed. Task 2 inserts the agent phase at the `# >>> AGENT_PHASE <<<` anchor line.
- Produces (test harness helpers other tasks reuse): `tests/test_doc_sync_hook.py` with `_init_repo(tmp_path) -> Path`, `_stub(path, body)`, `_git(args, cwd, env=None)`, `_merge(repo, env, *, on_main=True, touch_src=True)`.

- [ ] **Step 1: Write the failing tests** — create `tests/test_doc_sync_hook.py`:

```python
import os
import subprocess
from pathlib import Path

_GITHOOKS = Path(__file__).resolve().parent.parent / ".githooks"


def _git(args, cwd, env=None):
    return subprocess.run(["git", *args], cwd=cwd, env=env, text=True, capture_output=True)


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "t@example.com"], repo)
    _git(["config", "user.name", "Test"], repo)
    hooks = repo / ".githooks"
    hooks.mkdir()
    for name in ("post-merge", "doc-sync.sh"):
        dst = hooks / name
        dst.write_text((_GITHOOKS / name).read_text())
        dst.chmod(0o755)
    _git(["config", "core.hooksPath", ".githooks"], repo)
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n")
    (repo / "CLAUDE.md").write_text("# CLAUDE\n\ninitial\n")
    (repo / "README.md").write_text("# readme\n")
    (repo / "ptflow.toml.example").write_text("# example\n")
    (repo / "docs").mkdir()
    (repo / "docs" / "example-pipeline-map.md").write_text("map v0\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-qm", "init"], repo)
    return repo


def _env(repo: Path, **overrides) -> dict:
    # default seams: regen = a stub that mutates a generated doc; claude = a no-op stub
    regen = repo / ".githooks" / "stub-regen.sh"
    _stub(regen, 'printf "map v1\\n" > docs/example-pipeline-map.md\n')
    noop = repo / ".githooks" / "stub-claude-noop.sh"
    _stub(noop, 'exit 0\n')
    env = {
        **os.environ,
        "PTFLOW_DOC_SYNC_REGEN": str(regen),
        "CLAUDE_BIN": str(noop),
    }
    env.update(overrides)
    return env


def _merge(repo: Path, env: dict, *, on_main: bool = True, touch_src: bool = True):
    _git(["checkout", "-q", "-b", "feat"], repo)
    if touch_src:
        (repo / "src" / "app.py").write_text("x = 2\n")
    else:
        (repo / "docs" / "notes.txt").write_text("doc only\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-qm", "feat change"], repo)
    if on_main:
        _git(["checkout", "-q", "main"], repo)
        return _git(["merge", "--no-ff", "-m", "merge feat", "feat"], repo, env)
    # merge main INTO feat → HEAD stays on feat (non-main target)
    return _git(["merge", "--no-ff", "-m", "merge main", "main"], repo, env)


def _subjects(repo: Path):
    return _git(["log", "--format=%s"], repo).stdout.splitlines()


def test_merge_on_main_commits_regen(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo))
    assert _subjects(repo)[0].startswith("docs: auto-sync after merge")
    assert (repo / "docs" / "example-pipeline-map.md").read_text() == "map v1\n"


def test_non_main_target_no_action(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo), on_main=False)
    assert not any(s.startswith("docs: auto-sync") for s in _subjects(repo))


def test_env_escape_no_action(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo, PTFLOW_NO_DOC_SYNC="1"))
    assert not any(s.startswith("docs: auto-sync") for s in _subjects(repo))


def test_no_src_change_no_action(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo), touch_src=False)
    assert not any(s.startswith("docs: auto-sync") for s in _subjects(repo))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_doc_sync_hook.py -v`
Expected: FAIL (the `.githooks/` scripts don't exist yet → `_init_repo` raises `FileNotFoundError` reading `post-merge`).

- [ ] **Step 3: Create `.githooks/post-merge`** (thin entry, never fails the merge):

```bash
#!/usr/bin/env bash
# post-merge — after a merge, sync documentation (delegates to doc-sync.sh).
# $1 = 1 when the merge was a squash. A post-merge hook cannot fail the merge; we also
# swallow any error so nothing noisy escapes.
"$(dirname "$0")/doc-sync.sh" "$@" || true
```

- [ ] **Step 4: Create `.githooks/doc-sync.sh`** (guards + regen + commit; agent phase is a Task-2 anchor):

```bash
#!/usr/bin/env bash
# doc-sync.sh — regenerate generated docs + (Task 2) run an agent to update prose docs after a merge
# landing on main, committed as one isolated `docs: auto-sync` follow-up. Always exits 0.
set -u

log() { printf 'doc-sync: %s\n' "$1" >&2; }

# run from the repo root regardless of where git invoked the hook
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

# --- guards -----------------------------------------------------------------
[ -n "${PTFLOW_NO_DOC_SYNC:-}" ] && { log "skip (PTFLOW_NO_DOC_SYNC set)"; exit 0; }

branch=$(git symbolic-ref --short -q HEAD) || { log "skip (detached HEAD)"; exit 0; }
[ "$branch" = "main" ] || { log "skip (branch '$branch' is not main)"; exit 0; }

git rev-parse --verify -q ORIG_HEAD >/dev/null || { log "skip (no ORIG_HEAD)"; exit 0; }

# prose docs describe the code — a merge that touches no src/ needs no doc sync
if git diff --quiet ORIG_HEAD HEAD -- src/; then
  log "skip (merge touched no src/)"; exit 0
fi

# --- phase 2: deterministic regeneration of the generated docs --------------
regen=${PTFLOW_DOC_SYNC_REGEN:-uv run python -m ptflow.core.flowdocs}
sh -c "$regen" || log "regen failed (continuing)"

# >>> AGENT_PHASE <<<

# --- phase 5: single scoped commit ------------------------------------------
for p in CLAUDE.md README.md ptflow.toml.example docs/*-pipeline-*.html docs/*-pipeline-*.md; do
  [ -e "$p" ] && git add -- "$p"
done

if git diff --cached --quiet; then
  log "no documentation changes to commit"; exit 0
fi

orig=$(git rev-parse --short ORIG_HEAD)
head=$(git rev-parse --short HEAD)
git commit -q -m "docs: auto-sync after merge ${orig}..${head}" -m "Automated by the post-merge doc-sync hook.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>" || log "commit failed"
log "committed documentation auto-sync"
exit 0
```

- [ ] **Step 5: Make the scripts executable**

Run: `chmod +x .githooks/post-merge .githooks/doc-sync.sh`
(Git records the exec bit; the test copies preserve it via `dst.chmod(0o755)`.)

- [ ] **Step 6: Add the ruff test ignores** — edit `pyproject.toml` line 37:

```toml
"tests/*" = ["S101", "ANN", "INP001", "PLR2004", "PLC0415", "SLF001", "S603", "S607"]
```
(The doc-sync test legitimately shells out to `git`/`bash`; `S603`/`S607` are the subprocess/partial-path rules that fire on that.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/test_doc_sync_hook.py -v`
Expected: PASS (4 tests). If `test_merge_on_main_commits_regen` fails because the stub regen didn't run, confirm `sh -c "$regen"` executes the stub with CWD at repo root.

- [ ] **Step 8: Lint the test + confirm gate isn't regressed**

Run: `uv run ruff check tests/test_doc_sync_hook.py pyproject.toml && uv run pytest -q`
Expected: ruff clean; full suite passes (378 + 4 = 382).

- [ ] **Step 9: Commit**

```bash
git add .githooks/post-merge .githooks/doc-sync.sh tests/test_doc_sync_hook.py pyproject.toml
git commit -m "feat(doc-sync): post-merge hook — guards + deterministic regen + commit"
```

---

### Task 2: Agent prose-update phase

Insert phase 3 (diff capture) + phase 4 (headless `claude` invocation) at the `# >>> AGENT_PHASE <<<` anchor, and add its tests.

**Files:**
- Modify: `.githooks/doc-sync.sh` (replace the `# >>> AGENT_PHASE <<<` line)
- Modify: `tests/test_doc_sync_hook.py` (append 3 tests)

**Interfaces:**
- Consumes: the `_init_repo`/`_stub`/`_env`/`_merge`/`_subjects` helpers from Task 1.
- Produces: the agent phase reads `CLAUDE_BIN` (default `claude`) and `PTFLOW_DOC_SYNC_TIMEOUT` (default 300); on failure/absence/timeout it logs and continues (phase 5 still commits the regen).

- [ ] **Step 1: Write the failing tests** — append to `tests/test_doc_sync_hook.py`:

```python
def test_agent_edits_are_committed(tmp_path):
    repo = _init_repo(tmp_path)
    # stub claude: append a marker to CLAUDE.md (proves the agent phase ran and its edits are picked up)
    claude = repo / ".githooks" / "stub-claude-edit.sh"
    _stub(claude, 'printf "\\nAGENT-MARKER\\n" >> CLAUDE.md\n')
    _merge(repo, _env(repo, CLAUDE_BIN=str(claude)))
    assert _subjects(repo)[0].startswith("docs: auto-sync after merge")
    assert "AGENT-MARKER" in (repo / "CLAUDE.md").read_text()


def test_claude_absent_still_commits_regen(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo, CLAUDE_BIN="/nonexistent/claude"))
    # agent skipped gracefully, but the deterministic regen is still committed
    assert _subjects(repo)[0].startswith("docs: auto-sync after merge")
    assert (repo / "docs" / "example-pipeline-map.md").read_text() == "map v1\n"


def test_claude_timeout_still_commits_regen(tmp_path):
    repo = _init_repo(tmp_path)
    slow = repo / ".githooks" / "stub-claude-slow.sh"
    _stub(slow, 'sleep 5\n')  # exceeds the 1s timeout below
    _merge(repo, _env(repo, CLAUDE_BIN=str(slow), PTFLOW_DOC_SYNC_TIMEOUT="1"))
    assert _subjects(repo)[0].startswith("docs: auto-sync after merge")
    assert (repo / "docs" / "example-pipeline-map.md").read_text() == "map v1\n"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_doc_sync_hook.py -k "agent or claude" -v`
Expected: `test_agent_edits_are_committed` FAILS (no `AGENT-MARKER` — the agent phase isn't wired yet). The other two may pass incidentally (no agent phase = no-op), which is fine; Step 4 must keep them green.

- [ ] **Step 3: Insert the agent phase** — in `.githooks/doc-sync.sh`, replace the line `# >>> AGENT_PHASE <<<` with:

```bash
# --- phase 3+4: agent prose update (best-effort) ----------------------------
claude_bin=${CLAUDE_BIN:-claude}
timeout_s=${PTFLOW_DOC_SYNC_TIMEOUT:-300}
if command -v "$claude_bin" >/dev/null 2>&1 || [ -x "$claude_bin" ]; then
  diffstat=$(git diff --stat ORIG_HEAD HEAD)
  # cap the full diff so a huge merge can't blow up the prompt (~200 KB)
  fulldiff=$(git diff ORIG_HEAD HEAD | head -c 200000)
  prompt="You are updating this repository's PROSE documentation after a git merge landed on main.

Update ONLY the prose that the merge below makes stale. You MAY edit these files: CLAUDE.md, README.md, ptflow.toml.example. Do NOT edit anything else — not code, not tests, and never anything under docs/superpowers/. Make surgical edits that preserve the existing structure, voice, and content; do not rewrite or delete sections wholesale. CLAUDE.md is the single source of truth — keep it coherent. If nothing is stale, make no changes.

Merge diff stat:
${diffstat}

Merge diff (may be truncated):
${fulldiff}"
  printf '%s' "$prompt" | timeout "$timeout_s" "$claude_bin" -p \
      --permission-mode acceptEdits --allowedTools "Read Edit Grep Glob" >/dev/null 2>&1 \
      || log "agent prose update skipped/failed (keeping deterministic regen)"
else
  log "agent skipped (claude not available)"
fi
```

- [ ] **Step 4: Run the agent tests to verify they pass**

Run: `uv run pytest tests/test_doc_sync_hook.py -v`
Expected: PASS (all 7). `test_agent_edits_are_committed` now finds `AGENT-MARKER`; the absent/timeout cases still commit the regen.

- [ ] **Step 5: Lint**

Run: `uv run ruff check tests/test_doc_sync_hook.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add .githooks/doc-sync.sh tests/test_doc_sync_hook.py
git commit -m "feat(doc-sync): agent prose-update phase (headless claude, tool-restricted, timeout)"
```

---

### Task 3: Install (activate hook) + documentation

Activate the hook in this repo and document it.

**Files:**
- Modify: `CLAUDE.md` (new subsection under an appropriate section — see Step 2)
- Modify: `README.md` (one line + the one-time setup)

- [ ] **Step 1: Activate the hook in this repo**

Run:
```bash
git config core.hooksPath .githooks
git config --get core.hooksPath
```
Expected: prints `.githooks`. NOTE: from now on, any merge landing on `main` in this repo triggers the hook (intended — this is the feature going live). Use `PTFLOW_NO_DOC_SYNC=1 git merge …` to opt out of a specific merge.

- [ ] **Step 2: Document in `CLAUDE.md`** — add this subsection at the end of the "## Observability (Prefect UI)" section's sibling area (place it as a new `## Documentation automation` section immediately before `## Architecture`):

```markdown
## Documentation automation

Two mechanisms keep docs current; both are best-effort and never block work:

- **Flow maps (edit-time, deterministic):** the Claude Code PostToolUse hook `.claude/hooks/regen-flowmap.sh`
  regenerates `docs/<pipeline>-pipeline-*` when a file under `src/ptflow/pipelines/` is edited (see "Pipeline
  flow map" below).
- **Post-merge doc-sync (agent-driven):** the versioned git hook `.githooks/post-merge` → `.githooks/doc-sync.sh`
  runs after a merge that lands on `main`. It regenerates the flow-map docs (`ptflow.core.flowdocs`) and runs a
  **headless Claude agent** (`claude -p`, tools limited to Read/Edit/Grep/Glob, no Bash, under a timeout) to update
  the PROSE docs (`CLAUDE.md`, `README.md`, `ptflow.toml.example`) to reflect the merged change — committing
  everything as one isolated `docs: auto-sync after merge …` follow-up you should review. It edits nothing else
  (never code/tests or `docs/superpowers/**`). **One-time activation:** `git config core.hooksPath .githooks`.
  Knobs: `PTFLOW_NO_DOC_SYNC=1` (skip a merge), `PTFLOW_DOC_SYNC_TIMEOUT` (agent seconds, default 300),
  `CLAUDE_BIN` (override the binary). It skips gracefully when `claude` is unavailable (the deterministic
  regeneration is still committed) and when the merge touched no `src/`.
```

- [ ] **Step 3: Document in `README.md`** — add a short subsection (near any existing setup/commands section; if none, append before the end):

```markdown
## Doc-sync hook (optional)

This repo ships a post-merge hook that auto-updates documentation after a merge to `main`
(regenerates the flow maps + a headless Claude agent refreshes the prose docs, as one reviewable
`docs: auto-sync` commit). Activate once with:

```bash
git config core.hooksPath .githooks
```

Skip it for a given merge with `PTFLOW_NO_DOC_SYNC=1 git merge …`. See CLAUDE.md → "Documentation automation".
```

- [ ] **Step 4: Confirm no code regression from the doc edits**

Run: `uv run ruff check .`
Expected: clean (docs aren't linted; confirms no stray change).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs(doc-sync): document the post-merge doc-sync hook + activation"
```

---

### Task 4: Full gate + end-to-end verification on a real clone

**Files:** none (verification only).

- [ ] **Step 1: Full dev gate**

Run: `uv run ruff check . && uv run ty check src/ && uv run pytest`
Expected: ruff clean, ty clean, all tests pass (382). Report the pytest summary line.

- [ ] **Step 2: Sanity-check the real regen command string** (the one hard-coded default the hermetic tests stub out)

Run: `uv run python -m ptflow.core.flowdocs && git status --porcelain docs/`
Expected: the command runs with exit 0; `git status` shows no diff under `docs/` (maps already current) — proving the exact default `PTFLOW_DOC_SYNC_REGEN` string is valid and produces deterministic output.

- [ ] **Step 3: End-to-end on a throwaway clone** (real committed hooks, real regen, STUB claude — no tokens, no touch to the real repo/main):

```bash
TMP=$(mktemp -d)
git clone -q . "$TMP/clone"
cd "$TMP/clone"
git config user.email t@example.com && git config user.name Test
git config core.hooksPath .githooks
printf '#!/usr/bin/env bash\nprintf "\\nE2E-AGENT-MARKER\\n" >> CLAUDE.md\n' > /tmp/stub-claude.sh && chmod +x /tmp/stub-claude.sh
git checkout -q -b feat
printf '# touch\n' >> src/ptflow/core/stage.py
git commit -aqm "e2e src touch"
git checkout -q main
CLAUDE_BIN=/tmp/stub-claude.sh git merge --no-ff -m "e2e merge" feat
git log --format='%s' -3
```
Expected: the top commit is `docs: auto-sync after merge …`; `grep E2E-AGENT-MARKER CLAUDE.md` finds the marker (stub agent ran); `git show --stat HEAD` shows only doc paths staged. Then clean up: `cd /opt/ptflow && rm -rf "$TMP"`.

- [ ] **Step 4: Confirm graceful real-claude-absent path on the clone** (optional, fast):

```bash
# in a second throwaway clone, merge with claude forced absent → still commits the regen, no error
```
Run the same as Step 3 but with `CLAUDE_BIN=/nonexistent git merge …`; expected: still a `docs: auto-sync` commit (regen only), exit 0, a `doc-sync: agent skipped` line on stderr.

- [ ] **Step 5: Commit** (only if a verification-only tweak was needed; otherwise report "nothing to commit").

---

## Self-Review

**1. Spec coverage** (spec section → task):
- §3 trigger/location (`.githooks/`, `core.hooksPath`, main-only) → Task 1 (scripts + guard) + Task 3 (activation).
- §4 phases 1-2,5 (guards, regen, scoped commit) → Task 1. Phases 3-4 (diff, agent) → Task 2.
- §5 agent guardrails (scope, tools, prompt) → Task 2 Step 3.
- §6 failure isolation (agent absent/timeout → regen still commits; exit 0) → Task 1 (`|| true`, `set -u`, guarded regen) + Task 2 (`command -v`/timeout guards) + tests `test_claude_absent…`/`test_claude_timeout…`.
- §7 knobs (`PTFLOW_NO_DOC_SYNC`, `PTFLOW_DOC_SYNC_TIMEOUT`, `CLAUDE_BIN`; +internal `PTFLOW_DOC_SYNC_REGEN`) → Task 1/Task 2, exercised by tests.
- §8 testing (5 hermetic cases) → Task 1 (4) + Task 2 (3, incl. timeout — exceeds the spec's 5, additive).
- §9 docs → Task 3.

**2. Placeholder scan:** no TBD/TODO; every script/test/doc block is complete; commands have expected outputs. The `# >>> AGENT_PHASE <<<` marker is an intentional, documented anchor replaced verbatim in Task 2, not a placeholder.

**3. Type/name consistency:** env seam names identical across tasks and the Global Constraints (`PTFLOW_NO_DOC_SYNC`, `PTFLOW_DOC_SYNC_TIMEOUT`, `CLAUDE_BIN`, `PTFLOW_DOC_SYNC_REGEN`). Test helpers (`_init_repo`/`_stub`/`_env`/`_merge`/`_subjects`) defined in Task 1, reused in Task 2. Staged paths and commit-subject prefix (`docs: auto-sync after merge`) consistent between the script (Task 1) and every test assertion (Tasks 1-2, 4).

**Known limitation (documented):** the hermetic tests stub `PTFLOW_DOC_SYNC_REGEN` and `CLAUDE_BIN`, so the real `uv run python -m ptflow.core.flowdocs` string and a real `claude` run are exercised only in Task 4 (Step 2 checks the regen string standalone; Step 3 runs the real hook end-to-end on a clone with a stub claude). A real-agent run is intentionally never automated (non-deterministic, costs tokens) — it happens for the first time when this branch itself is merged to main with the hook active.
