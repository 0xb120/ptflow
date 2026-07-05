# Design — Post-merge doc-sync hook (agent-driven)

- **Date:** 2026-07-05
- **Status:** Approved (design); pending implementation plan
- **Scope:** repo tooling — a versioned git `post-merge` hook + a small driver script. No changes to
  `src/ptflow/` runtime code. Touches: `.githooks/`, docs (CLAUDE.md/README), a test.

## 1. Motivation

The repo has no automation that keeps documentation current after a merge to `main`. Only the flow-map
docs (`docs/<pipeline>-pipeline-{flow.html,map.html,map.md}`, 9 files) are machine-generated (from the
`Stage` objects via `python -m ptflow.core.flowdocs`); the prose docs (`CLAUDE.md`, `README.md`,
`ptflow.toml.example`) are hand-written and drift silently until someone remembers to update them (as
happened with the step-toggles feature — CLAUDE.md needed a manual follow-up commit after merge).

The operator wants a **post-merge hook that updates ALL documentation — human- and agent-facing —
automatically**. Because most docs are prose that a deterministic script cannot author, the hook combines
two mechanisms: a deterministic regeneration of the generated docs, and a **headless Claude agent** that
rewrites the prose docs to reflect the merged change.

## 2. Goals / Non-goals

**Goals:**
- After a merge whose result is on `main`, automatically: regenerate the generated flow-map docs, and run
  a headless Claude agent to update the living prose docs (`CLAUDE.md`, `README.md`, `ptflow.toml.example`)
  to reflect the merged code changes.
- Commit all doc changes as ONE isolated follow-up commit (`docs: auto-sync after merge <sha>`) — reviewable,
  amendable, revertable in one shot; never mixed into the merge commit.
- Default-ON once installed (installing the hook IS the opt-in); a one-off escape via
  `PTFLOW_NO_DOC_SYNC=1`.
- Fully failure-isolated: never fail or block the merge; skip gracefully when `claude` is unavailable
  (still commit the deterministic regeneration); bound the agent with a timeout.
- Live in the repo (versioned `.githooks/`), so the logic is reviewable and testable — not a private
  `.git/hooks/` script.

**Non-goals:**
- Running the full dev gate (`ruff`/`ty`/`pytest`) as a merge gate — that stays the human's manual
  responsibility; the hook is doc-sync only.
- Editing design records (`docs/superpowers/specs/**`, `docs/superpowers/plans/**`) — those are
  point-in-time artifacts, never retroactively rewritten.
- Editing code, tests, or configuration logic — the agent touches prose docs only.
- Propagating the hook to other clones automatically — `core.hooksPath` is a documented one-time setup
  (the repo is local/single-dev today).
- Running on merges that don't land on `main`, or on `git pull` on other branches.

## 3. Trigger & location

- **`.githooks/post-merge`** (versioned, executable), activated once with
  `git config core.hooksPath .githooks`. The repo has no active git hooks today, so pointing
  `core.hooksPath` at `.githooks/` is clean (and does not affect the Claude Code PostToolUse hook, which
  is a separate mechanism).
- The hook body is thin; the real logic lives in `.githooks/doc-sync.sh` (sourced/called by `post-merge`)
  so it is unit-testable in isolation and the `post-merge` entry stays a one-liner.
- Fires only when the merge result is on `main`: `[ "$(git symbolic-ref --short -q HEAD)" = "main" ]`
  (detached HEAD or any other branch → clean skip). `git merge` sets `ORIG_HEAD` to the pre-merge tip, so
  the merged-in change is `ORIG_HEAD..HEAD`.

## 4. Flow (5 phases)

1. **Guards → clean skip (exit 0, no output beyond a one-line note):**
   - not on `main`;
   - `PTFLOW_NO_DOC_SYNC=1`;
   - no changes under `src/` in `ORIG_HEAD..HEAD` (`git diff --quiet ORIG_HEAD HEAD -- src/`) — prose docs
     describe the code, so a merge that touches no source needs no doc sync (token-saving default);
   - `ORIG_HEAD` unset (not a real merge context).
2. **Deterministic regeneration:** `uv run python -m ptflow.core.flowdocs` — realigns the 9
   `docs/*-pipeline-*` files. Always runs (independent of the agent).
3. **Merge diff context:** capture `git diff --stat ORIG_HEAD HEAD` + the full `git diff ORIG_HEAD HEAD`
   (truncated to a byte cap, e.g. ~200 KB, with a "[truncated]" marker) to feed the agent as prompt context.
4. **Agent prose update (best-effort):** invoke `claude` headless (print mode) with the diff + guardrails.
   - Allowed tools: `Read`, `Edit`, `Grep`, `Glob` — **no `Bash`** (the agent cannot run git or arbitrary
     commands; the diff is supplied in the prompt).
   - Edits auto-accepted non-interactively (exact flags — `--print`, `--allowedTools`, permission mode —
     pinned in the plan after checking `claude --help`; intent: headless, edit-capable, tool-restricted).
   - Bounded by `timeout ${PTFLOW_DOC_SYNC_TIMEOUT:-300}`.
   - Binary resolved via `${CLAUDE_BIN:-claude}` (override enables test stubbing).
   - Scope: may edit only `CLAUDE.md`, `README.md`, `ptflow.toml.example`.
5. **Single commit:** stage ONLY the specific doc paths — the generated maps (`docs/*-pipeline-*.html`,
   `docs/*-pipeline-*.md`) plus `CLAUDE.md`, `README.md`, `ptflow.toml.example`. **Deliberately NOT `docs/`
   broadly** (that would risk staging `docs/superpowers/**` design records). If `git diff --cached --quiet`
   (nothing changed) → no commit. Else commit `docs: auto-sync after merge <ORIG_HEAD-short>..<HEAD-short>`
   with a `Co-Authored-By: Claude` trailer and a body noting whether the agent ran. Staging only these
   explicit paths prevents dragging unrelated working-tree changes (e.g. the untracked `run-test.sh`, or a
   design record) into the commit.

## 5. Agent guardrails (prompt)

The prompt instructs the agent to:
- Update ONLY prose that the merge diff makes stale; preserve structure, voice, and existing content —
  surgical edits, not rewrites; never delete sections wholesale.
- Edit only `CLAUDE.md`, `README.md`, `ptflow.toml.example`; never `docs/superpowers/**`, code, or tests.
- Do nothing if nothing is stale (an empty result is correct and fine).
- Keep CLAUDE.md's role as the single source of truth intact.

Safety rests on three layers: the restricted tool set (no Bash), the path scope, and the isolated
reviewable commit (a bad edit is one `git revert`/amend away, never entangled with the merge).

## 6. Failure isolation

- The agent failing, timing out, or being offline → the deterministic regeneration (phase 2) is still
  committed, with a WARNING that the prose auto-update was skipped.
- `claude` absent/unauthenticated → phase 4 skipped, phase 2 still commits.
- No recursion: a commit does not re-trigger `post-merge`; the agent has no Bash/git access.
- The hook always exits 0 (a post-merge hook cannot fail the merge, but it must also not error noisily);
  every external call is guarded.

## 7. Control knobs (env)

- `PTFLOW_NO_DOC_SYNC=1` — skip the whole hook for this merge.
- `PTFLOW_DOC_SYNC_TIMEOUT` — agent wall-clock cap in seconds (default 300).
- `CLAUDE_BIN` — override the `claude` binary path (also the test seam: point it at a stub).

## 8. Testing

The logic lives in `.githooks/doc-sync.sh` with a `CLAUDE_BIN` seam so the agent call is stubbable. A
pytest module shells out against a throwaway git repo (created in a tmp dir) with a stub `claude` script:
- **main-merge + stub claude** → a `docs: auto-sync` commit appears (stub edits a marker into CLAUDE.md).
- **merge on a non-main branch** → no commit, no edits.
- **`PTFLOW_NO_DOC_SYNC=1`** → no action.
- **`claude` absent** (`CLAUDE_BIN=/nonexistent`) → graceful skip of phase 4, but the deterministic
  flowdocs regeneration is still committed.
- **no `src/` changes in the merge** → no action.
The stub `claude` is a tiny script that ignores its args and writes a known marker to a doc file, so the
test asserts the orchestration (guards, regen, staging, commit), not Claude's real output.

## 9. Docs (meta)

Document the hook and the one-time `git config core.hooksPath .githooks` setup in `CLAUDE.md` (and a short
line in `README.md`), including the `PTFLOW_NO_DOC_SYNC` / `PTFLOW_DOC_SYNC_TIMEOUT` / `CLAUDE_BIN` knobs
and the "commits a separate `docs: auto-sync` commit you should review" behavior.

## 10. Rejected alternatives

- **Deterministic-only hook (approach A in brainstorming)** — regenerate generated docs + flag prose
  staleness without rewriting it. Rejected by the operator in favor of the agent-driven prose update (B).
- **Auto-amend the doc changes into the merge commit** — cleaner history but rewrites a commit and
  entangles non-deterministic agent edits with the merge; the isolated follow-up commit is safer/reviewable.
- **Stage-only (no commit)** — safest but not the automatic behavior requested; the isolated commit is the
  chosen middle ground (automatic yet trivially reversible).
- **Opt-in per merge (`PTFLOW_DOC_SYNC=on`)** — matches the AI-layer's default-off convention, but the
  operator wants automatic behavior; installing the hook is the opt-in, with `PTFLOW_NO_DOC_SYNC` as the
  escape.
- **Giving the agent `Bash`/git access** — unnecessary (diff supplied in prompt) and a needless blast
  radius; restricted tools + path scope keep it contained.
- **Running the full dev gate in the hook** — scope creep; verification stays the manual `pytest` gate.
