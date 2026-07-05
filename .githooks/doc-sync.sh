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

# --- phase 5: single scoped commit ------------------------------------------
for p in CLAUDE.md README.md ptflow.toml.example docs/*-pipeline-*.html docs/*-pipeline-*.md; do
  [ -e "$p" ] && git add -- "$p"
done

if git diff --cached --quiet; then
  log "no documentation changes to commit"; exit 0
fi

orig=$(git rev-parse --short ORIG_HEAD)
head=$(git rev-parse --short HEAD)
if git commit -q -m "docs: auto-sync after merge ${orig}..${head}" -m "Automated by the post-merge doc-sync hook.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"; then
  log "committed documentation auto-sync"
else
  log "commit failed"
fi
exit 0
