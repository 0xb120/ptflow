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
