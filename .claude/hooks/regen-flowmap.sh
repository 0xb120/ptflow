#!/usr/bin/env sh
# PostToolUse hook — keep docs/<pipeline>-pipeline-{flow,map}.{html,md} in sync with the pipeline code.
# Fires after Edit/Write/MultiEdit; regenerates EVERY pipeline's flow map ONLY when the edited file
# lives under src/ptflow/pipelines/ (where the steps are). Reads the tool payload as JSON on stdin.
# Never blocks the edit (always exits 0); the regen is deterministic, so an unchanged flow leaves no diff.
payload=$(cat 2>/dev/null)
file=$(printf '%s' "$payload" | sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$file" in
  *src/ptflow/pipelines/*) ;;
  *) exit 0 ;;
esac

root="${CLAUDE_PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}"
cd "$root" 2>/dev/null || exit 0
uv run python -m ptflow.core.flowdocs >/dev/null 2>&1 || true
exit 0
