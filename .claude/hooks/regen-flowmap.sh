#!/usr/bin/env sh
# PostToolUse hook — keep docs/pipeline-flow.html in sync with the pipeline code.
# Fires after Edit/Write/MultiEdit; regenerates the flow map ONLY when the edited file lives under
# src/pipt/pipelines/ (where the steps are). Reads the tool payload as JSON on stdin. Never blocks
# the edit (always exits 0); the regen is deterministic, so an unchanged flow leaves no git diff.
payload=$(cat 2>/dev/null)
file=$(printf '%s' "$payload" | sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

case "$file" in
  *src/pipt/pipelines/*) ;;
  *) exit 0 ;;
esac

root="${CLAUDE_PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}"
cd "$root" 2>/dev/null || exit 0
uv run python -m pipt.pipelines.external.flowmeta >/dev/null 2>&1 || true
exit 0
