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
