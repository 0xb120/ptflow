"""meta.json helpers — per-app identity (cluster signature + member hosts)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_meta(meta_path: Path, data: dict[str, Any]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_meta(meta_path: Path) -> dict[str, Any]:
    return json.loads(meta_path.read_text(encoding="utf-8"))
