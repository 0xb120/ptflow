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
