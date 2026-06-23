"""Single source of truth for every path — no literal paths in tasks/flows.

Activity workspace layout (parent dir = activity name):

    <activity>/
      scope.txt                       # the raw input scope
      scope/                          # parsed/expanded scope
        scope_init.txt  scope_urls.txt  scope_dns.txt  scope_ip.txt
      scans/
        asset_discovery/              # BREADTH phase (whole-scope discovery/enumeration)
          raw/<tool>/                 #   raw tool dumps
          hosts.jsonl                 #   canonical discovery output
        <app_id>/                     # one per clustered "application group" (DEPTH)
          meta.json  hosts.txt  services.jsonl  endpoints.txt
          wl_custom/                  #   per-app GENERATED wordlists (seed.txt, …)
          responses/                  #   downloaded HTML/JS corpus (katana -srd) — mined offline
          raw/<tool>/
      findings/                       # agent output (hypotheses.jsonl)
      poc/   tmp/   logs/
      wl_global/                      # shared/global INPUT wordlists (SecLists & co.)
"""

from __future__ import annotations

from pathlib import Path


class AppWorkspace:
    """Per application-group workspace (output of DEPTH stages): scans/<app_id>/."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def meta(self) -> Path:
        return self.root / "meta.json"

    @property
    def hosts(self) -> Path:
        """Canonical enum input — the group's host list (written by clustering)."""
        return self.root / "hosts.txt"

    @property
    def wl_custom(self) -> Path:
        """Per-app GENERATED wordlists (seed, shortnames, combined — derived from the
        app's crawled/collected corpus). Distinct from the activity-level wl_global/."""
        return self.root / "wl_custom"

    @property
    def responses(self) -> Path:
        """Per-app response store (katana -srd): the downloaded HTML/JS corpus that
        offline steps mine without re-fetching — the crawler IS the downloader for
        the linked surface. A canonical corpus, not raw/ provenance."""
        return self.root / "responses"

    def raw(self, tool: str) -> Path:
        return self.root / "raw" / tool

    def canonical(self, name: str) -> Path:
        return self.root / name

    def ensure(self) -> AppWorkspace:
        self.root.mkdir(parents=True, exist_ok=True)
        return self


class Activity:
    """Top-level activity workspace. Parent directory is the activity name."""

    def __init__(self, base: Path) -> None:
        self.base = base

    @classmethod
    def named(cls, name: str, root: Path | None = None) -> Activity:
        return cls((root or Path.cwd()) / name)

    @property
    def scope(self) -> Path:
        return self.base / "scope.txt"

    # --- scope/ expansion ---
    @property
    def scope_dir(self) -> Path:
        return self.base / "scope"

    @property
    def scope_init(self) -> Path:
        return self.scope_dir / "scope_init.txt"

    @property
    def scope_urls(self) -> Path:
        return self.scope_dir / "scope_urls.txt"

    @property
    def scope_dns(self) -> Path:
        return self.scope_dir / "scope_dns.txt"

    @property
    def scope_ip(self) -> Path:
        return self.scope_dir / "scope_ip.txt"

    # --- scans/ ---
    @property
    def scans(self) -> Path:
        return self.base / "scans"

    @property
    def asset_discovery(self) -> Path:
        return self.scans / "asset_discovery"

    def asset_discovery_raw(self, tool: str) -> Path:
        return self.asset_discovery / "raw" / tool

    def asset_discovery_canonical(self, name: str) -> Path:
        return self.asset_discovery / name

    def app(self, app_id: str) -> AppWorkspace:
        return AppWorkspace(self.scans / app_id)

    def list_apps(self) -> list[AppWorkspace]:
        """Every clustered app group under scans/, excluding asset_discovery/."""
        if not self.scans.exists():
            return []
        return [
            AppWorkspace(d)
            for d in sorted(self.scans.iterdir())
            if d.is_dir() and d.name != "asset_discovery"
        ]

    # --- other top-level dirs ---
    @property
    def findings(self) -> Path:
        return self.base / "findings"

    @property
    def poc(self) -> Path:
        return self.base / "poc"

    @property
    def tmp(self) -> Path:
        return self.base / "tmp"

    @property
    def wl_global(self) -> Path:
        """Shared/global INPUT wordlists for the run (e.g. SecLists). Per-app GENERATED
        wordlists live under each AppWorkspace.wl_custom instead."""
        return self.base / "wl_global"

    @property
    def logs(self) -> Path:
        return self.base / "logs"

    def ensure(self) -> Activity:
        for d in (
            self.scope_dir,
            self.asset_discovery,
            self.findings,
            self.poc,
            self.tmp,
            self.wl_global,
            self.logs,
        ):
            d.mkdir(parents=True, exist_ok=True)
        return self
