"""Single source of truth for every path — no literal paths in tasks/flows.

Activity workspace layout (parent dir = activity name):

    <activity>/
      scope.txt                       # the raw input scope
      scope/                          # parsed/expanded scope
        scope_init.txt  scope_urls.txt  scope_dns.txt  scope_ip.txt
      asset_discovery/                # BREADTH phase (whole-scope, activity-scope) — TOP-LEVEL,
        raw/<tool>/                   #   not under scans/, so scans/ holds only app groups
        hosts.jsonl                   #   canonical discovery output
      scans/                          # ONLY per-app group workspaces (DEPTH)
        <app_id>/                     # one per clustered "application group"
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
    """Per application-group workspace (output of DEPTH stages): scans/<app_id>/.

    LOCATION ENCODES ROLE — one home per file, no copies:
    - ``canonical(name)`` — an artifact read by a later stage OR a final deliverable. One writer;
      NEVER a byte-copy of a ``raw/`` file.
    - ``raw(tool)`` — provenance + a tool's own inputs/scratch. Never read as a canonical artifact
      downstream (it may be re-read inside the same stage). Multi-mode tools nest: ``raw/<tool>/<mode>/``.
    - ``wl_custom`` — generated wordlist PRODUCTS only (seed/shortnames/round*); tool scratch → raw/.
    - ``responses`` — the downloaded corpus.
    - ``findings`` — per-app findings (one file per scanner); the ``consolidate`` terminal step lifts
      these into the activity-level ``<activity>/findings/<type>.jsonl``.
    """

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
        """Per-app GENERATED wordlist PRODUCTS (seed, shortnames, per-round deltas — derived from the
        app's crawled/collected corpus). Tool scratch (e.g. shortscan rainbow tables) belongs in
        raw/, NOT here. Distinct from the activity-level wl_global/."""
        return self.root / "wl_custom"

    @property
    def responses(self) -> Path:
        """Per-app response store (katana -srd): the downloaded HTML/JS corpus that
        offline steps mine without re-fetching — the crawler IS the downloader for
        the linked surface. A canonical corpus, not raw/ provenance."""
        return self.root / "responses"

    @property
    def findings(self) -> Path:
        """Per-app findings folder: scans/<app_id>/findings/. Each scanner that produces a finding
        writes its own file here (e.g. tilde_enum.jsonl); a per-app dir keeps the fan-out race-free.
        The consolidate terminal step lifts these into the activity-level <activity>/findings/."""
        return self.root / "findings"

    @property
    def state(self) -> Path:
        """Resume markers for this app's per-app stages (one empty <stage>.done per completed stage).
        Consulted only with --resume, to skip stages that already finished cleanly. See Activity.state."""
        return self.root / ".state"

    def raw(self, tool: str) -> Path:
        """Provenance / tool scratch dir: scans/<app_id>/raw/<tool>/. Nothing downstream reads a
        canonical artifact from here. Multi-mode tools nest as raw/<tool>/<mode>/ (e.g.
        raw/httpx/{screenshot,osint,discovered}, raw/katana/{crawl,headless})."""
        return self.root / "raw" / tool

    def canonical(self, name: str) -> Path:
        """A downstream-read artifact or a final deliverable: scans/<app_id>/<name>. One writer,
        never a copy of a raw/ file. Tool inputs/scratch go to raw() instead."""
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
        """Activity-scope BREADTH output. A TOP-LEVEL dir (sibling of scans/), deliberately NOT
        under scans/ — scans/ holds only per-app group workspaces, so list_apps() needs no
        special-casing and the breadth dir never gets lost among the app_id dirs."""
        return self.base / "asset_discovery"

    def asset_discovery_raw(self, tool: str) -> Path:
        """Breadth provenance / tool scratch: asset_discovery/raw/<tool>/ (same role rule as
        AppWorkspace.raw — nothing downstream reads a canonical artifact from here)."""
        return self.asset_discovery / "raw" / tool

    def asset_discovery_canonical(self, name: str) -> Path:
        """Breadth artifact read by a later stage OR a final deliverable (e.g. domain_ip_map.txt,
        nerva_full_metadata.jsonl are write-only deliverables). One writer, never a raw/ copy."""
        return self.asset_discovery / name

    def app(self, app_id: str) -> AppWorkspace:
        return AppWorkspace(self.scans / app_id)

    def list_apps(self) -> list[AppWorkspace]:
        """Every clustered app group under scans/. scans/ holds ONLY app-group workspaces (breadth
        output lives in the top-level asset_discovery/), so nothing is special-cased by name."""
        if not self.scans.exists():
            return []
        return [AppWorkspace(d) for d in sorted(self.scans.iterdir()) if d.is_dir()]

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

    @property
    def state(self) -> Path:
        """Resume markers (one empty <stage>.done per completed activity/spanning stage). Hidden dir
        so it never shows among app groups; consulted only with --resume to skip already-done stages.
        A stale-after-scope-change guard (orchestrate) invalidates all markers if scope.txt changed."""
        return self.base / ".state"

    @property
    def screenshots(self) -> Path:
        """Activity-level screenshot output: the single batched httpx/EyeWitness run writes its
        UNIFIED gallery here (screenshot/screenshot.html, eyewitness/report.html) over one host per
        group; per-group screenshots are reconciled back into each scans/<app_id>/screenshot.png."""
        return self.base / "screenshots"

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
