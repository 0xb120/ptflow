"""Environment-agnostic wordlist resolution: roles → files.

The pipeline references global wordlists by ROLE (`content`, `wordpress`, …), never by a
specific file or collection. `provision()` resolves each role to a concrete file and
symlinks it into the activity's wl_global/ (paths-as-contract + provenance); steps then
read wl_global/<role>.txt by role. Resolution per role, in priority order:

  1. BYO       — wl_global/<role>.txt already present (user-dropped, or a prior provision)
  2. explicit  — env PIPT_WL_<ROLE> = /abs/path/to/list.txt
  3. discovery — first existing candidate filename under a search dir
  4. (none)    — unresolved; the step degrades to the generated wl_custom only

Search dirs = env PIPT_WORDLISTS (':'-separated) ++ common collection locations. This keeps
the pipeline independent of WHICH collection (roles + candidate names suit SecLists or any
other), WHERE it's installed (env/discovery), and whether it's installed at all (degrade).
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipt.core.paths import Activity

_DEFAULT_DIRS = (
    "/usr/share/seclists", "/opt/SecLists", "/opt/wordlist/SecLists",
    "/usr/share/wordlists/seclists", "/usr/share/wordlists",
)

# role -> ordered candidate paths relative to a search dir; first existing wins. Lists the
# common filenames across collections, so it's provider-agnostic (not SecLists-only).
ROLE_CANDIDATES: dict[str, tuple[str, ...]] = {
    "content": (
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "Discovery/Web-Content/common.txt",
        "raft-medium-directories.txt", "common.txt", "directory-list-2.3-medium.txt",
    ),
    "params": (  # hidden-parameter names for arjun/x8 (param_fuzz, loop 3)
        "Discovery/Web-Content/burp-parameter-names.txt",
        "burp-parameter-names.txt",
    ),
    "wordpress": ("Discovery/Web-Content/CMS/wordpress.fuzz.txt",),
    "drupal": ("Discovery/Web-Content/CMS/Drupal.txt", "Discovery/Web-Content/CMS/drupal-themes.fuzz.txt"),
    "joomla": ("Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",),
}
TECH_ROLES = ("wordpress", "drupal", "joomla")  # roles matched against detected tech tags


def search_dirs() -> list[Path]:
    """Wordlist base dirs: env PIPT_WORDLISTS (':'-sep) prepended to common locations,
    filtered to those that exist."""
    env = os.environ.get("PIPT_WORDLISTS", "")
    return [p for d in (*env.split(":"), *_DEFAULT_DIRS) if d and (p := Path(d)).is_dir()]


def _resolve(role: str) -> Path | None:
    """Resolve a role to a concrete file: env override first, else the first candidate
    filename found under a search dir. None if unresolved."""
    override = os.environ.get(f"PIPT_WL_{role.upper()}")
    if override and Path(override).is_file():
        return Path(override)
    for base in search_dirs():
        for rel in ROLE_CANDIDATES.get(role, ()):
            cand = base / rel
            if cand.is_file():
                return cand
    return None


def provision(activity: Activity) -> dict[str, Path]:
    """Resolve every known role and symlink the found files into wl_global/<role>.txt.
    A pre-existing wl_global/<role>.txt (BYO) is left untouched. Best-effort + idempotent.
    """
    wl = activity.wl_global
    wl.mkdir(parents=True, exist_ok=True)
    resolved: dict[str, Path] = {}
    for role in ROLE_CANDIDATES:
        dst = wl / f"{role}.txt"
        if dst.is_symlink() or dst.is_file():  # BYO or already provisioned
            resolved[role] = dst
            continue
        src = _resolve(role)
        if src is not None:
            with contextlib.suppress(OSError):  # race / no symlink support → best-effort
                dst.symlink_to(src)
            resolved[role] = dst
    return resolved


def role_path(activity: Activity, role: str) -> Path | None:
    """The provisioned wl_global/<role>.txt for `role`, or None if unresolved."""
    p = activity.wl_global / f"{role}.txt"
    return p if p.is_file() else None


def tech_role_paths(tech: list[str], wl_global: Path) -> list[Path]:
    """wl_global/<role>.txt files for the tech roles matched by the detected tech tags."""
    tags = [t.lower() for t in tech]
    return [p for role in TECH_ROLES
            if any(role in tag for tag in tags) and (p := wl_global / f"{role}.txt").is_file()]
