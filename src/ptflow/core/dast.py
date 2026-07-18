"""Nuclei DAST pack and all-template execution resolution.

The pipeline only accepts local template directories and always executes every template in every
enabled pack without tag/ID filters or phase-specific policies.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

_BUILTIN_STABLE = Path(__file__).resolve().parents[1] / "data" / "nuclei-dast" / "stable"
_BUILTIN_EXPERIMENTAL = Path(__file__).resolve().parents[1] / "data" / "nuclei-dast" / "experimental"
_OFFICIAL_DAST = Path.home() / "nuclei-templates" / "dast"
_PACK_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
_TOP_LEVEL_ID = re.compile(r"^id:\s*(['\"]?)([^'\"#\s]+)\1\s*(?:#.*)?$")
_AGGRESSIONS = frozenset({"low", "medium", "high"})


class DastConfigError(ValueError):
    """Raised when a DAST pack or global execution setting is malformed or ambiguous."""


@dataclass(frozen=True)
class Pack:
    """One locally available source of nuclei fuzzing templates."""

    name: str
    path: Path
    source: str = "custom"
    revision: str = ""
    enabled: bool = True


@dataclass(frozen=True)
class Settings:
    """Effective pack set and global all-template execution settings."""

    packs: tuple[Pack, ...]
    aggression: str = "high"
    fuzz_param_frequency: int = 10_000


@dataclass(frozen=True)
class TemplateRef:
    """A template ID mapped back to its source pack."""

    template_id: str
    path: Path
    pack: str


@dataclass(frozen=True)
class Selection:
    """The exact unfiltered template set resolved for a DAST pass."""

    packs: tuple[dict[str, Any], ...]
    templates: tuple[TemplateRef, ...]
    template_args: tuple[str, ...]
    aggression: str
    fuzz_param_frequency: int
    engine_omitted: tuple[TemplateRef, ...] = ()
    unresolved_paths: tuple[str, ...] = ()

    def manifest(self, *, status: str = "selected", error: str | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": 1,
            "status": status,
            "selection": {
                "mode": "all",
                "aggression": self.aggression,
                "fuzz_param_frequency": self.fuzz_param_frequency,
                "filters": [],
            },
            "packs": list(self.packs),
            # ``configured_count`` is the local pack inventory. ``effective_preview_count`` is what
            # the installed nuclei engine reports through ``-tl``. Keep ``selected_count`` as a
            # compatibility alias for the configured set; consumers must not mistake it for proof
            # that the engine loaded every template.
            "configured_count": len(self.templates) + len(self.unresolved_paths),
            "selected_count": len(self.templates) + len(self.unresolved_paths),
            "effective_preview_count": len(self.templates) - len(self.engine_omitted),
            "templates": [
                {"id": item.template_id, "path": str(item.path), "pack": item.pack}
                for item in self.templates
            ],
            "engine_preview": {
                "listed_count": len(self.templates) - len(self.engine_omitted),
                "omitted_templates": [
                    {"id": item.template_id, "path": str(item.path), "pack": item.pack}
                    for item in self.engine_omitted
                ],
            },
            "unresolved_template_paths": list(self.unresolved_paths),
        }
        if error:
            data["error"] = error
        return data


def _expand_pack_path(value: str) -> Path:
    if value == "@ptflow/stable":
        return _BUILTIN_STABLE
    if value == "@ptflow/experimental":
        return _BUILTIN_EXPERIMENTAL
    return Path(os.path.expandvars(value)).expanduser().resolve()


def _json_env(env: Mapping[str, str], name: str) -> Any | None:
    raw = env.get(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"{name} must contain valid JSON: {exc}"
        raise DastConfigError(msg) from exc


def _parse_pack(raw: Any, *, index: int) -> Pack:
    if not isinstance(raw, dict):
        msg = f"DAST pack #{index} must be an object"
        raise DastConfigError(msg)
    name = str(raw.get("name", "")).strip()
    path = str(raw.get("path", "")).strip()
    if not name or not _PACK_NAME.fullmatch(name):
        msg = f"DAST pack #{index} has invalid name {name!r}"
        raise DastConfigError(msg)
    if not path:
        msg = f"DAST pack {name!r} has no path"
        raise DastConfigError(msg)
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        msg = f"DAST pack {name!r} field 'enabled' must be boolean"
        raise DastConfigError(msg)
    return Pack(
        name=name,
        path=_expand_pack_path(path),
        source=str(raw.get("source", "custom")).strip() or "custom",
        revision=str(raw.get("revision", "")).strip(),
        enabled=enabled,
    )


def settings_from_env(
    env: Mapping[str, str] | None = None, *, legacy_path: str | None = None,
) -> Settings:
    """Build effective settings from PTFLOW_DAST_* JSON/string variables.

    ``legacy_path`` keeps ``PTFLOW_NUCLEI_DAST_TEMPLATES`` compatible when no structured pack list
    was supplied. Structured packs replace the default set. Every template in every enabled pack is
    selected; only global payload aggression and repeated-parameter frequency remain configurable.
    """
    source = os.environ if env is None else env
    raw_packs = _json_env(source, "PTFLOW_DAST_PACKS")
    if raw_packs is not None:
        if not isinstance(raw_packs, list):
            msg = "PTFLOW_DAST_PACKS must be a JSON array"
            raise DastConfigError(msg)
        packs = tuple(_parse_pack(item, index=index) for index, item in enumerate(raw_packs, 1))
    else:
        official_path = legacy_path or str(_OFFICIAL_DAST)
        packs = (
            Pack("official", _expand_pack_path(official_path), source="projectdiscovery"),
            Pack("ptflow-stable", _BUILTIN_STABLE, source="ptflow", revision="bundled"),
        )
    names = [pack.name for pack in packs]
    if len(names) != len(set(names)):
        msg = "DAST pack names must be unique"
        raise DastConfigError(msg)

    aggression = source.get("PTFLOW_DAST_AGGRESSION", "high").strip().lower() or "high"
    if aggression not in _AGGRESSIONS:
        msg = f"DAST aggression must be one of: {', '.join(sorted(_AGGRESSIONS))}"
        raise DastConfigError(msg)
    raw_frequency = source.get("PTFLOW_DAST_FUZZ_PARAM_FREQUENCY", "10000").strip() or "10000"
    frequency_error = "DAST fuzz_param_frequency must be a positive integer"
    try:
        frequency = int(raw_frequency)
    except ValueError as exc:
        raise DastConfigError(frequency_error) from exc
    if frequency < 1:
        raise DastConfigError(frequency_error)
    return Settings(packs=packs, aggression=aggression, fuzz_param_frequency=frequency)


def _yaml_files(path: Path) -> tuple[Path, ...]:
    return tuple(sorted((*path.rglob("*.yaml"), *path.rglob("*.yml"))))


@lru_cache(maxsize=64)
def _pack_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for template in _yaml_files(path):
        digest.update(str(template.relative_to(path)).encode())
        digest.update(b"\0")
        digest.update(template.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _template_id(path: Path) -> str:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith((" ", "\t", "#")) or not line.strip():
            continue
        match = _TOP_LEVEL_ID.fullmatch(line.strip())
        if match:
            return match.group(2)
        break
    msg = f"template has no top-level id: {path}"
    raise DastConfigError(msg)


def catalog(packs: Sequence[Pack]) -> tuple[TemplateRef, ...]:
    """Index every enabled, present template and reject duplicate IDs across packs."""
    records: list[TemplateRef] = []
    by_id: dict[str, TemplateRef] = {}
    for pack in packs:
        if not pack.enabled or not pack.path.is_dir():
            continue
        for path in _yaml_files(pack.path):
            ref = TemplateRef(_template_id(path), path.resolve(), pack.name)
            if previous := by_id.get(ref.template_id):
                msg = (
                    f"duplicate nuclei template id {ref.template_id!r}: "
                    f"{previous.path} and {ref.path}"
                )
                raise DastConfigError(msg)
            by_id[ref.template_id] = ref
            records.append(ref)
    return tuple(records)


def pack_manifests(packs: Sequence[Pack]) -> tuple[dict[str, Any], ...]:
    out: list[dict[str, Any]] = []
    for pack in packs:
        if not pack.enabled or not pack.path.is_dir():
            continue
        files = _yaml_files(pack.path)
        digest = _pack_digest(pack.path)
        out.append({
            "name": pack.name,
            "path": str(pack.path),
            "source": pack.source,
            "configured_revision": pack.revision or None,
            "sha256": digest,
            "effective_revision": pack.revision or f"sha256:{digest[:16]}",
            "template_count": len(files),
        })
    return tuple(out)


def template_args(packs: Sequence[Pack]) -> tuple[str, ...]:
    args: list[str] = []
    for pack in packs:
        if pack.enabled and pack.path.is_dir():
            args.extend(("-t", str(pack.path)))
    return tuple(args)


def _match_listed_path(line: str, refs: Sequence[TemplateRef]) -> TemplateRef | None:
    candidate = Path(line).expanduser()
    if candidate.is_absolute():
        resolved = candidate.resolve()
        return next((ref for ref in refs if ref.path == resolved), None)
    normalized = candidate.as_posix().lstrip("./")
    matches = [ref for ref in refs if ref.path.as_posix().endswith(f"/{normalized}")]
    if len(matches) == 1:
        return matches[0]
    matches = [ref for ref in refs if normalized.endswith(f"/{ref.path.name}")]
    return matches[0] if len(matches) == 1 else None


def list_selection(
    settings: Settings,
    *,
    run: Callable[[Sequence[str]], str],
    nuclei: str = "nuclei",
) -> Selection:
    """Ask nuclei for every available template, then map it back to pack provenance."""
    packs = tuple(pack for pack in settings.packs if pack.enabled and pack.path.is_dir())
    if not packs:
        msg = "no enabled DAST template pack directory exists"
        raise DastConfigError(msg)
    refs = catalog(packs)
    templates_argv = template_args(packs)
    output = run((nuclei, "-dast", "-tl", "-silent", "-nc", "-duc", *templates_argv))
    listed = tuple(
        line.strip() for line in output.splitlines()
        if line.strip().lower().endswith((".yaml", ".yml"))
    )
    unresolved: list[str] = []
    engine_listed: set[str] = set()
    for line in listed:
        ref = _match_listed_path(line, refs)
        if ref is None:
            unresolved.append(line)
        else:
            engine_listed.add(ref.template_id)
    return Selection(
        packs=pack_manifests(packs),
        templates=refs,
        template_args=templates_argv,
        aggression=settings.aggression,
        fuzz_param_frequency=settings.fuzz_param_frequency,
        engine_omitted=tuple(ref for ref in refs if ref.template_id not in engine_listed),
        unresolved_paths=tuple(unresolved),
    )


def stamp_findings(records: Sequence[dict], selection: Selection) -> list[dict]:
    """Attach pack revision and all-template provenance without discarding native fields."""
    refs = {ref.template_id: ref for ref in selection.templates}
    revisions = {pack["name"]: pack["effective_revision"] for pack in selection.packs}
    out: list[dict] = []
    for raw in records:
        record = dict(raw)
        template_id = str(record.get("template-id") or record.get("template_id") or "")
        ref = refs.get(template_id)
        record["ptflow_dast"] = {
            "selection": "all",
            "pack": ref.pack if ref else "unresolved",
            "pack_revision": revisions.get(ref.pack) if ref else None,
        }
        out.append(record)
    return out
