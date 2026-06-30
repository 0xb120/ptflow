"""Run config — load the operator-facing knobs (the PIPT_* env vars) from an optional TOML file.

Distinct from ``core/config.py`` (the structural ``Config``/``CONFIG`` defaults): this is the
*operator/run* layer. Precedence: ``--set`` CLI override > ``PIPT_*`` env var > config file > code
default. The ~119 internal tuning constants are deliberately NOT here — they stay as expert defaults in
the pipeline code (the ``profile`` bundle covers the rate-sensitive ones). The mechanism is thin:
``resolve()`` yields the effective ``{ENV: value}`` set that the CLI writes into ``os.environ`` BEFORE
importing the pipeline (whose constants read ``PIPT_*`` at import), so the existing env reads stay the
single consumption point — no constant is re-plumbed. ``snapshot()`` records the effective values
(secrets redacted) next to the run for reproducibility.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple

from pipt.core.log import get_logger

log = get_logger()

_HTTP_HEADER_SEP = ";;"          # PIPT_HTTP_HEADER multi-value separator (env reader also accepts \n)
_TRUE = {"1", "on", "true", "yes"}
_ENUMS = {"PIPT_PROFILE": ("wide", "home"), "PIPT_RECRAWL": ("off", "preview", "on")}
_ROLES_PREFIX = "wordlists.roles."   # dynamic: wordlists.roles.<role> → PIPT_WL_<ROLE>


class Knob(NamedTuple):
    """One operator knob: its dotted config key, the PIPT_* env var it feeds, its value kind, and
    whether it's a secret (redacted in the snapshot)."""

    path: str
    env: str
    kind: str          # str | bool | int | list | path
    secret: bool = False


# config-key → PIPT_* env var — the SINGLE source of truth for the operator knobs. (wordlists.roles.<role>
# → PIPT_WL_<ROLE> is handled dynamically below since the role names are open-ended.)
_KNOBS: tuple[Knob, ...] = (
    Knob("profile", "PIPT_PROFILE", "str"),
    Knob("net_limit", "PIPT_NET_LIMIT", "int"),
    Knob("http_header", "PIPT_HTTP_HEADER", "list", secret=True),
    Knob("oast", "PIPT_OAST", "bool"),
    Knob("recrawl", "PIPT_RECRAWL", "str"),
    Knob("deep_dive", "PIPT_DEEP_DIVE", "bool"),
    Knob("tools.sqlmap", "PIPT_SQLMAP", "path"),
    Knob("tools.search_vulns", "PIPT_SEARCH_VULNS", "path"),
    Knob("tools.nuclei_dast_templates", "PIPT_NUCLEI_DAST_TEMPLATES", "path"),
    Knob("tools.eyewitness", "PIPT_EYEWITNESS", "path"),
    Knob("wordlists.dir", "PIPT_WORDLISTS", "path"),
    Knob("interactsh.server", "PIPT_INTERACTSH_SERVER", "str"),
    Knob("interactsh.token", "PIPT_INTERACTSH_TOKEN", "str", secret=True),
)
_BY_PATH = {k.path: k for k in _KNOBS}


class Resolved(NamedTuple):
    """An effective knob value: the env var to set, its dotted config key (for the snapshot), the
    coerced string value, and whether to redact it."""

    env: str
    path: str
    value: str
    secret: bool


class ConfigError(ValueError):
    """A missing/malformed config file, a malformed --set, or an invalid enum value."""


def load_config(path: str | None) -> dict[str, Any]:
    """Parse the TOML config file → dict (``{}`` when no path given). Raises ConfigError on a missing
    or malformed file."""
    if not path:
        return {}
    p = Path(path).expanduser()
    if not p.is_file():
        msg = f"config file not found: {path}"
        raise ConfigError(msg)
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        msg = f"malformed config {path}: {e}"
        raise ConfigError(msg) from e


def _flatten(cfg: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested TOML tables → flat dotted keys (so ``[tools] sqlmap=…`` becomes ``tools.sqlmap``)."""
    out: dict[str, Any] = {}
    for k, v in cfg.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{key}."))
        else:
            out[key] = v
    return out


def _coerce(kind: str, value: Any) -> str:
    """A config/override value → the string form the PIPT_* env reader expects."""
    if kind == "bool":
        truthy = value is True or (isinstance(value, str) and value.strip().lower() in _TRUE)
        return "on" if truthy else "off"
    if kind == "list":
        items = value if isinstance(value, list) else [value]
        return _HTTP_HEADER_SEP.join(str(x) for x in items)
    if kind == "path":
        return str(Path(str(value)).expanduser())
    return str(value)


def _parse_overrides(sets: Iterable[str] | None) -> dict[str, str]:
    """``--set KEY=VALUE`` items → {dotted-key: raw-value}. Raises ConfigError on a malformed item."""
    out: dict[str, str] = {}
    for item in sets or []:
        if "=" not in item:
            msg = f"--set expects KEY=VALUE, got: {item!r}"
            raise ConfigError(msg)
        key, val = item.split("=", 1)
        out[key.strip()] = val
    return out


def _validate(env: str, value: str) -> None:
    allowed = _ENUMS.get(env)
    if allowed and value not in allowed:
        msg = f"invalid {env}={value!r} — expected one of {', '.join(allowed)}"
        raise ConfigError(msg)


def _pick(knob: Knob, overrides: dict[str, str], env: Mapping[str, str],
          flat: Mapping[str, Any]) -> str | None:
    """Effective value for one knob with precedence override > env > config (None if unset). An env
    value is already in env-string form (used as-is); override/config values are coerced."""
    if knob.path in overrides:
        return _coerce(knob.kind, overrides[knob.path])
    if knob.env in env:
        return env[knob.env]
    if knob.path in flat:
        return _coerce(knob.kind, flat[knob.path])
    return None


def resolve(config: Mapping[str, Any], env: Mapping[str, str],
            sets: Iterable[str] | None = None) -> list[Resolved]:
    """Effective knob values (precedence --set > env > config), coerced to the env string form and
    validated (enums; unknown keys warned as likely typos). Pure — env and overrides are passed in."""
    overrides = _parse_overrides(sets)
    flat = _flatten(config)
    for source, keys in (("config", flat), ("--set", overrides)):
        for key in keys:
            if key not in _BY_PATH and not key.startswith(_ROLES_PREFIX):
                log.warning("⚠ unknown %s key '%s' — ignored (typo?)", source, key)

    out: list[Resolved] = []
    for knob in _KNOBS:
        value = _pick(knob, overrides, env, flat)
        if value is not None:
            _validate(knob.env, value)
            out.append(Resolved(knob.env, knob.path, value, secret=knob.secret))
    # dynamic per-role wordlist pins: wordlists.roles.<role> → PIPT_WL_<ROLE>
    roles = {k[len(_ROLES_PREFIX):] for k in (*flat, *overrides) if k.startswith(_ROLES_PREFIX)}
    for role in sorted(roles):
        rk = Knob(f"{_ROLES_PREFIX}{role}", f"PIPT_WL_{role.upper()}", "path")
        value = _pick(rk, overrides, env, flat)
        if value is not None:
            out.append(Resolved(rk.env, rk.path, value, secret=False))
    return out


def apply(resolved: Iterable[Resolved]) -> None:
    """Write the resolved knobs into os.environ — MUST run before importing the pipeline (its constants
    read PIPT_* at import). An env var already set to its own value is a harmless no-op."""
    for r in resolved:
        os.environ[r.env] = r.value


def _toml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def snapshot(activity_dir: Path, resolved: Iterable[Resolved]) -> Path | None:
    """Write the effective run config to ``<activity>/config.toml`` (secrets redacted) for
    reproducibility — re-feedable with ``--config``. Returns the path, or None if nothing was set."""
    rows = sorted(resolved, key=lambda r: r.path)
    if not rows:
        return None
    lines = ["# pipt — effective run config (auto-generated; secrets redacted).",
             "# Re-feed with:  pipt run <pipeline> <activity> <scope> --config config.toml", ""]
    lines += [f"{r.path} = {_toml_quote('<redacted>' if r.secret else r.value)}" for r in rows]
    out = activity_dir / "config.toml"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
