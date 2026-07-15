"""Run config — load the operator-facing knobs (the PTFLOW_* env vars) from an optional TOML file.

Distinct from ``core/config.py`` (the structural ``Config``/``CONFIG`` defaults): this is the
*operator/run* layer. Precedence: ``--set`` CLI override > ``PTFLOW_*`` env var > config file > code
default. The ~119 internal tuning constants are deliberately NOT here — they stay as expert defaults in
the pipeline code (the ``profile`` bundle covers the rate-sensitive ones). The mechanism is thin:
``resolve()`` yields the effective ``{ENV: value}`` set that the CLI writes into ``os.environ`` BEFORE
importing the pipeline (whose constants read ``PTFLOW_*`` at import), so the existing env reads stay the
single consumption point — no constant is re-plumbed. ``snapshot()`` records the effective values
(secrets redacted) next to the run for reproducibility.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Collection, Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple

from ptflow.core.log import get_logger

log = get_logger()

_HTTP_HEADER_SEP = ";;"          # PTFLOW_HTTP_HEADER multi-value separator (env reader also accepts \n)
_TRUE = {"1", "on", "true", "yes"}
_AI_PROVIDERS = (
    "ollama", "openrouter", "huggingface", "openai-compatible", "openai", "claude-code",
)
_AI_STAGE_NAMES = ("wordlist", "secret_triage", "triage", "report")
_ENUMS = {
    "PTFLOW_PROFILE": ("wide", "home"),
    "PTFLOW_RECRAWL": ("off", "preview", "on"),
    "PTFLOW_AI_PROVIDER": _AI_PROVIDERS,
    "PTFLOW_AI_REMOTE_SECRETS": ("off", "redacted", "full"),
    "PTFLOW_DAST_AGGRESSION": ("low", "medium", "high"),
}
_KEY_ALIASES = {"ai": "ai.enabled"}  # legacy `ai=on`; canonical table-safe key is ai.enabled
_ROLES_PREFIX = "wordlists.roles."   # dynamic: wordlists.roles.<role> → PTFLOW_WL_<ROLE>
_STEPS_PREFIX = "steps."   # dynamic: steps.<pipeline>.<step> → per-step on/off (filters pipeline.stages)
_STEPS_KEY_SEGMENTS = 3   # steps.<pipeline>.<step> — fewer segments is a malformed (unrecognized) key
_ATOMIC_TABLES: frozenset[str] = frozenset()


class Knob(NamedTuple):
    """One operator knob: its dotted config key, the PTFLOW_* env var it feeds, its value kind, and
    whether it's a secret (redacted in the snapshot)."""

    path: str
    env: str
    kind: str          # str | bool | int | list | path | json
    secret: bool = False


# config-key → PTFLOW_* env var — the SINGLE source of truth for the operator knobs. (wordlists.roles.<role>
# → PTFLOW_WL_<ROLE> is handled dynamically below since the role names are open-ended.)
_KNOBS: tuple[Knob, ...] = (
    Knob("profile", "PTFLOW_PROFILE", "str"),
    Knob("net_limit", "PTFLOW_NET_LIMIT", "int"),
    Knob("http_header", "PTFLOW_HTTP_HEADER", "list", secret=True),
    Knob("oast", "PTFLOW_OAST", "bool"),
    Knob("recrawl", "PTFLOW_RECRAWL", "str"),
    Knob("deep_dive", "PTFLOW_DEEP_DIVE", "bool"),
    Knob("ai.enabled", "PTFLOW_AI", "bool"),
    Knob("ai.model", "PTFLOW_AI_MODEL", "str"),
    Knob("ai.base_url", "PTFLOW_AI_BASE_URL", "str"),
    Knob("ai.provider", "PTFLOW_AI_PROVIDER", "str"),
    Knob("ai.cache", "PTFLOW_AI_CACHE", "bool"),
    Knob("ai.concurrency", "PTFLOW_AI_CONCURRENCY", "int"),
    Knob("ai.timeout_seconds", "PTFLOW_AI_TIMEOUT_SECONDS", "int"),
    Knob("ai.max_retries", "PTFLOW_AI_MAX_RETRIES", "int"),
    Knob("ai.max_calls", "PTFLOW_AI_MAX_CALLS", "int"),
    Knob("ai.max_input_tokens", "PTFLOW_AI_MAX_INPUT_TOKENS", "int"),
    Knob("ai.max_output_tokens", "PTFLOW_AI_MAX_OUTPUT_TOKENS", "int"),
    Knob("ai.max_cost", "PTFLOW_AI_MAX_COST", "str"),
    Knob("ai.remote_secrets", "PTFLOW_AI_REMOTE_SECRETS", "str"),
    *(Knob(f"ai.stages.{stage}.enabled", f"PTFLOW_AI_STAGE_{stage.upper()}_ENABLED", "bool")
      for stage in _AI_STAGE_NAMES),
    *(Knob(f"ai.stages.{stage}.provider", f"PTFLOW_AI_STAGE_{stage.upper()}_PROVIDER", "str")
      for stage in _AI_STAGE_NAMES),
    *(Knob(f"ai.stages.{stage}.model", f"PTFLOW_AI_STAGE_{stage.upper()}_MODEL", "str")
      for stage in _AI_STAGE_NAMES),
    *(Knob(f"ai.stages.{stage}.base_url", f"PTFLOW_AI_STAGE_{stage.upper()}_BASE_URL", "str")
      for stage in _AI_STAGE_NAMES),
    *(Knob(f"ai.stages.{stage}.max_output_tokens",
           f"PTFLOW_AI_STAGE_{stage.upper()}_MAX_OUTPUT_TOKENS", "int")
      for stage in _AI_STAGE_NAMES),
    Knob("dast.aggression", "PTFLOW_DAST_AGGRESSION", "str"),
    Knob("dast.fuzz_param_frequency", "PTFLOW_DAST_FUZZ_PARAM_FREQUENCY", "int"),
    Knob("dast.packs", "PTFLOW_DAST_PACKS", "json"),
    Knob("tools.sqlmap", "PTFLOW_SQLMAP", "path"),
    Knob("tools.search_vulns", "PTFLOW_SEARCH_VULNS", "path"),
    Knob("tools.nuclei_dast_templates", "PTFLOW_NUCLEI_DAST_TEMPLATES", "path"),
    Knob("tools.eyewitness", "PTFLOW_EYEWITNESS", "path"),
    Knob("wordlists.dir", "PTFLOW_WORDLISTS", "path"),
    Knob("interactsh.server", "PTFLOW_INTERACTSH_SERVER", "str"),
    Knob("interactsh.token", "PTFLOW_INTERACTSH_TOKEN", "str", secret=True),
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
        if isinstance(v, dict) and key not in _ATOMIC_TABLES:
            out.update(_flatten(v, f"{key}."))
        else:
            out[key] = v
    return out


def _coerce(kind: str, value: Any) -> str:
    """A config/override value → the string form the PTFLOW_* env reader expects."""
    if kind == "bool":
        truthy = value is True or (isinstance(value, str) and value.strip().lower() in _TRUE)
        return "on" if truthy else "off"
    if kind == "list":
        items = value if isinstance(value, list) else [value]
        return _HTTP_HEADER_SEP.join(str(x) for x in items)
    if kind == "json":
        if isinstance(value, str):
            try:
                json.loads(value)
            except json.JSONDecodeError as exc:
                msg = f"invalid JSON config value: {exc}"
                raise ConfigError(msg) from exc
            return value
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
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
        normalized = key.strip()
        out[_KEY_ALIASES.get(normalized, normalized)] = val
    return out


def _validate(env: str, value: str) -> None:
    allowed = _AI_PROVIDERS if env.startswith("PTFLOW_AI_STAGE_") and env.endswith("_PROVIDER") \
        else _ENUMS.get(env)
    if allowed and value not in allowed:
        msg = f"invalid {env}={value!r} — expected one of {', '.join(allowed)}"
        raise ConfigError(msg)
    if env == "PTFLOW_DAST_PACKS":
        try:
            json.loads(value)
        except json.JSONDecodeError as exc:
            msg = f"invalid {env}: {exc}"
            raise ConfigError(msg) from exc


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


def _is_recognized_key(key: str) -> bool:
    """A config/override key the resolver knows about — a declared knob, a wordlist-role pin, or a
    FULLY-FORMED per-step toggle (`steps.<pipeline>.<step>`). A malformed `steps.` key (missing the
    pipeline or step segment) is deliberately NOT recognized, so resolve() warns it as a likely typo."""
    if key in _BY_PATH or key in _KEY_ALIASES or key.startswith(_ROLES_PREFIX):
        return True
    if key.startswith(_STEPS_PREFIX):
        return len(key.split(".")) >= _STEPS_KEY_SEGMENTS
    return False


def resolve(config: Mapping[str, Any], env: Mapping[str, str],
            sets: Iterable[str] | None = None) -> list[Resolved]:
    """Effective knob values (precedence --set > env > config), coerced to the env string form and
    validated (enums; unknown keys warned as likely typos). Pure — env and overrides are passed in."""
    overrides = _parse_overrides(sets)
    flat = {_KEY_ALIASES.get(k, k): v for k, v in _flatten(config).items()}
    for source, keys in (("config", flat), ("--set", overrides)):
        for key in keys:
            if not _is_recognized_key(key):
                log.warning("⚠ unknown %s key '%s' — ignored (typo?)", source, key)

    out: list[Resolved] = []
    for knob in _KNOBS:
        value = _pick(knob, overrides, env, flat)
        if value is not None:
            _validate(knob.env, value)
            out.append(Resolved(knob.env, knob.path, value, secret=knob.secret))
    # dynamic per-role wordlist pins: wordlists.roles.<role> → PTFLOW_WL_<ROLE>
    roles = {k[len(_ROLES_PREFIX):] for k in (*flat, *overrides) if k.startswith(_ROLES_PREFIX)}
    for role in sorted(roles):
        rk = Knob(f"{_ROLES_PREFIX}{role}", f"PTFLOW_WL_{role.upper()}", "path")
        value = _pick(rk, overrides, env, flat)
        if value is not None:
            out.append(Resolved(rk.env, rk.path, value, secret=False))
    return out


def resolve_disabled_steps(config: Mapping[str, Any], sets: Iterable[str] | None,
                           pipeline: str, stage_names: Collection[str]) -> frozenset[str]:
    """The steps to DISABLE for `pipeline`, from the `[steps.<pipeline>]` config table + `--set
    steps.<pipeline>.<step>=off` (precedence --set > config), validated against the pipeline's LIVE
    stage names. Sparse: only a step set to a falsey value is disabled; an unlisted step stays on.
    Pure. Raises ConfigError on an unknown step name (so a stale/renamed step can't be referenced)."""
    flat = _flatten(config)
    overrides = _parse_overrides(sets)
    prefix = f"{_STEPS_PREFIX}{pipeline}."
    names = {k[len(prefix):] for src in (flat, overrides) for k in src if k.startswith(prefix)}
    disabled: set[str] = set()
    for name in names:
        if name not in stage_names:
            valid = ", ".join(sorted(stage_names))
            msg = f"unknown step '{name}' for pipeline '{pipeline}' — valid: {valid}"
            raise ConfigError(msg)
        key = f"{prefix}{name}"
        raw = overrides[key] if key in overrides else flat[key]  # --set wins over config
        if _coerce("bool", raw) == "off":
            disabled.add(name)
    return frozenset(disabled)


def apply(resolved: Iterable[Resolved]) -> None:
    """Write the resolved knobs into os.environ — MUST run before importing the pipeline (its constants
    read PTFLOW_* at import). An env var already set to its own value is a harmless no-op."""
    for r in resolved:
        os.environ[r.env] = r.value


def _toml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def snapshot(activity_dir: Path, resolved: Iterable[Resolved], *,
             disabled_keys: Iterable[str] = ()) -> Path | None:
    """Write the effective run config to ``<activity>/config.toml`` (secrets redacted) for
    reproducibility — re-feedable with ``--config``. Includes disabled steps as ``steps.<pipeline>.<step>
    = "off"`` lines. Returns the path, or None if nothing was set."""
    rows = sorted(resolved, key=lambda r: r.path)
    steps = sorted(disabled_keys)
    if not rows and not steps:
        return None
    lines = ["# ptflow — effective run config (auto-generated; secrets redacted).",
             "# Re-feed with:  ptflow run <pipeline> <activity> <scope> --config config.toml", ""]
    lines += [f"{r.path} = {_toml_quote('<redacted>' if r.secret else r.value)}" for r in rows]
    lines += [f"{k} = {_toml_quote('off')}" for k in steps]
    out = activity_dir / "config.toml"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
