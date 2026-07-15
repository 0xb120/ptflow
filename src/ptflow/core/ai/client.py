"""Provider-neutral LLM clients plus the run-scoped AI control plane.

Provider adapters only translate a completion into :class:`LLMResult`.  ``make_client(stage,
activity)`` adds the operational controls shared by every provider: per-stage routing, a local
content-addressed cache, run budgets, bounded concurrency, and append-only usage telemetry.
Failures remain best-effort and never abort a scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar
from urllib.parse import urlparse

import anyio
from pydantic import BaseModel

from ptflow.core.log import get_logger

if TYPE_CHECKING:
    from ptflow.core.paths import Activity

log = get_logger()

_TRUE = {"1", "on", "true", "yes"}
_FALSE = {"0", "off", "false", "no"}
_DEFAULT_PROVIDER = "ollama"
_OPENAI_COMPATIBLE_PROVIDERS = frozenset({
    "ollama", "openrouter", "huggingface", "openai-compatible", "openai",
})
_DEFAULT_BASE_URLS = {
    "ollama": "http://127.0.0.1:11434/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "huggingface": "https://router.huggingface.co/v1",
}
_DEFAULT_STAGE_MAX_TOKENS = {
    "wordlist": 2_000,
    "secret_triage": 4_000,
    "triage": 8_000,
    "report": 12_000,
}
_CACHE_VERSION = 1

T = TypeVar("T")
P = TypeVar("P", bound="BaseModel")


@dataclass(frozen=True)
class LLMResult(Generic[T]):
    """One observable provider call. ``value=None`` is the uniform failure/no-output state."""

    value: T | None
    provider: str
    model: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost: float | None = None
    latency_ms: int = 0
    finish_reason: str | None = None
    structured_fallback: bool = False
    cache_hit: bool = False
    error: str | None = None


class LLMClient(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str | None: ...

    @property
    def remote(self) -> bool: ...

    def complete_json(
        self, system: str, user: str, schema: type[P], *, max_tokens: int = 4096,
    ) -> LLMResult[P]: ...

    def complete_text(
        self, system: str, user: str, *, max_tokens: int = 4096,
    ) -> LLMResult[str]: ...


def _failure(provider: str, model: str | None, error: str, started: float) -> LLMResult[Any]:
    return LLMResult(
        value=None,
        provider=provider,
        model=model,
        latency_ms=round((time.monotonic() - started) * 1000),
        error=error,
    )


def _extract_json(text: str) -> str | None:
    """Pull the first JSON object/array from a reply, stripping fences and surrounding prose."""
    if not text:
        return None
    value = text.strip()
    if value.startswith("```"):
        value = value[3:]
        if value[:4].lower() == "json":
            value = value[4:]
        value = value.rsplit("```", 1)[0].strip()
    starts = [position for position in (value.find("{"), value.find("[")) if position != -1]
    if not starts:
        return None
    start = min(starts)
    end = max(value.rfind("}"), value.rfind("]"))
    return value[start : end + 1] if end > start else None


def _combine_results(results: list[LLMResult[Any]], value: T | None, *,
                     error: str | None = None) -> LLMResult[T]:
    last = results[-1]
    costs = [result.cost for result in results if result.cost is not None]
    return LLMResult(
        value=value,
        provider=last.provider,
        model=last.model,
        prompt_tokens=sum(result.prompt_tokens for result in results),
        completion_tokens=sum(result.completion_tokens for result in results),
        total_tokens=sum(result.total_tokens for result in results),
        cost=sum(costs) if costs else None,
        latency_ms=sum(result.latency_ms for result in results),
        finish_reason=last.finish_reason,
        structured_fallback=True,
        error=error,
    )


def _json_via_prompt(
    complete_text_fn: Callable[[str, str], LLMResult[str]], system: str, user: str,
    schema: type[P], *, retries: int = 1,
) -> LLMResult[P]:
    """Portable structured-output fallback using JSON Schema in the prompt plus validation."""
    prompted_system = (
        system
        + "\n\nRespond with ONLY a JSON value conforming to this JSON Schema — no prose, "
        + "no markdown fences:\n"
        + json.dumps(schema.model_json_schema(), sort_keys=True)
    )
    attempts: list[LLMResult[Any]] = []
    for _ in range(retries + 1):
        result = complete_text_fn(prompted_system, user)
        attempts.append(result)
        raw = _extract_json(result.value or "")
        if raw:
            try:
                return _combine_results(attempts, schema.model_validate_json(raw))
            except Exception:  # noqa: BLE001 - invalid model output is a normal retry path
                log.debug("AI structured-output validation failed; retrying")
    return _combine_results(attempts, None, error=attempts[-1].error or "invalid_structured_output")


def _usage_value(usage: object | None, *names: str) -> Any:
    for name in names:
        value = usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
        if value is not None:
            return value
    return None


def _result_from_response(resp: object, value: T | None, provider: str, model: str,
                          started: float) -> LLMResult[T]:
    usage = getattr(resp, "usage", None)
    prompt = int(_usage_value(usage, "prompt_tokens", "input_tokens") or 0)
    completion = int(_usage_value(usage, "completion_tokens", "output_tokens") or 0)
    total = int(_usage_value(usage, "total_tokens") or prompt + completion)
    cost_value = _usage_value(usage, "cost")
    choices = getattr(resp, "choices", None) or []
    finish = getattr(choices[0], "finish_reason", None) if choices else None
    return LLMResult(
        value=value,
        provider=provider,
        model=model,
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
        cost=float(cost_value) if cost_value is not None else None,
        latency_ms=round((time.monotonic() - started) * 1000),
        finish_reason=finish,
    )


def _is_remote(provider: str, base_url: str | None) -> bool:
    if provider == "ollama":
        return False
    host = (urlparse(base_url).hostname or "").lower() if base_url else ""
    return host not in {"127.0.0.1", "localhost", "::1"}


class OpenAICompatibleClient:
    """Chat-completions adapter shared by Ollama, OpenRouter, HF and compatible endpoints."""

    def __init__(  # noqa: PLR0913
        self, model: str, base_url: str | None = None, api_key: str | None = None,
        client: object | None = None, *, provider: str = "openai-compatible",
        timeout_seconds: float = 180, max_retries: int = 2,
    ) -> None:
        self.name = provider
        self.model = model
        self.remote = _is_remote(provider, base_url)
        self._base_url = base_url
        self._api_key = api_key or "not-needed"
        self._client = client
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries

    def _sdk(self) -> object:
        if self._client is None:
            import openai  # noqa: PLC0415 - optional dependency

            self._client = openai.OpenAI(
                base_url=self._base_url,
                api_key=self._api_key,
                timeout=self._timeout_seconds,
                max_retries=self._max_retries,
            )
        return self._client

    @staticmethod
    def _messages(system: str, user: str) -> list[dict[str, str]]:
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def complete_text(
        self, system: str, user: str, *, max_tokens: int = 4096,
    ) -> LLMResult[str]:
        started = time.monotonic()
        try:
            response = self._sdk().chat.completions.create(  # ty: ignore[unresolved-attribute]
                model=self.model,
                messages=self._messages(system, user),
                max_tokens=max_tokens,
                temperature=0,
            )
            content = response.choices[0].message.content or None
            return _result_from_response(response, content, self.name, self.model, started)
        except Exception as exc:  # best-effort provider boundary
            log.exception("AI complete_text failed")
            return _failure(self.name, self.model, type(exc).__name__, started)

    def complete_json(
        self, system: str, user: str, schema: type[P], *, max_tokens: int = 4096,
    ) -> LLMResult[P]:
        started = time.monotonic()
        try:
            response = self._sdk().chat.completions.create(  # ty: ignore[unresolved-attribute]
                model=self.model,
                messages=self._messages(system, user),
                max_tokens=max_tokens,
                temperature=0,
                response_format={"type": "json_schema", "json_schema": {
                    "name": "out", "schema": schema.model_json_schema(), "strict": True,
                }},
            )
            content = response.choices[0].message.content
            if content:
                parsed = schema.model_validate_json(content)
                return _result_from_response(response, parsed, self.name, self.model, started)
        except Exception:  # noqa: BLE001 - structured output is optional across providers
            log.debug("native response_format unavailable; using prompt fallback")
        return _json_via_prompt(
            lambda prompted_system, prompted_user: self.complete_text(
                prompted_system, prompted_user, max_tokens=max_tokens,
            ),
            system,
            user,
            schema,
        )


def _cc_text(messages: list[object]) -> str:
    parts: list[str] = []
    for message in messages:
        for block in getattr(message, "content", None) or []:
            value = getattr(block, "text", None)
            if value:
                parts.append(value)
    return "".join(parts)


def _cc_structured(messages: list[object]) -> object | None:
    for message in messages:
        value = getattr(message, "structured_output", None)
        if value is not None:
            return value
    return None


class ClaudeCodeClient:
    """Optional legacy Claude Agent SDK adapter, kept behind the ``ai-claude`` extra."""

    name = "claude-code"
    remote = True

    def __init__(
        self, model: str | None = None, *, query: Callable[..., Any] | None = None,
        options_cls: Callable[..., Any] | None = None, timeout_seconds: float = 180,
    ) -> None:
        self.model = model
        self._query = query
        self._options_cls = options_cls
        self._timeout_seconds = timeout_seconds

    def _sdk(self) -> tuple[Callable[..., Any], Callable[..., Any]]:
        if self._query is None or self._options_cls is None:
            from claude_agent_sdk import ClaudeAgentOptions, query  # noqa: PLC0415

            self._query = self._query or query
            self._options_cls = self._options_cls or ClaudeAgentOptions
        return self._query, self._options_cls

    async def _arun(self, system: str, user: str, output_format: object | None = None) -> list[object]:
        query, options_cls = self._sdk()
        options: dict[str, Any] = {"system_prompt": system, "tools": []}
        if self.model:
            options["model"] = self.model
        query_options: dict[str, Any] = {"prompt": user, "options": options_cls(**options)}
        if output_format is not None:
            query_options["output_format"] = output_format
        with anyio.fail_after(self._timeout_seconds):
            return [message async for message in query(**query_options)]

    def complete_text(
        self, system: str, user: str, *, max_tokens: int = 4096,  # noqa: ARG002
    ) -> LLMResult[str]:
        started = time.monotonic()
        try:
            value = _cc_text(anyio.run(self._arun, system, user)) or None
            return LLMResult(
                value=value, provider=self.name, model=self.model,
                latency_ms=round((time.monotonic() - started) * 1000),
            )
        except Exception as exc:
            log.exception("AI complete_text failed")
            return _failure(self.name, self.model, type(exc).__name__, started)

    def complete_json(
        self, system: str, user: str, schema: type[P], *, max_tokens: int = 4096,
    ) -> LLMResult[P]:
        started = time.monotonic()
        try:
            output_format = {"type": "json_schema", "schema": schema.model_json_schema()}
            structured = _cc_structured(anyio.run(self._arun, system, user, output_format))
            if structured is not None:
                return LLMResult(
                    value=schema.model_validate(structured), provider=self.name, model=self.model,
                    latency_ms=round((time.monotonic() - started) * 1000),
                )
        except Exception:  # noqa: BLE001 - structured output is optional in legacy provider
            log.debug("native structured output unavailable; using prompt fallback")
        return _json_via_prompt(
            lambda prompted_system, prompted_user: self.complete_text(
                prompted_system, prompted_user, max_tokens=max_tokens,
            ),
            system,
            user,
            schema,
        )


@dataclass(frozen=True)
class _RuntimeSettings:
    cache: bool
    concurrency: int
    max_calls: int
    max_input_tokens: int
    max_output_tokens: int
    max_cost: float
    stage_max_tokens: int


_IO_LOCK = threading.Lock()
_SEMAPHORE_LOCK = threading.Lock()
_SEMAPHORES: dict[int, threading.BoundedSemaphore] = {}
_RESERVATIONS: dict[str, tuple[int, int]] = {}


def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        log.warning("invalid %s; using %d", name, default)
        return default


def _float_env(name: str, default: float, *, minimum: float = 0) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        log.warning("invalid %s; using %s", name, default)
        return default


def _stage_prefix(stage: str) -> str:
    return "PTFLOW_AI_STAGE_" + stage.upper().replace("-", "_")


def stage_enabled(stage: str) -> bool:
    """A stage inherits global AI enablement unless its optional override disables it."""
    if os.getenv("PTFLOW_AI", "").strip().lower() not in _TRUE:
        return False
    value = os.getenv(f"{_stage_prefix(stage)}_ENABLED", "").strip().lower()
    return value not in _FALSE


def _runtime_settings(stage: str) -> _RuntimeSettings:
    prefix = _stage_prefix(stage)
    default_stage = _DEFAULT_STAGE_MAX_TOKENS.get(stage, 4096)
    return _RuntimeSettings(
        cache=os.getenv("PTFLOW_AI_CACHE", "on").strip().lower() not in _FALSE,
        concurrency=_int_env("PTFLOW_AI_CONCURRENCY", 2, minimum=1),
        max_calls=_int_env("PTFLOW_AI_MAX_CALLS", 50),
        max_input_tokens=_int_env("PTFLOW_AI_MAX_INPUT_TOKENS", 250_000),
        max_output_tokens=_int_env("PTFLOW_AI_MAX_OUTPUT_TOKENS", 30_000),
        max_cost=_float_env("PTFLOW_AI_MAX_COST", 0),
        stage_max_tokens=_int_env(
            f"{prefix}_MAX_OUTPUT_TOKENS",
            _int_env("PTFLOW_AI_STAGE_MAX_OUTPUT_TOKENS", default_stage),
            minimum=1,
        ),
    )


def _serialize_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


class ManagedLLMClient:
    """Run-scoped cache, budget, concurrency, and usage wrapper around a provider adapter."""

    def __init__(self, client: LLMClient, activity: Activity, stage: str) -> None:
        self._client = client
        self._activity = activity
        self.stage = stage
        self.name = client.name
        self.model = client.model
        self.remote = client.remote
        self._settings = _runtime_settings(stage)

    @property
    def _ai_dir(self) -> Path:
        return self._activity.base / "ai"

    @property
    def _usage_path(self) -> Path:
        return self._ai_dir / "usage.jsonl"

    def _cache_key(self, call_type: str, system: str, user: str, schema: object | None,
                   max_tokens: int) -> str:
        payload = {
            "version": _CACHE_VERSION,
            "provider": self.name,
            "model": self.model,
            "stage": self.stage,
            "call_type": call_type,
            "system": system,
            "user": user,
            "schema": schema,
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _cache_read(self, key: str, schema: type[P] | None) -> LLMResult[Any] | None:
        if not self._settings.cache:
            return None
        path = self._ai_dir / "cache" / f"{key}.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            value = payload["value"]
            if schema is not None:
                value = schema.model_validate(value)
            return LLMResult(
                value=value, provider=self.name, model=self.model, cache_hit=True,
                finish_reason=payload.get("finish_reason"),
                structured_fallback=bool(payload.get("structured_fallback")),
            )
        except (FileNotFoundError, KeyError, json.JSONDecodeError, ValueError):
            return None

    def _cache_write(self, key: str, result: LLMResult[Any]) -> None:
        if not self._settings.cache or result.value is None:
            return
        path = self._ai_dir / "cache" / f"{key}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": _CACHE_VERSION,
            "value": _serialize_value(result.value),
            "finish_reason": result.finish_reason,
            "structured_fallback": result.structured_fallback,
        }
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    def _usage_rows(self) -> list[dict[str, Any]]:
        if not self._usage_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in self._usage_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    def _reserve(self, estimated_input: int) -> str | None:
        identity = str(self._activity.base.resolve())
        with _IO_LOCK:
            rows = [
                row for row in self._usage_rows()
                if not row.get("cache_hit") and not str(row.get("error") or "").startswith("budget_")
            ]
            calls = len(rows)
            prompt = sum(int(row.get("prompt_tokens") or 0) for row in rows)
            completion = sum(int(row.get("completion_tokens") or 0) for row in rows)
            cost = sum(float(row.get("cost") or 0) for row in rows)
            reserved_calls, reserved_input = _RESERVATIONS.get(identity, (0, 0))
            if self._settings.max_calls and calls + reserved_calls >= self._settings.max_calls:
                return "budget_max_calls"
            if (self._settings.max_input_tokens
                    and prompt + reserved_input + estimated_input > self._settings.max_input_tokens):
                return "budget_max_input_tokens"
            if self._settings.max_output_tokens and completion >= self._settings.max_output_tokens:
                return "budget_max_output_tokens"
            if self._settings.max_cost and cost >= self._settings.max_cost:
                return "budget_max_cost"
            _RESERVATIONS[identity] = (reserved_calls + 1, reserved_input + estimated_input)
        return None

    def _release(self, estimated_input: int) -> None:
        identity = str(self._activity.base.resolve())
        with _IO_LOCK:
            calls, input_tokens = _RESERVATIONS.get(identity, (0, 0))
            next_value = (max(0, calls - 1), max(0, input_tokens - estimated_input))
            if next_value == (0, 0):
                _RESERVATIONS.pop(identity, None)
            else:
                _RESERVATIONS[identity] = next_value

    def _record(self, call_type: str, result: LLMResult[Any]) -> None:
        row = {
            "schema_version": 1,
            "timestamp": datetime.now(UTC).isoformat(),
            "stage": self.stage,
            "call_type": call_type,
            **{key: value for key, value in asdict(result).items() if key != "value"},
        }
        with _IO_LOCK:
            self._usage_path.parent.mkdir(parents=True, exist_ok=True)
            with self._usage_path.open("a", encoding="utf-8") as usage_file:
                usage_file.write(json.dumps(row, sort_keys=True) + "\n")

    def _call(
        self, call_type: str, system: str, user: str, schema: type[P] | None,
        max_tokens: int | None,
    ) -> LLMResult[Any]:
        effective_max = max_tokens or self._settings.stage_max_tokens
        schema_json = schema.model_json_schema() if schema is not None else None
        key = self._cache_key(call_type, system, user, schema_json, effective_max)
        cached = self._cache_read(key, schema)
        if cached is not None:
            self._record(call_type, cached)
            return cached

        estimated_input = max(1, (len(system) + len(user)) // 4)
        blocked = self._reserve(estimated_input)
        if blocked:
            result = LLMResult(value=None, provider=self.name, model=self.model, error=blocked)
            self._record(call_type, result)
            log.warning("AI %s skipped: %s", self.stage, blocked)
            return result

        with _SEMAPHORE_LOCK:
            semaphore = _SEMAPHORES.setdefault(
                self._settings.concurrency,
                threading.BoundedSemaphore(self._settings.concurrency),
            )
        try:
            with semaphore:
                if schema is None:
                    result = self._client.complete_text(
                        system, user, max_tokens=effective_max,
                    )
                else:
                    result = self._client.complete_json(
                        system, user, schema, max_tokens=effective_max,
                    )
            if result.prompt_tokens == 0:
                result = replace(
                    result,
                    prompt_tokens=estimated_input,
                    total_tokens=estimated_input + result.completion_tokens,
                )
            if result.completion_tokens == 0 and result.value is not None:
                estimated_output = max(1, len(json.dumps(
                    _serialize_value(result.value), sort_keys=True, default=str,
                )) // 4)
                result = replace(
                    result,
                    completion_tokens=estimated_output,
                    total_tokens=result.prompt_tokens + estimated_output,
                )
            self._cache_write(key, result)
            self._record(call_type, result)
            return result
        finally:
            self._release(estimated_input)

    def complete_text(
        self, system: str, user: str, *, max_tokens: int | None = None,
    ) -> LLMResult[str]:
        return self._call("text", system, user, None, max_tokens)

    def complete_json(
        self, system: str, user: str, schema: type[P], *, max_tokens: int | None = None,
    ) -> LLMResult[P]:
        return self._call("json", system, user, schema, max_tokens)


def _first_env(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _provider_api_key(provider: str) -> str | None:
    if provider == "ollama":
        return "ollama"
    if provider == "openrouter":
        return _first_env("OPENROUTER_API_KEY")
    if provider == "huggingface":
        return _first_env("HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN")
    return _first_env("OPENAI_API_KEY") or "not-needed"


def _stage_value(stage: str | None, suffix: str, global_name: str) -> str | None:
    if stage:
        value = os.getenv(f"{_stage_prefix(stage)}_{suffix}")
        if value:
            return value
    return os.getenv(global_name) or None


def make_client(  # noqa: PLR0911
    stage: str | None = None, activity: Activity | None = None,
) -> LLMClient | None:
    """Build the routed provider and optionally wrap it in run-scoped controls."""
    if os.getenv("PTFLOW_AI", "").strip().lower() not in _TRUE:
        return None
    if stage and not stage_enabled(stage):
        return None

    provider = (_stage_value(stage, "PROVIDER", "PTFLOW_AI_PROVIDER") or _DEFAULT_PROVIDER).lower()
    model = _stage_value(stage, "MODEL", "PTFLOW_AI_MODEL")
    timeout = _float_env("PTFLOW_AI_TIMEOUT_SECONDS", 180, minimum=1)
    retries = _int_env("PTFLOW_AI_MAX_RETRIES", 2)
    client: LLMClient
    if provider == "claude-code":
        try:
            import claude_agent_sdk  # noqa: F401, PLC0415
        except ImportError:
            log.warning("PTFLOW_AI_PROVIDER=claude-code requires ptflow[ai-claude] — AI disabled")
            return None
        client = ClaudeCodeClient(model=model, timeout_seconds=timeout)
    elif provider in _OPENAI_COMPATIBLE_PROVIDERS:
        if not model:
            log.warning("AI provider %s requires a model — stage %s disabled", provider, stage or "*")
            return None
        base_url = _stage_value(stage, "BASE_URL", "PTFLOW_AI_BASE_URL") or _DEFAULT_BASE_URLS.get(provider)
        if provider == "openai-compatible" and not base_url:
            log.warning("openai-compatible requires a base_url — AI disabled")
            return None
        api_key = _provider_api_key(provider)
        if provider in {"openrouter", "huggingface"} and not api_key:
            expected = "OPENROUTER_API_KEY" if provider == "openrouter" else "HF_TOKEN"
            log.warning("AI provider %s requires %s — AI disabled", provider, expected)
            return None
        try:
            import openai  # noqa: F401, PLC0415
        except ImportError:
            log.warning("AI enabled but 'openai' is missing (install ptflow[ai]) — AI disabled")
            return None
        client = OpenAICompatibleClient(
            model=model,
            base_url=base_url,
            api_key=api_key,
            provider=provider,
            timeout_seconds=timeout,
            max_retries=retries,
        )
    else:
        expected = " | ".join((*sorted(_OPENAI_COMPATIBLE_PROVIDERS), "claude-code"))
        log.warning("PTFLOW_AI_PROVIDER=%s unsupported (expected %s) — AI disabled", provider, expected)
        return None
    return ManagedLLMClient(client, activity, stage) if activity is not None and stage else client
