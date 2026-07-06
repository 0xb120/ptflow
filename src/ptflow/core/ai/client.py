"""LLM provider seam + two concrete implementations.

`LLMClient` is the provider-agnostic seam: any provider that can return structured JSON and free text
implements it. Two providers ship: `ClaudeCodeClient` (the Claude Agent SDK, running on the operator's
subscription or ANTHROPIC_API_KEY — the default) and `OpenAICompatibleClient` (any OpenAI-compatible
endpoint — Ollama local/cloud, OpenRouter, etc. — driven by `base_url`). Both providers' SDKs
(`claude-agent-sdk`, `openai`) are OPTIONAL dependencies (extra `ai`), imported lazily and guarded —
`make_client()` returns None (and the caller degrades) when the selected provider's SDK is absent,
when PTFLOW_AI is off, when the provider is unsupported, or when a required knob is missing.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, TypeVar

import anyio

from ptflow.core.log import get_logger

if TYPE_CHECKING:
    from pydantic import BaseModel

log = get_logger()

_TRUE = {"1", "on", "true", "yes"}

T = TypeVar("T", bound="BaseModel")


class LLMClient(Protocol):
    name: str

    def complete_json(self, system: str, user: str, schema: type[T]) -> T | None: ...

    def complete_text(self, system: str, user: str, *, max_tokens: int = 64000) -> str | None: ...


def _extract_json(text: str) -> str | None:
    """Pull the first JSON object/array out of a model's text reply — strips ``` fences and prose."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t[3:]
        if t[:4].lower() == "json":
            t = t[4:]
        t = t.rsplit("```", 1)[0].strip()
    starts = [p for p in (t.find("{"), t.find("[")) if p != -1]
    if not starts:
        return None
    start = min(starts)
    end = max(t.rfind("}"), t.rfind("]"))
    if end <= start:
        return None
    return t[start : end + 1]


def _json_via_prompt(complete_text_fn: Callable[[str, str], str | None], system: str, user: str,
                     schema: type[T], *, retries: int = 1) -> T | None:
    """Provider-agnostic structured-output fallback: put the JSON Schema in the prompt, call the text
    completion, extract + validate, retry on failure. Returns None if never valid."""
    sys2 = (system + "\n\nRespond with ONLY a JSON value conforming to this JSON Schema — no prose, "
            "no markdown fences:\n" + json.dumps(schema.model_json_schema()))
    for _ in range(retries + 1):
        raw = _extract_json(complete_text_fn(sys2, user) or "")
        if raw:
            try:
                return schema.model_validate_json(raw)
            except Exception:  # noqa: BLE001  (best-effort: bad JSON → retry/None)
                log.debug("AI structured-output validation failed; retrying")
    return None


class OpenAICompatibleClient:
    """OpenAI-compatible client (Ollama local/cloud, OpenRouter) driven by base_url. Hybrid
    structured output: native response_format json_schema first, prompt-based fallback otherwise.
    `client` is injected in tests; in production it's built lazily so importing this module never
    requires the optional `openai` extra."""

    name = "openai"

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 client: object | None = None) -> None:
        self.model = model
        self._base_url = base_url
        self._api_key = api_key or "ollama"   # Ollama needs no key; the SDK requires a non-empty str
        self._client = client

    def _sdk(self) -> object:
        if self._client is None:
            import openai  # noqa: PLC0415  (lazy — optional 'ai' extra)

            self._client = openai.OpenAI(base_url=self._base_url, api_key=self._api_key)
        return self._client

    def _messages(self, system: str, user: str) -> list[dict]:
        return [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def complete_text(self, system: str, user: str, *, max_tokens: int = 64000) -> str | None:
        try:
            resp = self._sdk().chat.completions.create(  # ty: ignore[unresolved-attribute]
                model=self.model, max_tokens=max_tokens, messages=self._messages(system, user))
            return resp.choices[0].message.content or None
        except Exception:  # best-effort: any failure degrades to None
            log.exception("AI complete_text failed")
            return None

    def complete_json(self, system: str, user: str, schema: type[T]) -> T | None:
        try:
            resp = self._sdk().chat.completions.create(  # ty: ignore[unresolved-attribute]
                model=self.model, max_tokens=16000, messages=self._messages(system, user),
                response_format={"type": "json_schema", "json_schema": {
                    "name": "out", "schema": schema.model_json_schema(), "strict": True}})
            content = resp.choices[0].message.content
            if content:
                return schema.model_validate_json(content)
        except Exception:  # noqa: BLE001  (model may not support response_format → fall back)
            log.debug("native response_format unavailable; using prompt fallback")
        return _json_via_prompt(self.complete_text, system, user, schema)


def _cc_text(messages: list) -> str:
    parts = []
    for m in messages:
        for b in getattr(m, "content", None) or []:
            t = getattr(b, "text", None)
            if t:
                parts.append(t)
    return "".join(parts)


def _cc_structured(messages: list) -> object | None:
    for m in messages:
        so = getattr(m, "structured_output", None)
        if so is not None:
            return so
    return None


class ClaudeCodeClient:
    """Claude Code Agent SDK client — runs the agent as a pure text generator (tools=[]) on the
    operator's subscription (CLAUDE_CODE_OAUTH_TOKEN) or ANTHROPIC_API_KEY. The SDK is async; the seam
    is sync, so each call bridges with anyio.run. `query`/`options_cls` are injected in tests; in
    production they're imported lazily so this module never requires the optional extra."""

    name = "claude-code"

    def __init__(self, model: str | None = None, *, query: object | None = None,
                 options_cls: object | None = None) -> None:
        self.model = model
        self._query = query
        self._options_cls = options_cls

    def _sdk(self) -> tuple:
        if self._query is None or self._options_cls is None:
            from claude_agent_sdk import ClaudeAgentOptions, query  # noqa: PLC0415  (lazy — extra)

            self._query = self._query or query
            self._options_cls = self._options_cls or ClaudeAgentOptions
        return self._query, self._options_cls

    async def _arun(self, system: str, user: str, output_format: object | None = None) -> list:
        query, options_cls = self._sdk()
        kw: dict = {"system_prompt": system, "tools": []}
        if self.model:
            kw["model"] = self.model
        qkw: dict = {"prompt": user, "options": options_cls(**kw)}
        if output_format is not None:
            qkw["output_format"] = output_format
        return [m async for m in query(**qkw)]

    def complete_text(self, system: str, user: str, *, max_tokens: int = 64000) -> str | None:  # noqa: ARG002
        try:
            return _cc_text(anyio.run(self._arun, system, user)) or None
        except Exception:  # best-effort
            log.exception("AI complete_text failed")
            return None

    def complete_json(self, system: str, user: str, schema: type[T]) -> T | None:
        try:
            of = {"type": "json_schema", "schema": schema.model_json_schema()}
            so = _cc_structured(anyio.run(self._arun, system, user, of))
            if so is not None:
                return schema.model_validate(so)
        except Exception:  # noqa: BLE001  (native output_format unsupported → fall back)
            log.debug("native structured output unavailable; using prompt fallback")
        return _json_via_prompt(self.complete_text, system, user, schema)


def make_client() -> LLMClient | None:  # noqa: PLR0911  (one early-return per degrade reason — clearer flat than nested)
    """The single entry point every AI stage uses. Returns None (⇒ the stage degrades to a no-op) when
    PTFLOW_AI is off, the provider is unsupported, a required knob is missing, or the provider's
    optional SDK is not installed."""
    if os.getenv("PTFLOW_AI", "").strip().lower() not in _TRUE:
        return None
    provider = os.getenv("PTFLOW_AI_PROVIDER", "claude-code").strip().lower()
    model = os.getenv("PTFLOW_AI_MODEL") or None
    if provider == "claude-code":
        try:
            import claude_agent_sdk  # noqa: F401, PLC0415  (presence check for the optional extra)
        except ImportError:
            log.warning("PTFLOW_AI on but 'claude-agent-sdk' is missing (install ptflow[ai]) — AI disabled")
            return None
        return ClaudeCodeClient(model=model)
    if provider == "openai":
        if not model:
            log.warning("PTFLOW_AI_PROVIDER=openai requires PTFLOW_AI_MODEL — AI disabled")
            return None
        try:
            import openai  # noqa: F401, PLC0415  (presence check for the optional extra)
        except ImportError:
            log.warning("PTFLOW_AI on but 'openai' is missing (install ptflow[ai]) — AI disabled")
            return None
        return OpenAICompatibleClient(model=model, base_url=os.getenv("PTFLOW_AI_BASE_URL") or None,
                                      api_key=os.getenv("OPENAI_API_KEY") or None)
    log.warning("PTFLOW_AI_PROVIDER=%s unsupported (expected claude-code | openai) — AI disabled",
                provider)
    return None
