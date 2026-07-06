"""LLM provider seam + Anthropic implementation.

`LLMClient` is the provider-agnostic seam: any provider that can return structured JSON and free text
implements it. v1 ships one concrete implementation, `AnthropicClient` (Anthropic Messages API). A
native non-Anthropic provider is a future implementation behind the same protocol (see the AI-layer
spec's Roadmap). The `anthropic` SDK is an OPTIONAL dependency (extra `ai`), imported lazily and
guarded — `make_client()` returns None (and the caller degrades) when it's absent, when PTFLOW_AI is
off, or when the provider is unsupported.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, TypeVar

from ptflow.core.log import get_logger

if TYPE_CHECKING:
    from pydantic import BaseModel

log = get_logger()

_TRUE = {"1", "on", "true", "yes"}
_DEFAULT_MODEL = "claude-opus-4-8"

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


class AnthropicClient:
    """Anthropic Messages API client. `client` is injected in tests; in production it's lazily built
    (so importing this module never requires the optional `anthropic` extra)."""

    name = "anthropic"

    def __init__(self, model: str = _DEFAULT_MODEL, base_url: str | None = None,
                 client: object | None = None) -> None:
        self.model = model
        self._base_url = base_url
        self._client = client

    def _sdk(self) -> object:
        if self._client is None:
            import anthropic  # noqa: PLC0415  (lazy — optional 'ai' extra)

            self._client = (anthropic.Anthropic(base_url=self._base_url) if self._base_url
                            else anthropic.Anthropic())
        return self._client

    @staticmethod
    def _system(text: str) -> list[dict]:
        # prompt caching on the stable system block to cut per-app cost
        return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]

    def complete_json(self, system: str, user: str, schema: type[T]) -> T | None:
        try:
            resp = self._sdk().messages.parse(  # ty: ignore[unresolved-attribute]
                model=self.model, max_tokens=16000,
                thinking={"type": "adaptive"},
                system=self._system(system),
                messages=[{"role": "user", "content": user}],
                output_format=schema,
            )
        except Exception:  # best-effort: any failure degrades to None
            log.exception("AI complete_json failed")
            return None
        else:
            return resp.parsed_output

    def complete_text(self, system: str, user: str, *, max_tokens: int = 64000) -> str | None:
        try:
            with self._sdk().messages.stream(  # ty: ignore[unresolved-attribute]
                model=self.model, max_tokens=max_tokens,
                thinking={"type": "adaptive"},
                system=self._system(system),
                messages=[{"role": "user", "content": user}],
            ) as stream:
                msg = stream.get_final_message()
            text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
        except Exception:  # best-effort: any failure degrades to None
            log.exception("AI complete_text failed")
            return None
        else:
            return text or None


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


def make_client() -> LLMClient | None:
    """The single entry point every AI stage uses. Returns None (⇒ the stage degrades to a no-op) when
    PTFLOW_AI is off, the provider is unsupported, or the `anthropic` extra is not installed."""
    if os.getenv("PTFLOW_AI", "").strip().lower() not in _TRUE:
        return None
    provider = os.getenv("PTFLOW_AI_PROVIDER", "anthropic").strip().lower()
    if provider != "anthropic":
        log.warning("PTFLOW_AI_PROVIDER=%s unsupported (v1: anthropic only) — AI disabled", provider)
        return None
    try:
        import anthropic  # noqa: F401, PLC0415  (presence check for the optional 'ai' extra)
    except ImportError:
        log.warning("PTFLOW_AI on but the 'anthropic' SDK is missing (install ptflow[ai]) — AI disabled")
        return None
    return AnthropicClient(model=os.getenv("PTFLOW_AI_MODEL", _DEFAULT_MODEL),
                           base_url=os.getenv("PTFLOW_AI_BASE_URL") or None)
