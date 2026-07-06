# AI provider-agnostic layer — design spec

**Date:** 2026-07-06
**Branch:** `feat/ai-provider-agnostic`
**Status:** approved (design), pending implementation plan

## Context & motivation

The optional AI layer (`--ai` / `PTFLOW_AI=on`) currently ships a single backend behind the
`core/ai/` seam: `AnthropicClient`, which calls the Anthropic Messages API and bills per token via
`ANTHROPIC_API_KEY`. The operator wants two things instead:

1. **Use a Claude Code Pro subscription** (not the metered API) for *all* AI functionality, accepting
   the higher per-call latency of the Claude Code runtime.
2. **Make the layer LLM-agnostic** — be able to point it at a local Ollama server, Ollama-cloud, or
   OpenRouter.

The Anthropic metered path is no longer wanted and is removed. The four AI stages
(`ai_triage`/`ai_report`/`ai_wordlist`/`ai_secret_triage`) and the `LLMClient` seam are unchanged in
shape; only the concrete backends behind `make_client()` change.

## Requirements

- Two selectable backends behind the existing `LLMClient` Protocol:
  - **`claude-code`** — the Claude Code Agent SDK, authenticated by the operator's subscription
    (`CLAUDE_CODE_OAUTH_TOKEN`) or `ANTHROPIC_API_KEY`; runs on all four stages.
  - **`openai`** — an OpenAI-compatible client driven by `base_url`, covering Ollama-local,
    Ollama-cloud, and OpenRouter with one implementation.
- Provider chosen by `PTFLOW_AI_PROVIDER`; **default `claude-code`**.
- `complete_json` (used by 3 of the 4 stages) must work on **heterogeneous providers**, including
  local Ollama models that do not support native schema-constrained output.
- Preserve the layer's invariants: best-effort (failure → no-op, never aborts a run), `net=False`
  stages, and **"AI off → DAG byte-identical"**.

## Non-goals (YAGNI)

- **No per-stage provider routing.** One provider is selected globally for a run (requirement 1 wants
  Claude Code on *all* stages). The existing per-stage `make_client()` call sites stay as-is.
- **No native non-OpenAI provider clients** beyond the one OpenAI-compatible client — Ollama-local,
  Ollama-cloud, and OpenRouter all speak the OpenAI API, so `base_url` + one client covers them.
- **No streaming** — the seam is request/response (`complete_json`/`complete_text`).
- **No Anthropic metered path** — `AnthropicClient` is removed.

## Architecture

### The `LLMClient` seam (unchanged)

`core/ai/client.py` remains the single provider seam. The Protocol is unchanged:

```python
class LLMClient(Protocol):
    name: str
    def complete_json(self, system: str, user: str, schema: type[T]) -> T | None: ...
    def complete_text(self, system: str, user: str, *, max_tokens: int = 64000) -> str | None: ...
```

Both new implementations accept an injectable client/callable in `__init__` (as `AnthropicClient`
did) so the concrete SDK is never required to unit-test them, and both import their SDK **lazily** so
importing the module never pulls the optional extra.

### `ClaudeCodeClient` (provider `claude-code`)

Wraps the Claude Code Agent SDK (`claude-agent-sdk`).

- Runs the agent as a **pure text generator**: `ClaudeAgentOptions(system_prompt=system, tools=[],
  model=<optional>)` — `tools=[]` disables bash/file/tool access so it behaves as a stateless LLM call.
- `complete_text`: `query(prompt=user, options=...)`, concatenate the text of the returned
  `AssistantMessage` `TextBlock`s.
- `complete_json`: request the SDK's native structured output (`output_format` with a
  `{"type": "json_schema", "schema": schema.model_json_schema()}`), read the validated
  `structured_output` from the result message, and coerce it with `schema.model_validate(...)`. If the
  installed SDK/version returns no `structured_output`, fall back to the shared prompt-based helper
  (below).
- The SDK is **async-only** while the seam is sync — each call wraps an async helper with
  `anyio.run(...)`. The AI stages run inside the `ThreadPoolTaskRunner`'s sync worker threads, so a
  per-call `anyio.run` is safe (no ambient event loop).
- **Auth** is handled by the SDK from the environment: `CLAUDE_CODE_OAUTH_TOKEN` (the subscription
  token from `claude setup-token`) or `ANTHROPIC_API_KEY`. Not a ptflow knob (consistent with the
  existing "AI key is a standard env var, not a `PTFLOW_*` knob" decision).
- **Model** is optional: `PTFLOW_AI_MODEL` if set, else the SDK/subscription default.
- Best-effort: any exception → log + `None`.

### `OpenAICompatibleClient` (provider `openai`)

Wraps the `openai` SDK with a configurable `base_url` — one client for Ollama-local
(`http://localhost:11434/v1`), Ollama-cloud, and OpenRouter (`https://openrouter.ai/api/v1`).

- `complete_text`: `chat.completions.create(model, messages=[system, user])`, return the message
  content.
- `complete_json` (**hybrid**, per the approved choice):
  1. Try native `response_format={"type": "json_schema", "json_schema": {"name": ...,
     "schema": schema.model_json_schema(), "strict": True}}`, then `schema.model_validate_json(...)`.
  2. On any failure (unsupported by the model, API error, invalid JSON) fall back to the shared
     prompt-based helper.
- **Model** is **required** (`PTFLOW_AI_MODEL`) — there is no sensible default across providers
  (`llama3.1` vs `openai/gpt-4o`); if unset, warn and return `None` (stage no-ops).
- **Auth**: `OPENAI_API_KEY` (the `openai` SDK's standard env). Ollama-local needs no key, but the SDK
  requires a non-empty `api_key` string, so pass a dummy (e.g. `"ollama"`) when the env var is unset.
- Best-effort: total failure → `None`.

### Shared hybrid structured-output helper

A module-level, unit-testable helper is the fallback path for both clients:

```python
def _json_via_prompt(complete_text_fn, system, user, schema, *, retries=1) -> T | None:
    # 1. append the JSON schema + "respond ONLY with JSON matching this schema" to the prompt
    # 2. call complete_text_fn, extract the JSON substring, schema.model_validate_json(...)
    # 3. on parse/validation failure, retry up to `retries` times, else return None
```

This keeps the "works even on a dumb local model" guarantee in one place, reused by
`OpenAICompatibleClient.complete_json` (fallback) and `ClaudeCodeClient.complete_json` (fallback).

### `make_client()` factory

The single entry point every stage uses. Behaviour:

- `PTFLOW_AI` off → `None` (unchanged; keeps the "AI off → DAG byte-identical" invariant).
- `PTFLOW_AI_PROVIDER` (default `claude-code`) selects the client:
  - `claude-code` → `ClaudeCodeClient(model=PTFLOW_AI_MODEL or None)`.
  - `openai` → `OpenAICompatibleClient(base_url=PTFLOW_AI_BASE_URL, model=PTFLOW_AI_MODEL,
    api_key=OPENAI_API_KEY or "ollama")`.
  - unknown → warn + `None`.
- Each branch guards its lazy import: if the extra isn't installed, log a warning and return `None`
  (the stage degrades to a no-op), exactly as the current anthropic-extra check does.

## Configuration surface

Reuses the existing knobs (`core/runconfig.py`); only the provider enum widens.

| Knob | Env | Change |
|---|---|---|
| `ai` | `PTFLOW_AI` | unchanged (master switch) |
| `ai.provider` | `PTFLOW_AI_PROVIDER` | enum → `("claude-code", "openai")`, **default `claude-code`** |
| `ai.model` | `PTFLOW_AI_MODEL` | unchanged; optional for claude-code, required for openai |
| `ai.base_url` | `PTFLOW_AI_BASE_URL` | unchanged; used by the openai provider |

Keys stay standard env vars, **not** ptflow knobs: `CLAUDE_CODE_OAUTH_TOKEN` / `ANTHROPIC_API_KEY`
(claude-code), `OPENAI_API_KEY` (openai).

## Dependencies

The `ai` optional extra in `pyproject.toml` changes from `anthropic` to `claude-agent-sdk` + `openai`.
Both get a `>=` floor pinned to the current released version at implementation time (resolved via
`uv add`), matching how `anthropic>=0.116.0` is pinned today.

Lazy imports mean an uninstalled SDK just degrades that provider to `None`. **Gotcha to document:**
`claude-agent-sdk` requires the `claude` CLI on PATH (it spawns it); the operator already has it.

## Error handling & invariants

- All new code is best-effort and `net=False`; any failure → log + `None` → the stage no-ops. A
  failure never aborts the run (unchanged invariant).
- `make_client()` returning `None` when AI is off keeps the DAG byte-identical to a non-AI run.
- With AI **on**, the default backend is now `claude-code` instead of `anthropic` — the intended
  behaviour change.

## Testing (TDD)

- **`_json_via_prompt` helper** (pure): native-success path is N/A here; test extract-parse-validate,
  retry-then-succeed, retry-exhausted → `None`, malformed-JSON → `None`. Inject a fake
  `complete_text_fn`.
- **`OpenAICompatibleClient`**: injected fake `openai` client — native `response_format` success;
  native failure → prompt fallback success; both fail → `None`; missing model → `None`;
  `complete_text` happy path.
- **`ClaudeCodeClient`**: injected fake SDK/callable — `structured_output` present → validated;
  absent → prompt fallback; `complete_text` happy path; exception → `None`.
- **`make_client()`**: env → correct class; unknown provider → `None` + warning; extra missing →
  `None` + warning; AI off → `None`.
- **`runconfig`**: accepts `claude-code`/`openai`, rejects unknown provider (config error, exit 2).
- **`tests/pipelines/test_external_ai.py`**: the four stages already inject fakes via the seam — verify
  they still pass unchanged.
- The existing **"AI off → stages byte-identical"** test stays green.

## Files touched

- `src/ptflow/core/ai/client.py` — rewrite: remove `AnthropicClient` + `_DEFAULT_MODEL`; add
  `ClaudeCodeClient`, `OpenAICompatibleClient`, `_json_via_prompt`, updated `make_client()`.
- `src/ptflow/core/runconfig.py` — widen the `PTFLOW_AI_PROVIDER` enum + default.
- `pyproject.toml` — `ai` extra deps.
- `tests/core/test_ai_client.py` — rewrite for the two new clients + `make_client` routing.
- `CLAUDE.md` — rewrite the AI-layer section (no more "Anthropic Messages API / claude-opus-4-8
  default"; document `claude-code`/`openai`, the knobs, the auth env vars, the `claude` CLI gotcha).
- `ptflow.toml.example` — update the AI knob annotations if present.

## Smoke tests (post-implementation, manual)

Cannot be verified offline; run against real endpoints after the code lands:

1. `CLAUDE_CODE_OAUTH_TOKEN` actually authenticates the Agent SDK headless (`PTFLOW_AI_PROVIDER=claude-code`).
2. `output_format` exists in the installed `claude-agent-sdk` version (else the prompt fallback carries it).
3. A run against a local Ollama server (`PTFLOW_AI_PROVIDER=openai`, `PTFLOW_AI_BASE_URL=http://localhost:11434/v1`,
   `PTFLOW_AI_MODEL=<a local model>`) produces a `report.md` and per-app AI artifacts.

## Rejected alternatives

- **Keep `anthropic` as a third provider** — the operator explicitly wants only claude-code + openai;
  Claude models remain reachable via the subscription through `claude-code`.
- **Per-stage provider routing** (claude-code on once-per-run stages, openai on per-app) — an earlier
  idea, dropped: requirement 1 wants Claude Code on *all* stages, so a single global provider is
  simpler and matches intent.
- **Three named providers** (`ollama`, `ollama-cloud`, `openrouter`) — unnecessary; one
  `openai`-compatible client + `base_url` covers all three.
- **Native-only structured output for the openai provider** — fails on local Ollama models that lack
  schema support, breaking the LLM-agnostic promise; the hybrid fallback is the cure.
