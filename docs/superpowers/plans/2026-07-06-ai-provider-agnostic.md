# AI Provider-Agnostic Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single Anthropic-metered AI backend with two selectable providers behind the existing `LLMClient` seam — `claude-code` (Agent SDK, subscription auth, default) and `openai` (OpenAI-compatible: Ollama local/cloud, OpenRouter) — with hybrid structured output that works on heterogeneous models.

**Architecture:** `core/ai/client.py` stays the single seam (`LLMClient` Protocol, unchanged). Two new lazy-imported, best-effort client classes join it, plus a shared prompt-based JSON helper used as the structured-output fallback. `make_client()` routes on `PTFLOW_AI_PROVIDER` (default `claude-code`). `AnthropicClient` is deleted. The four AI stages and their tests are unchanged.

**Tech Stack:** Python 3.11, `claude-agent-sdk` (async, spawns the `claude` CLI), `openai` SDK (OpenAI-compatible, `base_url`-driven), `anyio` (already a Prefect dep, for the sync→async bridge), Pydantic, pytest, ruff (`select=ALL`), ty.

## Global Constraints

- **Best-effort:** every client method catches all exceptions → logs → returns `None`. A failure never propagates to the orchestrator.
- **AI off → DAG byte-identical:** `make_client()` returns `None` when `PTFLOW_AI` is unset/false; nothing else changes.
- **Keys are standard env vars, NOT `PTFLOW_*` knobs:** `CLAUDE_CODE_OAUTH_TOKEN`/`ANTHROPIC_API_KEY` (claude-code), `OPENAI_API_KEY` (openai).
- **`client.py` must import without the `ai` extra:** the `claude-agent-sdk` / `openai` imports are lazy (inside methods/factory); only stdlib + `anyio` + `ptflow.core.log` at module top.
- **Default provider is `claude-code`.**
- **`openai` provider requires `PTFLOW_AI_MODEL`** (no cross-provider default); missing → warn + `None`.
- **Dependency floors** are pinned to the current released version via `uv add` at Task 1 (matching today's `anthropic>=0.116.0` style).
- Ruff `select=ALL`; respect existing `ignore`/`per-file-ignores` (tests already ignore `S101`/`ANN`/`PLC0415`/`SLF001`). Lazy imports inside functions need `# noqa: PLC0415`. Broad `except Exception` needs `# noqa: BLE001`.

---

### Task 1: Dependencies + provider enum

**Files:**
- Modify: `pyproject.toml:14-17` (the `ai` optional-dependencies extra)
- Modify: `src/ptflow/core/runconfig.py:30` (`_ENUMS["PTFLOW_AI_PROVIDER"]`)
- Test: `tests/core/test_runconfig.py` (add two tests)

**Interfaces:**
- Consumes: nothing.
- Produces: the `ai` extra now installs `claude-agent-sdk` + `openai`; `PTFLOW_AI_PROVIDER` validates against `("claude-code", "openai")`.

- [ ] **Step 1: Add the failing runconfig tests**

Append to `tests/core/test_runconfig.py`:

```python
def test_ai_provider_enum_accepts_new_values():
    from ptflow.core import runconfig
    for prov in ("claude-code", "openai"):
        resolved = runconfig.resolve({"ai": {"provider": prov}}, {})
        assert any(r.env == "PTFLOW_AI_PROVIDER" and r.value == prov for r in resolved)


def test_ai_provider_enum_rejects_unknown():
    import pytest
    from ptflow.core import runconfig
    with pytest.raises(runconfig.ConfigError):
        runconfig.resolve({"ai": {"provider": "anthropic"}}, {})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_runconfig.py::test_ai_provider_enum_accepts_new_values tests/core/test_runconfig.py::test_ai_provider_enum_rejects_unknown -v`
Expected: `test_ai_provider_enum_accepts_new_values` FAILS (`claude-code` rejected by the current `("anthropic",)` enum → `ConfigError`); the reject test may PASS coincidentally (anthropic still allowed) — both will be correct after Step 3.

- [ ] **Step 3: Widen the provider enum**

In `src/ptflow/core/runconfig.py`, change line 30 from:

```python
    "PTFLOW_AI_PROVIDER": ("anthropic",),
```

to:

```python
    "PTFLOW_AI_PROVIDER": ("claude-code", "openai"),
```

- [ ] **Step 4: Update the `ai` extra**

In `pyproject.toml`, replace lines 15-17:

```toml
ai = [
    "anthropic>=0.116.0",
]
```

with:

```toml
ai = [
    "claude-agent-sdk",
    "openai",
]
```

Then pin current floors and install:

Run: `uv add --optional ai claude-agent-sdk openai`
Then: `uv sync --all-groups --extra ai`
Expected: both packages resolve and install; `uv.lock` updates; `anthropic` no longer in the `ai` extra.

- [ ] **Step 5: Run the runconfig tests to verify they pass**

Run: `uv run pytest tests/core/test_runconfig.py -v`
Expected: PASS (both new tests green; the rest of the file unaffected).

- [ ] **Step 6: Guard against a stale anthropic assertion**

Run: `grep -n "anthropic" tests/core/test_runconfig.py`
Expected: no hits. If any test asserts `ai.provider == "anthropic"` resolves cleanly, change that value to `"claude-code"`. (There is no such test today; this step confirms it.)

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock src/ptflow/core/runconfig.py tests/core/test_runconfig.py
git commit -m "$(printf 'feat(ai): claude-agent-sdk + openai extras, widen provider enum\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 2: Shared JSON helpers (`_extract_json`, `_json_via_prompt`)

**Files:**
- Modify: `src/ptflow/core/ai/client.py` (add two module-level helpers; leave `AnthropicClient` in place for now)
- Test: `tests/core/test_ai_client.py` (add helper tests)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `_extract_json(text: str) -> str | None` — pulls the first JSON object/array out of a text reply (strips ``` fences / prose).
  - `_json_via_prompt(complete_text_fn: Callable[[str, str], str | None], system: str, user: str, schema: type[T], *, retries: int = 1) -> T | None` — schema-in-prompt → `complete_text_fn` → extract → `schema.model_validate_json` → retry.

- [ ] **Step 1: Write the failing helper tests**

Append to `tests/core/test_ai_client.py`:

```python
def test_extract_json_plain():
    assert aic._extract_json('{"value": "hi"}') == '{"value": "hi"}'


def test_extract_json_fenced_and_prose():
    text = 'Sure!\n```json\n{"value": "hi"}\n```\nDone.'
    assert aic._extract_json(text) == '{"value": "hi"}'


def test_extract_json_none_when_absent():
    assert aic._extract_json("no json here") is None
    assert aic._extract_json("") is None


def test_json_via_prompt_valid_first_try():
    calls = []

    def fake_text(system, user):
        calls.append((system, user))
        return '{"value": "ok"}'

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out)
    assert out is not None and out.value == "ok"
    assert "JSON Schema" in calls[0][0]  # schema was appended to the system prompt


def test_json_via_prompt_retries_then_succeeds():
    seq = iter(["garbage", '{"value": "ok"}'])

    def fake_text(system, user):
        return next(seq)

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out, retries=1)
    assert out is not None and out.value == "ok"


def test_json_via_prompt_none_when_never_valid():
    assert aic._json_via_prompt(lambda s, u: "nope", "sys", "usr", _Out, retries=1) is None
    assert aic._json_via_prompt(lambda s, u: None, "sys", "usr", _Out) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_ai_client.py -k "extract_json or json_via_prompt" -v`
Expected: FAIL with `AttributeError: module ... has no attribute '_extract_json'`.

- [ ] **Step 3: Implement the helpers**

In `src/ptflow/core/ai/client.py`, add these imports at the top if missing (`json` and the typing bits) and insert the helpers below the `LLMClient` Protocol definition:

```python
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
```

Add `Callable` to the typing import (`from collections.abc import Callable` — under `TYPE_CHECKING` is fine since it's only an annotation; if ruff flags a runtime need, import it at top level).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_ai_client.py -k "extract_json or json_via_prompt" -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check src/ptflow/core/ai/client.py tests/core/test_ai_client.py`
Expected: clean.

```bash
git add src/ptflow/core/ai/client.py tests/core/test_ai_client.py
git commit -m "$(printf 'feat(ai): shared prompt-based JSON helper for structured-output fallback\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 3: `OpenAICompatibleClient`

**Files:**
- Modify: `src/ptflow/core/ai/client.py` (add the class)
- Test: `tests/core/test_ai_client.py` (add tests)

**Interfaces:**
- Consumes: `_json_via_prompt` (Task 2).
- Produces: `OpenAICompatibleClient(model: str, base_url: str | None = None, api_key: str | None = None, client: object | None = None)` with `name = "openai"` and the two `LLMClient` methods. Native `response_format` json_schema first; on any failure, `_json_via_prompt` fallback.

- [ ] **Step 1: Write the failing tests**

Append to `tests/core/test_ai_client.py`:

```python
def _openai_fake(*, native_json=None, native_raises=False, text=None):
    class _Msg:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content):
            self.message = _Msg(content)

    class _Resp:
        def __init__(self, content):
            self.choices = [_Choice(content)]

    class _Completions:
        @staticmethod
        def create(**kwargs):
            if "response_format" in kwargs:
                if native_raises:
                    raise RuntimeError("no structured output")  # noqa: EM101
                return _Resp(native_json)
            return _Resp(text)

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    return _Client()


def test_openai_complete_json_native():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_json='{"value": "hi"}'))
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None and out.value == "hi"


def test_openai_complete_json_falls_back_to_prompt():
    # native path raises; plain create() (no response_format) returns the JSON for the fallback
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_raises=True,
                                                                  text='{"value": "fb"}'))
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None and out.value == "fb"


def test_openai_complete_text():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(text="hello world"))
    assert c.complete_text("sys", "usr") == "hello world"


def test_openai_complete_json_none_when_all_fail():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_raises=True, text="garbage"))
    assert c.complete_json("sys", "usr", _Out) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_ai_client.py -k openai -v`
Expected: FAIL with `AttributeError: ... has no attribute 'OpenAICompatibleClient'`.

- [ ] **Step 3: Implement the class**

In `src/ptflow/core/ai/client.py`, add:

```python
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
        except Exception:  # noqa: BLE001  (best-effort)
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_ai_client.py -k openai -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check src/ptflow/core/ai/client.py tests/core/test_ai_client.py`
Expected: clean.

```bash
git add src/ptflow/core/ai/client.py tests/core/test_ai_client.py
git commit -m "$(printf 'feat(ai): OpenAICompatibleClient (Ollama/OpenRouter) with hybrid structured output\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 4: `ClaudeCodeClient`

**Files:**
- Modify: `src/ptflow/core/ai/client.py` (add the class + two message-reading helpers; add `import anyio` at top)
- Test: `tests/core/test_ai_client.py` (add tests)

**Interfaces:**
- Consumes: `_json_via_prompt` (Task 2).
- Produces: `ClaudeCodeClient(model: str | None = None, *, query=None, options_cls=None)` with `name = "claude-code"` and the two `LLMClient` methods. `query`/`options_cls` are injectable async-SDK seams for tests; production imports `claude_agent_sdk.query` / `ClaudeAgentOptions` lazily. Runs the agent with `tools=[]` (pure text-gen). `complete_json` reads native `structured_output` first, falls back to `_json_via_prompt`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/core/test_ai_client.py`:

```python
class _CCBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _CCMsg:
    def __init__(self, blocks=None, structured_output=None):
        self.content = blocks or []
        if structured_output is not None:
            self.structured_output = structured_output


def _cc_query(messages):
    async def _q(**_kwargs):
        for m in messages:
            yield m
    return _q


class _CCOptions:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def test_claude_code_complete_text():
    q = _cc_query([_CCMsg([_CCBlock("hello "), _CCBlock("world")])])
    c = aic.ClaudeCodeClient(query=q, options_cls=_CCOptions)
    assert c.complete_text("sys", "usr") == "hello world"


def test_claude_code_complete_json_native():
    q = _cc_query([_CCMsg(structured_output={"value": "hi"})])
    c = aic.ClaudeCodeClient(query=q, options_cls=_CCOptions)
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None and out.value == "hi"


def test_claude_code_complete_json_falls_back_to_prompt():
    # no structured_output on the message → complete_json re-runs via complete_text (prompt fallback)
    q = _cc_query([_CCMsg([_CCBlock('{"value": "fb"}')])])
    c = aic.ClaudeCodeClient(query=q, options_cls=_CCOptions)
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None and out.value == "fb"


def test_claude_code_options_disable_tools():
    captured = {}

    class _Opts:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    q = _cc_query([_CCMsg([_CCBlock("x")])])
    aic.ClaudeCodeClient(query=q, options_cls=_Opts).complete_text("sys", "usr")
    assert captured.get("tools") == []
    assert captured.get("system_prompt") == "sys"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/core/test_ai_client.py -k claude_code -v`
Expected: FAIL with `AttributeError: ... has no attribute 'ClaudeCodeClient'`.

- [ ] **Step 3: Implement the class + helpers**

In `src/ptflow/core/ai/client.py`, add `import anyio` at the top of the module, then add:

```python
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
        except Exception:  # noqa: BLE001  (best-effort)
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/core/test_ai_client.py -k claude_code -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Lint + commit**

Run: `uv run ruff check src/ptflow/core/ai/client.py tests/core/test_ai_client.py`
Expected: clean.

```bash
git add src/ptflow/core/ai/client.py tests/core/test_ai_client.py
git commit -m "$(printf 'feat(ai): ClaudeCodeClient (Agent SDK, subscription auth, tools disabled)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 5: Rewrite `make_client`; remove `AnthropicClient`

**Files:**
- Modify: `src/ptflow/core/ai/client.py` (rewrite `make_client`; delete `AnthropicClient` + `_DEFAULT_MODEL`; refresh the module docstring)
- Test: `tests/core/test_ai_client.py` (remove the four `AnthropicClient`/old-`make_client` tests; add the new routing tests)

**Interfaces:**
- Consumes: `ClaudeCodeClient` (Task 4), `OpenAICompatibleClient` (Task 3).
- Produces: `make_client() -> LLMClient | None` routing on `PTFLOW_AI` + `PTFLOW_AI_PROVIDER` (default `claude-code`). No `AnthropicClient` in the module.

- [ ] **Step 1: Replace the make_client tests**

In `tests/core/test_ai_client.py`, DELETE these four tests: `test_make_client_none_for_unsupported_provider`, `test_make_client_builds_when_enabled`, `test_complete_json_maps_parsed_output`, `test_complete_json_returns_none_on_error`, and `test_complete_text_concatenates_text_blocks` (all reference `AnthropicClient`). Keep `test_make_client_none_when_disabled` and the `_Out` model. Add:

```python
def test_make_client_default_provider_is_claude_code(monkeypatch):
    pytest.importorskip("claude_agent_sdk")
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.delenv("PTFLOW_AI_PROVIDER", raising=False)
    monkeypatch.delenv("PTFLOW_AI_MODEL", raising=False)
    c = aic.make_client()
    assert isinstance(c, aic.ClaudeCodeClient)


def test_make_client_openai_requires_model(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "openai")
    monkeypatch.delenv("PTFLOW_AI_MODEL", raising=False)
    assert aic.make_client() is None


def test_make_client_openai_builds_with_model(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "openai")
    monkeypatch.setenv("PTFLOW_AI_MODEL", "llama3.1")
    monkeypatch.setenv("PTFLOW_AI_BASE_URL", "http://localhost:11434/v1")
    c = aic.make_client()
    assert isinstance(c, aic.OpenAICompatibleClient)
    assert c.model == "llama3.1"


def test_make_client_unknown_provider(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "bogus")
    assert aic.make_client() is None
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `uv run pytest tests/core/test_ai_client.py -k make_client -v`
Expected: FAIL — `test_make_client_default_provider_is_claude_code` still gets an `AnthropicClient` (old make_client), and `AnthropicClient` no longer referenced tests were removed. (The default test fails because make_client still routes to anthropic.)

- [ ] **Step 3: Rewrite make_client + delete AnthropicClient**

In `src/ptflow/core/ai/client.py`: delete the `AnthropicClient` class and the `_DEFAULT_MODEL = "claude-opus-4-8"` line, and replace the whole `make_client()` function with:

```python
def make_client() -> LLMClient | None:
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
```

Also update the module docstring (lines 1-9): replace the "ships one concrete implementation, `AnthropicClient`" wording with a description of the two providers (`claude-code` default, `openai`-compatible) and note both SDKs are lazy optional-extra imports.

- [ ] **Step 4: Run the full AI-client test file**

Run: `uv run pytest tests/core/test_ai_client.py -v`
Expected: PASS (helper + openai + claude_code + make_client tests; no `AnthropicClient` references remain).

- [ ] **Step 5: Run the AI stage tests (verify the seam still satisfies the stages)**

Run: `uv run pytest tests/pipelines/test_external_ai.py -v`
Expected: PASS unchanged (the stages inject their own `_FakeClient` and monkeypatch `make_client`).

- [ ] **Step 6: Confirm no lingering AnthropicClient references**

Run: `grep -rn "AnthropicClient\|_DEFAULT_MODEL\|import anthropic\|from anthropic" src/ tests/`
Expected: no hits.

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check src/ptflow/core/ai/client.py tests/core/test_ai_client.py && uv run ty check src/`
Expected: clean.

```bash
git add src/ptflow/core/ai/client.py tests/core/test_ai_client.py
git commit -m "$(printf 'feat(ai): provider-agnostic make_client (claude-code default | openai); drop AnthropicClient\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 6: Docs + full dev gate

**Files:**
- Modify: `CLAUDE.md` (the "AI layer" bullet under "External environment gotchas")
- Modify: `ptflow.toml.example` (the AI knob annotations, if present)

**Interfaces:**
- Consumes: the finished implementation.
- Produces: docs describing the two providers, the knobs, the auth env vars, and the `claude` CLI gotcha.

- [ ] **Step 1: Update the CLAUDE.md AI-layer section**

Rewrite the `**AI layer (opt-in, `--ai` / `PTFLOW_AI=on`)**` bullet in `CLAUDE.md` so it states: the layer is provider-agnostic behind `core/ai/` (`LLMClient` + `make_client`); two providers via `PTFLOW_AI_PROVIDER` — **`claude-code`** (default; Claude Code Agent SDK on the operator's subscription, auth via `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`, or `ANTHROPIC_API_KEY`; requires the `claude` CLI on PATH) and **`openai`** (OpenAI-compatible: Ollama local/cloud, OpenRouter, via `PTFLOW_AI_BASE_URL` + `PTFLOW_AI_MODEL` [required] + `OPENAI_API_KEY`); structured output is hybrid (native first, prompt+validate+retry fallback for models like local Ollama that lack schema support); `claude-agent-sdk` + `openai` are the optional `ai` extra; the four stages (`ai_wordlist`/`ai_secret_triage`/`ai_triage`/`ai_report`) and the "AI off → DAG byte-identical" invariant are unchanged. Remove the old "Anthropic Messages API, `claude-opus-4-8` default" wording and the "v1: anthropic only" provider note.

- [ ] **Step 2: Update ptflow.toml.example**

Run: `grep -n "provider\|ai\." ptflow.toml.example`
If the AI knobs are present, update the `provider` annotation to `claude-code | openai` (default `claude-code`), note `model` is required for `openai`, and that keys are standard env vars (`CLAUDE_CODE_OAUTH_TOKEN`/`OPENAI_API_KEY`), not TOML knobs. If the file has no AI section, skip (no change).

- [ ] **Step 3: Regenerate flow maps (docs automation, if the hook didn't)**

Run: `uv run python -m ptflow.core.flowdocs`
Expected: no diff for this change (the AI stages' graph is unchanged), or a deterministic regeneration — stage any resulting `docs/*-pipeline-*` changes.

- [ ] **Step 4: Run the full dev gate**

Run: `uv run ruff check . && uv run ty check src/ && uv run pytest`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md ptflow.toml.example docs/
git commit -m "$(printf 'docs(ai): document provider-agnostic AI layer (claude-code | openai)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Post-implementation smoke tests (manual, cannot run offline)

These verify the two uncertainties the unit tests can't cover; run against real endpoints:

1. **claude-code auth headless:** `claude setup-token` → export `CLAUDE_CODE_OAUTH_TOKEN`; run `uv run ptflow run external <act> <scope> --ai` (provider defaults to claude-code) and confirm `report.md` + `findings/hypotheses.jsonl` are produced.
2. **claude-code native structured output:** confirm `ai_triage`/`ai_wordlist` produce validated output; if the installed `claude-agent-sdk` ignores `output_format`, the prompt fallback still yields valid output (check the logs for "using prompt fallback").
3. **openai / Ollama local:** `PTFLOW_AI_PROVIDER=openai PTFLOW_AI_BASE_URL=http://localhost:11434/v1 PTFLOW_AI_MODEL=<local-model> uv run ptflow run external <act> <scope> --ai` → confirm the AI artifacts appear (and the hybrid fallback engages for a model without native schema support).

---

## Self-Review

**1. Spec coverage:**
- Two backends behind `LLMClient` → Tasks 3, 4. ✔
- `claude-code` default, subscription auth, tools disabled → Task 4 (tools=[]) + Task 5 (default). ✔
- `openai` covers Ollama/OpenRouter via base_url → Task 3. ✔
- Hybrid structured output → Task 2 helper, used by Tasks 3 & 4. ✔
- Provider enum + knobs → Task 1. ✔
- Dependencies (`ai` extra) → Task 1. ✔
- Remove `AnthropicClient` → Task 5. ✔
- Best-effort / net=False / AI-off byte-identical invariants → preserved (make_client None path unchanged; stages untouched; verified in Task 5 Step 5). ✔
- Testing (helper, both clients, make_client routing, runconfig enum, stage tests stay green) → Tasks 1-5. ✔
- Docs (CLAUDE.md, ptflow.toml.example) → Task 6. ✔

**2. Placeholder scan:** No "TBD"/"handle edge cases"/"similar to Task N" — every code step shows full code. Task 6 Step 2 is conditional (grep-then-edit) but concrete. ✔

**3. Type consistency:** `_json_via_prompt(complete_text_fn, system, user, schema, *, retries=1)` — same signature where called in Tasks 3 & 4. `OpenAICompatibleClient(model, base_url, api_key, client)` and `ClaudeCodeClient(model, *, query, options_cls)` — match the tests and `make_client` construction in Task 5. `name` attrs: `"openai"`, `"claude-code"`. ✔
