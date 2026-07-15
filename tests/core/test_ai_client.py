import json

import pydantic
import pytest

from ptflow.core.ai import client as aic
from ptflow.core.paths import Activity


class _Out(pydantic.BaseModel):
    value: str


def _result(value, *, provider="fake", model="m"):
    return aic.LLMResult(value=value, provider=provider, model=model)


def test_make_client_none_when_disabled(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    assert aic.make_client() is None


def test_make_client_default_provider_is_local_ollama(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.delenv("PTFLOW_AI_PROVIDER", raising=False)
    monkeypatch.setenv("PTFLOW_AI_MODEL", "gpt-oss:20b")
    monkeypatch.delenv("PTFLOW_AI_BASE_URL", raising=False)
    c = aic.make_client()
    assert isinstance(c, aic.OpenAICompatibleClient)
    assert c.name == "ollama"
    assert c._base_url == "http://127.0.0.1:11434/v1"
    assert c._api_key == "ollama"


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


@pytest.mark.parametrize(("provider", "key_env", "key", "base_url"), [
    ("openrouter", "OPENROUTER_API_KEY", "or-key", "https://openrouter.ai/api/v1"),
    ("huggingface", "HF_TOKEN", "hf-key", "https://router.huggingface.co/v1"),
])
def test_make_client_named_hosted_provider(monkeypatch, provider, key_env, key, base_url):
    pytest.importorskip("openai")
    for name in ("OPENROUTER_API_KEY", "HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", provider)
    monkeypatch.setenv("PTFLOW_AI_MODEL", "provider/model")
    monkeypatch.delenv("PTFLOW_AI_BASE_URL", raising=False)
    monkeypatch.setenv(key_env, key)

    c = aic.make_client()

    assert isinstance(c, aic.OpenAICompatibleClient)
    assert c.name == provider
    assert c._base_url == base_url
    assert c._api_key == key


@pytest.mark.parametrize("provider", ["openrouter", "huggingface"])
def test_make_client_hosted_provider_requires_credential(monkeypatch, provider):
    for name in ("OPENROUTER_API_KEY", "HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", provider)
    monkeypatch.setenv("PTFLOW_AI_MODEL", "provider/model")
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-provider-key")
    assert aic.make_client() is None


def test_make_client_generic_provider_requires_base_url(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "openai-compatible")
    monkeypatch.setenv("PTFLOW_AI_MODEL", "provider/model")
    monkeypatch.delenv("PTFLOW_AI_BASE_URL", raising=False)
    assert aic.make_client() is None


def test_make_client_claude_code_remains_explicit_legacy_provider(monkeypatch):
    pytest.importorskip("claude_agent_sdk")
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "claude-code")
    monkeypatch.delenv("PTFLOW_AI_MODEL", raising=False)
    assert isinstance(aic.make_client(), aic.ClaudeCodeClient)


def test_make_client_unknown_provider(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "bogus")
    assert aic.make_client() is None


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
        return _result('{"value": "ok"}')

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out)
    assert out.value is not None
    assert out.value.value == "ok"
    assert "JSON Schema" in calls[0][0]  # schema was appended to the system prompt


def test_json_via_prompt_retries_then_succeeds():
    seq = iter(["garbage", '{"value": "ok"}'])

    def fake_text(_system, _user):
        return _result(next(seq))

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out, retries=1)
    assert out.value is not None
    assert out.value.value == "ok"


def test_json_via_prompt_none_when_never_valid():
    assert aic._json_via_prompt(
        lambda _s, _u: _result("nope"), "sys", "usr", _Out, retries=1,
    ).value is None
    assert aic._json_via_prompt(
        lambda _s, _u: _result(None), "sys", "usr", _Out,
    ).value is None


def test_extract_json_fence_only_no_prose():
    # input that STARTS with the fence — exercises the fence-stripping branch, not the bracket fallback
    assert aic._extract_json('```json\n{"value": "hi"}\n```') == '{"value": "hi"}'


def test_json_via_prompt_retries_on_schema_invalid():
    # first reply is syntactically valid JSON but fails schema validation → validate-retry path
    seq = iter(['{"wrong": "x"}', '{"value": "ok"}'])

    def fake_text(_system, _user):
        return _result(next(seq))

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out, retries=1)
    assert out.value is not None
    assert out.value.value == "ok"


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
                    msg = "no structured output"
                    raise RuntimeError(msg)
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
    assert out.value is not None
    assert out.value.value == "hi"


def test_openai_complete_json_falls_back_to_prompt():
    # native path raises; plain create() (no response_format) returns the JSON for the fallback
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_raises=True,
                                                                  text='{"value": "fb"}'))
    out = c.complete_json("sys", "usr", _Out)
    assert out.value is not None
    assert out.value.value == "fb"
    assert out.structured_fallback is True


def test_openai_complete_text():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(text="hello world"))
    assert c.complete_text("sys", "usr").value == "hello world"


def test_openai_complete_json_none_when_all_fail():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_raises=True, text="garbage"))
    result = c.complete_json("sys", "usr", _Out)
    assert result.value is None
    assert result.error == "invalid_structured_output"


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
    assert c.complete_text("sys", "usr").value == "hello world"


def test_claude_code_complete_json_native():
    q = _cc_query([_CCMsg(structured_output={"value": "hi"})])
    c = aic.ClaudeCodeClient(query=q, options_cls=_CCOptions)
    out = c.complete_json("sys", "usr", _Out)
    assert out.value is not None
    assert out.value.value == "hi"


def test_claude_code_complete_json_falls_back_to_prompt():
    # no structured_output on the message → complete_json re-runs via complete_text (prompt fallback)
    q = _cc_query([_CCMsg([_CCBlock('{"value": "fb"}')])])
    c = aic.ClaudeCodeClient(query=q, options_cls=_CCOptions)
    out = c.complete_json("sys", "usr", _Out)
    assert out.value is not None
    assert out.value.value == "fb"
    assert out.structured_fallback is True


def test_openai_forwards_explicit_bounded_generation_settings():
    captured = []

    class _Msg:
        content = '{"value": "x"}'

    class _Choice:
        message = _Msg()

    class _Resp:
        def __init__(self):
            self.choices = [_Choice()]

    class _Completions:
        @staticmethod
        def create(**kwargs):
            captured.append(kwargs)
            return _Resp()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    c = aic.OpenAICompatibleClient(model="m", client=_Client())
    c.complete_text("s", "u", max_tokens=123)
    c.complete_json("s", "u", _Out, max_tokens=456)
    assert captured, "create was never called"
    assert [item["max_tokens"] for item in captured] == [123, 456]
    assert all(item["temperature"] == 0 for item in captured)


def test_claude_code_options_disable_tools():
    captured = {}

    class _Opts:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    q = _cc_query([_CCMsg([_CCBlock("x")])])
    aic.ClaudeCodeClient(query=q, options_cls=_Opts).complete_text("sys", "usr")
    assert captured.get("tools") == []
    assert captured.get("system_prompt") == "sys"


class _StaticClient:
    name = "static"
    model = "static-model"
    remote = False

    def __init__(self):
        self.calls = 0

    def complete_text(self, system, user, *, max_tokens=4096):  # noqa: ARG002
        self.calls += 1
        return aic.LLMResult(
            value="hello", provider=self.name, model=self.model,
            prompt_tokens=3, completion_tokens=2, total_tokens=5, cost=0.01, latency_ms=4,
        )

    def complete_json(self, system, user, schema, *, max_tokens=4096):  # noqa: ARG002
        self.calls += 1
        return aic.LLMResult(
            value=schema(value="ok"), provider=self.name, model=self.model,
            prompt_tokens=3, completion_tokens=2, total_tokens=5, cost=0.01, latency_ms=4,
        )


def test_managed_client_caches_and_records_usage(tmp_path, monkeypatch):
    monkeypatch.setenv("PTFLOW_AI_CACHE", "on")
    act = Activity.named("cache", root=tmp_path).ensure()
    raw = _StaticClient()
    client = aic.ManagedLLMClient(raw, act, "triage")

    first = client.complete_json("system", "user", _Out)
    second = client.complete_json("system", "user", _Out)

    assert first.value == _Out(value="ok")
    assert second.value == _Out(value="ok")
    assert second.cache_hit is True
    assert raw.calls == 1
    usage = [json.loads(line) for line in (act.base / "ai" / "usage.jsonl").read_text().splitlines()]
    assert [row["cache_hit"] for row in usage] == [False, True]
    assert usage[0]["cost"] == 0.01
    assert "value" not in usage[0]


def test_managed_client_enforces_call_budget_without_raising(tmp_path, monkeypatch):
    monkeypatch.setenv("PTFLOW_AI_CACHE", "off")
    monkeypatch.setenv("PTFLOW_AI_MAX_CALLS", "1")
    act = Activity.named("budget", root=tmp_path).ensure()
    raw = _StaticClient()
    client = aic.ManagedLLMClient(raw, act, "report")

    assert client.complete_text("system", "one").value == "hello"
    blocked = client.complete_text("system", "two")

    assert blocked.value is None
    assert blocked.error == "budget_max_calls"
    assert raw.calls == 1


def test_make_client_uses_stage_routing(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "ollama")
    monkeypatch.setenv("PTFLOW_AI_MODEL", "local")
    monkeypatch.setenv("PTFLOW_AI_STAGE_REPORT_PROVIDER", "openrouter")
    monkeypatch.setenv("PTFLOW_AI_STAGE_REPORT_MODEL", "hosted/model")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")

    client = aic.make_client("report")

    assert isinstance(client, aic.OpenAICompatibleClient)
    assert client.name == "openrouter"
    assert client.model == "hosted/model"
