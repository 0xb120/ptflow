import pydantic
import pytest

from ptflow.core.ai import client as aic


class _Out(pydantic.BaseModel):
    value: str


def test_make_client_none_when_disabled(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    assert aic.make_client() is None


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
    assert out is not None
    assert out.value == "ok"
    assert "JSON Schema" in calls[0][0]  # schema was appended to the system prompt


def test_json_via_prompt_retries_then_succeeds():
    seq = iter(["garbage", '{"value": "ok"}'])

    def fake_text(_system, _user):
        return next(seq)

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out, retries=1)
    assert out is not None
    assert out.value == "ok"


def test_json_via_prompt_none_when_never_valid():
    assert aic._json_via_prompt(lambda _s, _u: "nope", "sys", "usr", _Out, retries=1) is None
    assert aic._json_via_prompt(lambda _s, _u: None, "sys", "usr", _Out) is None


def test_extract_json_fence_only_no_prose():
    # input that STARTS with the fence — exercises the fence-stripping branch, not the bracket fallback
    assert aic._extract_json('```json\n{"value": "hi"}\n```') == '{"value": "hi"}'


def test_json_via_prompt_retries_on_schema_invalid():
    # first reply is syntactically valid JSON but fails schema validation → validate-retry path
    seq = iter(['{"wrong": "x"}', '{"value": "ok"}'])

    def fake_text(_system, _user):
        return next(seq)

    out = aic._json_via_prompt(fake_text, "sys", "usr", _Out, retries=1)
    assert out is not None
    assert out.value == "ok"


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
    assert out is not None
    assert out.value == "hi"


def test_openai_complete_json_falls_back_to_prompt():
    # native path raises; plain create() (no response_format) returns the JSON for the fallback
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_raises=True,
                                                                  text='{"value": "fb"}'))
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None
    assert out.value == "fb"


def test_openai_complete_text():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(text="hello world"))
    assert c.complete_text("sys", "usr") == "hello world"


def test_openai_complete_json_none_when_all_fail():
    c = aic.OpenAICompatibleClient(model="m", client=_openai_fake(native_raises=True, text="garbage"))
    assert c.complete_json("sys", "usr", _Out) is None


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
    assert out is not None
    assert out.value == "hi"


def test_claude_code_complete_json_falls_back_to_prompt():
    # no structured_output on the message → complete_json re-runs via complete_text (prompt fallback)
    q = _cc_query([_CCMsg([_CCBlock('{"value": "fb"}')])])
    c = aic.ClaudeCodeClient(query=q, options_cls=_CCOptions)
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None
    assert out.value == "fb"


def test_openai_does_not_forward_max_tokens():
    # OpenAI-compatible cloud endpoints (OpenRouter, OpenAI) 400 on a max_tokens above the model's
    # output cap; forwarding our best-effort default (64000 / 16000) would silently degrade to None.
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
    c.complete_text("s", "u")
    c.complete_json("s", "u", _Out)  # exercises the native path
    assert captured, "create was never called"
    assert all("max_tokens" not in kw for kw in captured), captured


def test_claude_code_options_disable_tools():
    captured = {}

    class _Opts:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    q = _cc_query([_CCMsg([_CCBlock("x")])])
    aic.ClaudeCodeClient(query=q, options_cls=_Opts).complete_text("sys", "usr")
    assert captured.get("tools") == []
    assert captured.get("system_prompt") == "sys"
