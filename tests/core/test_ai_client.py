import pydantic
import pytest

from ptflow.core.ai import client as aic


class _Out(pydantic.BaseModel):
    value: str


def test_make_client_none_when_disabled(monkeypatch):
    monkeypatch.delenv("PTFLOW_AI", raising=False)
    assert aic.make_client() is None


def test_make_client_none_for_unsupported_provider(monkeypatch):
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.setenv("PTFLOW_AI_PROVIDER", "openai")
    assert aic.make_client() is None


def test_make_client_builds_when_enabled(monkeypatch):
    pytest.importorskip("anthropic")
    monkeypatch.setenv("PTFLOW_AI", "on")
    monkeypatch.delenv("PTFLOW_AI_PROVIDER", raising=False)
    monkeypatch.setenv("PTFLOW_AI_MODEL", "claude-opus-4-8")
    c = aic.make_client()
    assert isinstance(c, aic.AnthropicClient)
    assert c.model == "claude-opus-4-8"


def test_complete_json_maps_parsed_output():
    class _Msg:
        parsed_output = _Out(value="hi")

    class _Fake:
        class messages:  # noqa: N801
            @staticmethod
            def parse(**_kwargs):
                return _Msg()

    c = aic.AnthropicClient(client=_Fake())
    out = c.complete_json("sys", "usr", _Out)
    assert out is not None
    assert out.value == "hi"


def test_complete_json_returns_none_on_error():
    class _Fake:
        class messages:  # noqa: N801
            @staticmethod
            def parse(**_kwargs):
                raise RuntimeError("boom")  # noqa: EM101

    c = aic.AnthropicClient(client=_Fake())
    assert c.complete_json("sys", "usr", _Out) is None


def test_complete_text_concatenates_text_blocks():
    class _Block:
        type = "text"
        text = "hello "

    class _Block2:
        type = "text"
        text = "world"

    class _Msg:
        content = [_Block(), _Block2()]  # noqa: RUF012

    class _Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return _Msg()

    class _Fake:
        class messages:  # noqa: N801
            @staticmethod
            def stream(**_kwargs):
                return _Stream()

    c = aic.AnthropicClient(client=_Fake())
    assert c.complete_text("sys", "usr") == "hello world"


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
