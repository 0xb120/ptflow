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
