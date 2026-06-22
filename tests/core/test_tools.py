from pipt.core import tools


def test_dedupe_preserves_order_strips_blanks():
    assert tools.dedupe(["b", " b ", "a", "", "a", "c"]) == ["b", "a", "c"]


def test_write_then_read_roundtrip(tmp_path):
    p = tmp_path / "out.txt"
    n = tools.write_lines(p, ["x", "x", "y"])
    assert n == 2
    assert tools.read_lines(p) == ["x", "y"]


def test_read_missing_returns_empty(tmp_path):
    assert tools.read_lines(tmp_path / "nope.txt") == []


def test_run_echoes_stdout():
    assert tools.run(["printf", "hello"]) == "hello"


def test_run_warns_on_nonzero_exit():
    import logging

    from pipt.core.log import get_logger

    lg = get_logger()
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append          # capture records directly (bypasses propagate)
    handler.setLevel(logging.WARNING)
    lg.addHandler(handler)
    try:
        tools.run(["false"])               # exits 1 → should warn, not stay silent
    finally:
        lg.removeHandler(handler)
    assert any(r.levelno == logging.WARNING and "exited 1" in r.getMessage() for r in records)


def test_pipe_chains_processes():
    out = tools.pipe([["printf", "a\nb\na\n"], ["sort", "-u"]])
    assert out.splitlines() == ["a", "b"]


def test_require_raises_for_missing_tool():
    import pytest

    with pytest.raises(tools.ToolNotFoundError):
        tools.require("definitely-not-a-real-binary-xyz")


def test_pipe_single_stage_stdin():
    out = tools.pipe([["sort", "-u"]], stdin="b\na\nb\n")
    assert out.splitlines() == ["a", "b"]


def test_pipe_multi_stage_stdin():
    out = tools.pipe([["cat"], ["sort", "-u"]], stdin="b\na\nb\n")
    assert out.splitlines() == ["a", "b"]


def test_read_lines_strips(tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("  a  \n\n b\n")
    assert tools.read_lines(p) == ["a", "b"]


def test_write_then_read_jsonl_roundtrip(tmp_path):
    p = tmp_path / "out.jsonl"
    n = tools.write_jsonl(p, [{"a": 1}, {"b": 2}])
    assert n == 2
    assert tools.read_jsonl(p) == [{"a": 1}, {"b": 2}]


def test_read_jsonl_missing_returns_empty(tmp_path):
    assert tools.read_jsonl(tmp_path / "nope.jsonl") == []


def test_run_stream_stderr_returns_stdout():
    assert tools.run(["printf", "hi"], stream_stderr=True) == "hi"
