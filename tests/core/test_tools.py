import time

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


def test_read_lines_tolerates_non_utf8(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"good\n\x93bad\nok\n")  # 0x93 = Windows-1252 byte, invalid UTF-8
    assert tools.read_lines(p) == ["good", "�bad", "ok"]  # replaced, not raised


def test_read_jsonl_tolerates_non_utf8(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_bytes(b'{"k": "a\x93b"}\n')  # invalid byte inside a JSON string value
    assert tools.read_jsonl(p) == [{"k": "a�b"}]  # decoded with replace, still valid JSON


def test_write_then_read_jsonl_roundtrip(tmp_path):
    p = tmp_path / "out.jsonl"
    n = tools.write_jsonl(p, [{"a": 1}, {"b": 2}])
    assert n == 2
    assert tools.read_jsonl(p) == [{"a": 1}, {"b": 2}]


def test_read_jsonl_missing_returns_empty(tmp_path):
    assert tools.read_jsonl(tmp_path / "nope.jsonl") == []


def test_read_jsonl_skips_unparseable_lines(tmp_path):
    # a file holding a tool's RAW stdout (nerva/nuclei) may carry a stray non-JSON line (banner/
    # progress) — it must be skipped, not crash the consuming stage.
    p = tmp_path / "raw.jsonl"
    p.write_text('{"a": 1}\nstarting scan...\n{"b": 2}\n   \nnot json\n', encoding="utf-8")
    assert tools.read_jsonl(p) == [{"a": 1}, {"b": 2}]


def test_run_stream_stderr_returns_stdout():
    assert tools.run(["printf", "hi"], stream_stderr=True) == "hi"


def test_run_tolerates_non_utf8_output():
    # a tool emitting a non-UTF-8 byte (0x93, a Windows-1252 smart quote — seen in urlfinder OSINT
    # output) must NOT raise UnicodeDecodeError and kill the stage; the bad byte → U+FFFD
    out = tools.run(["printf", r"a\x93b"])
    assert out.startswith("a")
    assert out.endswith("b")
    assert "�" in out  # replaced, not raised


def test_run_aborts_without_spawning():
    import pytest

    tools.signal_abort()
    try:
        with pytest.raises(tools.AbortedError):
            tools.run(["printf", "x"])  # must NOT spawn while aborting
        with pytest.raises(tools.AbortedError):
            tools.pipe([["printf", "x"]])
    finally:
        tools.clear_abort()
    assert tools.run(["printf", "x"]) == "x"  # spawns normally again after clear


def test_run_reap_group_returns_output():
    # reap_group SIGKILLs the child's process group on exit (to sweep stragglers like headless
    # chrome); a normal command with no stragglers must still return its stdout unaffected
    assert tools.run(["printf", "ok"], reap_group=True) == "ok"


def test_run_unregisters_after_completion():
    # a finished tool leaves nothing in the live-subprocess registry
    tools.run(["printf", "x"])
    assert not [p for p in tools._live if p.poll() is None]


def test_terminate_all_noop_when_idle():
    assert tools.terminate_all() == 0


def test_run_stdin_tty_makes_child_stdin_a_tty():
    # sqlmap (and kin) gate on os.isatty(0): a plain pipe makes `sqlmap -r` silently switch to
    # reading targets from STDIN and test NOTHING. stdin_tty hands the child a pty slave so
    # isatty(0) is True. This regression-guards that fix.
    import sys

    out = tools.run([sys.executable, "-c", "import os,sys; print(os.isatty(sys.stdin.fileno()))"],
                    stdin_tty=True)
    assert out.strip() == "True"


def test_terminate_all_kills_running_process():
    import threading

    done = threading.Event()

    def _long():
        tools.run(["sleep", "30"])  # blocks until killed
        done.set()

    t = threading.Thread(target=_long, daemon=True)
    t.start()
    # wait until the sleep is registered as live
    for _ in range(100):
        if [p for p in tools._live if p.poll() is None]:
            break
        time.sleep(0.05)
    assert [p for p in tools._live if p.poll() is None], "sleep never registered"

    killed = tools.terminate_all()
    assert killed >= 1
    assert done.wait(timeout=10), "tools.run did not return after terminate_all"
    assert not [p for p in tools._live if p.poll() is None]
