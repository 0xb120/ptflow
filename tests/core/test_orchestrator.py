from pipt.core import orchestrator
from pipt.core.stage import Mode, Stage


def test_split_stages():
    s1 = Stage(name="a", mode=Mode.BREADTH, run=lambda *_: None)
    s2 = Stage(name="b", mode=Mode.DEPTH, run=lambda *_: None)
    breadth, depth = orchestrator.split_stages([s1, s2])
    assert breadth == [s1]
    assert depth == [s2]
