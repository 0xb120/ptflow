from pipt.core import orchestrator
from pipt.core.stage import Stage


def test_topo_order_respects_deps():
    a = Stage("a", lambda *_: None)
    b = Stage("b", lambda *_: None, needs=("a",))
    c = Stage("c", lambda *_: None, needs=("a",))
    d = Stage("d", lambda *_: None, needs=("b", "c"))
    order = [s.name for s in orchestrator.topo_order([d, c, b, a])]
    assert order.index("a") < order.index("b")
    assert order.index("a") < order.index("c")
    assert order.index("b") < order.index("d")
    assert order.index("c") < order.index("d")


def test_topo_order_ignores_foreign_needs():
    # a need that isn't in the given set (e.g. a cross-scope dep) is skipped
    s = Stage("only", lambda *_: None, needs=("not_here",))
    assert [x.name for x in orchestrator.topo_order([s])] == ["only"]


def test_per_app_loops_groups_by_phase_in_order():
    stages = [
        Stage("expand", lambda *_: None),                          # activity → excluded
        Stage("a", lambda *_: None, per_app=True, phase=1),
        Stage("b", lambda *_: None, needs=("a",), per_app=True, phase=1),
        Stage("c", lambda *_: None, per_app=True, phase=2),
    ]
    loops = orchestrator.per_app_loops(stages)
    assert [phase for phase, _ in loops] == [1, 2]
    assert [[s.name for s in ss] for _, ss in loops] == [["a", "b"], ["c"]]
