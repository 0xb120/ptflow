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
